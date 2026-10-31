use crate::{cli::Network, diagnostics::DiagnosticBuffer};
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use std::{
    io::{self, IsTerminal, Stdout, Write},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(80);
const SNAPSHOT_STALE_AFTER: Duration = Duration::from_secs(20);
const EMERALD: Color = Color::Rgb(41, 242, 107);
const AMBER: Color = Color::Rgb(245, 184, 72);
const GENESIS_AMBER: Color = Color::Rgb(190, 148, 72);
const ERROR_RED: Color = Color::Rgb(239, 83, 80);
const MUTED: Color = Color::Rgb(135, 145, 151);
const LIGHT: Color = Color::Rgb(220, 226, 229);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeStatus {
    Mining,
    CheckingProof,
    Signed,
    Finalizing,
    Confirming,
    Syncing,
    Waiting,
    WaitingForGenesis,
    WaitingForChain,
    FinalizationRequired,
    FinalizationRetrying,
    FinalizationBlocked,
    Recovering,
    Paused,
    Ended,
    RpcError,
}

impl NodeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mining => "● MINING",
            Self::CheckingProof => "CHECKING",
            Self::Signed => "SIGNED",
            Self::Finalizing => "FINALIZING",
            Self::Confirming => "CONFIRMING",
            Self::Syncing => "SYNCING",
            Self::Waiting => "WAITING",
            Self::WaitingForGenesis => "WAIT GENESIS",
            Self::WaitingForChain => "WAIT CHAIN",
            Self::FinalizationRequired => "FINALIZE",
            Self::FinalizationRetrying => "RETRYING",
            Self::FinalizationBlocked => "BLOCKED",
            Self::Recovering => "RECOVERING",
            Self::Paused => "PAUSED",
            Self::Ended => "ENDED",
            Self::RpcError => "RPC ERROR",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Mining => EMERALD,
            Self::Finalizing
            | Self::CheckingProof
            | Self::Signed
            | Self::Confirming
            | Self::Syncing
            | Self::WaitingForChain
            | Self::FinalizationRequired
            | Self::FinalizationRetrying
            | Self::FinalizationBlocked
            | Self::Recovering => AMBER,
            Self::RpcError => ERROR_RED,
            Self::WaitingForGenesis => GENESIS_AMBER,
            Self::Waiting | Self::Paused | Self::Ended => MUTED,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DashboardNode {
    pub id: u8,
    pub window_id: Option<u64>,
    pub status: NodeStatus,
    pub expiry_timestamp: Option<u64>,
    pub mining_deadline: Option<Instant>,
    pub countdown: Option<WindowCountdown>,
    pub candidate: Option<Address>,
    pub reward: Option<U256>,
}

#[derive(Clone, Debug)]
pub struct WindowCountdown {
    window_id: u64,
    pub(crate) expiry_timestamp: u64,
    remaining_at_observed: u64,
    observed_at: Instant,
}

impl WindowCountdown {
    pub fn from_snapshot(
        window_id: u64,
        expiry_timestamp: u64,
        chain_timestamp: u64,
        observed_at: Instant,
    ) -> Self {
        Self {
            window_id,
            expiry_timestamp,
            remaining_at_observed: expiry_timestamp.saturating_sub(chain_timestamp),
            observed_at,
        }
    }

    fn remaining_at(&self, now: Instant) -> u64 {
        self.remaining_at_observed
            .saturating_sub(now.saturating_duration_since(self.observed_at).as_secs())
    }

    pub(crate) fn reconcile_same_window(
        &self,
        expiry_timestamp: u64,
        chain_timestamp: u64,
        observed_at: Instant,
    ) -> Self {
        let old_remaining = self.remaining_at(observed_at);
        let snapshot_remaining = expiry_timestamp.saturating_sub(chain_timestamp);
        Self {
            window_id: self.window_id,
            expiry_timestamp,
            remaining_at_observed: old_remaining.min(snapshot_remaining),
            observed_at,
        }
    }

    pub(crate) fn reanchor(&self, observed_at: Instant) -> Self {
        Self {
            window_id: self.window_id,
            expiry_timestamp: self.expiry_timestamp,
            remaining_at_observed: self.remaining_at(observed_at),
            observed_at,
        }
    }
}

impl DashboardNode {
    pub fn status_at(&self, now: Instant) -> NodeStatus {
        if matches!(self.status, NodeStatus::Mining | NodeStatus::CheckingProof)
            && self.mining_deadline.is_none_or(|deadline| now >= deadline)
        {
            NodeStatus::WaitingForChain
        } else {
            self.status
        }
    }

    pub fn time_left(&self, now: Instant) -> Option<u64> {
        if !matches!(
            self.status_at(now),
            NodeStatus::Mining
                | NodeStatus::CheckingProof
                | NodeStatus::Signed
                | NodeStatus::Confirming
                | NodeStatus::Syncing
        ) || self.mining_deadline.is_none_or(|deadline| now >= deadline)
        {
            return None;
        }
        let countdown = self.countdown.as_ref()?;
        if Some(countdown.window_id) != self.window_id {
            return None;
        }
        let remaining = countdown.remaining_at(now);
        (remaining > 0).then_some(remaining)
    }
}

#[derive(Clone, Debug)]
pub struct DashboardModel {
    pub network: Network,
    pub chain_id: u64,
    pub wallet: Address,
    pub inj_balance: Option<U256>,
    pub ast_balance: Option<U256>,
    pub mined_rewards: U256,
    pub device_label: String,
    pub device_detail: String,
    pub session_limit: Option<U256>,
    pub authorization_used: Option<U256>,
    pub actual_rpc_cost: Option<U256>,
    pub block_number: u64,
    pub block_hash: B256,
    pub snapshot_observed_at: Instant,
    pub last_block_advanced_at: Instant,
    pub snapshot_ready: bool,
    pub selected_nodes: Vec<DashboardNode>,
    pub compute_only: bool,
    pub signing_enabled: bool,
    pub recovering: bool,
    pub stopping: bool,
    pub hashrate: f64,
    pub current_action: Option<String>,
    pub connection_error: Option<String>,
    pub critical_error: Option<String>,
}

impl DashboardModel {
    pub fn mode(&self, now: Instant) -> &'static str {
        if self.stopping {
            "STOPPING"
        } else if self.recovering {
            "RECOVERING"
        } else if self.connection_error.is_some() {
            "RPC ERROR"
        } else if !self.snapshot_ready {
            "CONNECTING"
        } else if now.saturating_duration_since(self.snapshot_observed_at) > SNAPSHOT_STALE_AFTER {
            "STALE DATA"
        } else if self
            .selected_nodes
            .iter()
            .any(|node| node.status_at(now) == NodeStatus::FinalizationBlocked)
        {
            "FINALIZATION BLOCKED"
        } else if self
            .selected_nodes
            .iter()
            .any(|node| node.status_at(now) == NodeStatus::FinalizationRequired)
        {
            "FINALIZATION REQUIRED"
        } else if self
            .selected_nodes
            .iter()
            .any(|node| node.status_at(now) == NodeStatus::FinalizationRetrying)
        {
            "RETRYING FINALIZATION"
        } else if self
            .selected_nodes
            .iter()
            .any(|node| node.status_at(now) == NodeStatus::WaitingForChain)
        {
            "WAITING FOR CHAIN"
        } else if !self.selected_nodes.is_empty()
            && self
                .selected_nodes
                .iter()
                .all(|node| node.status_at(now) == NodeStatus::WaitingForGenesis)
        {
            "WAITING FOR GENESIS"
        } else if !self
            .selected_nodes
            .iter()
            .any(|node| node.status_at(now) == NodeStatus::Mining || node.time_left(now).is_some())
        {
            "WAITING FOR WORK"
        } else if self.compute_only || !self.signing_enabled {
            "COMPUTE ONLY"
        } else {
            "LIVE MINING"
        }
    }
}

#[derive(Clone, Debug)]
enum DashboardEvent {
    StopRequested,
    Failure(String),
}

struct ActiveDashboard {
    shutdown: watch::Sender<bool>,
    renderer: JoinHandle<()>,
    input_stop: Arc<AtomicBool>,
    input_thread: Option<thread::JoinHandle<()>>,
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

struct PanicHookGuard {
    previous: Arc<Mutex<Option<PanicHook>>>,
}

#[derive(Clone, Default)]
pub struct DashboardSignal {
    state: Arc<SignalState>,
}

#[derive(Default)]
struct SignalState {
    event: Mutex<Option<DashboardEvent>>,
    notify: Notify,
    stop_requested: Arc<AtomicBool>,
}

pub struct Dashboard {
    model: Arc<RwLock<DashboardModel>>,
    diagnostics: DiagnosticBuffer,
    signal: DashboardSignal,
    terminal: Option<TerminalHandle>,
    panic_terminal: Arc<Mutex<Option<TerminalHandle>>>,
    panic_hook: Option<PanicHookGuard>,
    active: Option<ActiveDashboard>,
}

#[derive(Clone)]
pub struct DashboardUpdater {
    model: Arc<RwLock<DashboardModel>>,
}

#[derive(Clone)]
struct TerminalHandle {
    terminal: Arc<Mutex<Option<TerminalSession>>>,
}

struct RestoreTerminalOnDrop(TerminalHandle);

impl Dashboard {
    pub fn start(
        model: DashboardModel,
        hash_counter: Arc<AtomicU64>,
        diagnostics: DiagnosticBuffer,
    ) -> Result<Option<Self>> {
        let term = std::env::var("TERM").unwrap_or_default();
        if !io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || term.is_empty()
            || term == "dumb"
        {
            return Ok(None);
        }

        let model = Arc::new(RwLock::new(model));
        let mut dashboard = Self {
            model,
            diagnostics,
            signal: DashboardSignal::default(),
            terminal: None,
            panic_terminal: Arc::new(Mutex::new(None)),
            panic_hook: None,
            active: None,
        };
        dashboard.start_active(hash_counter)?;
        Ok(Some(dashboard))
    }

    pub fn update(&self, update: impl FnOnce(&mut DashboardModel)) {
        DashboardUpdater {
            model: Arc::clone(&self.model),
        }
        .update(update);
    }

    pub fn updater(&self) -> DashboardUpdater {
        DashboardUpdater {
            model: Arc::clone(&self.model),
        }
    }

    pub fn diagnostics(&self) -> DiagnosticBuffer {
        self.diagnostics.clone()
    }

    pub fn drain_diagnostics(&self) -> Vec<String> {
        self.diagnostics.drain()
    }

    pub fn signal(&self) -> DashboardSignal {
        self.signal.clone()
    }

    pub async fn suspend(&mut self) -> Result<()> {
        self.stop_active().await
    }

    pub fn resume(&mut self, hash_counter: Arc<AtomicU64>) -> Result<()> {
        if self.active.is_none() {
            self.start_active(hash_counter)?;
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.update(|model| model.stopping = true);
        self.stop_active().await
    }

    fn start_active(&mut self, hash_counter: Arc<AtomicU64>) -> Result<()> {
        let terminal = TerminalHandle::new(
            TerminalSession::enter().context("initialize mining dashboard terminal")?,
        );
        *self
            .panic_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(terminal.clone());
        if self.panic_hook.is_none() {
            self.panic_hook = Some(PanicHookGuard::install(Arc::clone(&self.panic_terminal)));
        }
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let input_stop = Arc::new(AtomicBool::new(false));
        let input_thread = spawn_input_thread(Arc::clone(&input_stop), self.signal.clone())?;

        let model = Arc::clone(&self.model);
        let diagnostics = self.diagnostics.clone();
        let signal = self.signal.clone();
        let stop_requested = Arc::clone(&self.signal.state.stop_requested);
        let render_terminal = terminal.clone();
        let term = std::env::var("TERM").unwrap_or_default();
        let colors = std::env::var_os("NO_COLOR").is_none() && !term.is_empty() && term != "dumb";
        let renderer_shutdown = shutdown_receiver.clone();
        let render_task = tokio::spawn(async move {
            render_loop(
                render_terminal,
                model,
                diagnostics,
                hash_counter,
                shutdown_receiver,
                stop_requested,
                colors,
            )
            .await
        });
        let renderer = tokio::spawn(async move {
            let result = render_task.await;
            let stopping = *renderer_shutdown.borrow();
            match result {
                Ok(Ok(())) if stopping => {}
                Ok(Ok(())) => signal.send(DashboardEvent::Failure(
                    "dashboard renderer stopped unexpectedly".to_owned(),
                )),
                Ok(Err(error)) => signal.send(DashboardEvent::Failure(format!("{error:#}"))),
                Err(error) => signal.send(DashboardEvent::Failure(format!(
                    "dashboard renderer task failed: {error}"
                ))),
            }
        });

        self.active = Some(ActiveDashboard {
            shutdown: shutdown_sender,
            renderer,
            input_stop,
            input_thread: Some(input_thread),
        });
        self.terminal = Some(terminal);
        Ok(())
    }

    async fn stop_active(&mut self) -> Result<()> {
        let Some(mut active) = self.active.take() else {
            return Ok(());
        };
        active.shutdown.send_replace(true);
        active.input_stop.store(true, Ordering::Release);
        let input_result = if let Some(input_thread) = active.input_thread.take() {
            tokio::task::spawn_blocking(move || input_thread.join())
                .await
                .context("join dashboard input thread")
                .and_then(|result| result.map_err(|_| anyhow!("dashboard input thread panicked")))
        } else {
            Ok(())
        };
        let renderer_result = active.renderer.await.context("join dashboard renderer");
        if let Some(terminal) = self.terminal.take() {
            terminal.restore();
        }
        self.panic_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        input_result?;
        renderer_result?;
        Ok(())
    }
}

impl DashboardUpdater {
    pub fn update(&self, update: impl FnOnce(&mut DashboardModel)) {
        let mut model = self
            .model
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        update(&mut model);
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        if let Some(mut active) = self.active.take() {
            active.shutdown.send_replace(true);
            active.input_stop.store(true, Ordering::Release);
            if let Some(input_thread) = active.input_thread.take() {
                let _ = input_thread.join();
            }
        }
        if let Some(terminal) = self.terminal.take() {
            terminal.restore();
        }
        self.panic_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.panic_hook.take();
        let mut stderr = io::stderr().lock();
        for message in self.diagnostics.drain() {
            let _ = writeln!(stderr, "astatine: {message}");
        }
    }
}

impl TerminalHandle {
    fn new(terminal: TerminalSession) -> Self {
        Self {
            terminal: Arc::new(Mutex::new(Some(terminal))),
        }
    }

    fn draw(
        &self,
        model: &DashboardModel,
        latest_diagnostic: Option<&str>,
        colors: bool,
    ) -> Result<()> {
        let mut terminal = self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let terminal = terminal
            .as_mut()
            .context("dashboard terminal has already been restored")?;
        terminal
            .terminal
            .draw(|frame| render_dashboard(frame, model, latest_diagnostic, colors))
            .context("draw mining dashboard")?;
        Ok(())
    }

    fn restore(&self) {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

impl Drop for RestoreTerminalOnDrop {
    fn drop(&mut self) {
        self.0.restore();
    }
}

impl PanicHookGuard {
    fn install(terminal: Arc<Mutex<Option<TerminalHandle>>>) -> Self {
        let previous = Arc::new(Mutex::new(Some(std::panic::take_hook())));
        let previous_for_hook = Arc::clone(&previous);
        std::panic::set_hook(Box::new(move |panic| {
            if let Some(terminal) = terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                terminal.restore();
            }
            if let Some(previous) = previous_for_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                previous(panic);
            }
        }));
        Self { previous }
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let _current = std::panic::take_hook();
        if let Some(previous) = self
            .previous
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            std::panic::set_hook(previous);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DashboardEventKind {
    StopRequested,
    Failure(String),
}

impl DashboardSignal {
    #[cfg(test)]
    pub(crate) fn request_stop(&self) {
        self.send(DashboardEvent::StopRequested);
    }

    fn send(&self, event: DashboardEvent) {
        if matches!(event, DashboardEvent::StopRequested) {
            self.state.stop_requested.store(true, Ordering::Release);
        }
        *self
            .state
            .event
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(event);
        self.state.notify.notify_one();
    }

    pub async fn wait(&self) -> DashboardEventKind {
        loop {
            let event = self
                .state
                .event
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(event) = event {
                return match event {
                    DashboardEvent::StopRequested => DashboardEventKind::StopRequested,
                    DashboardEvent::Failure(error) => DashboardEventKind::Failure(error),
                };
            }
            self.state.notify.notified().await;
        }
    }
}

fn spawn_input_thread(
    stop: Arc<AtomicBool>,
    events: DashboardSignal,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("astatine-dashboard-input".to_owned())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                match event::poll(INPUT_POLL_INTERVAL) {
                    Ok(false) => continue,
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key))
                            if key.kind == KeyEventKind::Press
                                && key.code == KeyCode::Char('c')
                                && key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            events.send(DashboardEvent::StopRequested);
                            break;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            events.send(DashboardEvent::Failure(format!(
                                "read dashboard keyboard event: {error}"
                            )));
                            break;
                        }
                    },
                    Err(error) => {
                        events.send(DashboardEvent::Failure(format!(
                            "poll dashboard keyboard: {error}"
                        )));
                        break;
                    }
                }
            }
        })
        .context("start dashboard input thread")
}

async fn render_loop(
    terminal: TerminalHandle,
    model: Arc<RwLock<DashboardModel>>,
    diagnostics: DiagnosticBuffer,
    hash_counter: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
    stop_requested: Arc<AtomicBool>,
    colors: bool,
) -> Result<()> {
    let _restore = RestoreTerminalOnDrop(terminal.clone());
    let mut ticker = time::interval(REFRESH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous_hashes = hash_counter.load(Ordering::Relaxed);
    let mut previous_sample = Instant::now();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    draw_frame(
                        &terminal,
                        &model,
                        &diagnostics,
                        &stop_requested,
                        colors,
                        None,
                    )?;
                    return Ok(());
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let hashes = hash_counter.load(Ordering::Relaxed);
                let elapsed = now.saturating_duration_since(previous_sample).as_secs_f64();
                let hashrate = hashes_per_second(previous_hashes, hashes, elapsed);
                previous_hashes = hashes;
                previous_sample = now;
                draw_frame(
                    &terminal,
                    &model,
                    &diagnostics,
                    &stop_requested,
                    colors,
                    Some(hashrate),
                )?;
            }
        }
    }
}

fn draw_frame(
    terminal: &TerminalHandle,
    model: &Arc<RwLock<DashboardModel>>,
    diagnostics: &DiagnosticBuffer,
    stop_requested: &AtomicBool,
    colors: bool,
    hashrate: Option<f64>,
) -> Result<()> {
    let mut snapshot = model
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    snapshot.stopping |= stop_requested.load(Ordering::Acquire);
    if let Some(hashrate) = hashrate {
        snapshot.hashrate = hashrate;
    }
    let latest_diagnostic = diagnostics.latest();
    terminal.draw(&snapshot, latest_diagnostic.as_deref(), colors)
}

fn render_dashboard(
    frame: &mut Frame<'_>,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let area = frame.area();
    if area.width < 20 || area.height == 0 {
        return;
    }
    if area.height <= 2 {
        let line = format!("ASTATINE • {} • Ctrl+C", model.mode(Instant::now()));
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    if area.width < 52 {
        render_narrow(frame, area, model, latest_diagnostic, colors);
    } else if area.width < 78 {
        render_compact(frame, area, model, latest_diagnostic, colors);
    } else {
        render_wide(frame, area, model, latest_diagnostic, colors);
    }
}

fn render_wide(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let top_height = 9.min(area.height.saturating_sub(7));
    let header_area = Rect::new(area.x, area.y, area.width, top_height);
    render_wide_header(frame, header_area, model, colors);

    let remaining_y = area.y.saturating_add(top_height);
    let footer_y = area.y.saturating_add(area.height).saturating_sub(1);
    if remaining_y >= footer_y {
        render_footer(
            frame,
            Rect::new(area.x, footer_y, area.width, 1),
            model,
            latest_diagnostic,
            colors,
        );
        return;
    }
    render_rule(frame, Rect::new(area.x, remaining_y, area.width, 1), colors);
    let title_y = remaining_y.saturating_add(1);
    render_heading(
        frame,
        Rect::new(
            area.x.saturating_add(2),
            title_y,
            area.width.saturating_sub(4),
            1,
        ),
        model,
        colors,
    );
    let labels_y = title_y.saturating_add(1);
    render_column_labels(
        frame,
        Rect::new(
            area.x.saturating_add(2),
            labels_y,
            area.width.saturating_sub(4),
            1,
        ),
        colors,
    );
    let rows_start = labels_y.saturating_add(1);
    render_rule(frame, Rect::new(area.x, rows_start, area.width, 1), colors);
    let rows_y = rows_start.saturating_add(1);
    let rows_height = footer_y.saturating_sub(rows_y).saturating_sub(1);
    render_wide_rows(
        frame,
        Rect::new(
            area.x.saturating_add(2),
            rows_y,
            area.width.saturating_sub(4),
            rows_height,
        ),
        model,
        colors,
    );
    if footer_y > rows_y {
        render_rule(
            frame,
            Rect::new(area.x, footer_y.saturating_sub(1), area.width, 1),
            colors,
        );
    }
    render_footer(
        frame,
        Rect::new(area.x, footer_y, area.width, 1),
        model,
        latest_diagnostic,
        colors,
    );
}

fn render_wide_header(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    if area.height == 0 {
        return;
    }
    let left_width = if model.mode(Instant::now()) == "WAITING FOR GENESIS" {
        39.min(area.width / 2)
    } else {
        31.min(area.width / 2)
    };
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(left_width), Constraint::Min(0)])
        .split(area);
    let left = vec![
        Line::from(Span::styled("ASTATINE", style(colors, EMERALD, true))),
        version_mode_line(model, colors),
        Line::from(Span::styled("", Style::default())),
        Line::from(Span::styled(
            "Injective EVM miner",
            style(colors, MUTED, false),
        )),
    ];
    frame.render_widget(Paragraph::new(left), chunks[0]);
    let mut lines = vec![
        metadata_line("NETWORK", network_name(model.network), colors),
        metadata_line("CHAIN ID", &model.chain_id.to_string(), colors),
        metadata_line("WALLET", &short_address(model.wallet), colors),
        metadata_line(
            "INJ BALANCE",
            &format_optional_inj_value(model.inj_balance),
            colors,
        ),
        metadata_line(
            "AST BALANCE",
            &format_optional_ast(model.ast_balance),
            colors,
        ),
        metadata_line("RPC MINED", &format_mined(model.mined_rewards), colors),
        metadata_line(
            "DEVICE",
            &format!(
                "{} · {} • {}",
                model.device_label,
                model.device_detail,
                format_hashrate(model.hashrate)
            ),
            colors,
        ),
        metadata_line("AUTH / LIMIT", &format_authorization(model), colors),
        metadata_line("RPC-REPORTED COST", &format_rpc_cost(model), colors),
    ];
    lines.truncate(usize::from(area.height));
    frame.render_widget(Paragraph::new(lines), chunks[1]);
}

fn render_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let header_height = 7.min(area.height.saturating_sub(5));
    let mut lines = vec![
        Line::from(Span::styled("ASTATINE", style(colors, EMERALD, true))),
        version_mode_line(model, colors),
        Line::from(Span::raw(format!(
            "{} • Chain {}",
            network_name(model.network),
            model.chain_id
        ))),
        Line::from(Span::raw(format!("Wallet {}", short_address(model.wallet)))),
        Line::from(Span::raw(format!(
            "INJ BALANCE {} • AST BALANCE {}",
            format_optional_inj_value(model.inj_balance),
            format_optional_ast(model.ast_balance)
        ))),
        Line::from(Span::raw(format!(
            "RPC MINED {}",
            format_mined(model.mined_rewards)
        ))),
        Line::from(Span::raw(format!(
            "DEVICE {} {} • {} • Auth {} • RPC cost {}",
            model.device_label,
            model.device_detail,
            format_hashrate(model.hashrate),
            format_authorization(model),
            format_rpc_cost(model)
        ))),
    ];
    lines.truncate(usize::from(header_height));
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(area.x, area.y, area.width, header_height),
    );

    let mut cursor = area.y.saturating_add(header_height);
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_rule(frame, Rect::new(area.x, cursor, area.width, 1), colors);
        cursor = cursor.saturating_add(1);
    }
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_heading(
            frame,
            Rect::new(
                area.x.saturating_add(1),
                cursor,
                area.width.saturating_sub(2),
                1,
            ),
            model,
            colors,
        );
        cursor = cursor.saturating_add(1);
    }
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_compact_column_labels(
            frame,
            Rect::new(
                area.x.saturating_add(1),
                cursor,
                area.width.saturating_sub(2),
                1,
            ),
            colors,
        );
        cursor = cursor.saturating_add(1);
    }
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_rule(frame, Rect::new(area.x, cursor, area.width, 1), colors);
        cursor = cursor.saturating_add(1);
    }
    let footer_y = area.y.saturating_add(area.height).saturating_sub(1);
    render_compact_rows(
        frame,
        Rect::new(
            area.x.saturating_add(1),
            cursor,
            area.width.saturating_sub(2),
            footer_y.saturating_sub(cursor),
        ),
        model,
        colors,
    );
    render_footer(
        frame,
        Rect::new(area.x, footer_y, area.width, 1),
        model,
        latest_diagnostic,
        colors,
    );
}

fn render_narrow(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let header_height = 4.min(area.height.saturating_sub(2));
    let ast_balance = model
        .ast_balance
        .map(|balance| format_units(balance, 9))
        .unwrap_or_else(|| "--".to_owned());
    let mined = format_units(model.mined_rewards, 9);
    let mode = model.mode(Instant::now());
    let mode_line = if mode == "WAITING FOR GENESIS" {
        mode.to_owned()
    } else {
        format!(
            "{} • {} • {}",
            network_name(model.network),
            mode,
            model.device_label
        )
    };
    let mode_span = if mode == "WAITING FOR GENESIS" {
        Span::styled(mode_line, style(colors, GENESIS_AMBER, false))
    } else {
        Span::raw(mode_line)
    };
    let balance_line = if area.width < 45 {
        format!("AST BAL {ast_balance} AST • RPC MINED +{mined} AST")
    } else {
        format!("AST BALANCE {ast_balance} AST • RPC MINED +{mined} AST")
    };
    let lines = vec![
        Line::from(Span::styled("ASTATINE", style(colors, EMERALD, true))),
        Line::from(mode_span),
        Line::from(Span::raw(format!(
            "{} · INJ {}",
            short_address(model.wallet),
            format_optional_inj_value(model.inj_balance),
        ))),
        Line::from(Span::raw(balance_line)),
    ];
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(area.x, area.y, area.width, header_height),
    );
    let title_y = area.y.saturating_add(header_height);
    if title_y < area.y.saturating_add(area.height).saturating_sub(1) {
        render_heading(
            frame,
            Rect::new(area.x, title_y, area.width, 1),
            model,
            colors,
        );
    }
    let rows_y = title_y.saturating_add(1);
    let footer_y = area.y.saturating_add(area.height).saturating_sub(1);
    render_narrow_rows(
        frame,
        Rect::new(area.x, rows_y, area.width, footer_y.saturating_sub(rows_y)),
        model,
        colors,
    );
    render_footer(
        frame,
        Rect::new(area.x, footer_y, area.width, 1),
        model,
        latest_diagnostic,
        colors,
    );
}

fn render_heading(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let heading = format!(
        "MINING NODES  {}",
        if area.width >= 28 {
            format!("{} selected / 9 total", model.selected_nodes.len())
        } else {
            format!(" {} / 9", model.selected_nodes.len())
        }
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            heading,
            style(colors, LIGHT, true),
        ))),
        area,
    );
}

fn render_column_labels(frame: &mut Frame<'_>, area: Rect, colors: bool) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(
                "{:<6}{:<8}{:<14}{:<10}{:<22}{}",
                "NODE", "WINDOW", "STATUS", "TIME LEFT", "BEST MINER", "WINDOW REWARD"
            ),
            style(colors, MUTED, false),
        ))),
        area,
    );
}

fn render_compact_column_labels(frame: &mut Frame<'_>, area: Rect, colors: bool) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "ID WINDOW STATUS TIME BEST MINER REWARD",
            style(colors, MUTED, false),
        ))),
        area,
    );
}

fn render_wide_rows(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let now = Instant::now();
    let lines = model
        .selected_nodes
        .iter()
        .map(|node| wide_node_line(node, model, now, colors))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_compact_rows(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let now = Instant::now();
    let lines = model
        .selected_nodes
        .iter()
        .map(|node| compact_node_line(node, model, now, colors))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_narrow_rows(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let now = Instant::now();
    let mut lines = Vec::with_capacity(model.selected_nodes.len() * 2);
    for node in &model.selected_nodes {
        let status = node.status_at(now);
        let time = node
            .time_left(now)
            .map(format_time_left)
            .unwrap_or_else(|| "--:--".to_owned());
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:02} {} ", node.id, format_window_id(node.window_id)),
                style(colors, MUTED, false),
            ),
            Span::styled(
                format!("{} ", status.label()),
                style(colors, status.color(), true),
            ),
            Span::styled(time, style(colors, LIGHT, false)),
        ]));
        lines.push(narrow_candidate_reward_line(node, model, colors));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn wide_node_line(
    node: &DashboardNode,
    model: &DashboardModel,
    now: Instant,
    colors: bool,
) -> Line<'static> {
    let status = node.status_at(now);
    let time = node
        .time_left(now)
        .map(format_time_left)
        .unwrap_or_else(|| "--:--".to_owned());
    let candidate = candidate_spans(node.candidate, model.wallet, 22, colors);
    let reward = format_reward(node.reward);
    let mut spans = vec![
        Span::styled(format!("{:02}    ", node.id), style(colors, LIGHT, false)),
        Span::styled(
            format!("{:<8}", format_window_id(node.window_id)),
            style(colors, LIGHT, false),
        ),
        Span::styled(
            format!("{:<12}  ", status.label()),
            style(colors, status.color(), true),
        ),
        Span::styled(format!("{time:<8}  "), style(colors, LIGHT, false)),
    ];
    let candidate_width = candidate
        .iter()
        .map(|span| span.content.chars().count())
        .sum::<usize>();
    spans.extend(candidate);
    spans.push(Span::raw(
        " ".repeat(22_usize.saturating_sub(candidate_width)),
    ));
    spans.push(Span::styled(reward, style(colors, LIGHT, false)));
    Line::from(spans)
}

fn compact_node_line(
    node: &DashboardNode,
    model: &DashboardModel,
    now: Instant,
    colors: bool,
) -> Line<'static> {
    let status = node.status_at(now);
    let time = node
        .time_left(now)
        .map(format_time_left)
        .unwrap_or_else(|| "--:--".to_owned());
    let mut spans = vec![
        Span::styled(format!("{:02} ", node.id), style(colors, MUTED, false)),
        Span::styled(
            format!("{} ", format_window_id(node.window_id)),
            style(colors, MUTED, false),
        ),
        Span::styled(
            format!("{} ", status.label()),
            style(colors, status.color(), true),
        ),
        Span::styled(format!("{time} "), style(colors, LIGHT, false)),
    ];
    spans.extend(candidate_spans(node.candidate, model.wallet, 11, colors));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        format_reward(node.reward),
        style(colors, LIGHT, false),
    ));
    Line::from(spans)
}

fn narrow_candidate_reward_line(
    node: &DashboardNode,
    model: &DashboardModel,
    colors: bool,
) -> Line<'static> {
    let mut spans = vec![Span::styled("  BEST ", style(colors, MUTED, false))];
    spans.extend(candidate_spans(node.candidate, model.wallet, 12, colors));
    spans.push(Span::styled(" · ", style(colors, MUTED, false)));
    spans.push(Span::styled(
        format_reward(node.reward),
        style(colors, LIGHT, false),
    ));
    Line::from(spans)
}

fn candidate_spans(
    candidate: Option<Address>,
    wallet: Address,
    max_chars: usize,
    colors: bool,
) -> Vec<Span<'static>> {
    let Some(candidate) = candidate else {
        return vec![Span::styled("None", style(colors, MUTED, false))];
    };
    let is_ours = candidate == wallet;
    let address = abbreviated_address(candidate, max_chars);
    if is_ours {
        vec![
            Span::styled(address, style(colors, EMERALD, true)),
            Span::styled(" YOU", style(colors, EMERALD, true)),
        ]
    } else {
        vec![Span::styled(address, style(colors, LIGHT, false))]
    }
}

fn render_footer(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let (text, tint) = if let Some(error) = model.critical_error.as_deref() {
        (format!("ERROR • {error}"), ERROR_RED)
    } else if let Some(error) = model.connection_error.as_deref() {
        (format!("RPC ERROR • {error}"), ERROR_RED)
    } else if !model.snapshot_ready {
        ("Connecting • Verifying Testnet state...".to_owned(), AMBER)
    } else if Instant::now().saturating_duration_since(model.snapshot_observed_at)
        > SNAPSHOT_STALE_AFTER
    {
        (
            format!(
                "STALE • Last verified block {} {} • Ctrl+C to stop",
                format_block(model.block_number),
                short_hash(model.block_hash)
            ),
            AMBER,
        )
    } else if let Some(action) = model.current_action.as_deref() {
        (
            format!(
                "{action} • Block {} • Ctrl+C to stop",
                format_block(model.block_number)
            ),
            AMBER,
        )
    } else if let Some(diagnostic) = latest_diagnostic {
        (format!("Notice • {diagnostic} • Ctrl+C to stop"), AMBER)
    } else if !model.signing_enabled {
        (
            format!(
                "Block {} • Potential reward • Signing off • Ctrl+C to stop",
                format_block(model.block_number)
            ),
            MUTED,
        )
    } else {
        (
            format!(
                "Connected • Block {} • Window reward is potential • Ctrl+C to stop",
                format_block(model.block_number)
            ),
            MUTED,
        )
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, style(colors, tint, false)))),
        area,
    );
}

fn render_rule(frame: &mut Frame<'_>, area: Rect, colors: bool) {
    if area.width == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(usize::from(area.width)),
            style(colors, Color::Rgb(54, 74, 63), false),
        ))),
        area,
    );
}

fn metadata_line(label: &str, value: &str, colors: bool) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), style(colors, MUTED, false)),
        Span::styled(value.to_owned(), style(colors, LIGHT, false)),
    ])
}

fn version_mode_line(model: &DashboardModel, colors: bool) -> Line<'static> {
    let mode = model.mode(Instant::now());
    let mode_color = match mode {
        "LIVE MINING" => EMERALD,
        "RECOVERING"
        | "STOPPING"
        | "WAITING FOR CHAIN"
        | "FINALIZATION REQUIRED"
        | "RETRYING FINALIZATION" => AMBER,
        "WAITING FOR GENESIS" => GENESIS_AMBER,
        "FINALIZATION BLOCKED" => ERROR_RED,
        "RPC ERROR" => ERROR_RED,
        "STALE DATA" => AMBER,
        _ => MUTED,
    };
    Line::from(vec![
        Span::styled(
            format!("v{} • ", env!("CARGO_PKG_VERSION")),
            style(colors, LIGHT, false),
        ),
        Span::styled(mode.to_owned(), style(colors, mode_color, true)),
    ])
}

fn style(colors: bool, foreground: Color, bold: bool) -> Style {
    if !colors {
        return Style::default();
    }
    let style = Style::default().fg(foreground);
    if bold {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

pub fn format_time_left(seconds: u64) -> String {
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

pub(crate) fn hashes_per_second(previous: u64, current: u64, elapsed_secs: f64) -> f64 {
    current.wrapping_sub(previous) as f64 / elapsed_secs.max(0.001)
}

pub fn format_reward(value: Option<U256>) -> String {
    value
        .map(|value| format!("{} AST", format_units(value, 9)))
        .unwrap_or_else(|| "-- AST".to_owned())
}

pub fn format_units(value: U256, decimals: u8) -> String {
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let whole = value / scale;
    let fraction = value % scale;
    if fraction.is_zero() {
        return whole.to_string();
    }
    let fractional = format!("{fraction:0>width$}", width = usize::from(decimals));
    format!("{whole}.{}", fractional.trim_end_matches('0'))
}

fn format_optional_inj_value(value: Option<U256>) -> String {
    value
        .map(|value| format!("{} INJ", format_units(value, 18)))
        .unwrap_or_else(|| "-- INJ".to_owned())
}

fn format_optional_ast_value(value: Option<U256>) -> String {
    value
        .map(|value| format!("{} AST", format_units(value, 9)))
        .unwrap_or_else(|| "-- AST".to_owned())
}

fn format_optional_ast(value: Option<U256>) -> String {
    format_optional_ast_value(value)
}

fn format_mined_value(value: U256) -> String {
    format!("+{} AST", format_units(value, 9))
}

fn format_mined(value: U256) -> String {
    format_mined_value(value)
}

fn format_authorization(model: &DashboardModel) -> String {
    match (model.authorization_used, model.session_limit) {
        (Some(used), Some(limit)) => {
            let remaining = limit.checked_sub(used).unwrap_or(U256::ZERO);
            format!(
                "{} / {} INJ · {} left",
                format_units(used, 18),
                format_units(limit, 18),
                format_units(remaining, 18)
            )
        }
        _ => "--".to_owned(),
    }
}

fn format_rpc_cost(model: &DashboardModel) -> String {
    model
        .actual_rpc_cost
        .map(|value| format!("{} INJ", format_units(value, 18)))
        .unwrap_or_else(|| "-- INJ".to_owned())
}

fn format_hashrate(rate: f64) -> String {
    if !rate.is_finite() || rate < 0.0 {
        return "-- H/s".to_owned();
    }
    if rate >= 1_000_000.0 {
        format!("{:.2} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.1} kH/s", rate / 1_000.0)
    } else {
        format!("{rate:.0} H/s")
    }
}

fn format_block(block: u64) -> String {
    let value = block.to_string();
    let mut result = String::with_capacity(value.len() + value.len() / 3);
    for (index, digit) in value.chars().enumerate() {
        if index > 0 && (value.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(digit);
    }
    result
}

fn short_address(address: Address) -> String {
    let value = format!("{address:#x}");
    format!("{}...{}", &value[..6], &value[value.len() - 4..])
}

fn short_hash(hash: B256) -> String {
    let value = format!("{hash:#x}");
    format!("{}...{}", &value[..8], &value[value.len() - 6..])
}

fn abbreviated_address(address: Address, max_chars: usize) -> String {
    let value = format!("{address:#x}");
    if max_chars >= 13 {
        return short_address(address);
    }
    if max_chars >= 11 {
        return format!("{}...{}", &value[..4], &value[value.len() - 4..]);
    }
    if max_chars >= 8 {
        return format!("{}..{}", &value[..2], &value[value.len() - 4..]);
    }
    fit_text(&value, max_chars)
}

fn format_window_id(window_id: Option<u64>) -> String {
    window_id
        .map(|window| format!("#{window}"))
        .unwrap_or_else(|| "--".to_owned())
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Testnet => "Injective Testnet",
        Network::Mainnet => "Injective Mainnet",
    }
}

fn fit_text(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_owned();
    }
    value.chars().take(max_chars).collect()
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    raw_mode: bool,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let mut session = Self {
            terminal,
            raw_mode: false,
        };
        execute!(session.terminal.backend_mut(), EnterAlternateScreen)?;
        enable_raw_mode()?;
        session.raw_mode = true;
        session.terminal.hide_cursor()?;
        session.terminal.clear()?;
        Ok(session)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if self.raw_mode {
            let _ = disable_raw_mode();
            self.raw_mode = false;
        }
        let backend = self.terminal.backend_mut();
        let _ = execute!(backend, crossterm::cursor::Show, LeaveAlternateScreen);
        let _ = backend.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardModel, DashboardNode, GENESIS_AMBER, NodeStatus, WindowCountdown, format_hashrate,
        format_mined_value, format_optional_ast_value, format_reward, format_time_left,
        format_units, hashes_per_second, render_dashboard,
    };
    use crate::cli::Network;
    use alloy_primitives::{Address, B256, U256};
    use ratatui::{Terminal, backend::TestBackend};
    use std::time::{Duration, Instant};

    fn wallet(last: u8) -> Address {
        Address::with_last_byte(last)
    }

    fn model(nodes: Vec<DashboardNode>) -> DashboardModel {
        DashboardModel {
            network: Network::Testnet,
            chain_id: 1439,
            wallet: wallet(1),
            inj_balance: Some(U256::from(2_948_000_000_000_000_000_u128)),
            ast_balance: Some(U256::from(39_000_000_000_000_u128)),
            mined_rewards: U256::from(26_000_000_000_000_u128),
            device_label: "CPU".to_owned(),
            device_detail: "6 Threads".to_owned(),
            session_limit: Some(U256::from(500_000_000_000_000_000_u128)),
            authorization_used: Some(U256::from(52_000_000_000_000_000_u128)),
            actual_rpc_cost: Some(U256::from(31_000_000_000_000_000_u128)),
            block_number: 144_123_456,
            block_hash: B256::with_last_byte(4),
            snapshot_observed_at: Instant::now(),
            last_block_advanced_at: Instant::now(),
            snapshot_ready: true,
            selected_nodes: nodes,
            compute_only: false,
            signing_enabled: true,
            recovering: false,
            stopping: false,
            hashrate: 184_200.0,
            current_action: None,
            connection_error: None,
            critical_error: None,
        }
    }

    fn node(id: u8, status: NodeStatus, candidate: Option<Address>) -> DashboardNode {
        let observed_at = Instant::now();
        let window_id = 100 + u64::from(id);
        DashboardNode {
            id,
            window_id: Some(window_id),
            status,
            expiry_timestamp: Some(1_160),
            mining_deadline: Some(observed_at + Duration::from_secs(160)),
            countdown: Some(WindowCountdown::from_snapshot(
                window_id,
                1_160,
                1_000,
                observed_at,
            )),
            candidate,
            reward: Some(U256::from(900_000_000_u64)),
        }
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn selected_nodes_are_rendered_in_id_order_and_best_miner_is_truthful() {
        let mut view = model(vec![
            node(7, NodeStatus::Mining, Some(wallet(1))),
            node(1, NodeStatus::Waiting, None),
            node(3, NodeStatus::Finalizing, Some(wallet(2))),
        ]);
        view.selected_nodes.sort_by_key(|node| node.id);
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        let one = text.find("01    WAITING").unwrap();
        let three = text.find("03    FINALIZING").unwrap();
        let seven = text.find("07    ● MINING").unwrap();
        assert!(one < three && three < seven);
        assert!(text.contains("None"));
        assert!(text.contains("YOU"));
        assert!(text.contains("0x0000...0002"));
        assert!(
            !text.lines().any(|line| line.starts_with("  02    ")),
            "{text}"
        );
    }

    #[test]
    fn dashboard_identifies_the_active_gpu_backend_in_each_layout() {
        let mut view = model(vec![node(1, NodeStatus::Mining, None)]);
        view.device_label = "GPU".to_owned();
        view.device_detail = "Apple M4 · CPU verify".to_owned();
        for (width, height) in [(100, 24), (70, 24), (50, 14)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| render_dashboard(frame, &view, None, false))
                .unwrap();
            let text = buffer_text(&terminal);
            assert!(
                text.contains("GPU"),
                "backend label was clipped at {width} columns: {text}"
            );
            if width >= 52 {
                assert!(
                    text.contains("Apple M4"),
                    "GPU model was not rendered at {width} columns: {text}"
                );
            }
        }
    }

    #[test]
    fn all_nine_nodes_fit_a_standard_terminal_and_only_selected_rows_are_shown() {
        let nodes = (1..=9)
            .rev()
            .map(|id| node(id, NodeStatus::Mining, None))
            .collect::<Vec<_>>();
        let mut view = model(nodes);
        view.selected_nodes.sort_by_key(|node| node.id);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        for id in 1..=9 {
            assert!(text.contains(&format!("{id:02}    ● MINING")));
            assert!(text.contains(&format!("#{:03}", 100 + id)));
        }
        assert!(text.contains("WINDOW"));
        assert!(text.contains("9 selected / 9 total"));
        assert!(!text.contains("10  "));
    }

    #[test]
    fn genesis_wait_is_muted_amber_one_row_per_node_without_a_countdown() {
        let nodes = (1..=9)
            .map(|id| node(id, NodeStatus::WaitingForGenesis, None))
            .collect::<Vec<_>>();
        let view = model(nodes);
        let now = Instant::now();
        assert_eq!(view.mode(now), "WAITING FOR GENESIS");
        assert_eq!(NodeStatus::WaitingForGenesis.label(), "WAIT GENESIS");
        assert_eq!(NodeStatus::WaitingForGenesis.color(), GENESIS_AMBER);
        assert!(
            view.selected_nodes
                .iter()
                .all(|node| node.time_left(now).is_none()),
            "unstarted work must never receive a window countdown"
        );

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("WAITING FOR GENESIS"), "{text}");
        for id in 1..=9 {
            assert!(
                text.contains(&format!("{id:02}    #{}    WAIT GENESIS", 100 + id)),
                "{text}"
            );
        }
        assert!(text.contains("--:--"), "{text}");
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("WAIT GENESIS"))
                .count(),
            9
        );

        let mut wide_threshold = Terminal::new(TestBackend::new(78, 24)).unwrap();
        wide_threshold
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        assert!(
            buffer_text(&wide_threshold).contains("WAITING FOR GENESIS"),
            "the exact global genesis status must fit the minimum wide layout"
        );

        let mut narrow = Terminal::new(TestBackend::new(48, 24)).unwrap();
        narrow
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let narrow_text = buffer_text(&narrow);
        assert!(narrow_text.contains("WAITING FOR GENESIS"), "{narrow_text}");
    }

    #[test]
    fn mixed_genesis_and_active_nodes_do_not_become_globally_waiting_for_genesis() {
        let view = model(vec![
            node(1, NodeStatus::Mining, None),
            node(3, NodeStatus::WaitingForGenesis, None),
            node(5, NodeStatus::WaitingForGenesis, None),
        ]);
        assert_eq!(view.mode(Instant::now()), "LIVE MINING");
    }

    #[test]
    fn ast_balance_and_mined_are_exact_and_visible_across_dashboard_widths() {
        assert_eq!(
            format_optional_ast_value(Some(U256::from(39_000_000_001_u64))),
            "39.000000001 AST"
        );
        assert_eq!(format_optional_ast_value(None), "-- AST");
        assert_eq!(
            format_mined_value(U256::from(26_000_000_000_000_u128)),
            "+26000 AST"
        );

        let nodes = (1..=9)
            .map(|id| node(id, NodeStatus::Mining, None))
            .collect::<Vec<_>>();
        for (width, expected_balance_label) in
            [(100, "AST BALANCE"), (60, "AST BALANCE"), (40, "AST BAL")]
        {
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal
                .draw(|frame| render_dashboard(frame, &model(nodes.clone()), None, false))
                .unwrap();
            let text = buffer_text(&terminal);
            assert!(text.contains(expected_balance_label), "{width}x24: {text}");
            assert!(text.contains("MINED"), "{width}x24: {text}");
            assert!(text.contains("+26000 AST"), "{width}x24: {text}");
            assert!(text.contains("39000 AST"), "{width}x24: {text}");
            if width >= 78 {
                assert!(text.contains("INJ BALANCE 2.948 INJ"), "{text}");
                assert!(text.contains("AST BALANCE 39000 AST"), "{text}");
            }
            assert!(
                text.contains("INJ BALANCE") || text.contains("INJ "),
                "{width}x24: {text}"
            );
            assert!(text.contains("9 selected / 9 total"), "{width}x24: {text}");
            for id in 1..=9 {
                assert!(text.contains(&format!("{id:02}")), "{width}x24: {text}");
            }
        }
    }

    #[test]
    fn ordinary_ast_balance_changes_do_not_change_the_session_mined_total() {
        let initial = model(Vec::new());
        let mut after_external_ast_transfer = initial.clone();
        after_external_ast_transfer.ast_balance =
            Some(initial.ast_balance.unwrap() + U256::from(7_000_000_000_u64));
        assert_ne!(initial.ast_balance, after_external_ast_transfer.ast_balance);
        assert_eq!(initial.mined_rewards, U256::from(26_000_000_000_000_u128));
        assert_eq!(
            after_external_ast_transfer.mined_rewards, initial.mined_rewards,
            "wallet balance deltas are not mined-session accounting"
        );
    }

    #[test]
    fn unavailable_ast_balance_remains_explicitly_unavailable() {
        let mut view = model(Vec::new());
        view.ast_balance = None;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("AST BALANCE"));
        assert!(text.contains("-- AST"));
        assert!(text.contains("MINED"));
        assert!(text.contains("+26000 AST"));
    }

    #[test]
    fn exact_rewards_countdowns_and_hashrate_formats_are_readable() {
        assert_eq!(format_reward(Some(U256::from(900_000_000_u64))), "0.9 AST");
        assert_eq!(format_reward(Some(U256::from(1_u8))), "0.000000001 AST");
        assert_eq!(format_reward(None), "-- AST");
        assert_eq!(format_time_left(161), "02:41");
        assert_eq!(
            format_units(U256::from(2_948_000_000_000_000_000_u128), 18),
            "2.948"
        );
        assert_eq!(format_hashrate(184_200.0), "184.2 kH/s");
        assert_eq!(hashes_per_second(100, 1_100, 2.0), 500.0);
        assert_eq!(hashes_per_second(u64::MAX - 1, 1, 1.0), 3.0);
    }

    #[test]
    fn deadline_and_expiry_never_render_positive_time_after_work_stops() {
        let observed = Instant::now();
        let mut view = model(vec![DashboardNode {
            id: 1,
            window_id: Some(1),
            status: NodeStatus::Mining,
            expiry_timestamp: Some(1_060),
            mining_deadline: Some(observed + Duration::from_secs(60)),
            countdown: Some(WindowCountdown::from_snapshot(1, 1_060, 1_000, observed)),
            candidate: None,
            reward: None,
        }]);
        view.snapshot_observed_at = observed;
        assert_eq!(view.selected_nodes[0].time_left(observed), Some(60));
        assert_eq!(
            view.selected_nodes[0].time_left(observed + Duration::from_secs(1)),
            Some(59)
        );
        assert_eq!(
            view.selected_nodes[0].status_at(observed + Duration::from_secs(60)),
            NodeStatus::WaitingForChain
        );
        assert_eq!(
            view.selected_nodes[0].time_left(observed + Duration::from_secs(60)),
            None
        );
        view.snapshot_observed_at = observed + Duration::from_secs(60);
        assert_eq!(
            view.mode(observed + Duration::from_secs(60)),
            "WAITING FOR CHAIN"
        );
        view.selected_nodes[0].status = NodeStatus::Paused;
        assert_eq!(
            view.selected_nodes[0].time_left(observed + Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn repeated_same_window_snapshots_cannot_extend_chain_time_countdown() {
        let observed = Instant::now();
        let initial = WindowCountdown::from_snapshot(184, 1_090, 1_000, observed);
        assert_eq!(initial.remaining_at(observed), 90);

        let after_sixty = observed + Duration::from_secs(60);
        let repeated_stale_timestamp = initial.reconcile_same_window(1_090, 1_000, after_sixty);
        assert_eq!(repeated_stale_timestamp.remaining_at(after_sixty), 30);

        let after_another_snapshot = after_sixty + Duration::from_secs(1);
        let repeated_again =
            repeated_stale_timestamp.reconcile_same_window(1_090, 1_000, after_another_snapshot);
        assert_eq!(repeated_again.remaining_at(after_another_snapshot), 29);

        let next_window = WindowCountdown::from_snapshot(185, 2_200, 2_110, after_another_snapshot);
        assert_eq!(next_window.remaining_at(after_another_snapshot), 90);
        assert_ne!(next_window.window_id, repeated_again.window_id);
    }

    #[test]
    fn mode_distinguishes_signing_compute_only_waiting_recovery_and_stopping() {
        let mut view = model(vec![node(1, NodeStatus::Mining, None)]);
        assert_eq!(view.mode(Instant::now()), "LIVE MINING");
        view.selected_nodes[0].status = NodeStatus::Confirming;
        assert_eq!(view.mode(Instant::now()), "LIVE MINING");
        view.selected_nodes[0].status = NodeStatus::Syncing;
        assert_eq!(view.mode(Instant::now()), "LIVE MINING");
        view.selected_nodes[0].status = NodeStatus::Mining;
        view.compute_only = true;
        assert_eq!(view.mode(Instant::now()), "COMPUTE ONLY");
        view.compute_only = false;
        view.signing_enabled = false;
        assert_eq!(view.mode(Instant::now()), "COMPUTE ONLY");
        view.signing_enabled = true;
        view.selected_nodes[0].status = NodeStatus::Waiting;
        assert_eq!(view.mode(Instant::now()), "WAITING FOR WORK");
        view.selected_nodes[0].status = NodeStatus::WaitingForChain;
        assert_eq!(view.mode(Instant::now()), "WAITING FOR CHAIN");
        view.selected_nodes[0].status = NodeStatus::FinalizationRequired;
        assert_eq!(view.mode(Instant::now()), "FINALIZATION REQUIRED");
        view.selected_nodes[0].status = NodeStatus::FinalizationRetrying;
        assert_eq!(view.mode(Instant::now()), "RETRYING FINALIZATION");
        view.selected_nodes[0].status = NodeStatus::FinalizationBlocked;
        assert_eq!(view.mode(Instant::now()), "FINALIZATION BLOCKED");
        view.selected_nodes[0].status = NodeStatus::Waiting;
        view.connection_error = Some("RPC unavailable".to_owned());
        assert_eq!(view.mode(Instant::now()), "RPC ERROR");
        view.connection_error = None;
        view.snapshot_observed_at = Instant::now() - Duration::from_secs(21);
        assert_eq!(view.mode(Instant::now()), "STALE DATA");
        view.snapshot_observed_at = Instant::now();
        view.recovering = true;
        assert_eq!(view.mode(Instant::now()), "RECOVERING");
        view.stopping = true;
        assert_eq!(view.mode(Instant::now()), "STOPPING");
    }

    #[test]
    fn narrow_dashboard_does_not_wrap_or_panic_and_keeps_selected_nodes() {
        let view = model(vec![
            node(1, NodeStatus::RpcError, None),
            node(3, NodeStatus::Waiting, Some(wallet(2))),
            node(7, NodeStatus::Mining, Some(wallet(1))),
        ]);
        let mut terminal = Terminal::new(TestBackend::new(48, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, Some("temporary RPC warning"), false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("ASTATINE"));
        assert!(text.contains("01 RPC ERROR"));
        assert!(text.contains("03 WAITING"));
        assert!(text.contains("07 ● MINING"));
        assert!(text.contains("YOU"));
        assert!(text.lines().all(|line| line.chars().count() <= 48));
    }

    #[test]
    fn transaction_exposure_and_critical_footer_are_displayed_without_guessing() {
        let mut view = model(vec![node(1, NodeStatus::Confirming, None)]);
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                render_dashboard(frame, &view, None, false);
            })
            .unwrap();
        assert!(buffer_text(&terminal).contains("0.052 / 0.5 INJ"));
        assert!(buffer_text(&terminal).contains("0.448 left"));
        assert!(buffer_text(&terminal).contains("RPC-REPORTED COST"));
        assert!(buffer_text(&terminal).contains("0.031 INJ"));

        view.authorization_used = None;
        view.connection_error = Some("snapshot unavailable".to_owned());
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("CONFIRMING"));
        assert!(text.contains("RPC ERROR • snapshot unavailable"));
        assert!(text.contains("AUTH / LIMIT"));
        assert!(text.contains("--"));

        view.connection_error = None;
        view.critical_error = Some("transaction journal verification failed".to_owned());
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("ERROR • transaction journal verification failed"));
        assert!(!text.contains("RPC ERROR"));
    }
}
