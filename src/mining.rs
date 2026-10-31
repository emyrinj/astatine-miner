use crate::{
    cli::{DeviceChoice, MineArgs},
    config::{ConfigStore, parse_inj_wei},
    dashboard::{
        Dashboard, DashboardEventKind, DashboardModel, DashboardNode, DashboardSignal,
        DashboardUpdater, NodeStatus, WindowCountdown,
    },
    deployment::DeploymentManifest,
    diagnostics::DiagnosticBuffer,
    gpu::{
        GPU_BATCH_SIZE, GpuBatchIdentity, GpuDeviceInfo, GpuEngine, PendingGpuBatch,
        benchmark_cpu_reference,
    },
    proof_telemetry::{ProofAttemptGuard, ProofMetric, ProofPipelineTelemetry},
    protocol::{WorkContext, WorkHasher, beats_incumbent, meets_target},
    rpc::{BlockSnapshot, NetworkClient, NodeState, ReadSnapshot, is_transient_rpc_error},
    startup::{CtrlCSignal, StartupProgress, race_with_ctrl_c},
    transaction::{
        AUTOMATIC_REWARD_FORWARDING_DISABLED, ConfirmedAction, ProofSubmission, TransactionAction,
        TransactionActivityState, TransactionDashboardState, TransactionManager,
        TransactionPolicyRefusalKind, is_stale_transaction_preflight, mined_transaction_reverted,
        transaction_policy_refusal,
    },
    wallet::{selected_address, unlock_selected_interactive},
};
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    time,
};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const GENESIS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
const REWARD_SCAN_SERVICE_INTERVAL: Duration = Duration::from_millis(250);
const IDLE_INTERVAL: Duration = Duration::from_millis(20);
const NONCE_BATCH_SIZE: usize = GPU_BATCH_SIZE;
const PENDING_PROOF_CANDIDATE_CAPACITY: usize = 9;
const PROOF_WAKE_CAPACITY: usize = 1;
const WORK_EXPIRY_SAFETY_SECS: u64 = 2;
const STALE_PREFLIGHT_RETRY: Duration = Duration::from_secs(1);
const OBSERVER_STALL_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_PROOF_PREFLIGHT_RETRIES: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
struct HashingContext {
    chain_id: u64,
    contract: Address,
    window_id: u64,
    seed: B256,
    miner: Address,
    header: Vec<u8>,
}

impl HashingContext {
    fn work_context(&self) -> WorkContext {
        WorkContext {
            chain_id: self.chain_id,
            contract: self.contract,
            window_id: self.window_id,
            seed: self.seed,
            miner: self.miner,
            header: self.header.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkFingerprint {
    hashing_context: HashingContext,
    target: U256,
    incumbent: Option<B256>,
    window_expiry_time: u64,
    max_header_length: u32,
}

struct WorkJob {
    fingerprint: WorkFingerprint,
    generation: u64,
    hasher: WorkHasher,
    target: U256,
    incumbent: Option<B256>,
    valid_until: Instant,
}

struct NonceAllocator {
    next: Option<u128>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalBestUpdate {
    NewBest,
    NotBetter,
    StaleGeneration,
    ExpiredDeadline,
}

impl Default for NonceAllocator {
    fn default() -> Self {
        Self { next: Some(0) }
    }
}

impl NonceAllocator {
    fn reserve(&mut self, requested: usize) -> Option<(u128, usize)> {
        let start = self.next?;
        let requested = requested as u128;
        let remaining = u128::MAX - start;
        if remaining >= requested {
            self.next = start.checked_add(requested);
            Some((start, requested as usize))
        } else {
            self.next = None;
            Some((start, (remaining + 1) as usize))
        }
    }
}

pub(crate) struct NodeSlot {
    id: u8,
    generation: AtomicU64,
    work: RwLock<Option<Arc<WorkJob>>>,
    suspended_work: Mutex<Option<Arc<WorkJob>>>,
    last_observed_head: Mutex<Option<(u64, B256)>>,
    completed_hashes: AtomicU64,
    nonces: Mutex<NonceAllocator>,
    local_best: Mutex<Option<B256>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActiveBackend {
    Cpu { threads: usize },
    Gpu(GpuDeviceInfo),
}

impl ActiveBackend {
    fn label(&self) -> &'static str {
        match self {
            Self::Cpu { .. } => "CPU",
            Self::Gpu(_) => "GPU",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Cpu { threads } => format!("{threads} Threads"),
            Self::Gpu(info) => {
                if info.tuned_hashes_per_second == 0 {
                    format!(
                        "{} · batch {} · WG{} · CPU verify",
                        info.name, info.batch_size, info.workgroup_size
                    )
                } else if info.cpu_comparison_threads > 0 {
                    format!(
                        "{} · batch {} · WG{} · auto GPU {:.1}/CPU {:.1} MH/s",
                        info.name,
                        info.batch_size,
                        info.workgroup_size,
                        info.tuned_hashes_per_second as f64 / 1_000_000.0,
                        info.cpu_comparison_hashes_per_second as f64 / 1_000_000.0,
                    )
                } else {
                    format!(
                        "{} · batch {} · WG{} · {:.2} MH/s · CPU verify",
                        info.name,
                        info.batch_size,
                        info.workgroup_size,
                        info.tuned_hashes_per_second as f64 / 1_000_000.0,
                    )
                }
            }
        }
    }
}

fn gpu_is_meaningfully_faster(gpu_hashes_per_second: u64, cpu_hashes_per_second: u64) -> bool {
    u128::from(gpu_hashes_per_second) * 100 > u128::from(cpu_hashes_per_second) * 110
}

impl NodeSlot {
    pub(crate) fn new(id: u8) -> Self {
        Self {
            id,
            generation: AtomicU64::new(0),
            work: RwLock::new(None),
            suspended_work: Mutex::new(None),
            last_observed_head: Mutex::new(None),
            completed_hashes: AtomicU64::new(0),
            nonces: Mutex::new(NonceAllocator::default()),
            local_best: Mutex::new(None),
        }
    }

    fn current_work(&self) -> Option<Arc<WorkJob>> {
        self.current_work_at(Instant::now())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn active_window_id(&self) -> Option<u64> {
        self.current_work()
            .map(|work| work.fingerprint.hashing_context.window_id)
    }

    pub(crate) fn completed_hashes(&self) -> u64 {
        self.completed_hashes.load(Ordering::Relaxed)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn set_test_nonce_start(&self, nonce: u128) {
        *self
            .nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            NonceAllocator { next: Some(nonce) };
    }

    fn current_work_at(&self, now: Instant) -> Option<Arc<WorkJob>> {
        let work = self
            .work
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        (now < work.valid_until).then_some(work)
    }

    fn diagnostic_work(&self) -> (bool, bool, Option<Instant>, Option<u64>) {
        let current = self
            .work
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let active = current
            .as_ref()
            .is_some_and(|work| Instant::now() < work.valid_until);
        if let Some(work) = current {
            return (
                active,
                false,
                Some(work.valid_until),
                Some(work.fingerprint.hashing_context.window_id),
            );
        }
        let suspended = self
            .suspended_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        suspended.map_or((false, false, None, None), |work| {
            (
                false,
                true,
                Some(work.valid_until),
                Some(work.fingerprint.hashing_context.window_id),
            )
        })
    }

    fn is_generation_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
    }

    fn reserve_nonces(&self, requested: usize) -> Option<(u128, usize)> {
        self.nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserve(requested)
    }

    fn reset_local_best_for_generation(&self, generation: u64) {
        let mut best = self
            .local_best
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_generation_current(generation) {
            *best = None;
        }
    }

    fn update_local_best(
        &self,
        generation: u64,
        valid_until: Instant,
        hash: B256,
    ) -> LocalBestUpdate {
        let mut best = self
            .local_best
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.is_generation_current(generation) {
            return LocalBestUpdate::StaleGeneration;
        }
        if Instant::now() >= valid_until {
            return LocalBestUpdate::ExpiredDeadline;
        }
        if best.is_some_and(|previous| hash >= previous) {
            return LocalBestUpdate::NotBetter;
        }
        *best = Some(hash);
        LocalBestUpdate::NewBest
    }

    fn set_work(
        &self,
        network: &DeploymentManifest,
        miner: Address,
        contract: Address,
        state: Option<&NodeState>,
        block: &BlockSnapshot,
    ) -> Result<bool> {
        self.set_work_at(network, miner, contract, state, block, Instant::now())
    }

    fn set_work_at(
        &self,
        network: &DeploymentManifest,
        miner: Address,
        contract: Address,
        state: Option<&NodeState>,
        block: &BlockSnapshot,
        now: Instant,
    ) -> Result<bool> {
        let head = (block.number, block.hash);
        let head_advanced = {
            let mut last_head = self
                .last_observed_head
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let advanced = last_head.is_some_and(|previous| previous != head);
            *last_head = Some(head);
            advanced
        };
        let next = if let Some(state) = state.filter(|state| state.eligible) {
            if state.work.max_header_length == 0 {
                bail!(
                    "node {} returned a zero-byte maximum header length",
                    self.id
                );
            }
            let hashing_context = HashingContext {
                chain_id: network.chain_id,
                contract,
                window_id: state.work.window_id,
                seed: state.work.seed,
                miner,
                header: Vec::new(),
            };
            let fingerprint = WorkFingerprint {
                hashing_context,
                target: state.work.target,
                incumbent: state
                    .candidate
                    .as_ref()
                    .map(|candidate| candidate.work_hash),
                window_expiry_time: state.work.window_expiry_time,
                max_header_length: state.work.max_header_length,
            };
            Some((
                fingerprint,
                state.work.target,
                state
                    .candidate
                    .as_ref()
                    .map(|candidate| candidate.work_hash),
            ))
        } else {
            None
        };

        let mut current = self
            .work
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((fingerprint, target, incumbent)) = next else {
            let Some(previous) = current.take() else {
                return Ok(false);
            };
            self.generation.fetch_add(1, Ordering::AcqRel);
            *self
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            *self
                .suspended_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(previous);
            return Ok(true);
        };

        let current_job = current.clone();
        let suspended_job = self
            .suspended_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let previous = current_job.as_ref().or(suspended_job.as_ref());
        let context_unchanged = previous.is_some_and(|existing| {
            existing.fingerprint.hashing_context == fingerprint.hashing_context
        });
        let same_expiry = previous.is_some_and(|existing| {
            existing.fingerprint.window_expiry_time == fingerprint.window_expiry_time
        });
        let deadline_source = previous.filter(|_| context_unchanged && same_expiry);

        let remaining = fingerprint
            .window_expiry_time
            .saturating_sub(block.timestamp)
            .saturating_sub(WORK_EXPIRY_SAFETY_SECS);
        let proposed_deadline = now
            .checked_add(Duration::from_secs(remaining))
            .unwrap_or(now);

        if let Some(existing) = current_job.as_ref()
            && existing.fingerprint == fingerprint
        {
            let valid_until = if existing.valid_until > now {
                existing.valid_until.min(proposed_deadline)
            } else if head_advanced {
                proposed_deadline
            } else {
                existing.valid_until
            };
            if valid_until == existing.valid_until {
                return Ok(false);
            }
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            if existing.valid_until <= now && head_advanced {
                *self
                    .local_best
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            }
            *current = Some(Arc::new(WorkJob {
                fingerprint,
                generation,
                hasher: existing.hasher.clone(),
                target,
                incumbent,
                valid_until,
            }));
            *self
                .suspended_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            return Ok(true);
        }

        let hasher = if let Some(previous) = deadline_source {
            previous.hasher.clone()
        } else {
            WorkHasher::new(&fingerprint.hashing_context.work_context())?
        };
        let valid_until = match deadline_source {
            Some(previous) if previous.valid_until > now => {
                previous.valid_until.min(proposed_deadline)
            }
            Some(previous) if !head_advanced => previous.valid_until,
            Some(_) | None => proposed_deadline,
        };

        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if !context_unchanged {
            *self
                .nonces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = NonceAllocator::default();
            *self
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        *current = Some(Arc::new(WorkJob {
            fingerprint,
            generation,
            hasher,
            target,
            incumbent,
            valid_until,
        }));
        *self
            .suspended_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        Ok(true)
    }
}

#[derive(Clone, Debug)]
struct ProofFound {
    node_id: u8,
    generation: u64,
    context: HashingContext,
    nonce: u128,
    hash: B256,
    target: U256,
    incumbent: Option<B256>,
    batch_identity: Option<GpuBatchIdentity>,
    queued_at: Instant,
}

#[derive(Clone)]
struct ProofInboxSender {
    pending: Arc<Mutex<[Option<ProofFound>; PENDING_PROOF_CANDIDATE_CAPACITY]>>,
    wake: mpsc::Sender<()>,
    attempts: Arc<ProofAttemptGuard>,
}

struct ProofInboxReceiver {
    pending: Arc<Mutex<[Option<ProofFound>; PENDING_PROOF_CANDIDATE_CAPACITY]>>,
    wake: mpsc::Receiver<()>,
    paused: Arc<AtomicBool>,
    sender: ProofInboxSender,
}

fn proof_inbox(
    attempts: Arc<ProofAttemptGuard>,
    initially_paused: bool,
) -> (ProofInboxSender, ProofInboxReceiver) {
    let pending = Arc::new(Mutex::new(std::array::from_fn(|_| None)));
    let paused = Arc::new(AtomicBool::new(initially_paused));
    let (wake, wake_receiver) = mpsc::channel(PROOF_WAKE_CAPACITY);
    let sender = ProofInboxSender {
        pending: Arc::clone(&pending),
        wake,
        attempts,
    };
    (
        sender.clone(),
        ProofInboxReceiver {
            pending,
            wake: wake_receiver,
            paused,
            sender,
        },
    )
}

impl ProofInboxSender {
    fn deliver(&self, proof: ProofFound, telemetry: &ProofPipelineTelemetry) -> bool {
        let Some(index) = proof
            .node_id
            .checked_sub(1)
            .map(usize::from)
            .filter(|index| *index < PENDING_PROOF_CANDIDATE_CAPACITY)
        else {
            return false;
        };
        if self
            .attempts
            .suppresses(proof.node_id, proof.context.window_id)
        {
            telemetry.record(proof.node_id, ProofMetric::SuppressedPriorAttempt);
            return false;
        }
        if self.wake.is_closed() {
            telemetry.record(proof.node_id, ProofMetric::QueueReceiverClosed);
            return false;
        }

        let accepted = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match pending[index].as_ref() {
                None => {
                    pending[index] = Some(proof.clone());
                    true
                }
                Some(existing) => {
                    telemetry.record(proof.node_id, ProofMetric::QueueFullCoalesced);
                    let replace = if existing.context == proof.context {
                        let replace = proof.hash < existing.hash;
                        telemetry.record(
                            proof.node_id,
                            if replace {
                                ProofMetric::QueueReplacedByBetter
                            } else {
                                ProofMetric::QueueCandidateSuperseded
                            },
                        );
                        replace
                    } else {
                        let replace = proof.generation > existing.generation;
                        telemetry.record(
                            proof.node_id,
                            if replace {
                                ProofMetric::QueueReplacedByNewContext
                            } else {
                                ProofMetric::QueueCandidateSuperseded
                            },
                        );
                        replace
                    };
                    if replace {
                        let mut proof = proof.clone();
                        proof.queued_at = existing.queued_at;
                        pending[index] = Some(proof);
                    }
                    replace
                }
            }
        };
        if !accepted {
            return false;
        }
        telemetry.record(proof.node_id, ProofMetric::QueuedCandidates);
        match self.wake.try_send(()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(())) => {
                telemetry.record(proof.node_id, ProofMetric::QueueWakeCoalesced);
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                let mut pending = self
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if pending[index].as_ref().is_some_and(|queued| {
                    queued.node_id == proof.node_id && queued.nonce == proof.nonce
                }) {
                    pending[index] = None;
                }
                telemetry.record(proof.node_id, ProofMetric::QueueReceiverClosed);
                return false;
            }
        }
        true
    }
}

impl ProofInboxReceiver {
    fn has_pending(&self) -> bool {
        !self.paused.load(Ordering::Acquire)
            && self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(Option::is_some)
    }

    fn set_paused(&self, paused: bool) {
        let was_paused = self.paused.swap(paused, Ordering::AcqRel);
        if was_paused && !paused {
            let _ = self.sender.wake.try_send(());
        }
    }

    fn requeue(&self, proof: ProofFound, telemetry: &ProofPipelineTelemetry) -> bool {
        self.sender.deliver(proof, telemetry)
    }

    fn take_next(&self) -> Option<ProofFound> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = pending
            .iter()
            .enumerate()
            .filter_map(|(index, proof)| proof.as_ref().map(|proof| (index, proof.queued_at)))
            .min_by_key(|(_, queued_at)| *queued_at)
            .map(|(index, _)| index)?;
        pending[index].take()
    }

    fn drain_pending(&self) -> Vec<ProofFound> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.iter_mut().filter_map(Option::take).collect()
    }

    fn discard_pending(&self, telemetry: &ProofPipelineTelemetry, reason: ProofMetric) {
        for proof in self.drain_pending() {
            telemetry.record(proof.node_id, reason);
        }
    }

    async fn recv(&mut self) -> Option<ProofFound> {
        loop {
            if !self.paused.load(Ordering::Acquire)
                && let Some(proof) = self.take_next()
            {
                return Some(proof);
            }
            self.wake.recv().await?;
        }
    }
}

fn should_unlock_recovered_wallet(
    transaction_mode: bool,
    spending_limit: U256,
    signer_is_unlocked: bool,
    has_unresolved_transaction: bool,
) -> bool {
    transaction_mode
        && !spending_limit.is_zero()
        && !signer_is_unlocked
        && !has_unresolved_transaction
}

struct MiningWorkers {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
    has_gpu_controller: bool,
}

#[derive(Clone)]
struct MiningWorkerContext {
    slots: Arc<Vec<NodeSlot>>,
    schedule: Arc<RwLock<Vec<usize>>>,
    stop: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    total_hashes: Arc<AtomicU64>,
    proofs: ProofInboxSender,
    telemetry: Arc<ProofPipelineTelemetry>,
}

#[derive(Clone, Copy)]
struct HashedCandidate {
    nonce: u128,
    hash: B256,
    reported_gpu_hash: Option<B256>,
    batch_identity: Option<GpuBatchIdentity>,
}

struct PendingGpuWorkBatch {
    slot_index: usize,
    work: Arc<WorkJob>,
    identity: GpuBatchIdentity,
    pending: PendingGpuBatch,
}

enum BackendEvent {
    Activated(ActiveBackend),
    FallbackNotice(String),
    Failed(String),
}

struct StartupControl<'a> {
    ctrl_c: &'a mut CtrlCSignal,
    progress: Option<&'a StartupProgress>,
}

impl MiningWorkers {
    fn stop_and_join(&mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        let mut failed = false;
        for worker in self.workers.drain(..) {
            if self.has_gpu_controller {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !worker.is_finished() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                if !worker.is_finished() {
                    eprintln!(
                        "astatine: GPU worker did not stop within 10 seconds; detaching the driver thread"
                    );
                    failed = true;
                    continue;
                }
            }
            failed |= worker.join().is_err();
        }
        failed
    }
}

impl Drop for MiningWorkers {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

#[derive(Clone)]
pub(crate) struct DashboardContext {
    pub(crate) network: crate::cli::Network,
    pub(crate) chain_id: u64,
    pub(crate) address: Address,
    pub(crate) active_backend: Arc<RwLock<ActiveBackend>>,
    pub(crate) spending_limit: U256,
    pub(crate) transaction_mode: bool,
    pub(crate) compute_only: bool,
    pub(crate) workers_started: Arc<AtomicBool>,
    pub(crate) total_hashes: Arc<AtomicU64>,
    pub(crate) selected: HashSet<u8>,
    pub(crate) slots: Arc<Vec<NodeSlot>>,
    pub(crate) schedule: Arc<RwLock<Vec<usize>>>,
    pub(crate) transaction_state: Arc<RwLock<TransactionDashboardState>>,
    pub(crate) pending_sync: Arc<RwLock<HashMap<u8, PendingDashboardSync>>>,
    pub(crate) finalization_state: Arc<RwLock<HashMap<u8, FinalizationState>>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingDashboardSync {
    window_id: u64,
    receipt_block: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FinalizationState {
    Retrying {
        window_id: u64,
        attempts: u8,
        retry_at: Instant,
        reason: String,
    },
    Blocked {
        window_id: u64,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum ObserverUpdate {
    Snapshot(ReadSnapshot),
    RpcError { message: String, report: bool },
    GenesisPollError { message: String, report: bool },
    Fatal(String),
}

enum ObserverWake {
    FullRefresh,
    GenesisProbe(Vec<u8>),
}

pub(crate) struct ReadOnlyObserver {
    shutdown: watch::Sender<bool>,
    pub(crate) updates: watch::Receiver<ObserverUpdate>,
    force_refresh: mpsc::Sender<()>,
    refresh_epoch: Arc<AtomicU64>,
    refresh_gate: Arc<Mutex<()>>,
    last_publication_at: Arc<Mutex<Instant>>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct MiningProbe {
    pub(crate) slots: Arc<Vec<NodeSlot>>,
    pub(crate) schedule: Arc<RwLock<Vec<usize>>>,
    pub(crate) observer_updates: watch::Receiver<ObserverUpdate>,
    pub(crate) observer_refresh: ObserverRefreshHandle,
    pub(crate) stop_signal: DashboardSignal,
    pub(crate) proof_telemetry: Arc<ProofPipelineTelemetry>,
    pub(crate) cpu_worker_threads: usize,
    pub(crate) active_backend: ActiveBackend,
    #[cfg(test)]
    pub(crate) transaction_state: Arc<RwLock<TransactionDashboardState>>,
    #[cfg(test)]
    pub(crate) history_telemetry: Arc<crate::history_telemetry::HistoryTelemetry>,
    #[cfg(test)]
    pub(crate) proof_processing_gate: watch::Sender<bool>,
}

#[derive(Clone)]
pub(crate) struct ObserverRefreshHandle {
    sender: mpsc::Sender<()>,
    epoch: Arc<AtomicU64>,
    gate: Arc<Mutex<()>>,
}

impl ObserverRefreshHandle {
    pub(crate) fn force_refresh(&self) {
        let _commit = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let _ = self.sender.try_send(());
    }
}

impl ReadOnlyObserver {
    pub(crate) fn force_refresh(&self) {
        self.refresh_handle().force_refresh();
    }

    fn refresh_handle(&self) -> ObserverRefreshHandle {
        ObserverRefreshHandle {
            sender: self.force_refresh.clone(),
            epoch: Arc::clone(&self.refresh_epoch),
            gate: Arc::clone(&self.refresh_gate),
        }
    }

    pub(crate) fn latest_snapshot(&self) -> Option<ReadSnapshot> {
        match &*self.updates.borrow() {
            ObserverUpdate::Snapshot(snapshot) => Some(snapshot.clone()),
            ObserverUpdate::RpcError { .. }
            | ObserverUpdate::GenesisPollError { .. }
            | ObserverUpdate::Fatal(_) => None,
        }
    }

    pub(crate) fn publication_age(&self) -> Duration {
        self.last_publication_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed()
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        self.shutdown.send_replace(true);
        self.task.abort();
        match (&mut self.task).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error).context("join read-only chain observer"),
        }
    }
}

impl Drop for ReadOnlyObserver {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.task.abort();
    }
}

pub async fn run(store: &ConfigStore, args: MineArgs) -> Result<()> {
    if args.send_rewards_to.is_some() {
        bail!("{AUTOMATIC_REWARD_FORWARDING_DISABLED}");
    }
    let progress = StartupProgress::start();
    let mut ctrl_c: CtrlCSignal = Box::pin(tokio::signal::ctrl_c());
    progress.begin("Loading configuration");
    let config = match store.load() {
        Ok(config) => config,
        Err(error) => {
            progress.fail(format!("Configuration loading failed: {error:#}"));
            return Err(error);
        }
    };
    progress.complete("Configuration loaded");
    progress.set_network(match config.network {
        crate::cli::Network::Testnet => "Injective EVM Testnet",
        crate::cli::Network::Mainnet => "Injective EVM Mainnet",
    });
    if !args.compute_only && config.network != crate::cli::Network::Testnet {
        progress.fail("Autonomous transaction signing is disabled outside Injective Testnet");
        bail!("autonomous transaction signing is disabled outside Injective Testnet");
    }
    progress.begin("Checking selected wallet");
    if let Err(error) = selected_address(&config) {
        progress.fail(format!("Selected wallet check failed: {error:#}"));
        return Err(error);
    }
    progress.complete("Selected wallet checked");
    progress.begin("Connecting to RPC · validating Chain ID");
    let connected = race_with_ctrl_c(
        NetworkClient::connect_with_progress(
            config.network,
            config.rpc_override(config.network),
            Some(&progress),
        ),
        &mut ctrl_c,
    )
    .await?;
    let Some(client) = connected else {
        progress.cancel();
        return Ok(());
    };
    let client = client?;
    run_runtime(
        store,
        config,
        args,
        client,
        None,
        None,
        StartupControl {
            ctrl_c: &mut ctrl_c,
            progress: Some(&progress),
        },
    )
    .await
}

#[cfg(test)]
pub(crate) async fn run_with_client(
    store: &ConfigStore,
    config: crate::config::AppConfig,
    args: MineArgs,
    client: NetworkClient,
    supplied_signer: Option<bip32::secp256k1::ecdsa::SigningKey>,
    probe_sender: Option<tokio::sync::oneshot::Sender<MiningProbe>>,
) -> Result<()> {
    let mut ctrl_c: CtrlCSignal = Box::pin(tokio::signal::ctrl_c());
    run_runtime(
        store,
        config,
        args,
        client,
        supplied_signer,
        probe_sender,
        StartupControl {
            ctrl_c: &mut ctrl_c,
            progress: None,
        },
    )
    .await
}

async fn run_runtime(
    store: &ConfigStore,
    config: crate::config::AppConfig,
    args: MineArgs,
    mut client: NetworkClient,
    supplied_signer: Option<bip32::secp256k1::ecdsa::SigningKey>,
    probe_sender: Option<tokio::sync::oneshot::Sender<MiningProbe>>,
    startup_control: StartupControl<'_>,
) -> Result<()> {
    let StartupControl {
        ctrl_c,
        progress: startup,
    } = startup_control;
    if args.send_rewards_to.is_some() {
        bail!("{AUTOMATIC_REWARD_FORWARDING_DISABLED}");
    }
    let show_history_profile =
        history_profile_enabled(std::env::var("ASTATINE_HISTORY_PROFILE").ok().as_deref());
    let probe_stop_signal = probe_sender.as_ref().map(|_| DashboardSignal::default());
    #[cfg(test)]
    let (proof_processing_gate, mut proof_processing_gate_receiver) = if probe_sender.is_some() {
        let (sender, receiver) = watch::channel(true);
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let proof_telemetry = Arc::new(ProofPipelineTelemetry::default());
    let proof_attempt_guard = Arc::new(ProofAttemptGuard::default());
    if !args.compute_only && config.network != crate::cli::Network::Testnet {
        bail!("autonomous transaction signing is disabled outside Injective Testnet");
    }
    let address = selected_address(&config)?;
    let spending_limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
    if args.new_session && (args.compute_only || spending_limit.is_zero()) {
        bail!(
            "--new-session requires transaction mode and a positive per-session authorization cap"
        );
    }
    let transaction_mode = !args.compute_only && !spending_limit.is_zero();
    let threads = args
        .threads
        .map(NonZeroUsize::get)
        .unwrap_or(config.cpu_threads);
    if threads == 0 || threads > config.cpu_threads || threads > 256 {
        bail!(
            "requested threads ({threads}) must be within the configured CPU budget ({}; max 256)",
            config.cpu_threads
        );
    }
    let selected = selected_nodes(&args.nodes)?;
    if !client.has_mining_deployment() {
        bail!(
            "{} has no verified Astatine mining deployment; mining is disabled",
            network_label(config.network)
        );
    }
    if transaction_mode && !client.can_broadcast() {
        bail!("the verified Testnet primary RPC is unavailable; refusing to sign or broadcast");
    }
    if transaction_mode && !client.verification.token_verified {
        bail!("AST token runtime is not verified; refusing autonomous transaction signing");
    }
    if let Some(startup) = startup {
        startup.begin("Recovering previous transactions");
    }
    let readonly_recovery = !args.compute_only
        && config.network == crate::cli::Network::Testnet
        && spending_limit.is_zero()
        && match store.read_transaction_journal() {
            Ok(journal) => journal.is_some(),
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!("Transaction journal could not be read: {error:#}"));
                }
                return Err(error).context("check for a read-only transaction recovery journal");
            }
        };
    let transaction_manager_mode = transaction_mode || readonly_recovery;
    let mut transactions = if transaction_manager_mode {
        let token = client
            .manifest
            .ast_token
            .as_ref()
            .context("AST token pin is missing from the Testnet manifest")?;
        let ast_token = crate::deployment::parse_address(&token.address)?;
        let mut manager = match TransactionManager::open_with_session_authorization(
            store,
            &config,
            address,
            ast_token,
            client.history_telemetry(),
            args.new_session,
        ) {
            Ok(manager) => manager,
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!(
                        "Transaction journal could not be opened: {error:#}"
                    ));
                }
                return Err(error).context("open transaction journal for startup recovery");
            }
        };
        manager.configure_reward_forwarding(args.send_rewards_to)?;
        manager.set_proof_telemetry(Arc::clone(&proof_telemetry));
        manager.set_proof_attempt_guard(Arc::clone(&proof_attempt_guard));
        for node in &client.manifest.nodes {
            let contract = crate::deployment::parse_address(&node.address)?;
            if let Some(window_id) = manager.proof_attempted_through(contract) {
                proof_attempt_guard.record_attempt(node.id, window_id);
            }
        }
        match race_with_ctrl_c(manager.reconcile(&client), ctrl_c).await? {
            Some(Ok(())) => {
                let legacy = manager.legacy_unverified_settled_count()?;
                if legacy > 0 {
                    let message = format!(
                        "{legacy} historical transaction settlement(s) retain their recorded costs but predate RC1 trusted-RPC processing"
                    );
                    if let Some(startup) = startup {
                        startup.note(message);
                    } else {
                        eprintln!("{message}");
                    }
                }
            }
            Some(Err(error)) => {
                if let Some(startup) = startup {
                    startup.fail(format!("Transaction recovery failed: {error:#}"));
                }
                return Err(error).context("recover previous Testnet transactions");
            }
            None => {
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(());
            }
        }
        Some(manager)
    } else {
        None
    };
    if let Some(startup) = startup {
        if transaction_manager_mode {
            startup.complete("Transaction recovery complete");
        } else {
            startup.complete("No previous transactions to recover");
        }
        if let Some(manager) = transactions.as_ref()
            && let Some(profile) =
                optional_history_profile(show_history_profile, || manager.history_profile_line())
        {
            startup.note(profile);
        }
    }
    let signing_ready = transactions
        .as_ref()
        .is_some_and(|manager| !manager.journal.has_unresolved());
    if transactions
        .as_ref()
        .is_some_and(|manager| manager.journal.has_unresolved())
    {
        eprintln!(
            "An unresolved or underconfirmed transaction is being recovered. No further transactions will be signed until it settles; maximum exposure remains reserved."
        );
    }
    let mut supplied_signer = supplied_signer;
    let mut signer = if transaction_mode {
        if let Some(signer) = supplied_signer.take() {
            Some(signer)
        } else if signing_ready {
            if let Some(startup) = startup {
                startup.begin("Unlocking wallet");
                match crate::wallet::unlock_selected_interactive_with_progress(
                    store, &config, startup,
                ) {
                    Ok(signer) => {
                        startup.complete("Wallet unlocked");
                        Some(signer)
                    }
                    Err(error) if crate::wallet::is_password_prompt_interrupted(&error) => {
                        startup.cancel();
                        return Ok(());
                    }
                    Err(error) => {
                        startup.fail(format!("Wallet unlock failed: {error:#}"));
                        return Err(error).context("unlock selected wallet for mining");
                    }
                }
            } else {
                Some(unlock_selected_interactive(store, &config)?)
            }
        } else {
            if let Some(startup) = startup {
                startup.note("Wallet unlock deferred until previous transaction recovery settles.");
            }
            None
        }
    } else {
        if let Some(startup) = startup {
            startup.note("Wallet unlock skipped because transaction signing is disabled.");
        }
        None
    };
    if signer
        .as_ref()
        .is_some_and(|signer| crate::wallet::signer_address(signer) != address)
    {
        if let Some(startup) = startup {
            startup.fail("Unlocked signer does not match the selected wallet");
        }
        bail!("unlocked signer does not match the selected wallet");
    }
    let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
    let schedule = Arc::new(RwLock::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicUsize::new(0));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let active_backend = Arc::new(RwLock::new(ActiveBackend::Cpu { threads }));
    let diagnostics = DiagnosticBuffer::default();
    let transaction_state = Arc::new(RwLock::new(initial_transaction_dashboard_state(
        transactions.as_ref(),
        &diagnostics,
    )));
    let dashboard_context = DashboardContext {
        network: client.manifest.network,
        chain_id: client.manifest.chain_id,
        address,
        active_backend: Arc::clone(&active_backend),
        spending_limit,
        transaction_mode,
        compute_only: args.compute_only,
        workers_started: Arc::new(AtomicBool::new(false)),
        total_hashes: Arc::clone(&total_hashes),
        selected: selected.clone(),
        slots: Arc::clone(&slots),
        schedule: Arc::clone(&schedule),
        transaction_state: Arc::clone(&transaction_state),
        pending_sync: Arc::new(RwLock::new(HashMap::new())),
        finalization_state: Arc::new(RwLock::new(HashMap::new())),
    };
    client.set_diagnostics(diagnostics.clone());
    if let Some(manager) = transactions.as_mut() {
        manager.set_diagnostics(diagnostics.clone());
    }
    if let Some(startup) = startup {
        startup.begin("Loading latest mining work");
    }
    let snapshot = match race_with_ctrl_c(client.snapshot(Some(address)), ctrl_c).await? {
        Some(Ok(snapshot)) => snapshot,
        Some(Err(error)) => {
            if let Some(startup) = startup {
                startup.fail(format!("Initial mining snapshot failed: {error:#}"));
            }
            return Err(error).context("load initial verified mining snapshot");
        }
        None => {
            if let Some(startup) = startup {
                startup.cancel();
            }
            return Ok(());
        }
    };
    let changed = match update_slots(
        &slots,
        &schedule,
        &client.manifest,
        address,
        &selected,
        &snapshot,
    ) {
        Ok(changed) => changed,
        Err(error) => {
            if let Some(startup) = startup {
                startup.fail(format!(
                    "Initial mining work could not be scheduled: {error:#}"
                ));
            }
            return Err(error).context("schedule initial verified mining work");
        }
    };
    #[cfg(test)]
    for slot in slots.iter() {
        if let Some(work) = slot.current_work()
            && let Some(nonce) = client.take_test_proof_nonce_start(
                slot.id,
                work.fingerprint.hashing_context.window_id,
                work.fingerprint.hashing_context.seed,
            )
        {
            slot.set_test_nonce_start(nonce);
        }
    }
    if let Some(startup) = startup {
        startup.complete(format!(
            "Latest mining work loaded · block #{}",
            snapshot.block.number
        ));
        if transactions.is_some() {
            startup.begin("Scheduling historical reward verification");
        }
    }
    if let Some(manager) = transactions.as_mut() {
        match manager
            .service_reward_reconciliation(&client, &snapshot)
            .await
        {
            Ok(scheduled) => {
                if let Some(startup) = startup {
                    startup.complete(if !client.verification.token_verified {
                        "Reward history waits for verified AST token"
                    } else if scheduled {
                        "Historical reward verification scheduled; mining continues"
                    } else {
                        "No pending historical reward evidence"
                    });
                }
            }
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!(
                        "Reward reconciliation scheduling failed: {error:#}"
                    ));
                }
                return Err(error).context("schedule historical reward verification");
            }
        }
    }
    let proof_delivery_paused = transaction_mode
        && (signer.is_none()
            || transactions
                .as_ref()
                .is_some_and(|manager| manager.journal.has_unresolved()));
    let (proof_sender, mut proof_receiver) =
        proof_inbox(Arc::clone(&proof_attempt_guard), proof_delivery_paused);
    let worker_context = MiningWorkerContext {
        slots: Arc::clone(&slots),
        schedule: Arc::clone(&schedule),
        stop: Arc::clone(&stop),
        cursor: Arc::clone(&cursor),
        total_hashes: Arc::clone(&total_hashes),
        proofs: proof_sender.clone(),
        telemetry: Arc::clone(&proof_telemetry),
    };
    if let Some(startup) = startup {
        startup.begin(match args.device {
            DeviceChoice::Cpu => "Preparing CPU mining workers",
            DeviceChoice::Gpu => "Initializing and self-testing physical GPU",
            DeviceChoice::Auto => "Detecting and self-testing physical GPU",
        });
    }
    let mut worker_guard = MiningWorkers {
        stop: Arc::clone(&stop),
        workers: Vec::new(),
        has_gpu_controller: false,
    };
    let mut backend_event_receiver = None;
    match args.device {
        DeviceChoice::Cpu => {
            worker_guard.workers = start_cpu_worker_threads(threads, worker_context.clone())
                .inspect_err(|error| {
                    if let Some(startup) = startup {
                        startup.fail(format!("Could not start CPU mining workers: {error:#}"));
                    }
                })?;
            if let Some(startup) = startup {
                startup.complete(format!("CPU workers ready · {threads} thread(s)"));
            }
        }
        DeviceChoice::Gpu | DeviceChoice::Auto => {
            if let Some(startup) = startup {
                startup.update("GPU initialization includes a real WGSL SHA-256d self-test");
            }
            let (events, receiver) = mpsc::unbounded_channel();
            backend_event_receiver = Some(receiver);
            let controller_context = worker_context.clone();
            worker_guard.has_gpu_controller = true;
            let controller = thread::Builder::new()
                .name("astatine-gpu-controller".to_owned())
                .spawn(move || {
                    gpu_worker_controller(args.device, threads, controller_context, events);
                })
                .context("start GPU backend controller")?;
            worker_guard.workers.push(controller);

            let initial_event = tokio::select! {
                event = receive_backend_event(&mut backend_event_receiver) => event,
                signal = ctrl_c.as_mut() => {
                    if let Err(error) = signal {
                        report_mining_warning(&None, format!("Ctrl+C signal handler failed: {error}"));
                    }
                    stop.store(true, Ordering::Release);
                    if let Some(startup) = startup { startup.cancel(); }
                    let _ = worker_guard.stop_and_join();
                    return Ok(());
                }
            };
            match initial_event {
                Some(BackendEvent::Activated(backend)) => {
                    *active_backend
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = backend.clone();
                    if let Some(startup) = startup {
                        startup.complete(match &backend {
                            ActiveBackend::Cpu { threads } if args.device == DeviceChoice::Auto => {
                                format!(
                                    "Auto selected CPU by measured throughput · {threads} thread(s)"
                                )
                            }
                            ActiveBackend::Cpu { threads } => {
                                format!("CPU fallback ready · {threads} thread(s)")
                            }
                            ActiveBackend::Gpu(info) => {
                                format!(
                                    "GPU self-test passed · {} · {} · batch {} · WG{}",
                                    info.name, info.backend, info.batch_size, info.workgroup_size
                                )
                            }
                        });
                    }
                }
                Some(BackendEvent::FallbackNotice(reason)) => {
                    diagnostics.push(format!("{reason}; using CPU fallback."));
                    *active_backend
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        ActiveBackend::Cpu { threads };
                    if let Some(startup) = startup {
                        startup.complete(format!("CPU fallback ready · {threads} thread(s)"));
                    }
                }
                Some(BackendEvent::Failed(message)) => {
                    stop.store(true, Ordering::Release);
                    let _ = worker_guard.stop_and_join();
                    if let Some(startup) = startup {
                        startup.fail(message.clone());
                    }
                    bail!("{message}");
                }
                None => {
                    stop.store(true, Ordering::Release);
                    let _ = worker_guard.stop_and_join();
                    let error = anyhow!("GPU backend stopped before initialization completed");
                    if let Some(startup) = startup {
                        startup.fail(format!("{error:#}"));
                    }
                    return Err(error);
                }
            }
        }
    }
    drop(proof_sender);
    dashboard_context
        .workers_started
        .store(true, Ordering::Release);
    if let Some(startup) = startup {
        startup.miner_ready();
    }
    let model = dashboard_model(&dashboard_context, &snapshot, Instant::now());
    let mut dashboard =
        match Dashboard::start(model, Arc::clone(&total_hashes), diagnostics.clone()) {
            Ok(dashboard) => dashboard,
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!("Mining dashboard could not start: {error:#}"));
                }
                return Err(error).context("initialize mining dashboard terminal");
            }
        };
    if let Some(dashboard) = &dashboard {
        let diagnostics = dashboard.diagnostics();
        client.set_diagnostics(diagnostics.clone());
        if let Some(manager) = transactions.as_mut() {
            manager.set_diagnostics(diagnostics);
        }
    }
    connect_transaction_dashboard(
        &mut transactions,
        &dashboard,
        Arc::clone(&transaction_state),
    );
    let dashboard_updater = dashboard.as_ref().map(Dashboard::updater);
    refresh_dashboard(dashboard_updater.as_ref(), &dashboard_context, &snapshot);
    if !client.verification.token_verified {
        report_mining_warning(
            &dashboard,
            "AST token runtime pin is unavailable; mining proofs can still be computed, but AST balance is not trusted.",
        );
    }
    if !cfg!(test) {
        let update_diagnostics = diagnostics.clone();
        tokio::spawn(async move {
            if let Ok(Some(version)) = crate::update::check_for_update().await {
                update_diagnostics.push(format!(
                    "Authenticated Astatine update {version} is available; run `astatine update` to install it."
                ));
            }
        });
    }
    if dashboard.is_none() {
        for message in diagnostics.drain() {
            eprintln!("astatine: {message}");
        }
        if !args.compute_only && spending_limit.is_zero() {
            println!(
                "Per-session spending limit is zero; autonomous signing is disabled. Hashing continues without submissions or finalizations."
            );
        }
        print_startup(
            &client,
            address,
            &active_backend,
            &snapshot,
            &slots,
            &selected,
            changed,
        );
    }
    let mut observer = start_read_only_observer(
        client.clone(),
        dashboard_context.clone(),
        snapshot.clone(),
        dashboard_updater.clone(),
        diagnostics.clone(),
    );
    let mut observed_updates = observer.updates.clone();
    let _ = observed_updates.borrow_and_update();
    observer.force_refresh();
    if let Some(probe_sender) = probe_sender {
        let _ = probe_sender.send(MiningProbe {
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            observer_updates: observer.updates.clone(),
            observer_refresh: observer.refresh_handle(),
            stop_signal: probe_stop_signal
                .as_ref()
                .expect("test stop signal must be initialized")
                .clone(),
            proof_telemetry: Arc::clone(&proof_telemetry),
            cpu_worker_threads: match active_backend
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                ActiveBackend::Cpu { threads } => threads,
                ActiveBackend::Gpu(_) => 0,
            },
            active_backend: active_backend
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            #[cfg(test)]
            transaction_state: Arc::clone(&transaction_state),
            #[cfg(test)]
            history_telemetry: client.history_telemetry(),
            #[cfg(test)]
            proof_processing_gate: proof_processing_gate
                .clone()
                .expect("test proof-processing gate must be initialized"),
        });
    }

    let mut progress_ticker = time::interval(PROGRESS_INTERVAL);
    progress_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    progress_ticker.tick().await;
    let mut reward_scan_ticker = time::interval(REWARD_SCAN_SERVICE_INTERVAL);
    reward_scan_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    reward_scan_ticker.tick().await;
    let mut last_progress = time::Instant::now();
    let mut last_snapshot = observer.latest_snapshot().unwrap_or(snapshot);
    let mut fatal_error = None;
    let mut budget_exhausted = false;
    let mut stale_proof_warning_window = HashMap::<u8, u64>::new();
    let dashboard_signal = dashboard
        .as_ref()
        .map(Dashboard::signal)
        .or_else(|| probe_stop_signal.clone());

    'mining_loop: loop {
        tokio::select! {
            signal = ctrl_c.as_mut() => {
                if let Err(error) = signal {
                    report_mining_warning(
                        &dashboard,
                        format!("Ctrl+C signal handler failed: {error}"),
                    );
                }
                break;
            }
            event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                match event {
                    DashboardEventKind::StopRequested => break,
                    DashboardEventKind::Failure(error) => {
                        fatal_error = Some(anyhow!("dashboard failed: {error}"));
                        break;
                    }
                }
            }
            update = observed_updates.changed() => {
                if update.is_err() {
                    fatal_error = Some(anyhow!("read-only chain observer stopped unexpectedly"));
                    break;
                }
                let update = take_observer_update(&mut observed_updates);
                match update {
                    ObserverUpdate::Snapshot(snapshot) => {
                        let mut snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        // Reward reconciliation must remain live under proof-inbox pressure.
                        // The service only harvests completed scans or schedules background work;
                        // it does not wait on in-flight RPC requests.
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager
                                .service_reward_reconciliation(&client, &snapshot)
                                .await
                        {
                            fatal_error = Some(error.context("service historical reward verification"));
                            break 'mining_loop;
                        }
                        if proof_receiver.has_pending()
                            && let Some(manager) = transactions.as_mut()
                            && manager.journal.has_unresolved()
                        {
                            if let Err(error) = manager
                                .monitor_at_snapshot(&client, &snapshot.block)
                                .await
                            {
                                fatal_error = Some(error.context(
                                    "monitor transaction recovery while proof delivery is deferred",
                                ));
                                break 'mining_loop;
                            }
                            proof_receiver.set_paused(
                                transaction_mode
                                    && (signer.is_none() || manager.journal.has_unresolved()),
                            );
                        }
                        if proof_receiver.has_pending() {
                            last_snapshot = snapshot;
                            continue 'mining_loop;
                        }
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager
                                .monitor_at_snapshot(&client, &snapshot.block)
                                .await
                        {
                            fatal_error = Some(error.context("monitor transaction finality and reorg state"));
                            break;
                        }
                        if transaction_mode
                            && let Some(manager) = transactions.as_ref()
                        {
                            match manager.budget_remaining() {
                                Ok(remaining) => budget_exhausted |= remaining.is_zero(),
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        }
                        if budget_exhausted {
                            proof_receiver
                                .discard_pending(&proof_telemetry, ProofMetric::RefusedSpendingLimit);
                        }
                        proof_receiver.set_paused(
                            transaction_mode
                                && (signer.is_none()
                                    || transactions
                                        .as_ref()
                                        .is_some_and(|manager| manager.journal.has_unresolved())),
                        );
                        snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        if proof_receiver.has_pending() {
                            last_snapshot = snapshot;
                            continue 'mining_loop;
                        }
                        if let Some(manager) = transactions.as_ref()
                            && should_unlock_recovered_wallet(
                                transaction_mode,
                                spending_limit,
                                signer.is_some(),
                                manager.journal.has_unresolved(),
                            )
                        {
                            if let Some(dashboard) = dashboard.as_mut()
                                && let Err(error) = dashboard.suspend().await
                            {
                                fatal_error = Some(error.context("suspend dashboard for wallet unlock"));
                                break;
                            }
                            let unlock_result = unlock_selected_interactive(store, &config);
                            if let Some(dashboard) = dashboard.as_mut()
                                && let Err(error) = dashboard.resume(Arc::clone(&total_hashes))
                            {
                                fatal_error = Some(error.context("resume dashboard after wallet unlock"));
                                break;
                            }
                            let recovered_signer = match unlock_result {
                                Ok(recovered_signer)
                                    if crate::wallet::signer_address(&recovered_signer) == address =>
                                {
                                    recovered_signer
                                }
                                Ok(_) => {
                                    fatal_error = Some(anyhow!(
                                        "unlocked signer does not match the selected wallet"
                                    ));
                                    break;
                                }
                                Err(error) => {
                                    fatal_error = Some(
                                        error.context("unlock selected wallet after transaction recovery"),
                                    );
                                    break;
                                }
                            };
                            signer = Some(recovered_signer);
                            proof_receiver.set_paused(false);
                            report_mining_info(
                                &dashboard,
                                "Transaction recovery settled; autonomous Testnet signing is resuming.",
                            );
                        }
                        snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        if let (Some(manager), Some(signer)) =
                            (transactions.as_mut(), signer.as_ref())
                        {
                            let finalization_result = tokio::select! {
                                result = maybe_finalize_expired(
                                    &client,
                                    &selected,
                                    manager,
                                    signer,
                                    address,
                                    &snapshot,
                                    FinalizationOptions {
                                        finalization_state: &dashboard_context.finalization_state,
                                        dashboard: &dashboard,
                                        pending_sync: &dashboard_context.pending_sync,
                                    },
                                ) => Some(result),
                                signal = ctrl_c.as_mut() => {
                                    if let Err(error) = signal {
                                        report_mining_warning(&dashboard, format!("Ctrl+C signal handler failed: {error}"));
                                    }
                                    None
                                }
                                event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                                    if let DashboardEventKind::Failure(error) = event {
                                        fatal_error = Some(anyhow!("dashboard failed: {error}"));
                                    }
                                    None
                                }
                            };
                            let Some(finalization_result) = finalization_result else {
                                break 'mining_loop;
                            };
                            match finalization_result {
                                Ok(true) => {
                                    observer.force_refresh();
                                }
                                Ok(false) => {}
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        }
                        proof_receiver.set_paused(
                            transaction_mode
                                && (signer.is_none()
                                    || transactions
                                        .as_ref()
                                        .is_some_and(|manager| manager.journal.has_unresolved())
                                    || budget_exhausted),
                        );
                        snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        // Harvest completed reward batches even while proof work is queued. This
                        // only awaits a scan task after it has finished; active RPC scans remain
                        // in the background and never hold up live proof processing.
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager
                                .service_reward_reconciliation(&client, &snapshot)
                                .await
                        {
                            fatal_error = Some(error.context("service historical reward verification"));
                            break 'mining_loop;
                        }
                        if proof_receiver.has_pending() {
                            last_snapshot = snapshot;
                            continue 'mining_loop;
                        }
                        proof_receiver.set_paused(
                            transaction_mode
                                && (signer.is_none()
                                    || transactions
                                        .as_ref()
                                        .is_some_and(|manager| manager.journal.has_unresolved())
                                    || budget_exhausted),
                        );
                        last_snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                    }
                    ObserverUpdate::RpcError { message, report } => {
                        if report && dashboard.is_none() {
                            report_mining_warning(&dashboard, message);
                        }
                        if dashboard.is_none() {
                            total_hashes.store(0, Ordering::Relaxed);
                        }
                    }
                    ObserverUpdate::GenesisPollError { message, report } => {
                        if report && dashboard.is_none() {
                            report_mining_warning(&dashboard, message);
                        }
                    }
                    ObserverUpdate::Fatal(error) => {
                        fatal_error = Some(anyhow!("read-only observer failed: {error}"));
                        break;
                    }
                }
            }
            _ = progress_ticker.tick() => {
                let observer_age = observer.publication_age();
                if observer_age > OBSERVER_STALL_TIMEOUT {
                    fatal_error = Some(anyhow!(
                        "read-only chain observer has not published a snapshot or error for {} seconds; mining is stopping rather than showing healthy WAITING",
                        observer_age.as_secs()
                    ));
                    break;
                }
                let elapsed = last_progress.elapsed();
                if dashboard.is_none() && elapsed >= PROGRESS_INTERVAL {
                    print_progress(
                        &last_snapshot,
                        &slots,
                        total_hashes.swap(0, Ordering::Relaxed),
                        elapsed,
                    );
                    last_progress = time::Instant::now();
                }
            }
            _ = reward_scan_ticker.tick(), if transactions.is_some() => {
                if let Some(manager) = transactions.as_mut()
                    && let Err(error) = manager
                        .service_reward_reconciliation(&client, &last_snapshot)
                        .await
                {
                    fatal_error = Some(error.context("service historical reward verification"));
                    break 'mining_loop;
                }
                proof_receiver.set_paused(
                    transaction_mode
                        && (signer.is_none()
                            || transactions
                                .as_ref()
                                .is_some_and(|manager| manager.journal.has_unresolved())
                            || budget_exhausted),
                );
            }
            event = receive_backend_event(&mut backend_event_receiver) => {
                match event {
                    Some(BackendEvent::Activated(backend)) => {
                        *active_backend
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = backend.clone();
                        if let Some(updater) = &dashboard_updater {
                            updater.update(|model| {
                                model.device_label = backend.label().to_owned();
                                model.device_detail = backend.detail();
                            });
                        }
                        match backend {
                            ActiveBackend::Cpu { threads } => report_mining_warning(
                                &dashboard,
                                format!("GPU backend stopped; safely continuing on CPU ({threads} worker thread(s)); reserved GPU nonce ranges will not be reused."),
                            ),
                            ActiveBackend::Gpu(info) => report_mining_info(
                                &dashboard,
                                format!("GPU backend active · {} · {}", info.name, info.backend),
                            ),
                        }
                    }
                    Some(BackendEvent::Failed(message)) => {
                        fatal_error = Some(anyhow!(message));
                        break 'mining_loop;
                    }
                    Some(BackendEvent::FallbackNotice(reason)) => {
                        report_mining_warning(
                            &dashboard,
                            format!("{reason}; continuing with the CPU backend."),
                        );
                    }
                    None => backend_event_receiver = None,
                }
            }
            proof = proof_receiver.recv() => {
                let Some(proof) = proof else {
                    fatal_error = Some(anyhow!("compute proof inbox closed while mining was active"));
                    break;
                };
                proof_telemetry.record(proof.node_id, ProofMetric::MainLoopReceived);
                #[cfg(test)]
                if let Some(gate) = proof_processing_gate_receiver.as_mut() {
                    while *gate.borrow() {
                        if gate.changed().await.is_err() {
                            break;
                        }
                    }
                }
                let Some(slot) = slots.get(usize::from(proof.node_id.saturating_sub(1))) else {
                    continue;
                };
                let work = match revalidate_queued_proof(slot, &proof, &proof_telemetry) {
                    Ok(work) => work,
                    Err(reason) => {
                        record_proof_revalidation_drop(slot, &proof, reason, &proof_telemetry);
                        continue;
                    }
                };
                let incumbent = proof
                    .incumbent
                    .map(|hash| format!("; found against incumbent {hash:#x}"))
                    .unwrap_or_default();
                let contract = work.fingerprint.hashing_context.contract;
                let window_id = work.fingerprint.hashing_context.window_id;
                if args.compute_only {
                    report_mining_info(
                        &dashboard,
                        format!(
                            "valid local proof: node={} window={} nonce={} hash={:#x} target={:#x}{}; compute-only, not submitted",
                            proof.node_id, window_id, proof.nonce, proof.hash, proof.target, incumbent
                        ),
                    );
                    continue;
                }
                let (Some(manager), Some(signer)) =
                    (transactions.as_mut(), signer.as_ref())
                else {
                    proof_telemetry.record(proof.node_id, ProofMetric::RefusedSigningDisabled);
                    continue;
                };
                if manager.proof_attempted(contract, window_id) {
                    proof_telemetry.record(proof.node_id, ProofMetric::SuppressedPriorAttempt);
                    continue;
                }
                if manager.journal.has_unresolved() {
                    proof_receiver.set_paused(true);
                    let _ = proof_receiver.requeue(proof.clone(), &proof_telemetry);
                    proof_telemetry.record(
                        proof.node_id,
                        ProofMetric::DeferredUnresolvedTransaction,
                    );
                    continue;
                }
                if budget_exhausted || manager.budget_remaining()?.is_zero() {
                    budget_exhausted = true;
                    proof_telemetry.record(proof.node_id, ProofMetric::RefusedSpendingLimit);
                    proof_receiver.set_paused(true);
                    proof_receiver
                        .discard_pending(&proof_telemetry, ProofMetric::RefusedSpendingLimit);
                    continue;
                }
                let header = work.fingerprint.hashing_context.header.clone();
                mark_dashboard_nodes(
                    &dashboard,
                    [proof.node_id],
                    NodeStatus::CheckingProof,
                    Some(format!(
                        "Node {:02} • Checking proof and transaction policy...",
                        proof.node_id
                    )),
                );
                let mut retry_attempts = 0_u8;
                let submission_result = loop {
                    proof_telemetry.record(proof.node_id, ProofMetric::PreflightStarted);
                    let result = tokio::select! {
                        result = manager.submit_proof(
                            &client,
                            signer,
                            ProofSubmission {
                                contract,
                                node_id: proof.node_id,
                                window_id,
                                nonce: proof.nonce,
                                header: header.clone(),
                                work_hash: proof.hash,
                            },
                        ) => Some(result),
                        signal = ctrl_c.as_mut() => {
                            if let Err(error) = signal {
                                report_mining_warning(&dashboard, format!("Ctrl+C signal handler failed: {error}"));
                            }
                            None
                        }
                        event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                            if let DashboardEventKind::Failure(error) = event {
                                fatal_error = Some(anyhow!("dashboard failed: {error}"));
                            }
                            None
                        }
                    };
                    let Some(result) = result else {
                        break 'mining_loop;
                    };
                    match result {
                        Err(error)
                            if is_transient_rpc_error(&error)
                                && !manager.journal.has_unresolved()
                                && !manager.journal.has_unverified_receipt() =>
                        {
                            proof_telemetry.record(
                                proof.node_id,
                                ProofMetric::PreflightRpcFailure,
                            );
                            retry_attempts = retry_attempts.saturating_add(1);
                            if retry_attempts >= MAX_PROOF_PREFLIGHT_RETRIES {
                                slot.reset_local_best_for_generation(work.generation);
                                report_mining_warning(
                                    &dashboard,
                                    format!(
                                        "transient proof RPC retry limit reached for node {:02} window {window_id}; returning to hashing with fresh nonces: {error:#}",
                                        proof.node_id
                                    ),
                                );
                                break Err(anyhow!(
                                    "transient proof preflight retry limit reached; resume local proof search"
                                ));
                            }
                            if retry_attempts == 1 || retry_attempts.is_multiple_of(5) {
                                report_mining_warning(
                                    &dashboard,
                                    format!(
                                        "proof preflight for node {:02} window {window_id} hit a transient RPC error; reserved nonce and proof attempt remain untouched, retry {retry_attempts} will revalidate: {error:#}",
                                        proof.node_id
                                    ),
                                );
                            }
                            observer.force_refresh();
                            let delay = finalization_retry_delay(retry_attempts);
                            mark_dashboard_nodes(
                                &dashboard,
                                [proof.node_id],
                                NodeStatus::CheckingProof,
                                Some(format!(
                                    "Node {:02} window #{window_id} • retrying proof preflight in {}s",
                                    proof.node_id,
                                    delay.as_secs()
                                )),
                            );
                            tokio::select! {
                                _ = time::sleep(delay) => {}
                                signal = ctrl_c.as_mut() => {
                                    if let Err(error) = signal {
                                        report_mining_warning(&dashboard, format!("Ctrl+C signal handler failed: {error}"));
                                    }
                                    break 'mining_loop;
                                }
                                event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                                    if let DashboardEventKind::Failure(error) = event {
                                        fatal_error = Some(anyhow!("dashboard failed: {error}"));
                                    }
                                    break 'mining_loop;
                                }
                            }
                            if let Err(reason) =
                                revalidate_queued_proof(slot, &proof, &proof_telemetry)
                            {
                                record_proof_revalidation_drop(
                                    slot,
                                    &proof,
                                    reason,
                                    &proof_telemetry,
                                );
                                break Err(anyhow!(
                                    "local proof failed canonical revalidation before transient retry: {reason:?}"
                                ));
                            }
                        }
                        result => break result,
                    }
                };
                match submission_result {
                    Ok(action) => {
                        report_mining_info(
                            &dashboard,
                            confirmed_action_message("proof", &action),
                        );
                        dashboard_context
                            .pending_sync
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(
                                proof.node_id,
                                PendingDashboardSync {
                                    window_id,
                                    receipt_block: action.receipt.block_number,
                                },
                            );
                        mark_dashboard_nodes(
                            &dashboard,
                            [proof.node_id],
                            NodeStatus::Syncing,
                            Some(format!(
                                "Node {:02} • Syncing accepted proof...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                        proof_receiver.set_paused(
                            transaction_mode
                                && manager.journal.has_unresolved(),
                        );
                    }
                    Err(error)
                        if manager.journal.has_unresolved()
                            || manager.journal.has_unverified_receipt() =>
                    {
                        report_mining_warning(
                            &dashboard,
                            format!(
                                "proof outcome remains journaled as unresolved; no further transaction will be signed, but read-only recovery and mining observation will continue: {error:#}"
                            ),
                        );
                        proof_receiver.set_paused(true);
                        mark_dashboard_nodes(
                            &dashboard,
                            [proof.node_id],
                            NodeStatus::Recovering,
                            Some(format!(
                                "Node {:02} • recovering journaled proof outcome...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                    }
                    Err(error) if is_policy_refusal(&error) => {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightPolicyRefusal);
                        budget_exhausted |= is_session_limit_refusal(&error);
                        if budget_exhausted {
                            proof_receiver.set_paused(true);
                        }
                        report_mining_warning(
                            &dashboard,
                            format!("valid proof was not submitted: {error:#}"),
                        );
                        mark_dashboard_nodes(&dashboard, [proof.node_id], NodeStatus::Mining, None);
                    }
                    Err(error) if is_stale_proof(&error) => {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightStaleProof);
                        if stale_proof_warning_window.get(&proof.node_id) != Some(&window_id) {
                            stale_proof_warning_window.insert(proof.node_id, window_id);
                            report_mining_warning(
                                &dashboard,
                                format!(
                                    "discarded stale proof for node {} window {window_id}: {error:#}",
                                    proof.node_id
                                ),
                            );
                        }
                        mark_dashboard_nodes(
                            &dashboard,
                            [proof.node_id],
                            NodeStatus::Syncing,
                            Some(format!(
                                "Node {:02} window #{window_id} • revalidating after stale proof...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                    }
                    Err(error) => {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightOtherFailure);
                        fatal_error = Some(error);
                        break;
                    }
                }
            }
        }
    }

    if worker_guard.stop_and_join() {
        report_mining_warning(
            &dashboard,
            "Compute worker stopped abnormally or exceeded the bounded shutdown interval.",
        );
    }
    for pending in proof_receiver.drain_pending() {
        proof_telemetry.record(pending.node_id, ProofMetric::DroppedOnShutdown);
    }
    if let Err(error) = observer.stop().await
        && fatal_error.is_none()
    {
        fatal_error = Some(error);
    }

    let mut stopped_message = None;
    if fatal_error.is_none() {
        if let Some(manager) = transactions.as_mut() {
            if manager.journal.has_unresolved() {
                stopped_message = Some(
                    "Stopped with transaction exposure reserved for read-only recovery. The session remains open in the private journal.",
                );
            } else if let Err(error) = manager.close_session() {
                fatal_error = Some(error.context("close transaction spending session"));
            } else {
                stopped_message = Some(
                    "Stopped autonomous Testnet mining. Transaction journal retained without private key material.",
                );
            }
        } else if args.compute_only {
            stopped_message =
                Some("Stopped compute-only mining. No transactions were signed or sent.");
        } else {
            stopped_message = Some(
                "Stopped mining. No transactions were signed or sent because the session limit is zero.",
            );
        }
    }

    if let Some(error) = fatal_error.as_ref()
        && let Some(dashboard) = &dashboard
    {
        dashboard.update(|model| {
            model.critical_error = Some(format!("{error:#}"));
            model.current_action = None;
        });
    }
    if let Some(manager) = transactions.as_ref()
        && let Some(profile) =
            optional_history_profile(show_history_profile, || manager.history_profile_line())
    {
        report_mining_info(&dashboard, profile);
    }
    for line in proof_telemetry.report_lines() {
        report_mining_info(&dashboard, line);
    }
    let restore_result = if let Some(dashboard) = dashboard.as_mut() {
        let result = dashboard.stop().await;
        flush_dashboard_diagnostics(dashboard);
        result
    } else {
        for message in diagnostics.drain() {
            eprintln!("astatine: {message}");
        }
        Ok(())
    };
    if let Err(error) = restore_result
        && fatal_error.is_none()
    {
        fatal_error = Some(error.context("restore mining dashboard terminal"));
    }
    if let Some(error) = fatal_error {
        return Err(error);
    }
    if let Some(message) = stopped_message {
        println!("{message}");
    }
    Ok(())
}

fn take_observer_update(updates: &mut watch::Receiver<ObserverUpdate>) -> ObserverUpdate {
    let borrowed = updates.borrow_and_update();
    (*borrowed).clone()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofRevalidationFailure {
    NoEligibleWork,
    ExpiredDeadline,
    WindowMismatch,
    WorkContextMismatch,
    HashMismatch,
    CurrentTarget,
    CurrentIncumbent,
    InvalidGpuBatchIdentity,
}

fn revalidate_queued_proof(
    slot: &NodeSlot,
    proof: &ProofFound,
    telemetry: &ProofPipelineTelemetry,
) -> std::result::Result<Arc<WorkJob>, ProofRevalidationFailure> {
    revalidate_queued_proof_at(slot, proof, telemetry, Instant::now())
}

fn revalidate_queued_proof_at(
    slot: &NodeSlot,
    proof: &ProofFound,
    telemetry: &ProofPipelineTelemetry,
    now: Instant,
) -> std::result::Result<Arc<WorkJob>, ProofRevalidationFailure> {
    let current = slot
        .work
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or(ProofRevalidationFailure::NoEligibleWork)?;
    if now >= current.valid_until {
        return Err(ProofRevalidationFailure::ExpiredDeadline);
    }
    if proof.batch_identity.is_some_and(|batch| {
        batch.node_id != proof.node_id
            || batch.node_id != slot.id
            || batch.generation != proof.generation
            || batch.window_id != proof.context.window_id
            || batch.nonce_count == 0
            || !batch.contains(proof.nonce)
    }) {
        return Err(ProofRevalidationFailure::InvalidGpuBatchIdentity);
    }
    if proof.context.window_id != current.fingerprint.hashing_context.window_id {
        return Err(ProofRevalidationFailure::WindowMismatch);
    }
    if proof.context != current.fingerprint.hashing_context {
        return Err(ProofRevalidationFailure::WorkContextMismatch);
    }
    let recomputed = WorkHasher::new(&current.fingerprint.hashing_context.work_context())
        .ok()
        .map(|hasher| hasher.hash(proof.nonce));
    if recomputed != Some(proof.hash) {
        return Err(ProofRevalidationFailure::HashMismatch);
    }
    if !meets_target(proof.hash, current.target) {
        return Err(ProofRevalidationFailure::CurrentTarget);
    }
    if current
        .incumbent
        .is_some_and(|incumbent| !beats_incumbent(proof.hash, incumbent))
    {
        return Err(ProofRevalidationFailure::CurrentIncumbent);
    }
    if proof.generation != current.generation {
        telemetry.record(slot.id, ProofMetric::GenerationMismatchRevalidated);
    }
    Ok(current)
}

fn record_proof_revalidation_drop(
    slot: &NodeSlot,
    proof: &ProofFound,
    failure: ProofRevalidationFailure,
    telemetry: &ProofPipelineTelemetry,
) {
    if proof.generation != slot.generation.load(Ordering::Acquire) {
        telemetry.record(slot.id, ProofMetric::GenerationMismatchDropped);
    }
    let metric = match failure {
        ProofRevalidationFailure::NoEligibleWork => ProofMetric::DroppedNoEligibleWork,
        ProofRevalidationFailure::ExpiredDeadline => ProofMetric::DroppedExpiredDeadline,
        ProofRevalidationFailure::WindowMismatch => ProofMetric::DroppedWindowMismatch,
        ProofRevalidationFailure::WorkContextMismatch => ProofMetric::DroppedWorkContextMismatch,
        ProofRevalidationFailure::HashMismatch => ProofMetric::DroppedHashMismatch,
        ProofRevalidationFailure::CurrentTarget => ProofMetric::DroppedCurrentTarget,
        ProofRevalidationFailure::CurrentIncumbent => ProofMetric::DroppedCurrentIncumbent,
        ProofRevalidationFailure::InvalidGpuBatchIdentity => ProofMetric::GpuBatchIdentityRejected,
    };
    telemetry.record(slot.id, metric);
}

pub(crate) struct FinalizationOptions<'a> {
    pub finalization_state: &'a Arc<RwLock<HashMap<u8, FinalizationState>>>,
    pub dashboard: &'a Option<Dashboard>,
    pub pending_sync: &'a Arc<RwLock<HashMap<u8, PendingDashboardSync>>>,
}

async fn maybe_finalize_expired(
    client: &NetworkClient,
    selected: &HashSet<u8>,
    manager: &mut TransactionManager,
    signer: &bip32::secp256k1::ecdsa::SigningKey,
    wallet: Address,
    last_verified_snapshot: &ReadSnapshot,
    options: FinalizationOptions<'_>,
) -> Result<bool> {
    if manager.journal.has_unresolved() {
        return Ok(false);
    }
    let snapshot = match client.snapshot(Some(wallet)).await {
        Ok(snapshot) => snapshot,
        Err(error) if is_transient_rpc_error(&error) => {
            for node in &last_verified_snapshot.nodes {
                let Some(state) = node
                    .state
                    .as_ref()
                    .filter(|state| selected.contains(&node.id) && state.finalizable)
                else {
                    continue;
                };
                let previous = options
                    .finalization_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&node.id)
                    .cloned();
                let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                let delay = finalization_retry_delay(attempts);
                record_finalization_state(
                    &options,
                    node.id,
                    FinalizationState::Retrying {
                        window_id: state.work.window_id,
                        attempts,
                        retry_at: Instant::now() + delay,
                        reason: format!("fresh finalization snapshot unavailable: {error:#}"),
                    },
                );
            }
            return Ok(false);
        }
        Err(error) => return Err(error).context("read fresh state before window finalization"),
    };
    {
        let mut states = options
            .finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        states.retain(|node_id, state| {
            let Some(node) = snapshot.nodes.iter().find(|node| node.id == *node_id) else {
                return true;
            };
            let Some(work) = node.state.as_ref() else {
                return true;
            };
            let tracked_window = match state {
                FinalizationState::Retrying { window_id, .. }
                | FinalizationState::Blocked { window_id, .. } => *window_id,
            };
            work.work.window_id == tracked_window && work.finalizable && !work.mining_paused
        });
    }
    let mut finalized_any = false;
    for node in &snapshot.nodes {
        if !selected.contains(&node.id) {
            continue;
        }
        let Some(state) = node
            .state
            .as_ref()
            .filter(|state| state.finalizable && !state.mining_paused)
        else {
            continue;
        };
        let previous = options
            .finalization_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&node.id)
            .filter(|tracked| match tracked {
                FinalizationState::Retrying { window_id, .. }
                | FinalizationState::Blocked { window_id, .. } => {
                    *window_id == state.work.window_id
                }
            })
            .cloned();
        if let Some(FinalizationState::Blocked { reason, .. }) = &previous {
            mark_dashboard_nodes(
                options.dashboard,
                [node.id],
                NodeStatus::FinalizationBlocked,
                Some(format!(
                    "Node {:02} • Finalization blocked: {reason}",
                    node.id
                )),
            );
            continue;
        }
        if let Some(FinalizationState::Retrying {
            retry_at, reason, ..
        }) = &previous
            && Instant::now() < *retry_at
        {
            let seconds = retry_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            mark_dashboard_nodes(
                options.dashboard,
                [node.id],
                NodeStatus::FinalizationRetrying,
                Some(format!(
                    "Node {:02} window #{} • Finalization retry in {seconds}s ({reason})",
                    node.id, state.work.window_id
                )),
            );
            continue;
        }
        if manager.budget_remaining()?.is_zero() {
            record_finalization_state(
                &options,
                node.id,
                FinalizationState::Blocked {
                    window_id: state.work.window_id,
                    reason: "configured session spending limit is exhausted".to_owned(),
                },
            );
            continue;
        }
        mark_dashboard_nodes(
            options.dashboard,
            [node.id],
            NodeStatus::Finalizing,
            Some(format!("Node {:02} • Finalizing window...", node.id)),
        );
        match manager
            .finalize_window(client, signer, node.address, node.id, state.work.window_id)
            .await
        {
            Ok(action) => {
                options
                    .finalization_state
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&node.id);
                report_mining_info(
                    options.dashboard,
                    confirmed_action_message("finalization", &action),
                );
                options
                    .pending_sync
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(
                        node.id,
                        PendingDashboardSync {
                            window_id: state.work.window_id,
                            receipt_block: action.receipt.block_number,
                        },
                    );
                mark_dashboard_nodes(
                    options.dashboard,
                    [node.id],
                    NodeStatus::Syncing,
                    Some(format!("Node {:02} • Syncing finalized window...", node.id)),
                );
                finalized_any = true;
            }
            Err(error)
                if manager.journal.has_unresolved() || manager.journal.has_unverified_receipt() =>
            {
                report_mining_warning(
                    options.dashboard,
                    format!(
                        "node {} window {} finalization outcome is journaled and requires recovery; no rebroadcast will occur: {error:#}",
                        node.id, state.work.window_id
                    ),
                );
                break;
            }
            Err(error) => {
                if let Some(kind) = transaction_policy_refusal(&error) {
                    let reason = match kind {
                        TransactionPolicyRefusalKind::SessionLimitExceeded => {
                            format!("session cap refuses this finalization: {error:#}")
                        }
                        TransactionPolicyRefusalKind::InsufficientConfirmedBalance => {
                            format!(
                                "confirmed INJ balance/reserve refuses this finalization: {error:#}"
                            )
                        }
                        TransactionPolicyRefusalKind::SigningDisabled => {
                            format!("transaction signing is disabled: {error:#}")
                        }
                    };
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Blocked {
                            window_id: state.work.window_id,
                            reason,
                        },
                    );
                } else if mined_transaction_reverted(&error).is_some_and(|(action, window_id)| {
                    action == TransactionAction::FinalizeWindow && window_id == state.work.window_id
                }) {
                    match client.snapshot(Some(wallet)).await {
                        Ok(fresh) => {
                            let still_finalizable = fresh.nodes.iter().any(|fresh_node| {
                                fresh_node.id == node.id
                                    && fresh_node.state.as_ref().is_some_and(|fresh_state| {
                                        fresh_state.work.window_id == state.work.window_id
                                            && fresh_state.finalizable
                                            && !fresh_state.mining_paused
                                    })
                            });
                            if still_finalizable {
                                record_finalization_state(
                                    &options,
                                    node.id,
                                    FinalizationState::Blocked {
                                        window_id: state.work.window_id,
                                        reason: format!(
                                            "a confirmed finalization transaction reverted while fresh canonical state still reports this window finalizable; inspect contract/RPC state before restarting: {error:#}"
                                        ),
                                    },
                                );
                            } else {
                                options
                                    .finalization_state
                                    .write()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .remove(&node.id);
                                report_mining_warning(
                                    options.dashboard,
                                    format!(
                                        "node {} window {} finalization reverted; fresh canonical state has advanced and the transaction will not be resent",
                                        node.id, state.work.window_id
                                    ),
                                );
                            }
                        }
                        Err(state_error) => record_finalization_state(
                            &options,
                            node.id,
                            FinalizationState::Blocked {
                                window_id: state.work.window_id,
                                reason: format!(
                                    "a confirmed finalization transaction reverted and fresh state could not be verified; inspect canonical state before restarting: {state_error:#}"
                                ),
                            },
                        ),
                    }
                } else if is_stale_transaction_preflight(&error) {
                    let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Retrying {
                            window_id: state.work.window_id,
                            attempts,
                            retry_at: Instant::now() + STALE_PREFLIGHT_RETRY,
                            reason: format!("fresh state changed; revalidating: {error:#}"),
                        },
                    );
                } else if is_transient_rpc_error(&error) {
                    let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                    let delay = finalization_retry_delay(attempts);
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Retrying {
                            window_id: state.work.window_id,
                            attempts,
                            retry_at: Instant::now() + delay,
                            reason: format!("transient RPC error: {error:#}"),
                        },
                    );
                } else {
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Blocked {
                            window_id: state.work.window_id,
                            reason: format!("permanent or unclassified failure: {error:#}"),
                        },
                    );
                }
            }
        }
        if manager.journal.has_unresolved() || manager.budget_remaining()?.is_zero() {
            break;
        }
    }
    Ok(finalized_any)
}

fn retry_attempts(previous: Option<&FinalizationState>) -> u8 {
    previous.map_or(0, |state| match state {
        FinalizationState::Retrying { attempts, .. } => *attempts,
        FinalizationState::Blocked { .. } => 0,
    })
}

fn finalization_retry_delay(attempts: u8) -> Duration {
    let exponent = attempts.saturating_sub(1).min(5);
    Duration::from_secs((1_u64 << exponent).min(MAX_POLL_INTERVAL.as_secs()))
}

fn record_finalization_state(
    options: &FinalizationOptions<'_>,
    node_id: u8,
    state: FinalizationState,
) {
    let changed = {
        let mut states = options
            .finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if states.get(&node_id) == Some(&state) {
            false
        } else {
            states.insert(node_id, state.clone());
            true
        }
    };
    if !changed {
        return;
    }
    match state {
        FinalizationState::Retrying {
            window_id,
            attempts,
            retry_at,
            reason,
        } => {
            let delay = retry_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            let message = format!(
                "node {node_id:02} window {window_id} finalization retry {attempts} scheduled in {delay}s: {reason}"
            );
            report_mining_warning(options.dashboard, message.clone());
            mark_dashboard_nodes(
                options.dashboard,
                [node_id],
                NodeStatus::FinalizationRetrying,
                Some(message),
            );
        }
        FinalizationState::Blocked { window_id, reason } => {
            let message =
                format!("node {node_id:02} window {window_id} finalization blocked: {reason}");
            report_mining_warning(options.dashboard, message.clone());
            mark_dashboard_nodes(
                options.dashboard,
                [node_id],
                NodeStatus::FinalizationBlocked,
                Some(message),
            );
        }
    }
}

#[cfg(test)]
pub(crate) async fn finalize_initial_expired_windows(
    client: &NetworkClient,
    selected: &HashSet<u8>,
    manager: &mut TransactionManager,
    signer: &bip32::secp256k1::ecdsa::SigningKey,
    wallet: Address,
    snapshot: &mut ReadSnapshot,
    options: FinalizationOptions<'_>,
) -> Result<bool> {
    if !maybe_finalize_expired(client, selected, manager, signer, wallet, snapshot, options).await?
    {
        return Ok(false);
    }
    *snapshot = client.snapshot(Some(wallet)).await?;
    Ok(true)
}

fn confirmed_action_message(label: &str, action: &ConfirmedAction) -> String {
    let effective_price = action
        .receipt
        .effective_gas_price
        .map(|price| price.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    format!(
        "{label} confirmed: tx={:#x} | {} | gas={} | effective price={} wei",
        action.transaction_hash, action.outcome, action.receipt.gas_used, effective_price
    )
}

fn is_policy_refusal(error: &anyhow::Error) -> bool {
    transaction_policy_refusal(error).is_some()
}

fn is_session_limit_refusal(error: &anyhow::Error) -> bool {
    matches!(
        transaction_policy_refusal(error),
        Some(
            TransactionPolicyRefusalKind::SessionLimitExceeded
                | TransactionPolicyRefusalKind::SigningDisabled
        )
    )
}

fn is_stale_proof(error: &anyhow::Error) -> bool {
    if mined_transaction_reverted(error)
        .is_some_and(|(action, _)| action == TransactionAction::SubmitProof)
    {
        return true;
    }
    if is_stale_transaction_preflight(error) {
        return true;
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("transient proof preflight retry limit reached")
        || message.contains("fresh on-chain")
        || message.contains("different window")
        || message.contains("no longer eligible")
        || message.contains("pending nonce changed")
        || message.contains("paid proof attempt already journaled")
}

fn selected_nodes(nodes: &[u8]) -> Result<HashSet<u8>> {
    let mut selected = HashSet::new();
    for node in nodes {
        if !(1..=9).contains(node) || !selected.insert(*node) {
            bail!("node selection must contain unique IDs in the range 1..=9");
        }
    }
    if selected.is_empty() {
        selected.extend(1..=9);
    }
    Ok(selected)
}

pub(crate) fn update_slots(
    slots: &[NodeSlot],
    schedule: &RwLock<Vec<usize>>,
    manifest: &DeploymentManifest,
    miner: Address,
    selected: &HashSet<u8>,
    snapshot: &ReadSnapshot,
) -> Result<bool> {
    let mut changed = false;
    let mut active = Vec::with_capacity(slots.len());
    for (index, slot) in slots.iter().enumerate() {
        let node = snapshot.nodes.iter().find(|node| node.id == slot.id);
        let state = node.and_then(|node| {
            (selected.contains(&node.id) && node.pin.runtime_verified && node.pin.abi_verified)
                .then_some(node.state.as_ref())
                .flatten()
        });
        let contract = node.map(|node| node.address).unwrap_or(Address::ZERO);
        changed |= slot.set_work(manifest, miner, contract, state, &snapshot.block)?;
        if slot.current_work().is_some() {
            active.push(index);
        }
    }
    *schedule
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = active;
    Ok(changed)
}

fn inactive_genesis_nodes(snapshot: &ReadSnapshot, selected: &HashSet<u8>) -> Vec<u8> {
    let mut nodes = snapshot
        .nodes
        .iter()
        .filter(|node| selected.contains(&node.id))
        .filter(|node| node.pin.runtime_verified && node.pin.abi_verified)
        .filter_map(|node| {
            node.state
                .as_ref()
                .and_then(|state| (!state.work.started && !state.work.ended).then_some(node.id))
        })
        .collect::<Vec<_>>();
    nodes.sort_unstable();
    nodes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotFreshness {
    Current,
    Reorg,
}

#[derive(Clone, Copy)]
struct ObserverProgress<'a> {
    last_snapshot: &'a ReadSnapshot,
    last_successful_read_at: Instant,
    last_head_advanced_at: Instant,
}

pub(crate) fn start_read_only_observer(
    client: NetworkClient,
    context: DashboardContext,
    initial_snapshot: ReadSnapshot,
    updater: Option<DashboardUpdater>,
    diagnostics: DiagnosticBuffer,
) -> ReadOnlyObserver {
    let (updates_tx, updates_rx) =
        watch::channel(ObserverUpdate::Snapshot(initial_snapshot.clone()));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (force_refresh, mut refresh_rx) = mpsc::channel(1);
    let refresh_epoch = Arc::new(AtomicU64::new(0));
    let refresh_gate = Arc::new(Mutex::new(()));
    let last_publication_at = Arc::new(Mutex::new(Instant::now()));
    let observer_refresh_epoch = Arc::clone(&refresh_epoch);
    let observer_refresh_gate = Arc::clone(&refresh_gate);
    let observer_last_publication_at = Arc::clone(&last_publication_at);
    let task = tokio::spawn(async move {
        let mut last_block = initial_snapshot.block.clone();
        let mut last_snapshot = initial_snapshot;
        let mut last_observed_at = Instant::now();
        let mut last_head_advanced_at = last_observed_at;
        let mut delay = POLL_INTERVAL;
        let mut next_full_refresh = time::Instant::now() + delay;
        let mut genesis_delay = GENESIS_POLL_INTERVAL;
        let mut next_genesis_poll = time::Instant::now() + genesis_delay;
        let mut consecutive_genesis_errors = 0_u8;
        let mut genesis_poll_error_message: Option<String> = None;
        let mut consecutive_errors = 0_u8;
        loop {
            let waiting_nodes = inactive_genesis_nodes(&last_snapshot, &context.selected);
            let wake = tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    ObserverWake::FullRefresh
                }
                refresh = refresh_rx.recv() => {
                    if refresh.is_none() {
                        break;
                    }
                    ObserverWake::FullRefresh
                }
                _ = time::sleep_until(next_full_refresh) => ObserverWake::FullRefresh,
                _ = time::sleep_until(next_genesis_poll), if !waiting_nodes.is_empty() => {
                    ObserverWake::GenesisProbe(waiting_nodes)
                }
            };
            match wake {
                ObserverWake::FullRefresh => {}
                ObserverWake::GenesisProbe(node_ids) => {
                    match client.poll_genesis(&node_ids).await {
                        Ok(candidates) => {
                            consecutive_genesis_errors = 0;
                            genesis_delay = GENESIS_POLL_INTERVAL;
                            next_genesis_poll = time::Instant::now() + genesis_delay;
                            if let Some(message) = genesis_poll_error_message.take() {
                                clear_observer_genesis_poll_error(&updater, &node_ids, &message);
                            }
                            if candidates.is_empty() {
                                continue;
                            }
                            diagnostics.push(format!(
                                "genesis activation candidate observed for selected node(s) {candidates:?}; requesting a canonical full refresh"
                            ));
                        }
                        Err(error) => {
                            consecutive_genesis_errors =
                                consecutive_genesis_errors.saturating_add(1);
                            let message = format!(
                                "genesis status poll failed for selected node(s) {node_ids:?}: {error:#}"
                            );
                            let report = consecutive_genesis_errors == 1
                                || consecutive_genesis_errors.is_multiple_of(5);
                            if report {
                                diagnostics.push(message.clone());
                            }
                            if observer_genesis_poll_error(&updater, &node_ids, &message) {
                                genesis_poll_error_message = Some(message.clone());
                            }
                            updates_tx
                                .send_replace(ObserverUpdate::GenesisPollError { message, report });
                            *observer_last_publication_at
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Instant::now();
                            genesis_delay = next_poll_delay(genesis_delay);
                            next_genesis_poll = time::Instant::now() + genesis_delay;
                            continue;
                        }
                    }
                }
            }

            let request_epoch = observer_refresh_epoch.load(Ordering::Acquire);
            let request_started = Instant::now();
            let result = client.snapshot(Some(context.address)).await;
            if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                delay = Duration::ZERO;
                next_full_refresh = time::Instant::now();
                continue;
            }
            match result {
                Ok(mut snapshot) => {
                    let freshness =
                        match snapshot_freshness(&client, &last_block, &snapshot.block).await {
                            Ok(SnapshotFreshness::Reorg) => client
                                .reverify_activated_nodes_after_reorg(&mut snapshot)
                                .await
                                .map(|()| SnapshotFreshness::Reorg),
                            result => result,
                        };
                    let freshness = match freshness {
                        Ok(freshness) => freshness,
                        Err(error) => {
                            client.clear_activation_work_verification();
                            let commit = observer_refresh_gate
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                                drop(commit);
                                delay = Duration::ZERO;
                                next_full_refresh = time::Instant::now();
                                continue;
                            }
                            let message = format!("read-only snapshot rejected: {error:#}");
                            clear_observed_work(&context, &client.manifest, &last_snapshot.block);
                            observer_rpc_error(
                                &context,
                                &updater,
                                &diagnostics,
                                ObserverProgress {
                                    last_snapshot: &last_snapshot,
                                    last_successful_read_at: last_observed_at,
                                    last_head_advanced_at,
                                },
                                &message,
                                &mut consecutive_errors,
                            );
                            let report =
                                consecutive_errors == 1 || consecutive_errors.is_multiple_of(5);
                            updates_tx.send_replace(ObserverUpdate::RpcError { message, report });
                            *observer_last_publication_at
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Instant::now();
                            drop(commit);
                            delay = next_poll_delay(delay);
                            continue;
                        }
                    };
                    let commit = observer_refresh_gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                        drop(commit);
                        delay = Duration::ZERO;
                        continue;
                    }
                    if freshness == SnapshotFreshness::Reorg {
                        diagnostics.push(format!(
                            "canonical chain head changed during observation at block {}",
                            snapshot.block.number
                        ));
                    }

                    if let Err(error) = update_slots(
                        &context.slots,
                        &context.schedule,
                        &client.manifest,
                        context.address,
                        &context.selected,
                        &snapshot,
                    ) {
                        let message = format!("update verified mining work: {error:#}");
                        clear_observed_work(&context, &client.manifest, &last_snapshot.block);
                        if let Some(updater) = &updater {
                            updater.update(|model| model.critical_error = Some(message.clone()));
                        }
                        diagnostics.push(message.clone());
                        updates_tx.send_replace(ObserverUpdate::Fatal(message));
                        drop(commit);
                        break;
                    }

                    trace_snapshot_transitions(
                        &context.selected,
                        &last_snapshot,
                        &snapshot,
                        last_observed_at,
                        request_started.elapsed(),
                        &diagnostics,
                    );
                    let observed_at = Instant::now();
                    if snapshot.block.number != last_block.number
                        || snapshot.block.hash != last_block.hash
                    {
                        last_head_advanced_at = observed_at;
                    }
                    trace_node_liveness(
                        &context,
                        &snapshot,
                        last_observed_at,
                        last_head_advanced_at,
                        observed_at,
                        &diagnostics,
                    );
                    last_block = snapshot.block.clone();
                    last_snapshot = snapshot.clone();
                    last_observed_at = observed_at;
                    consecutive_errors = 0;
                    delay = POLL_INTERVAL;
                    next_full_refresh = time::Instant::now() + delay;
                    if consecutive_genesis_errors == 0 {
                        genesis_delay = GENESIS_POLL_INTERVAL;
                        if next_genesis_poll <= time::Instant::now() {
                            next_genesis_poll = time::Instant::now() + genesis_delay;
                        }
                    }
                    refresh_dashboard(updater.as_ref(), &context, &snapshot);
                    genesis_poll_error_message = None;
                    updates_tx.send_replace(ObserverUpdate::Snapshot(snapshot));
                    *observer_last_publication_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                    drop(commit);
                }
                Err(error) => {
                    let commit = observer_refresh_gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                        drop(commit);
                        delay = Duration::ZERO;
                        next_full_refresh = time::Instant::now();
                        continue;
                    }
                    let message = format!("RPC refresh failed; stale work stopped: {error:#}");
                    client.clear_activation_work_verification();
                    clear_observed_work(&context, &client.manifest, &last_snapshot.block);
                    observer_rpc_error(
                        &context,
                        &updater,
                        &diagnostics,
                        ObserverProgress {
                            last_snapshot: &last_snapshot,
                            last_successful_read_at: last_observed_at,
                            last_head_advanced_at,
                        },
                        &message,
                        &mut consecutive_errors,
                    );
                    let report = consecutive_errors == 1 || consecutive_errors.is_multiple_of(5);
                    updates_tx.send_replace(ObserverUpdate::RpcError { message, report });
                    *observer_last_publication_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                    drop(commit);
                    delay = next_poll_delay(delay);
                    next_full_refresh = time::Instant::now() + delay;
                    genesis_delay = next_poll_delay(genesis_delay);
                    next_genesis_poll = time::Instant::now() + genesis_delay;
                }
            }
        }
    });
    ReadOnlyObserver {
        shutdown: shutdown_tx,
        updates: updates_rx,
        force_refresh,
        refresh_epoch,
        refresh_gate,
        last_publication_at,
        task,
    }
}

async fn snapshot_freshness(
    client: &NetworkClient,
    previous: &crate::rpc::BlockSnapshot,
    next: &crate::rpc::BlockSnapshot,
) -> Result<SnapshotFreshness> {
    let previous_canonical = if next.number < previous.number {
        match client.canonical_block_hash(previous.number).await {
            Ok(hash) => Some(hash),
            Err(previous_error) => {
                let next_canonical = client.canonical_block_hash(next.number).await?;
                let current_head = client.latest_block_snapshot().await?;
                if next_canonical == next.hash
                    && current_head.number == next.number
                    && current_head.hash == next.hash
                {
                    // A reorging provider head may no longer serve the removed height.
                    // Accept the lower snapshot only when the selected RPC still reports it
                    // as the current canonical head.
                    return Ok(SnapshotFreshness::Reorg);
                }
                return Err(previous_error)
                    .context("cannot verify a lower snapshot after the prior block disappeared");
            }
        }
    } else {
        None
    };
    let next_canonical = if next.number == previous.number && next.hash != previous.hash {
        Some(client.canonical_block_hash(next.number).await?)
    } else {
        None
    };
    let freshness = compare_snapshot_freshness(previous, next, previous_canonical, next_canonical)?;
    if freshness == SnapshotFreshness::Reorg && next.number < previous.number {
        if client.canonical_block_hash(next.number).await? != next.hash {
            bail!(
                "selected RPC does not report lower snapshot block {} as canonical",
                next.number
            );
        }
        let current_head = client.latest_block_snapshot().await?;
        if current_head.number != next.number || current_head.hash != next.hash {
            bail!(
                "lower snapshot block {} is not the current canonical head {}",
                next.number,
                current_head.number
            );
        }
    }
    Ok(freshness)
}

fn compare_snapshot_freshness(
    previous: &crate::rpc::BlockSnapshot,
    next: &crate::rpc::BlockSnapshot,
    previous_canonical: Option<B256>,
    next_canonical: Option<B256>,
) -> Result<SnapshotFreshness> {
    if next.number < previous.number {
        match previous_canonical {
            Some(hash) if hash == previous.hash => bail!(
                "RPC returned block {} after verified block {} while the previous head remains canonical",
                next.number,
                previous.number
            ),
            Some(_) => return Ok(SnapshotFreshness::Reorg),
            None => bail!("cannot establish whether the prior chain head remains canonical"),
        }
    }
    if next.number == previous.number && next.hash != previous.hash {
        if next_canonical != Some(next.hash) {
            bail!(
                "selected RPC does not report snapshot block {} as canonical",
                next.number
            );
        }
        return Ok(SnapshotFreshness::Reorg);
    }
    Ok(SnapshotFreshness::Current)
}

fn trace_snapshot_transitions(
    selected: &HashSet<u8>,
    previous: &ReadSnapshot,
    current: &ReadSnapshot,
    previous_observed_at: Instant,
    request_elapsed: Duration,
    diagnostics: &DiagnosticBuffer,
) {
    for node_id in selected {
        let before = previous.nodes.iter().find(|node| node.id == *node_id);
        let after = current.nodes.iter().find(|node| node.id == *node_id);
        let before_trusted =
            before.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let after_trusted =
            after.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let before_state = before
            .filter(|_| before_trusted)
            .and_then(|node| node.state.as_ref());
        let after_state = after
            .filter(|_| after_trusted)
            .and_then(|node| node.state.as_ref());
        let before_window = before_state.map(|state| state.work.window_id);
        let after_window = after_state.map(|state| state.work.window_id);
        let before_status = traced_node_status(before_state, before_trusted);
        let after_status = traced_node_status(after_state, after_trusted);
        let before_candidate = before_state
            .and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner));
        let after_candidate =
            after_state.and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner));
        let before_expiry = before_state.map(|state| state.work.window_expiry_time);
        let after_expiry = after_state.map(|state| state.work.window_expiry_time);
        if before_window == after_window
            && before_status == after_status
            && before_candidate == after_candidate
            && before_expiry == after_expiry
        {
            continue;
        }
        let observation_interval_ms = Instant::now()
            .saturating_duration_since(previous_observed_at)
            .as_millis();
        let message = format!(
            "state-transition node={node_id:02} block={}..{} hash={:#x}->{:#x} window={before_window:?}->{after_window:?} status={before_status}->{after_status} candidate={}->{} expiry={before_expiry:?}->{after_expiry:?} chain_ts={} observation_interval_ms={} rpc_ms={}",
            previous.block.number,
            current.block.number,
            previous.block.hash,
            current.block.hash,
            display_candidate(before_candidate),
            display_candidate(after_candidate),
            current.block.timestamp,
            observation_interval_ms,
            request_elapsed.as_millis(),
        );
        diagnostics.push(message);
    }
}

fn trace_node_liveness(
    context: &DashboardContext,
    snapshot: &ReadSnapshot,
    last_successful_read_at: Instant,
    last_head_advanced_at: Instant,
    observed_at: Instant,
    diagnostics: &DiagnosticBuffer,
) {
    let schedule = context
        .schedule
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let activities = context
        .transaction_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let finalization = context
        .finalization_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let worker_enabled = context.workers_started.load(Ordering::Acquire);
    let authorization_used = activities
        .authorization_used
        .map(|amount| amount.to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    for node_id in &context.selected {
        let node = snapshot.nodes.iter().find(|node| node.id == *node_id);
        let trusted = node.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let state = node
            .filter(|_| trusted)
            .and_then(|node| node.state.as_ref());
        let slot = &context.slots[usize::from(*node_id - 1)];
        let (slot_active, slot_suspended, deadline, slot_window) = slot.diagnostic_work();
        let scheduled = schedule.contains(&usize::from(*node_id - 1));
        let local_deadline_expired = deadline.is_some_and(|deadline| observed_at >= deadline);
        let transaction = activities
            .activities
            .iter()
            .find(|activity| activity.node_id == *node_id)
            .map(|activity| format!("{:?}@{}", activity.state, activity.window_id))
            .unwrap_or_else(|| "none".to_owned());
        let finalization_state = finalization
            .get(node_id)
            .map(|state| format!("{state:?}"))
            .unwrap_or_else(|| "none".to_owned());
        let (eligible, finalizable, paused, ended, chain_window) =
            state.map_or((false, false, false, false, None), |state| {
                (
                    state.eligible,
                    state.finalizable,
                    state.mining_paused,
                    state.work.ended,
                    Some(state.work.window_id),
                )
            });
        let deadline_state = deadline.map_or_else(
            || "none".to_owned(),
            |deadline| {
                format!(
                    "{}ms_remaining",
                    deadline.saturating_duration_since(observed_at).as_millis()
                )
            },
        );
        diagnostics.push(format!(
            "node-liveness node={node_id:02} window={chain_window:?} block={} hash={:#x} verified={trusted} eligible={eligible} finalizable={finalizable} paused={paused} ended={ended} local_slot={slot_active} suspended={slot_suspended} slot_window={slot_window:?} scheduled={scheduled} workers_enabled={worker_enabled} deadline={deadline_state} deadline_expired={local_deadline_expired} head_progress_age_ms={} successful_rpc_age_ms={} node_hashes={} hashes_total={} tx={transaction} authorization_used_wei={authorization_used} finalization={finalization_state}",
            snapshot.block.number,
            snapshot.block.hash,
            observed_at
                .saturating_duration_since(last_head_advanced_at)
                .as_millis(),
            observed_at
                .saturating_duration_since(last_successful_read_at)
                .as_millis(),
            slot.completed_hashes(),
            context.total_hashes.load(Ordering::Relaxed),
        ));
    }
}

fn traced_node_status(state: Option<&NodeState>, trusted: bool) -> &'static str {
    if !trusted || state.is_none() {
        return "RPC ERROR";
    }
    let state = state.expect("checked above");
    if state.work.ended {
        "ENDED"
    } else if !state.work.started {
        "WAIT GENESIS"
    } else if state.work.remaining_allocation.is_zero() {
        "ENDED"
    } else if state.mining_paused {
        "PAUSED"
    } else if state.finalizable {
        "FINALIZING"
    } else if state.eligible {
        "MINING"
    } else {
        "WAITING"
    }
}

fn display_candidate(candidate: Option<Address>) -> String {
    candidate
        .map(|address| format!("{address:#x}"))
        .unwrap_or_else(|| "None".to_owned())
}

fn clear_observed_work(
    context: &DashboardContext,
    manifest: &DeploymentManifest,
    block: &BlockSnapshot,
) {
    for slot in context.slots.iter() {
        let _ = slot.set_work(manifest, context.address, Address::ZERO, None, block);
    }
    *context
        .schedule
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
}

fn observer_rpc_error(
    context: &DashboardContext,
    updater: &Option<DashboardUpdater>,
    diagnostics: &DiagnosticBuffer,
    progress: ObserverProgress<'_>,
    message: &str,
    consecutive_errors: &mut u8,
) {
    *consecutive_errors = consecutive_errors.saturating_add(1);
    if *consecutive_errors == 1 || consecutive_errors.is_multiple_of(5) {
        diagnostics.push(format!(
            "{message}; last_verified_block={} hash={:#x} last_successful_read_age_ms={} last_head_advance_age_ms={}",
            progress.last_snapshot.block.number,
            progress.last_snapshot.block.hash,
            Instant::now()
                .saturating_duration_since(progress.last_successful_read_at)
                .as_millis(),
            Instant::now()
                .saturating_duration_since(progress.last_head_advanced_at)
                .as_millis(),
        ));
    }
    if let Some(updater) = updater {
        let activities = context
            .transaction_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .activities
            .clone();
        updater.update(|model| {
            model.connection_error = Some(message.to_owned());
            for node in &mut model.selected_nodes {
                if let Some(activity) = activities
                    .iter()
                    .find(|item| item.node_id == node.id && node.window_id == Some(item.window_id))
                {
                    node.status = match activity.state {
                        TransactionActivityState::Finalizing => NodeStatus::Finalizing,
                        TransactionActivityState::Signed => NodeStatus::Signed,
                        TransactionActivityState::Confirming => NodeStatus::Confirming,
                        TransactionActivityState::Recovering => NodeStatus::Recovering,
                    };
                } else {
                    node.status = NodeStatus::RpcError;
                    node.mining_deadline = None;
                }
            }
        });
    }
}

fn observer_genesis_poll_error(
    updater: &Option<DashboardUpdater>,
    node_ids: &[u8],
    message: &str,
) -> bool {
    let Some(updater) = updater else {
        return false;
    };
    let mut installed = false;
    updater.update(|model| installed = apply_genesis_poll_error(model, node_ids, message));
    installed
}

fn apply_genesis_poll_error(model: &mut DashboardModel, node_ids: &[u8], message: &str) -> bool {
    if model.connection_error.is_some() {
        return false;
    }
    model.connection_error = Some(message.to_owned());
    for node in &mut model.selected_nodes {
        if node_ids.contains(&node.id) && node.status == NodeStatus::WaitingForGenesis {
            node.status = NodeStatus::RpcError;
            node.mining_deadline = None;
        }
    }
    true
}

fn clear_observer_genesis_poll_error(
    updater: &Option<DashboardUpdater>,
    node_ids: &[u8],
    message: &str,
) {
    let Some(updater) = updater else {
        return;
    };
    updater.update(|model| {
        clear_genesis_poll_error(model, node_ids, message);
    });
}

fn clear_genesis_poll_error(model: &mut DashboardModel, node_ids: &[u8], message: &str) -> bool {
    if model.connection_error.as_deref() != Some(message) {
        return false;
    }
    model.connection_error = None;
    for node in &mut model.selected_nodes {
        if node_ids.contains(&node.id) && node.status == NodeStatus::RpcError {
            node.status = NodeStatus::WaitingForGenesis;
        }
    }
    true
}

fn dashboard_model(
    context: &DashboardContext,
    snapshot: &ReadSnapshot,
    observed_at: Instant,
) -> DashboardModel {
    let mut selected_ids = context.selected.iter().copied().collect::<Vec<_>>();
    selected_ids.sort_unstable();
    let transaction_state = context
        .transaction_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let active_backend = context
        .active_backend
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let pending_sync = context
        .pending_sync
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let finalization_state = context
        .finalization_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut nodes = Vec::with_capacity(selected_ids.len());
    let mut first_error = None;
    for id in selected_ids {
        let view = snapshot.nodes.iter().find(|node| node.id == id);
        let trusted = view.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let state = view
            .filter(|_| trusted)
            .and_then(|node| node.state.as_ref());
        let activity = transaction_state.activities.iter().find(|activity| {
            activity.node_id == id
                && state.is_some_and(|state| state.work.window_id == activity.window_id)
        });
        let slot_work = context.slots[usize::from(id - 1)].current_work();
        let mut status = dashboard_node_status(
            state,
            trusted,
            context.workers_started.load(Ordering::Acquire) && slot_work.is_some(),
            context.workers_started.load(Ordering::Acquire),
            activity.map(|activity| activity.state),
        );
        if activity.is_none()
            && let Some(state) = state
            && let Some(finalization) = finalization_state.get(&id)
        {
            status = match finalization {
                FinalizationState::Retrying { window_id, .. }
                    if *window_id == state.work.window_id =>
                {
                    NodeStatus::FinalizationRetrying
                }
                FinalizationState::Blocked { window_id, .. }
                    if *window_id == state.work.window_id =>
                {
                    NodeStatus::FinalizationBlocked
                }
                _ => status,
            };
        }
        let pending = pending_sync.get(&id).copied();
        let syncing = pending.is_some_and(|pending| {
            activity.is_none()
                && (snapshot.block.number < pending.receipt_block
                    || !trusted
                    || state.is_none()
                    || state.is_some_and(|state| state.work.window_id < pending.window_id))
        });
        if syncing {
            status = NodeStatus::Syncing;
        }
        if first_error.is_none() {
            first_error = view
                .and_then(|node| node.error.as_deref().or(node.pin.error.as_deref()))
                .map(str::to_owned);
        }
        let candidate = (!syncing && trusted)
            .then(|| {
                state.and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner))
            })
            .flatten();
        let reward = trusted
            .then(|| state.map(|state| state.work.reward_per_window))
            .flatten();
        nodes.push(DashboardNode {
            id,
            window_id: state.map(|state| state.work.window_id),
            status,
            expiry_timestamp: state.map(|state| state.work.window_expiry_time),
            mining_deadline: slot_work.map(|work| work.valid_until),
            countdown: state.map(|state| {
                WindowCountdown::from_snapshot(
                    state.work.window_id,
                    state.work.window_expiry_time,
                    snapshot.block.timestamp,
                    observed_at,
                )
            }),
            candidate,
            reward,
        });
    }
    let current_action = nodes.iter().find_map(|node| {
        let window_id = node.window_id?;
        match (node.status, finalization_state.get(&node.id)) {
            (
                NodeStatus::FinalizationRetrying,
                Some(FinalizationState::Retrying {
                    window_id: tracked,
                    retry_at,
                    reason,
                    ..
                }),
            ) if *tracked == window_id => {
                let seconds = retry_at
                    .saturating_duration_since(Instant::now())
                    .as_secs()
                    .max(1);
                Some(format!(
                    "Node {:02} window #{window_id} • retrying finalization in {seconds}s: {reason}",
                    node.id
                ))
            }
            (
                NodeStatus::FinalizationBlocked,
                Some(FinalizationState::Blocked {
                    window_id: tracked,
                    reason,
                }),
            ) if *tracked == window_id => Some(format!(
                "Node {:02} window #{window_id} • finalization blocked: {reason}",
                node.id
            )),
            (NodeStatus::FinalizationRequired, _) => Some(format!(
                "Node {:02} window #{window_id} • finalization required{}",
                node.id,
                if context.compute_only || !context.transaction_mode {
                    "; Testnet transaction signing is disabled"
                } else {
                    "; verifying transaction budget and canonical state"
                }
            )),
            (NodeStatus::WaitingForChain, _) => Some(format!(
                "Node {:02} window #{window_id} • local work stopped at its safety deadline; waiting for a newer canonical block",
                node.id
            )),
            _ => None,
        }
    });
    DashboardModel {
        network: context.network,
        chain_id: context.chain_id,
        wallet: context.address,
        inj_balance: snapshot.native_balance,
        ast_balance: snapshot.ast_balance,
        mined_rewards: transaction_state.mined_rewards,
        device_label: active_backend.label().to_owned(),
        device_detail: active_backend.detail(),
        session_limit: Some(context.spending_limit),
        authorization_used: transaction_state.authorization_used,
        actual_rpc_cost: transaction_state.actual_rpc_cost,
        block_number: snapshot.block.number,
        block_hash: snapshot.block.hash,
        snapshot_observed_at: observed_at,
        last_block_advanced_at: observed_at,
        snapshot_ready: true,
        selected_nodes: nodes,
        compute_only: context.compute_only,
        signing_enabled: context.transaction_mode,
        recovering: transaction_state
            .activities
            .iter()
            .any(|activity| activity.state == TransactionActivityState::Recovering),
        stopping: false,
        hashrate: 0.0,
        current_action,
        connection_error: first_error,
        critical_error: None,
    }
}

fn dashboard_node_status(
    state: Option<&NodeState>,
    trusted: bool,
    has_current_work: bool,
    workers_started: bool,
    activity: Option<TransactionActivityState>,
) -> NodeStatus {
    if let Some(activity) = activity {
        return match activity {
            TransactionActivityState::Finalizing => NodeStatus::Finalizing,
            TransactionActivityState::Signed => NodeStatus::Signed,
            TransactionActivityState::Confirming => NodeStatus::Confirming,
            TransactionActivityState::Recovering => NodeStatus::Recovering,
        };
    }
    if !trusted || state.is_none() {
        return NodeStatus::RpcError;
    }
    let state = state.expect("checked above");
    if state.work.ended {
        NodeStatus::Ended
    } else if !state.work.started {
        NodeStatus::WaitingForGenesis
    } else if state.work.remaining_allocation.is_zero() {
        NodeStatus::Ended
    } else if state.mining_paused {
        NodeStatus::Paused
    } else if state.finalizable {
        NodeStatus::FinalizationRequired
    } else if state.eligible && has_current_work {
        NodeStatus::Mining
    } else if state.eligible && workers_started {
        NodeStatus::WaitingForChain
    } else {
        NodeStatus::Waiting
    }
}

fn refresh_dashboard(
    updater: Option<&DashboardUpdater>,
    context: &DashboardContext,
    snapshot: &ReadSnapshot,
) {
    let Some(updater) = updater else {
        return;
    };
    let observed_at = Instant::now();
    {
        let mut pending = context
            .pending_sync
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|node_id, action| {
            snapshot.block.number < action.receipt_block
                || !snapshot.nodes.iter().any(|node| {
                    node.id == *node_id
                        && node.pin.runtime_verified
                        && node.pin.abi_verified
                        && node
                            .state
                            .as_ref()
                            .is_some_and(|state| state.work.window_id >= action.window_id)
                })
        });
    }
    let mut updated = dashboard_model(context, snapshot, observed_at);
    let chain_timestamp = snapshot.block.timestamp;
    updater.update(|model| {
        let hashrate = model.hashrate;
        let head_advanced = reconcile_head_progress(model, &mut updated, observed_at);
        if !head_advanced
            && let Some(node) = updated
                .selected_nodes
                .iter()
                .find(|node| node.status == NodeStatus::WaitingForChain)
        {
            let age = observed_at
                .saturating_duration_since(updated.last_block_advanced_at)
                .as_secs();
            updated.current_action = Some(format!(
                "Node {:02} window #{} • waiting for a new canonical block ({age}s); stale work is stopped",
                node.id,
                node.window_id.unwrap_or_default()
            ));
        }
        for node in &mut updated.selected_nodes {
            let Some(previous) = model.selected_nodes.iter().find(|old| old.id == node.id) else {
                continue;
            };
            if node.window_id.is_some() && node.window_id == previous.window_id {
                if let (Some(previous_clock), Some(new_clock)) =
                    (previous.countdown.as_ref(), node.countdown.as_ref())
                {
                    node.countdown = Some(previous_clock.reconcile_same_window(
                        new_clock.expiry_timestamp,
                        chain_timestamp,
                        observed_at,
                    ));
                }
            } else if node.status == NodeStatus::RpcError && node.window_id.is_none() {
                node.window_id = previous.window_id;
                node.expiry_timestamp = previous.expiry_timestamp;
                node.countdown = previous
                    .countdown
                    .as_ref()
                    .map(|countdown| countdown.reanchor(observed_at));
                node.candidate = previous.candidate;
                node.reward = previous.reward;
            }
        }
        *model = updated;
        model.hashrate = hashrate;
        let transaction_state = context
            .transaction_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        apply_transaction_state_to_model(model, &transaction_state);
    });
}

fn reconcile_head_progress(
    previous: &DashboardModel,
    next: &mut DashboardModel,
    observed_at: Instant,
) -> bool {
    let advanced = !previous.snapshot_ready
        || next.block_number != previous.block_number
        || next.block_hash != previous.block_hash;
    next.last_block_advanced_at = if advanced {
        observed_at
    } else {
        previous.last_block_advanced_at
    };
    advanced
}

fn mark_dashboard_nodes(
    dashboard: &Option<Dashboard>,
    node_ids: impl IntoIterator<Item = u8>,
    status: NodeStatus,
    action: Option<String>,
) {
    let Some(dashboard) = dashboard else {
        return;
    };
    let node_ids = node_ids.into_iter().collect::<HashSet<_>>();
    dashboard.update(|model| {
        for node in &mut model.selected_nodes {
            if node_ids.contains(&node.id) {
                node.status = status;
                if status == NodeStatus::Syncing {
                    node.candidate = None;
                }
            }
        }
        model.current_action = action;
    });
}

fn connect_transaction_dashboard(
    transactions: &mut Option<TransactionManager>,
    dashboard: &Option<Dashboard>,
    transaction_state: Arc<RwLock<TransactionDashboardState>>,
) {
    let Some(manager) = transactions.as_mut() else {
        return;
    };
    let updater = dashboard.as_ref().map(Dashboard::updater);
    manager.set_dashboard_sink(Arc::new(move |state| {
        *transaction_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state.clone();
        if let Some(updater) = &updater {
            updater.update(|model| apply_transaction_state_to_model(model, &state));
        }
    }));
}

fn apply_transaction_state_to_model(model: &mut DashboardModel, state: &TransactionDashboardState) {
    model.authorization_used = state.authorization_used;
    model.actual_rpc_cost = state.actual_rpc_cost;
    model.mined_rewards = state.mined_rewards;
    model.recovering = state
        .activities
        .iter()
        .any(|activity| activity.state == TransactionActivityState::Recovering);
    for activity in &state.activities {
        let Some(node) = model
            .selected_nodes
            .iter_mut()
            .find(|node| node.id == activity.node_id)
        else {
            continue;
        };
        if node.window_id == Some(activity.window_id) {
            node.status = match activity.state {
                TransactionActivityState::Finalizing => NodeStatus::Finalizing,
                TransactionActivityState::Signed => NodeStatus::Signed,
                TransactionActivityState::Confirming => NodeStatus::Confirming,
                TransactionActivityState::Recovering => NodeStatus::Recovering,
            };
        }
    }
    let transaction_action = state.activities.first().map(|activity| {
        let action = match activity.state {
            TransactionActivityState::Finalizing => "Finalizing window",
            TransactionActivityState::Signed => "Signed; awaiting RPC broadcast",
            TransactionActivityState::Confirming => "Confirming transaction",
            TransactionActivityState::Recovering => "Recovering transaction",
        };
        format!(
            "Node {:02} window #{} • {action}...",
            activity.node_id, activity.window_id
        )
    });
    if transaction_action.is_some() {
        model.current_action = transaction_action;
    } else if model.current_action.as_deref().is_some_and(|action| {
        action.contains("Confirming transaction")
            || action.contains("Signed; awaiting RPC broadcast")
            || action.contains("Finalizing window...")
            || action.contains("Recovering transaction")
    }) {
        model.current_action = None;
    }
}

fn initial_transaction_dashboard_state(
    manager: Option<&TransactionManager>,
    diagnostics: &DiagnosticBuffer,
) -> TransactionDashboardState {
    let Some(manager) = manager else {
        return TransactionDashboardState::default();
    };
    let authorization_used = match manager.authorization_used() {
        Ok(exposure) => exposure,
        Err(error) => {
            diagnostics.push(format!(
                "dashboard could not read session authorization total: {error:#}"
            ));
            None
        }
    };
    let actual_rpc_cost = match manager.actual_rpc_cost() {
        Ok(cost) => cost,
        Err(error) => {
            diagnostics.push(format!(
                "dashboard could not read RPC-reported transaction costs: {error:#}"
            ));
            None
        }
    };
    TransactionDashboardState {
        authorization_used,
        actual_rpc_cost,
        mined_rewards: manager.mined_rewards_total(),
        activities: manager.dashboard_activities(),
    }
}

fn report_mining_info(dashboard: &Option<Dashboard>, message: impl Into<String>) {
    let message = message.into();
    if let Some(dashboard) = dashboard {
        dashboard.diagnostics().push(message);
    } else {
        println!("{message}");
    }
}

fn history_profile_enabled(value: Option<&str>) -> bool {
    value == Some("1")
}

pub(crate) fn optional_history_profile(
    enabled: bool,
    profile: impl FnOnce() -> String,
) -> Option<String> {
    enabled.then(profile)
}

fn report_mining_warning(dashboard: &Option<Dashboard>, message: impl Into<String>) {
    let message = message.into();
    if let Some(dashboard) = dashboard {
        dashboard.diagnostics().push(message);
    } else {
        eprintln!("{message}");
    }
}

fn flush_dashboard_diagnostics(dashboard: &Dashboard) {
    for message in dashboard.drain_diagnostics() {
        eprintln!("astatine: {message}");
    }
}

async fn wait_for_dashboard_event(signal: Option<DashboardSignal>) -> DashboardEventKind {
    match signal {
        Some(signal) => signal.wait().await,
        None => std::future::pending().await,
    }
}

fn print_startup(
    client: &NetworkClient,
    address: Address,
    active_backend: &Arc<RwLock<ActiveBackend>>,
    snapshot: &ReadSnapshot,
    slots: &[NodeSlot],
    selected: &HashSet<u8>,
    selected_work_changed: bool,
) {
    let backend = active_backend
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let ast_decimals = client
        .manifest
        .ast_token
        .as_ref()
        .map(|token| token.decimals)
        .unwrap_or(9);
    println!(
        "Astatine {} | {} (chain {}) | wallet {:#x} | INJ {} | AST {} | DEVICE {} · {} | block {}",
        env!("CARGO_PKG_VERSION"),
        network_label(client.manifest.network),
        client.manifest.chain_id,
        address,
        format_inj(snapshot.native_balance),
        format_token_units(snapshot.ast_balance, ast_decimals),
        backend.label(),
        backend.detail(),
        snapshot.block.number
    );
    let eligible = slots
        .iter()
        .filter(|slot| slot.current_work().is_some())
        .count();
    let finalizable = snapshot
        .nodes
        .iter()
        .filter(|node| selected.contains(&node.id))
        .filter(|node| {
            node.state
                .as_ref()
                .is_some_and(|state| state.finalizable && !state.mining_paused)
        })
        .count();
    if eligible == 0 {
        if finalizable > 0 {
            println!(
                "{} selected window(s) require permissionless finalization; read-only observation and automatic finalization are active.",
                finalizable
            );
        } else if snapshot.nodes.iter().any(|node| {
            selected.contains(&node.id) && node.state.as_ref().is_some_and(|state| state.eligible)
        }) {
            println!(
                "Verified work is eligible but the local slot is waiting for a fresh canonical head; stale work is stopped."
            );
        } else {
            println!("No eligible work in selected nodes; waiting for fresh verified windows.");
        }
    } else {
        println!(
            "Hashing {} eligible node(s); Ctrl+C stops safely.",
            eligible
        );
    }
    if !selected_work_changed {
        println!("No work state changed during startup verification.");
    }
}

fn print_progress(snapshot: &ReadSnapshot, slots: &[NodeSlot], hashes: u64, elapsed: Duration) {
    let eligible = slots
        .iter()
        .filter(|slot| slot.current_work().is_some())
        .count();
    let hashrate = hashes as f64 / elapsed.as_secs_f64().max(0.001);
    println!(
        "block {} | eligible {}/9 | {:.0} H/s",
        snapshot.block.number, eligible, hashrate
    );
    for node in &snapshot.nodes {
        if let Some(state) = &node.state {
            if !state.eligible {
                println!(
                    "  node {}: {} (window {})",
                    node.id, state.eligibility_reason, state.work.window_id
                );
            }
        } else if let Some(error) = &node.error {
            println!("  node {}: unavailable ({})", node.id, error);
        }
    }
}

fn start_cpu_worker_threads(
    threads: usize,
    context: MiningWorkerContext,
) -> Result<Vec<thread::JoinHandle<()>>> {
    let mut workers = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let worker_context = context.clone();
        match thread::Builder::new()
            .name(format!("astatine-pow-{worker_id}"))
            .spawn(move || {
                worker_loop(
                    worker_context.slots,
                    worker_context.schedule,
                    worker_context.stop,
                    worker_context.cursor,
                    worker_context.total_hashes,
                    worker_context.proofs,
                    worker_context.telemetry,
                )
            }) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                context.stop.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(error).context("start CPU mining worker");
            }
        }
    }
    Ok(workers)
}

async fn receive_backend_event(
    receiver: &mut Option<mpsc::UnboundedReceiver<BackendEvent>>,
) -> Option<BackendEvent> {
    match receiver.as_mut() {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

fn gpu_worker_controller(
    selection: DeviceChoice,
    cpu_threads: usize,
    context: MiningWorkerContext,
    events: mpsc::UnboundedSender<BackendEvent>,
) {
    let gpu_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let mut engine = GpuEngine::initialize()?;
        if selection == DeviceChoice::Auto {
            let cpu_rate = benchmark_cpu_reference(cpu_threads)?;
            let gpu_rate = engine.info().tuned_hashes_per_second;
            engine.record_cpu_comparison(cpu_rate, cpu_threads);
            if !gpu_is_meaningfully_faster(gpu_rate, cpu_rate) {
                let reason = format!(
                    "auto selected CPU: measured CPU {:.3} MH/s ({cpu_threads} threads) versus GPU {:.3} MH/s; GPU was not at least 10% faster",
                    cpu_rate as f64 / 1_000_000.0,
                    gpu_rate as f64 / 1_000_000.0,
                );
                activate_cpu_fallback(cpu_threads, context.clone(), events.clone(), reason);
                return Ok(());
            }
        }
        events
            .send(BackendEvent::Activated(ActiveBackend::Gpu(
                engine.info().clone(),
            )))
            .map_err(|_| anyhow!("GPU backend status channel closed during startup"))?;
        let result = gpu_worker_loop(&mut engine, &context);
        if context.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        result?;
        bail!("GPU compute worker stopped unexpectedly")
    }));

    if context.stop.load(Ordering::Acquire) {
        return;
    }
    let failure = match gpu_result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => format!("GPU failed: {error:#}"),
        Err(payload) => format!("GPU backend panicked: {}", panic_payload_message(payload)),
    };
    if selection == DeviceChoice::Auto {
        activate_cpu_fallback(cpu_threads, context, events, failure);
    } else {
        let _ = events.send(BackendEvent::Failed(format!(
            "{failure}; explicit GPU mode does not substitute CPU hashing"
        )));
    }
}

fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else {
        "unknown panic payload".to_owned()
    }
}

fn activate_cpu_fallback(
    cpu_threads: usize,
    context: MiningWorkerContext,
    events: mpsc::UnboundedSender<BackendEvent>,
    reason: String,
) {
    if context.stop.load(Ordering::Acquire) {
        return;
    }
    let workers = match start_cpu_worker_threads(cpu_threads, context.clone()) {
        Ok(workers) => workers,
        Err(error) => {
            let _ = events.send(BackendEvent::Failed(format!(
                "{reason}; CPU backend could not start: {error:#}"
            )));
            return;
        }
    };
    let _ = events.send(BackendEvent::Activated(ActiveBackend::Cpu {
        threads: cpu_threads,
    }));
    let _ = events.send(BackendEvent::FallbackNotice(reason));
    for worker in workers {
        if worker.join().is_err() && !context.stop.load(Ordering::Acquire) {
            let _ = events.send(BackendEvent::Failed(
                "a CPU fallback worker panicked".to_owned(),
            ));
            context.stop.store(true, Ordering::Release);
            return;
        }
    }
}

fn gpu_worker_loop(engine: &mut GpuEngine, context: &MiningWorkerContext) -> Result<()> {
    let mut nonce_exhaustion_reported = false;
    let mut pending: Option<PendingGpuWorkBatch> = None;
    while !context.stop.load(Ordering::Acquire) {
        let mut active = context
            .schedule
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        active.retain(|index| context.slots[*index].current_work().is_some());
        let Some(slot_index) = next_scheduled_slot(&active, &context.cursor) else {
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            } else {
                thread::sleep(IDLE_INTERVAL);
            }
            continue;
        };
        let slot = &context.slots[slot_index];
        let Some(work) = slot.current_work() else {
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            } else {
                thread::sleep(IDLE_INTERVAL);
            }
            continue;
        };
        if !slot.is_generation_current(work.generation) {
            context
                .telemetry
                .record(slot.id, ProofMetric::WorkerStoppedGeneration);
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            }
            continue;
        }
        let Some((first_nonce, count)) = slot.reserve_nonces(engine.batch_size()) else {
            if !nonce_exhaustion_reported {
                context
                    .telemetry
                    .record(slot.id, ProofMetric::WorkerNonceRangeExhausted);
                nonce_exhaustion_reported = true;
            }
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            } else {
                thread::sleep(IDLE_INTERVAL);
            }
            continue;
        };
        nonce_exhaustion_reported = false;
        let batch = GpuBatchIdentity {
            node_id: slot.id,
            generation: work.generation,
            window_id: work.fingerprint.hashing_context.window_id,
            first_nonce,
            nonce_count: count,
        };
        let submitted = match engine.dispatch_batch(
            &work.hasher,
            first_nonce,
            count,
            work.target,
            work.incumbent,
            &context.stop,
        ) {
            Ok(pending) => pending,
            Err(_error) if context.stop.load(Ordering::Acquire) => return Ok(()),
            Err(error) => return Err(error).context("dispatch GPU SHA-256d nonce batch"),
        };
        let next = PendingGpuWorkBatch {
            slot_index,
            work,
            identity: batch,
            pending: submitted,
        };
        if let Some(previous) = pending.replace(next) {
            complete_gpu_work_batch(engine, context, previous)?;
        }
    }
    if !context.stop.load(Ordering::Acquire)
        && let Some(previous) = pending.take()
    {
        complete_gpu_work_batch(engine, context, previous)?;
    }
    Ok(())
}

fn complete_gpu_work_batch(
    engine: &mut GpuEngine,
    context: &MiningWorkerContext,
    pending: PendingGpuWorkBatch,
) -> Result<()> {
    let PendingGpuWorkBatch {
        slot_index,
        work,
        identity,
        pending,
    } = pending;
    let result = match engine.collect_batch(pending, Some(&context.stop)) {
        Ok(result) => result,
        Err(_error) if context.stop.load(Ordering::Acquire) => return Ok(()),
        Err(error) => return Err(error).context("collect GPU SHA-256d batch readback"),
    };
    if result.completed_hashes != identity.nonce_count
        || result.workgroup_count != identity.nonce_count.div_ceil(result.workgroup_size)
    {
        bail!(
            "GPU completed {} of {} reserved nonce hashes or returned an invalid workgroup count",
            result.completed_hashes,
            identity.nonce_count
        );
    }
    if let Some(batch_size) = engine.observe_batch_latency(result.timings.submission_to_readback) {
        eprintln!(
            "astatine: GPU batch latency exceeded 100 ms; reduced the next dispatch to {batch_size} nonces"
        );
    }
    let slot = &context.slots[slot_index];
    if slot.id != identity.node_id {
        bail!("GPU pending batch crossed into another node's state");
    }
    context
        .total_hashes
        .fetch_add(u64::try_from(result.completed_hashes)?, Ordering::Relaxed);
    slot.completed_hashes
        .fetch_add(u64::try_from(result.completed_hashes)?, Ordering::Relaxed);
    context
        .telemetry
        .record(slot.id, ProofMetric::GpuCompletedBatches);

    let mut seen_nonces = HashSet::with_capacity(result.candidates.len());
    let mut seen_groups = HashSet::with_capacity(result.candidates.len());
    for candidate in &result.candidates {
        let offset = candidate
            .nonce
            .checked_sub(identity.first_nonce)
            .ok_or_else(|| anyhow!("GPU returned a nonce before its reserved batch"))?;
        if offset >= identity.nonce_count as u128
            || usize::try_from(offset)? / result.workgroup_size != candidate.workgroup_index
            || !seen_nonces.insert(candidate.nonce)
            || !seen_groups.insert(candidate.workgroup_index)
        {
            bail!("GPU returned a duplicate, misattributed, or out-of-batch group winner");
        }
    }
    if let Some(candidate) = result.candidates.into_iter().min_by(|left, right| {
        left.hash
            .cmp(&right.hash)
            .then(left.nonce.cmp(&right.nonce))
    }) {
        process_hashed_candidate(
            slot,
            &work,
            HashedCandidate {
                nonce: candidate.nonce,
                hash: candidate.hash,
                reported_gpu_hash: Some(candidate.hash),
                batch_identity: Some(identity),
            },
            &context.proofs,
            &context.telemetry,
        )
        .map_err(|failure| anyhow!("GPU candidate failed CPU verification: {failure}"))?;
    }
    Ok(())
}

fn process_hashed_candidate(
    slot: &NodeSlot,
    work: &Arc<WorkJob>,
    candidate: HashedCandidate,
    proofs: &ProofInboxSender,
    telemetry: &ProofPipelineTelemetry,
) -> std::result::Result<(), GpuCandidateFailure> {
    let HashedCandidate {
        nonce,
        hash,
        reported_gpu_hash,
        batch_identity,
    } = candidate;
    if let Some(batch) = batch_identity {
        if batch.node_id != slot.id
            || batch.generation != work.generation
            || batch.window_id != work.fingerprint.hashing_context.window_id
            || batch.nonce_count == 0
            || !batch.contains(nonce)
        {
            telemetry.record(slot.id, ProofMetric::GpuBatchIdentityRejected);
            return Err(GpuCandidateFailure::InvalidBatchIdentity);
        }
        let Some(reported) = reported_gpu_hash else {
            telemetry.record(slot.id, ProofMetric::GpuBatchIdentityRejected);
            return Err(GpuCandidateFailure::MissingGpuHash);
        };
        let canonical = work.hasher.hash(nonce);
        if canonical != reported || canonical != hash {
            telemetry.record(slot.id, ProofMetric::GpuHashMismatch);
            return Err(GpuCandidateFailure::HashMismatch {
                gpu: reported,
                cpu: canonical,
            });
        }
        telemetry.record(slot.id, ProofMetric::GpuCandidatesCpuVerified);
    } else if reported_gpu_hash.is_some() {
        telemetry.record(slot.id, ProofMetric::GpuBatchIdentityRejected);
        return Err(GpuCandidateFailure::UnexpectedGpuHash);
    }

    if !meets_target(hash, work.target) {
        return Ok(());
    }
    telemetry.record(slot.id, ProofMetric::TargetValidHashes);
    if !slot.is_generation_current(work.generation) {
        telemetry.record(slot.id, ProofMetric::WorkerStaleGenerationHash);
        return Ok(());
    }
    if Instant::now() >= work.valid_until {
        telemetry.record(slot.id, ProofMetric::WorkerDeadlineHashDropped);
        return Ok(());
    }
    if work
        .incumbent
        .is_some_and(|incumbent| !beats_incumbent(hash, incumbent))
    {
        telemetry.record(slot.id, ProofMetric::IncumbentRejectedHashes);
        return Ok(());
    }
    telemetry.record(slot.id, ProofMetric::IncumbentPassedHashes);
    match slot.update_local_best(work.generation, work.valid_until, hash) {
        LocalBestUpdate::NewBest => {}
        LocalBestUpdate::NotBetter => {
            telemetry.record(slot.id, ProofMetric::TargetValidNotNewLocalBest);
            return Ok(());
        }
        LocalBestUpdate::StaleGeneration => {
            telemetry.record(slot.id, ProofMetric::WorkerStaleGenerationHash);
            return Ok(());
        }
        LocalBestUpdate::ExpiredDeadline => {
            telemetry.record(slot.id, ProofMetric::WorkerDeadlineHashDropped);
            return Ok(());
        }
    }
    telemetry.record(slot.id, ProofMetric::NewLocalBestHashes);
    if proofs
        .attempts
        .suppresses(slot.id, work.fingerprint.hashing_context.window_id)
    {
        telemetry.record(slot.id, ProofMetric::SuppressedPriorAttempt);
        return Ok(());
    }
    let _ = proofs.deliver(
        ProofFound {
            node_id: slot.id,
            generation: work.generation,
            context: work.fingerprint.hashing_context.clone(),
            nonce,
            hash,
            target: work.target,
            incumbent: work.incumbent,
            batch_identity,
            queued_at: Instant::now(),
        },
        telemetry,
    );
    Ok(())
}

#[derive(Debug)]
enum GpuCandidateFailure {
    InvalidBatchIdentity,
    MissingGpuHash,
    UnexpectedGpuHash,
    HashMismatch { gpu: B256, cpu: B256 },
}

impl std::fmt::Display for GpuCandidateFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBatchIdentity => {
                formatter.write_str("nonce is outside its assigned batch")
            }
            Self::MissingGpuHash => formatter.write_str("GPU candidate has no reported digest"),
            Self::UnexpectedGpuHash => formatter.write_str("CPU candidate carries a GPU digest"),
            Self::HashMismatch { gpu, cpu } => {
                write!(
                    formatter,
                    "GPU digest {gpu:#x} differs from CPU digest {cpu:#x}"
                )
            }
        }
    }
}

fn worker_loop(
    slots: Arc<Vec<NodeSlot>>,
    schedule: Arc<RwLock<Vec<usize>>>,
    stop: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    total_hashes: Arc<AtomicU64>,
    proofs: ProofInboxSender,
    telemetry: Arc<ProofPipelineTelemetry>,
) {
    let mut nonce_exhaustion_reported = false;
    while !stop.load(Ordering::Acquire) {
        let mut active = schedule
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        active.retain(|index| slots[*index].current_work().is_some());
        let Some(slot_index) = next_scheduled_slot(&active, &cursor) else {
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        let slot = &slots[slot_index];
        let Some(work) = slot.current_work() else {
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        if !slot.is_generation_current(work.generation) {
            telemetry.record(slot.id, ProofMetric::WorkerStoppedGeneration);
            continue;
        }
        let Some((first_nonce, count)) = slot.reserve_nonces(NONCE_BATCH_SIZE) else {
            if !nonce_exhaustion_reported {
                telemetry.record(slot.id, ProofMetric::WorkerNonceRangeExhausted);
                nonce_exhaustion_reported = true;
            }
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        nonce_exhaustion_reported = false;
        let mut scratch = vec![0_u8; work.hasher.scratch_len()];
        let mut completed = 0_u64;
        for offset in 0..count {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if !slot.is_generation_current(work.generation) {
                telemetry.record(slot.id, ProofMetric::WorkerStoppedGeneration);
                break;
            }
            if Instant::now() >= work.valid_until {
                telemetry.record(slot.id, ProofMetric::WorkerStoppedDeadline);
                break;
            }
            let Some(nonce) = first_nonce.checked_add(offset as u128) else {
                break;
            };
            let Ok(hash) = work.hasher.hash_into(nonce, &mut scratch) else {
                telemetry.record(slot.id, ProofMetric::WorkerHashFailure);
                break;
            };
            completed += 1;
            if process_hashed_candidate(
                slot,
                &work,
                HashedCandidate {
                    nonce,
                    hash,
                    reported_gpu_hash: None,
                    batch_identity: None,
                },
                &proofs,
                &telemetry,
            )
            .is_err()
            {
                telemetry.record(slot.id, ProofMetric::WorkerHashFailure);
                break;
            }
        }
        total_hashes.fetch_add(completed, Ordering::Relaxed);
        slot.completed_hashes
            .fetch_add(completed, Ordering::Relaxed);
    }
}

fn next_scheduled_slot(active: &[usize], cursor: &AtomicUsize) -> Option<usize> {
    if active.is_empty() {
        return None;
    }
    Some(active[cursor.fetch_add(1, Ordering::Relaxed) % active.len()])
}

fn next_poll_delay(current: Duration) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(MAX_POLL_INTERVAL)
        .min(MAX_POLL_INTERVAL)
}

fn format_inj(value: Option<U256>) -> String {
    let Some(value) = value else {
        return "unavailable".to_owned();
    };
    let scale = U256::from(1_000_000_000_000_000_000_u128);
    let whole = value / scale;
    let fractional = (value % scale).to_string();
    format!("{whole}.{fractional:0>18}")
}

fn format_token_units(value: Option<U256>, decimals: u8) -> String {
    let Some(value) = value else {
        return "unavailable".to_owned();
    };
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let whole = value / scale;
    let fractional = (value % scale).to_string();
    let fractional = format!("{fractional:0>width$}", width = usize::from(decimals))
        .trim_end_matches('0')
        .to_owned();
    if fractional.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fractional}")
    }
}

fn network_label(network: crate::cli::Network) -> &'static str {
    match network {
        crate::cli::Network::Testnet => "Testnet",
        crate::cli::Network::Mainnet => "Mainnet",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveBackend, DashboardContext, FinalizationState, HashedCandidate, HashingContext,
        MiningWorkerContext, NodeSlot, NonceAllocator, ObserverUpdate,
        PENDING_PROOF_CANDIDATE_CAPACITY, PendingDashboardSync, ProofFound, SnapshotFreshness,
        activate_cpu_fallback, apply_genesis_poll_error, clear_genesis_poll_error,
        compare_snapshot_freshness, dashboard_model, dashboard_node_status,
        finalization_retry_delay, gpu_is_meaningfully_faster, history_profile_enabled,
        inactive_genesis_nodes, next_poll_delay, next_scheduled_slot, process_hashed_candidate,
        proof_inbox, reconcile_head_progress, revalidate_queued_proof, revalidate_queued_proof_at,
        selected_nodes, should_unlock_recovered_wallet, take_observer_update, traced_node_status,
        update_slots, worker_loop,
    };
    use crate::{
        cli::{DeviceChoice, MineArgs, Network},
        config::ConfigStore,
        dashboard::{NodeStatus, hashes_per_second},
        deployment::DeploymentManifest,
        gpu::GpuBatchIdentity,
        proof_telemetry::{ProofAttemptGuard, ProofMetric, ProofPipelineTelemetry},
        protocol::{WorkContext, WorkHasher, meets_target},
        rpc::{
            BlockSnapshot, CandidateInfo, ContractPinStatus, NetworkClient, NodeState, NodeView,
            ReadSnapshot, WorkInfo,
        },
        transaction::{
            AUTOMATIC_REWARD_FORWARDING_DISABLED, TransactionActivityState,
            TransactionDashboardState,
        },
    };
    use alloy_primitives::{Address, B256, Bytes, U256};
    use std::{
        collections::{HashMap, HashSet},
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use tempfile::tempdir;
    use tokio::sync::{oneshot, watch};
    use tokio::time::timeout;

    fn eligible_state() -> NodeState {
        NodeState {
            work: WorkInfo {
                started: true,
                ended: false,
                window_id: 7,
                window_start_time: 100,
                window_expiry_time: 200,
                seed: B256::with_last_byte(1),
                prev_hash: B256::with_last_byte(2),
                target: U256::MAX,
                reward_per_window: U256::from(100),
                remaining_allocation: U256::from(1_000),
                max_header_length: 64,
                submission_fee: U256::from(10),
            },
            candidate: None,
            mining_paused: false,
            eligible: true,
            finalizable: false,
            eligibility_reason: "eligible",
        }
    }

    #[test]
    fn auto_uses_gpu_only_when_measured_rate_clearly_beats_cpu() {
        assert!(!gpu_is_meaningfully_faster(0, 1));
        assert!(!gpu_is_meaningfully_faster(100, 100));
        assert!(!gpu_is_meaningfully_faster(105, 100));
        assert!(!gpu_is_meaningfully_faster(110, 100));
        assert!(gpu_is_meaningfully_faster(111, 100));
        assert!(!gpu_is_meaningfully_faster(100, 111));
        assert!(gpu_is_meaningfully_faster(200, 100));
    }

    fn test_block(number: u64, timestamp: u64) -> BlockSnapshot {
        BlockSnapshot {
            number,
            timestamp,
            hash: B256::with_last_byte(number as u8),
        }
    }

    #[test]
    fn aggregate_history_profile_requires_explicit_developer_opt_in() {
        assert!(!history_profile_enabled(None));
        assert!(!history_profile_enabled(Some("0")));
        assert!(!history_profile_enabled(Some("true")));
        assert!(history_profile_enabled(Some("1")));
    }

    #[test]
    fn dashboard_node_status_requires_verified_live_work_and_respects_transactions() {
        let mut state = eligible_state();
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, true, None),
            NodeStatus::Mining
        );
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::Waiting
        );
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, true, None),
            NodeStatus::WaitingForChain
        );
        assert_eq!(
            dashboard_node_status(Some(&state), false, true, true, None),
            NodeStatus::RpcError
        );
        assert_eq!(
            dashboard_node_status(None, true, false, false, None),
            NodeStatus::RpcError
        );

        state.work.started = false;
        state.work.ended = false;
        state.work.remaining_allocation = U256::from(10_u8);
        state.eligible = false;
        state.finalizable = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::WaitingForGenesis
        );
        assert_eq!(traced_node_status(Some(&state), true), "WAIT GENESIS");
        state.work.remaining_allocation = U256::ZERO;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::WaitingForGenesis,
            "a verified unstarted node is waiting for genesis even before allocation is visible"
        );
        assert_eq!(traced_node_status(Some(&state), true), "WAIT GENESIS");
        assert_eq!(
            dashboard_node_status(Some(&state), false, false, false, None),
            NodeStatus::RpcError,
            "an inactive but unverified runtime must not be shown as waiting for genesis"
        );
        assert_eq!(traced_node_status(Some(&state), false), "RPC ERROR");
        state.work.ended = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::Ended,
            "a permanently ended node must not wait for genesis"
        );

        state.work.started = true;
        state.work.ended = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::Ended,
            "an active node with exhausted allocation is ended"
        );
        assert_eq!(traced_node_status(Some(&state), true), "ENDED");
        state.work.remaining_allocation = U256::from(10_u8);
        state.mining_paused = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, true, None),
            NodeStatus::Paused
        );
        state.mining_paused = false;
        state.work.ended = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, true, None),
            NodeStatus::Ended
        );
        state.work.ended = false;
        state.finalizable = true;
        state.eligible = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, true, None),
            NodeStatus::FinalizationRequired
        );

        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Finalizing)
            ),
            NodeStatus::Finalizing
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Confirming)
            ),
            NodeStatus::Confirming
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Signed)
            ),
            NodeStatus::Signed
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Recovering)
            ),
            NodeStatus::Recovering
        );
    }

    #[test]
    fn genesis_poll_selection_is_limited_to_selected_verified_unstarted_nodes() {
        let mut inactive = eligible_state();
        inactive.work.started = false;
        inactive.eligible = false;
        inactive.finalizable = false;

        let mut ended = inactive.clone();
        ended.work.ended = true;

        let mut unallocated = inactive.clone();
        unallocated.work.remaining_allocation = U256::ZERO;

        let mut exhausted = eligible_state();
        exhausted.work.remaining_allocation = U256::ZERO;

        let mut nodes = vec![
            NodeView {
                id: 1,
                address: Address::with_last_byte(1),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(inactive.clone()),
                error: None,
            },
            NodeView {
                id: 2,
                address: Address::with_last_byte(2),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            },
            NodeView {
                id: 3,
                address: Address::with_last_byte(3),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(ended),
                error: None,
            },
            NodeView {
                id: 4,
                address: Address::with_last_byte(4),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(unallocated),
                error: None,
            },
            NodeView {
                id: 5,
                address: Address::with_last_byte(5),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: None,
                error: Some("state unavailable".to_owned()),
            },
            NodeView {
                id: 6,
                address: Address::with_last_byte(6),
                pin: ContractPinStatus {
                    runtime_verified: false,
                    abi_verified: false,
                    error: Some("runtime pin not trusted".to_owned()),
                },
                state: Some(inactive),
                error: None,
            },
            NodeView {
                id: 7,
                address: Address::with_last_byte(7),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some({
                    let mut state = eligible_state();
                    state.work.started = false;
                    state.eligible = false;
                    state.finalizable = false;
                    state
                }),
                error: None,
            },
            NodeView {
                id: 8,
                address: Address::with_last_byte(8),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(exhausted),
                error: None,
            },
        ];
        nodes.reverse();
        let snapshot = ReadSnapshot {
            block: test_block(100, 500),
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes,
        };
        let selected = HashSet::from([1, 2, 3, 4, 5, 6, 8]);

        assert_eq!(inactive_genesis_nodes(&snapshot, &selected), [1, 4]);
        assert!(inactive_genesis_nodes(&snapshot, &HashSet::new()).is_empty());
    }

    #[test]
    fn dashboard_model_sorts_and_only_copies_selected_nodes() {
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let selected = HashSet::from([7, 1, 3]);
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let nodes = [7, 2, 3, 1]
            .into_iter()
            .map(|id| NodeView {
                id,
                address: Address::with_last_byte(id),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            })
            .collect();
        let snapshot = ReadSnapshot {
            block: BlockSnapshot {
                number: 123,
                timestamp: 100,
                hash: B256::with_last_byte(1),
            },
            native_balance: Some(U256::from(1_000)),
            native_balance_error: None,
            ast_balance: Some(U256::from(39_000_000_000_000_u128)),
            ast_balance_error: None,
            nodes,
        };
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: Address::with_last_byte(9),
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 2 })),
            spending_limit: U256::ZERO,
            transaction_mode: false,
            compute_only: true,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: selected.clone(),
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState {
                authorization_used: None,
                actual_rpc_cost: None,
                mined_rewards: U256::from(26_000_000_000_000_u128),
                activities: Vec::new(),
            })),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };
        update_slots(
            &slots,
            &schedule,
            &DeploymentManifest::load(Network::Testnet).unwrap(),
            context.address,
            &selected,
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            *schedule
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [0, 2, 6]
        );

        let model = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(model.ast_balance, Some(U256::from(39_000_000_000_000_u128)));
        assert_eq!(model.mined_rewards, U256::from(26_000_000_000_000_u128));
        assert_eq!(
            model
                .selected_nodes
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            [1, 3, 7]
        );
        let advanced_at = model.last_block_advanced_at;
        let repeated_read_at = Instant::now() + Duration::from_secs(5);
        let mut repeated = model.clone();
        repeated.snapshot_observed_at = repeated_read_at;
        assert!(!reconcile_head_progress(
            &model,
            &mut repeated,
            repeated_read_at
        ));
        assert_eq!(repeated.last_block_advanced_at, advanced_at);

        repeated.block_number += 1;
        repeated.block_hash = B256::with_last_byte(2);
        assert!(reconcile_head_progress(
            &model,
            &mut repeated,
            repeated_read_at
        ));
        assert_eq!(repeated.last_block_advanced_at, repeated_read_at);

        let mut probe_error_model = model.clone();
        probe_error_model
            .selected_nodes
            .iter_mut()
            .find(|node| node.id == 3)
            .unwrap()
            .status = NodeStatus::WaitingForGenesis;
        let probe_error = "genesis status poll failed for selected node(s) [3]: timeout";
        assert!(apply_genesis_poll_error(
            &mut probe_error_model,
            &[3],
            probe_error
        ));
        assert_eq!(probe_error_model.mode(Instant::now()), "RPC ERROR");
        assert_eq!(
            probe_error_model
                .selected_nodes
                .iter()
                .find(|node| node.id == 3)
                .unwrap()
                .status,
            NodeStatus::RpcError
        );
        assert_eq!(
            probe_error_model
                .selected_nodes
                .iter()
                .find(|node| node.id == 1)
                .unwrap()
                .status,
            NodeStatus::Mining,
            "an inactive-node poll error must not mark other selected mining nodes failed"
        );
        assert!(!clear_genesis_poll_error(
            &mut probe_error_model,
            &[3],
            "a different RPC error"
        ));
        assert!(clear_genesis_poll_error(
            &mut probe_error_model,
            &[3],
            probe_error
        ));
        assert_eq!(probe_error_model.connection_error, None);
        assert_eq!(
            probe_error_model
                .selected_nodes
                .iter()
                .find(|node| node.id == 3)
                .unwrap()
                .status,
            NodeStatus::WaitingForGenesis
        );
    }

    #[test]
    fn dashboard_distinguishes_required_retrying_and_blocked_finalization_from_chain_wait() {
        let wallet = Address::with_last_byte(9);
        let selected = HashSet::from([1_u8]);
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let mut state = eligible_state();
        state.eligible = false;
        state.finalizable = true;
        let snapshot = ReadSnapshot {
            block: test_block(101, state.work.window_expiry_time + 1),
            native_balance: Some(U256::from(100)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: Address::with_last_byte(1),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(state.clone()),
                error: None,
            }],
        };
        let finalization_state = Arc::new(RwLock::new(HashMap::new()));
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 1 })),
            spending_limit: U256::from(1),
            transaction_mode: true,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: selected.clone(),
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState::default())),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::clone(&finalization_state),
        };
        let required = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            required.selected_nodes[0].status,
            NodeStatus::FinalizationRequired
        );
        assert_eq!(required.mode(Instant::now()), "FINALIZATION REQUIRED");

        finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                1,
                FinalizationState::Retrying {
                    window_id: state.work.window_id,
                    attempts: 1,
                    retry_at: Instant::now() + Duration::from_secs(1),
                    reason: "temporary RPC failure".to_owned(),
                },
            );
        let retrying = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            retrying.selected_nodes[0].status,
            NodeStatus::FinalizationRetrying
        );
        assert!(
            retrying
                .current_action
                .as_deref()
                .unwrap()
                .contains("temporary RPC")
        );

        finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                1,
                FinalizationState::Blocked {
                    window_id: state.work.window_id,
                    reason: "session cap exhausted".to_owned(),
                },
            );
        let blocked = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            blocked.selected_nodes[0].status,
            NodeStatus::FinalizationBlocked
        );
        assert_eq!(blocked.mode(Instant::now()), "FINALIZATION BLOCKED");
        assert!(
            blocked
                .current_action
                .as_deref()
                .unwrap()
                .contains("session cap")
        );

        finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        state.eligible = true;
        state.finalizable = false;
        let mut waiting_snapshot = snapshot.clone();
        waiting_snapshot.nodes[0].state = Some(state);
        let waiting = dashboard_model(&context, &waiting_snapshot, Instant::now());
        assert_eq!(
            waiting.selected_nodes[0].status,
            NodeStatus::WaitingForChain
        );
        assert_eq!(waiting.mode(Instant::now()), "WAITING FOR CHAIN");
    }

    #[test]
    fn snapshot_freshness_rejects_stale_heads_and_accepts_selected_rpc_reorgs() {
        let previous = BlockSnapshot {
            number: 100,
            timestamp: 1_000,
            hash: B256::with_last_byte(1),
        };
        let same = previous.clone();
        assert_eq!(
            compare_snapshot_freshness(&previous, &same, None, None).unwrap(),
            SnapshotFreshness::Current
        );

        let higher = BlockSnapshot {
            number: 101,
            timestamp: 1_001,
            hash: B256::with_last_byte(2),
        };
        assert_eq!(
            compare_snapshot_freshness(&previous, &higher, None, None).unwrap(),
            SnapshotFreshness::Current
        );

        let stale = BlockSnapshot {
            number: 99,
            timestamp: 999,
            hash: B256::with_last_byte(3),
        };
        assert!(compare_snapshot_freshness(&previous, &stale, Some(previous.hash), None).is_err());
        assert_eq!(
            compare_snapshot_freshness(&previous, &stale, Some(B256::with_last_byte(4)), None,)
                .unwrap(),
            SnapshotFreshness::Reorg
        );

        let same_height_reorg = BlockSnapshot {
            number: previous.number,
            timestamp: 1_000,
            hash: B256::with_last_byte(5),
        };
        assert!(compare_snapshot_freshness(&previous, &same_height_reorg, None, None).is_err());
        assert_eq!(
            compare_snapshot_freshness(
                &previous,
                &same_height_reorg,
                None,
                Some(same_height_reorg.hash),
            )
            .unwrap(),
            SnapshotFreshness::Reorg
        );
    }

    #[tokio::test]
    async fn watch_ref_from_match_scrutinee_blocks_publisher_across_async_arm() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (sender, receiver) = watch::channel(ObserverUpdate::RpcError {
                    message: "initial".to_owned(),
                    report: false,
                });
                let (entered_tx, entered_rx) = oneshot::channel();
                let (finish_tx, finish_rx) = oneshot::channel();
                let mut consumer_receiver = receiver.clone();
                let consumer = tokio::task::spawn_local(async move {
                    match consumer_receiver.borrow_and_update().clone() {
                        ObserverUpdate::RpcError { .. } => {
                            entered_tx.send(()).unwrap();
                            finish_rx.await.unwrap();
                        }
                        _ => panic!("unexpected observer update"),
                    }
                });
                entered_rx.await.unwrap();

                let publisher = sender.clone();
                let (published_tx, published_rx) = std::sync::mpsc::channel();
                let thread = thread::spawn(move || {
                    publisher.send_replace(ObserverUpdate::RpcError {
                        message: "next".to_owned(),
                        report: false,
                    });
                    published_tx.send(()).unwrap();
                });
                assert_eq!(
                    published_rx.recv_timeout(Duration::from_millis(50)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                    "the match scrutinee read guard should remain held through the async arm"
                );
                finish_tx.send(()).unwrap();
                consumer.await.unwrap();
                published_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("publisher should continue after the match expression ends");
                thread.join().unwrap();
                assert!(matches!(
                    &*receiver.borrow(),
                    ObserverUpdate::RpcError { message, .. } if message == "next"
                ));
            })
            .await;
    }

    #[tokio::test]
    async fn owned_observer_update_does_not_block_publication_during_await() {
        let initial = ObserverUpdate::RpcError {
            message: "initial".to_owned(),
            report: false,
        };
        let (sender, mut receiver) = watch::channel(initial);
        let update = take_observer_update(&mut receiver);
        let (finish_transaction_tx, finish_transaction_rx) = oneshot::channel();
        let consumer = tokio::spawn(async move {
            let _owned_update = update;
            finish_transaction_rx.await.unwrap();
        });

        tokio::task::yield_now().await;
        assert!(
            !consumer.is_finished(),
            "simulated transaction wait is pending"
        );

        let refresh_gate = Arc::new(std::sync::Mutex::new(()));
        let publisher_gate = Arc::clone(&refresh_gate);
        let publisher = tokio::task::spawn_blocking(move || {
            let _commit = publisher_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sender.send_replace(ObserverUpdate::RpcError {
                message: "published while transaction awaits".to_owned(),
                report: false,
            });
        });
        tokio::time::timeout(Duration::from_secs(1), publisher)
            .await
            .expect("watch publisher must not wait for transaction completion")
            .unwrap();

        let force_refresh_gate = Arc::clone(&refresh_gate);
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(move || {
                let _commit = force_refresh_gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }),
        )
        .await
        .expect("forced refresh must not deadlock behind publication")
        .unwrap();
        finish_transaction_tx.send(()).unwrap();
        consumer.await.unwrap();
        assert!(matches!(
            &*receiver.borrow(),
            ObserverUpdate::RpcError { message, .. }
                if message == "published while transaction awaits"
        ));
    }

    #[test]
    fn accepted_proof_waits_for_receipt_block_then_uses_only_verified_best_candidate() {
        let wallet = Address::with_last_byte(9);
        let selected = HashSet::from([1_u8]);
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let mut state = eligible_state();
        let initial_view = NodeView {
            id: 1,
            address: Address::with_last_byte(1),
            pin: ContractPinStatus {
                runtime_verified: true,
                abi_verified: true,
                error: None,
            },
            state: Some(state.clone()),
            error: None,
        };
        let mut snapshot = ReadSnapshot {
            block: BlockSnapshot {
                number: 9,
                timestamp: 100,
                hash: B256::with_last_byte(9),
            },
            native_balance: Some(U256::from(1_000)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![initial_view],
        };
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        update_slots(&slots, &schedule, &manifest, wallet, &selected, &snapshot).unwrap();
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 2 })),
            spending_limit: U256::ZERO,
            transaction_mode: false,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: selected.clone(),
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState::default())),
            pending_sync: Arc::new(RwLock::new(HashMap::from([(
                1,
                PendingDashboardSync {
                    window_id: state.work.window_id,
                    receipt_block: 10,
                },
            )]))),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };

        let syncing = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(syncing.selected_nodes[0].status, NodeStatus::Syncing);
        assert_eq!(syncing.selected_nodes[0].candidate, None);
        assert_eq!(
            syncing.selected_nodes[0].window_id,
            Some(state.work.window_id)
        );

        state.candidate = Some(CandidateInfo {
            miner: wallet,
            nonce: 17,
            work_hash: B256::with_last_byte(3),
            submitted_at: 101,
            header: Bytes::new(),
            first_valid_solve_secs: 1,
        });
        snapshot.block.number = 10;
        snapshot.nodes[0].state = Some(state.clone());
        let verified = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(verified.selected_nodes[0].status, NodeStatus::Mining);
        assert_eq!(verified.selected_nodes[0].candidate, Some(wallet));

        state.candidate.as_mut().unwrap().miner = Address::with_last_byte(8);
        snapshot.block.number = 11;
        snapshot.nodes[0].state = Some(state.clone());
        let replaced = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            replaced.selected_nodes[0].candidate,
            Some(Address::with_last_byte(8))
        );

        state.work.window_id = 8;
        state.work.window_expiry_time = 260;
        state.candidate = None;
        snapshot.block.number = 11;
        snapshot.block.timestamp = 200;
        snapshot.nodes[0].state = Some(state);
        update_slots(&slots, &schedule, &manifest, wallet, &selected, &snapshot).unwrap();
        let next_window = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(next_window.selected_nodes[0].window_id, Some(8));
        assert_eq!(next_window.selected_nodes[0].candidate, None);
        let next_window_time_left = next_window.selected_nodes[0]
            .time_left(Instant::now())
            .unwrap();
        assert!((58..=60).contains(&next_window_time_left));
    }

    #[test]
    fn nonce_ranges_are_non_overlapping_and_stop_at_u128_maximum() {
        let mut allocator = NonceAllocator::default();
        assert_eq!(allocator.reserve(4), Some((0, 4)));
        assert_eq!(allocator.reserve(4), Some((4, 4)));

        let mut final_range = NonceAllocator {
            next: Some(u128::MAX - 1),
        };
        assert_eq!(final_range.reserve(4), Some((u128::MAX - 1, 2)));
        assert_eq!(final_range.reserve(4), None);

        let slot = NodeSlot::new(1);
        let gpu_reserved = slot.reserve_nonces(crate::gpu::MAX_GPU_BATCH_SIZE).unwrap();
        let cpu_fallback = slot.reserve_nonces(super::NONCE_BATCH_SIZE).unwrap();
        assert_eq!(gpu_reserved, (0, crate::gpu::MAX_GPU_BATCH_SIZE));
        assert_eq!(
            cpu_fallback,
            (
                crate::gpu::MAX_GPU_BATCH_SIZE as u128,
                super::NONCE_BATCH_SIZE
            )
        );
    }

    #[test]
    fn gpu_candidate_is_batch_bound_and_cpu_revalidated_before_proof_queueing() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.target = U256::MAX;
        let now = Instant::now();
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
            now,
        )
        .unwrap();
        let work = slot.current_work_at(now).unwrap();
        let nonce = u128::from(u64::MAX) + 1;
        let hash = work.hasher.hash(nonce);
        let batch = GpuBatchIdentity {
            node_id: 1,
            generation: work.generation,
            window_id: state.work.window_id,
            first_nonce: nonce - 1,
            nonce_count: 3,
        };
        let telemetry = ProofPipelineTelemetry::default();
        let (proofs, receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);

        let mismatch = process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce,
                hash: B256::ZERO,
                reported_gpu_hash: Some(B256::ZERO),
                batch_identity: Some(batch),
            },
            &proofs,
            &telemetry,
        );
        assert!(matches!(
            mismatch,
            Err(super::GpuCandidateFailure::HashMismatch { .. })
        ));
        assert!(!receiver.has_pending());
        assert_eq!(telemetry.count(1, ProofMetric::GpuHashMismatch), 1);

        let outside_batch = GpuBatchIdentity {
            first_nonce: nonce + 1,
            nonce_count: 1,
            ..batch
        };
        let rejected = process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce,
                hash,
                reported_gpu_hash: Some(hash),
                batch_identity: Some(outside_batch),
            },
            &proofs,
            &telemetry,
        );
        assert!(matches!(
            rejected,
            Err(super::GpuCandidateFailure::InvalidBatchIdentity)
        ));
        assert!(!receiver.has_pending());

        process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce,
                hash,
                reported_gpu_hash: Some(hash),
                batch_identity: Some(batch),
            },
            &proofs,
            &telemetry,
        )
        .unwrap();
        let queued = receiver.take_next().unwrap();
        assert_eq!(queued.batch_identity, Some(batch));
        revalidate_queued_proof(&slot, &queued, &telemetry)
            .expect("GPU proof must pass the existing final CPU preflight");
        assert_eq!(telemetry.count(1, ProofMetric::GpuCandidatesCpuVerified), 1);
        assert_eq!(telemetry.count(1, ProofMetric::GpuBatchIdentityRejected), 1);
    }

    #[test]
    fn gpu_candidate_from_invalidated_work_generation_is_never_queued() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let state = eligible_state();
        let start = Instant::now();
        let first_block = test_block(1, 100);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &first_block,
            start,
        )
        .unwrap();
        let old_work = slot.current_work_at(start).unwrap();
        let nonce = u128::from(u64::MAX) + 5;
        let hash = old_work.hasher.hash(nonce);
        let batch = GpuBatchIdentity {
            node_id: 1,
            generation: old_work.generation,
            window_id: old_work.fingerprint.hashing_context.window_id,
            first_nonce: nonce,
            nonce_count: 1,
        };

        let mut new_state = state;
        new_state.work.seed = B256::with_last_byte(0xa7);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&new_state),
            &test_block(2, 101),
            start + Duration::from_secs(1),
        )
        .unwrap();
        assert_ne!(slot.generation(), old_work.generation);

        let telemetry = ProofPipelineTelemetry::default();
        let (proofs, receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        process_hashed_candidate(
            &slot,
            &old_work,
            HashedCandidate {
                nonce,
                hash,
                reported_gpu_hash: Some(hash),
                batch_identity: Some(batch),
            },
            &proofs,
            &telemetry,
        )
        .unwrap();
        assert!(!receiver.has_pending());
        assert_eq!(
            telemetry.count(1, ProofMetric::WorkerStaleGenerationHash),
            1
        );
    }

    #[test]
    fn automatic_backend_fallback_starts_shared_allocator_cpu_workers() {
        let stop = Arc::new(AtomicBool::new(false));
        let (proof_sender, _proof_receiver) =
            proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        let (events, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = MiningWorkerContext {
            slots: Arc::new((1..=9).map(NodeSlot::new).collect()),
            schedule: Arc::new(RwLock::new(Vec::new())),
            stop: Arc::clone(&stop),
            cursor: Arc::new(AtomicUsize::new(0)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            proofs: proof_sender,
            telemetry: Arc::new(ProofPipelineTelemetry::default()),
        };
        let controller = thread::spawn(move || {
            activate_cpu_fallback(2, context, events, "test-injected GPU failure".to_owned());
        });
        let event = receiver.blocking_recv().unwrap();
        assert!(matches!(
            event,
            super::BackendEvent::Activated(ActiveBackend::Cpu { threads: 2 })
        ));
        let fallback_notice = receiver.blocking_recv().unwrap();
        assert!(matches!(
            fallback_notice,
            super::BackendEvent::FallbackNotice(reason)
                if reason.contains("test-injected GPU failure")
        ));
        stop.store(true, Ordering::Release);
        controller.join().unwrap();
    }

    #[test]
    fn target_and_incumbent_changes_preserve_nonces_but_context_changes_reset_them() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let state = eligible_state();
        let block = test_block(1, 100);

        assert!(
            slot.set_work(&manifest, miner, contract, Some(&state), &block)
                .unwrap()
        );
        let initial_generation = slot.current_work().unwrap().generation;
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((0, super::NONCE_BATCH_SIZE))
        );
        assert!(
            !slot
                .set_work(&manifest, miner, contract, Some(&state), &block)
                .unwrap()
        );
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((2048, super::NONCE_BATCH_SIZE))
        );

        let mut changed_state = eligible_state();
        changed_state.work.target = U256::MAX - U256::from(1);
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), &block)
                .unwrap()
        );
        let target_generation = slot.current_work().unwrap().generation;
        assert!(target_generation > initial_generation);
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((4096, super::NONCE_BATCH_SIZE))
        );

        changed_state.candidate = Some(CandidateInfo {
            miner: Address::with_last_byte(7),
            nonce: 9,
            work_hash: B256::with_last_byte(3),
            submitted_at: 150,
            header: Bytes::new(),
            first_valid_solve_secs: 2,
        });
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), &block)
                .unwrap()
        );
        let incumbent_generation = slot.current_work().unwrap().generation;
        assert!(incumbent_generation > target_generation);
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((6144, super::NONCE_BATCH_SIZE))
        );

        changed_state.work.seed = B256::with_last_byte(4);
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), &block)
                .unwrap()
        );
        let context_generation = slot.current_work().unwrap().generation;
        assert!(context_generation > incumbent_generation);
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((0, super::NONCE_BATCH_SIZE))
        );

        assert!(
            slot.set_work(&manifest, miner, contract, None, &block)
                .unwrap()
        );
        assert!(!slot.is_generation_current(context_generation));
        assert!(slot.current_work().is_none());
    }

    #[test]
    fn old_worker_hash_cannot_poison_local_best_after_context_invalidation() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let initial = eligible_state();
        let block = test_block(1, 100);
        slot.set_work(&manifest, miner, contract, Some(&initial), &block)
            .unwrap();
        let old_work = slot.current_work().unwrap();
        let old_hash = old_work.hasher.hash(17);

        let mut changed = initial;
        changed.work.seed = B256::with_last_byte(4);
        slot.set_work(&manifest, miner, contract, Some(&changed), &block)
            .unwrap();
        assert_eq!(
            slot.update_local_best(old_work.generation, old_work.valid_until, old_hash),
            super::LocalBestUpdate::StaleGeneration
        );
        assert_eq!(
            *slot
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            None
        );
        assert_eq!(
            slot.update_local_best(
                slot.current_work().unwrap().generation,
                Instant::now() + Duration::from_secs(1),
                B256::with_last_byte(1),
            ),
            super::LocalBestUpdate::NewBest
        );
        assert_eq!(
            slot.update_local_best(
                slot.current_work().unwrap().generation,
                Instant::now() - Duration::from_secs(1),
                B256::with_last_byte(0),
            ),
            super::LocalBestUpdate::ExpiredDeadline
        );
    }

    #[test]
    fn scheduler_round_robins_across_only_the_active_nodes() {
        let active = [0, 8];
        let cursor = AtomicUsize::new(0);
        let mut counts = [0_usize; 9];
        for _ in 0..900 {
            counts[next_scheduled_slot(&active, &cursor).unwrap()] += 1;
        }
        assert_eq!(counts[0], 450);
        assert_eq!(counts[8], 450);
        assert!(counts[1..8].iter().all(|count| *count == 0));
        assert_eq!(next_scheduled_slot(&[], &cursor), None);
    }

    #[test]
    fn deadline_stops_work_before_the_cached_window_expires() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let mut state = eligible_state();
        state.work.window_expiry_time = 102;
        let block = test_block(1, 100);
        slot.set_work(
            &manifest,
            Address::with_last_byte(8),
            Address::with_last_byte(9),
            Some(&state),
            &block,
        )
        .unwrap();
        assert!(slot.current_work().is_none());
    }

    #[tokio::test]
    async fn eligible_slot_rearms_only_after_a_new_verified_head_and_hashes_again() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let slot = NodeSlot::new(1);
        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let selected = HashSet::from([1_u8]);
        let mut state = eligible_state();
        state.work.window_expiry_time = 110;
        state.work.target = U256::MAX;

        let start = Instant::now();
        let first_head = test_block(100, 100);
        assert!(
            slots[0]
                .set_work_at(&manifest, miner, contract, Some(&state), &first_head, start)
                .unwrap()
        );
        let initial_generation = slots[0].current_work_at(start).unwrap().generation;
        let initial_job = slots[0].current_work_at(start).unwrap();
        assert_eq!(
            slots[0].update_local_best(
                initial_generation,
                initial_job.valid_until,
                B256::with_last_byte(8),
            ),
            super::LocalBestUpdate::NewBest
        );
        let local_deadline = start + Duration::from_secs(8);
        let after_local_deadline = local_deadline + Duration::from_secs(1);
        assert!(slots[0].current_work_at(after_local_deadline).is_none());

        assert!(
            !slots[0]
                .set_work_at(
                    &manifest,
                    miner,
                    contract,
                    Some(&state),
                    &first_head,
                    after_local_deadline,
                )
                .unwrap()
        );
        assert!(slots[0].current_work_at(after_local_deadline).is_none());

        let next_head = test_block(101, 100);
        assert!(
            slots[0]
                .set_work_at(
                    &manifest,
                    miner,
                    contract,
                    Some(&state),
                    &next_head,
                    after_local_deadline,
                )
                .unwrap()
        );
        let restarted = slots[0].current_work_at(after_local_deadline).unwrap();
        assert!(restarted.generation > initial_generation);
        assert_eq!(
            *slots[0]
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            None,
            "rearmed work must allow a fresh candidate after the prior local deadline"
        );
        assert_eq!(
            restarted.fingerprint.hashing_context.window_id,
            state.work.window_id
        );

        let snapshot = ReadSnapshot {
            block: next_head,
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(state),
                error: None,
            }],
        };
        update_slots(&slots, &schedule, &manifest, miner, &selected, &snapshot).unwrap();
        assert_eq!(
            *schedule
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [0]
        );

        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, mut receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });
        let proof = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("worker should resume hashing on a new eligible head")
            .expect("worker should find a proof under the maximum target");
        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
        assert_eq!(proof.node_id, 1);
        assert!(hashes.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn verified_chain_time_can_shorten_but_never_extend_a_work_deadline() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let mut state = eligible_state();
        state.work.window_expiry_time = 110;
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let start = Instant::now();
        let first_head = test_block(1, 100);
        slot.set_work_at(&manifest, miner, contract, Some(&state), &first_head, start)
            .unwrap();
        let original_deadline = slot.current_work_at(start).unwrap().valid_until;

        let advanced_head = test_block(2, 106);
        let observed_at = start + Duration::from_secs(1);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &advanced_head,
            observed_at,
        )
        .unwrap();
        let shortened_deadline = slot.current_work_at(observed_at).unwrap().valid_until;
        assert!(shortened_deadline < original_deadline);
        assert_eq!(shortened_deadline, start + Duration::from_secs(3));

        let repeated_observation = observed_at + Duration::from_secs(1);
        assert!(
            !slot
                .set_work_at(
                    &manifest,
                    miner,
                    contract,
                    Some(&state),
                    &advanced_head,
                    repeated_observation,
                )
                .unwrap()
        );
        assert!(slot.current_work_at(shortened_deadline).is_none());

        let next_head = test_block(3, 107);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &next_head,
            shortened_deadline + Duration::from_secs(1),
        )
        .unwrap();
        assert!(
            slot.current_work_at(shortened_deadline + Duration::from_secs(1))
                .is_some()
        );
    }

    #[test]
    fn deadline_only_generation_change_revalidates_a_valid_queued_proof() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.window_expiry_time = 110;
        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        let proof_hash = WorkHasher::new(&context).unwrap().hash(0);
        let target = U256::from_be_bytes(proof_hash.0);
        state.work.target = target;
        assert!(meets_target(proof_hash, target));

        let start = Instant::now();
        let first_head = test_block(100, 100);
        slot.set_work_at(&manifest, miner, contract, Some(&state), &first_head, start)
            .unwrap();
        let original = slot.current_work_at(start).unwrap();
        let queued_proof = ProofFound {
            node_id: 1,
            generation: original.generation,
            context: original.fingerprint.hashing_context.clone(),
            nonce: 0,
            hash: proof_hash,
            target: state.work.target,
            incumbent: None,
            batch_identity: None,
            queued_at: start,
        };

        let updated_at = start + Duration::from_secs(1);
        let deadline_shortening_head = test_block(101, 103);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &deadline_shortening_head,
            updated_at,
        )
        .unwrap();
        let current = slot.current_work_at(updated_at).unwrap();

        assert_eq!(current.fingerprint, original.fingerprint);
        assert!(current.valid_until < original.valid_until);
        assert!(meets_target(queued_proof.hash, current.target));
        assert_eq!(current.incumbent, queued_proof.incumbent);
        assert_ne!(queued_proof.generation, current.generation);
        let telemetry = ProofPipelineTelemetry::default();
        let revalidated = revalidate_queued_proof(&slot, &queued_proof, &telemetry)
            .expect("same-window proof remains valid after deadline-only generation change");
        assert_eq!(revalidated.generation, current.generation);
        assert_eq!(
            telemetry.count(1, ProofMetric::GenerationMismatchRevalidated),
            1
        );
    }

    #[test]
    fn queued_proof_revalidation_rejects_expiry_window_seed_target_and_incumbent_changes() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let start = Instant::now();
        let initial_block = test_block(1, 100);
        let mut state = eligible_state();
        state.work.window_expiry_time = 200;
        let hashing_context = HashingContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        let work_hash = WorkHasher::new(&hashing_context.work_context())
            .unwrap()
            .hash(0);
        let target = U256::from_be_bytes(work_hash.0);
        state.work.target = target;
        assert!(meets_target(work_hash, target));

        let create_slot = |node_state: &NodeState, block: &BlockSnapshot| {
            let slot = NodeSlot::new(1);
            slot.set_work_at(&manifest, miner, contract, Some(node_state), block, start)
                .unwrap();
            slot
        };
        let make_proof = |slot: &NodeSlot| ProofFound {
            node_id: 1,
            generation: slot.current_work_at(start).unwrap().generation,
            context: hashing_context.clone(),
            nonce: 0,
            hash: work_hash,
            target,
            incumbent: None,
            batch_identity: None,
            queued_at: start,
        };
        let telemetry = ProofPipelineTelemetry::default();

        let expired_slot = create_slot(&state, &initial_block);
        let expired_proof = make_proof(&expired_slot);
        let expiry = expired_slot.current_work_at(start).unwrap().valid_until;
        assert_eq!(
            revalidate_queued_proof_at(&expired_slot, &expired_proof, &telemetry, expiry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::ExpiredDeadline
        );

        let changed_window_slot = create_slot(&state, &initial_block);
        let changed_window_proof = make_proof(&changed_window_slot);
        let mut changed_window = state.clone();
        changed_window.work.window_id += 1;
        changed_window.work.window_expiry_time += 100;
        let next_block = test_block(2, 101);
        changed_window_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_window),
                &next_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(&changed_window_slot, &changed_window_proof, &telemetry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::WindowMismatch
        );

        let changed_seed_slot = create_slot(&state, &initial_block);
        let changed_seed_proof = make_proof(&changed_seed_slot);
        let mut changed_seed = state.clone();
        changed_seed.work.seed = B256::with_last_byte(0x77);
        let seed_block = test_block(2, 101);
        changed_seed_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_seed),
                &seed_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(&changed_seed_slot, &changed_seed_proof, &telemetry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::WorkContextMismatch
        );

        let changed_target_slot = create_slot(&state, &initial_block);
        let changed_target_proof = make_proof(&changed_target_slot);
        let mut changed_target = state.clone();
        changed_target.work.target = target.saturating_sub(U256::from(1));
        let target_block = test_block(2, 101);
        changed_target_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_target),
                &target_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(&changed_target_slot, &changed_target_proof, &telemetry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::CurrentTarget
        );

        let changed_incumbent_slot = create_slot(&state, &initial_block);
        let changed_incumbent_proof = make_proof(&changed_incumbent_slot);
        let mut changed_incumbent = state;
        changed_incumbent.candidate = Some(CandidateInfo {
            miner: Address::with_last_byte(7),
            nonce: 0,
            work_hash,
            submitted_at: 100,
            header: Bytes::new(),
            first_valid_solve_secs: 1,
        });
        let incumbent_block = test_block(2, 101);
        changed_incumbent_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_incumbent),
                &incumbent_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(
                &changed_incumbent_slot,
                &changed_incumbent_proof,
                &telemetry,
            )
            .err()
            .unwrap(),
            super::ProofRevalidationFailure::CurrentIncumbent
        );
    }

    #[test]
    fn proof_inbox_saturation_preserves_the_best_undelivered_candidate() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        state.work.target = U256::MAX / U256::from(1_000_u64);

        let slot = NodeSlot::new(1);
        slot.set_work(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
        )
        .unwrap();
        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        let work = slots[0].current_work().unwrap();
        for node_id in 1..=PENDING_PROOF_CANDIDATE_CAPACITY as u8 {
            let queued_context = if node_id == 1 {
                work.fingerprint.hashing_context.clone()
            } else {
                HashingContext {
                    chain_id: manifest.chain_id,
                    contract: Address::with_last_byte(node_id),
                    window_id: state.work.window_id,
                    seed: state.work.seed,
                    miner,
                    header: Vec::new(),
                }
            };
            let queued_hash = if node_id == 1 {
                B256::from(U256::MAX.to_be_bytes::<32>())
            } else {
                B256::with_last_byte(2)
            };
            assert!(sender.deliver(
                ProofFound {
                    node_id,
                    generation: work.generation,
                    context: queued_context,
                    nonce: u128::from(node_id),
                    hash: queued_hash,
                    target: state.work.target,
                    incumbent: None,
                    batch_identity: None,
                    queued_at: Instant::now(),
                },
                &telemetry,
            ));
        }

        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while telemetry.count(1, ProofMetric::QueueFullCoalesced) == 0 && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert!(telemetry.count(1, ProofMetric::QueueFullCoalesced) > 0);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();

        let mut node_one_candidate = None;
        for _ in 0..PENDING_PROOF_CANDIDATE_CAPACITY {
            let delivered = receiver
                .take_next()
                .expect("every bounded inbox slot is populated");
            if delivered.node_id == 1 {
                node_one_candidate = Some(delivered);
            }
        }
        let delivered = node_one_candidate.expect("saturated inbox retains node 1");
        let local_best = *slots[0]
            .local_best
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .unwrap();
        assert_eq!(delivered.hash, local_best);
        assert_eq!(
            WorkHasher::new(&context).unwrap().hash(delivered.nonce),
            delivered.hash
        );
        assert!(meets_target(delivered.hash, delivered.target));
        assert!(telemetry.count(1, ProofMetric::QueuedCandidates) >= 2);
        assert!(
            telemetry.count(1, ProofMetric::QueueWakeCoalesced) > 0,
            "saturation coalesces bounded wakeups without losing inbox candidates"
        );
        assert!(hashes.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn proof_inbox_reports_receiver_closure_without_claiming_delivery() {
        let telemetry = ProofPipelineTelemetry::default();
        let (sender, receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        drop(receiver);
        let proof = ProofFound {
            node_id: 1,
            generation: 1,
            context: HashingContext {
                chain_id: 1439,
                contract: Address::with_last_byte(9),
                window_id: 3,
                seed: B256::with_last_byte(1),
                miner: Address::with_last_byte(8),
                header: Vec::new(),
            },
            nonce: 7,
            hash: B256::with_last_byte(1),
            target: U256::MAX,
            incumbent: None,
            batch_identity: None,
            queued_at: Instant::now(),
        };

        assert!(!sender.deliver(proof, &telemetry));
        assert_eq!(telemetry.count(1, ProofMetric::QueueReceiverClosed), 1);
        assert_eq!(telemetry.count(1, ProofMetric::QueuedCandidates), 0);
    }

    #[tokio::test]
    async fn proof_inbox_defers_and_releases_best_candidate_across_unresolved_transaction() {
        let telemetry = ProofPipelineTelemetry::default();
        let (sender, mut receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), true);
        let proof = ProofFound {
            node_id: 1,
            generation: 1,
            context: HashingContext {
                chain_id: 1439,
                contract: Address::with_last_byte(9),
                window_id: 3,
                seed: B256::with_last_byte(1),
                miner: Address::with_last_byte(8),
                header: Vec::new(),
            },
            nonce: 7,
            hash: B256::with_last_byte(1),
            target: U256::MAX,
            incumbent: None,
            batch_identity: None,
            queued_at: Instant::now(),
        };
        assert!(sender.deliver(proof.clone(), &telemetry));
        assert!(
            timeout(Duration::from_millis(25), receiver.recv())
                .await
                .is_err()
        );

        receiver.set_paused(false);
        let first_delivery = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_delivery.nonce, proof.nonce);
        receiver.set_paused(true);
        assert!(receiver.requeue(first_delivery, &telemetry));
        assert!(
            timeout(Duration::from_millis(25), receiver.recv())
                .await
                .is_err()
        );

        receiver.set_paused(false);
        let deferred = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deferred.hash, proof.hash);
        assert_eq!(telemetry.count(1, ProofMetric::QueuedCandidates), 2);
    }

    #[test]
    fn rpc_retry_backoff_is_exponential_and_bounded() {
        assert_eq!(
            super::GENESIS_POLL_INTERVAL,
            Duration::from_secs(1),
            "healthy inactive-genesis polling starts at one second"
        );
        assert_eq!(
            next_poll_delay(super::GENESIS_POLL_INTERVAL),
            Duration::from_secs(2),
            "a failed genesis poll applies the same bounded exponential backoff"
        );
        assert_eq!(
            next_poll_delay(super::POLL_INTERVAL),
            Duration::from_secs(10)
        );
        assert_eq!(
            next_poll_delay(Duration::from_secs(10)),
            Duration::from_secs(20)
        );
        assert_eq!(
            next_poll_delay(Duration::from_secs(20)),
            super::MAX_POLL_INTERVAL
        );
        assert_eq!(
            next_poll_delay(super::MAX_POLL_INTERVAL),
            super::MAX_POLL_INTERVAL
        );
        assert_eq!(finalization_retry_delay(1), Duration::from_secs(1));
        assert_eq!(finalization_retry_delay(2), Duration::from_secs(2));
        assert_eq!(finalization_retry_delay(3), Duration::from_secs(4));
        assert_eq!(finalization_retry_delay(7), super::MAX_POLL_INTERVAL);
        assert_eq!(finalization_retry_delay(u8::MAX), super::MAX_POLL_INTERVAL);
    }

    #[test]
    fn recovered_transaction_enables_autonomous_unlock_only_after_settlement() {
        let positive_limit = U256::from(1);
        assert!(!should_unlock_recovered_wallet(
            true,
            positive_limit,
            false,
            true
        ));
        assert!(should_unlock_recovered_wallet(
            true,
            positive_limit,
            false,
            false
        ));
        assert!(!should_unlock_recovered_wallet(
            true,
            U256::ZERO,
            false,
            false
        ));
        assert!(!should_unlock_recovered_wallet(
            false,
            positive_limit,
            false,
            false
        ));
        assert!(!should_unlock_recovered_wallet(
            true,
            positive_limit,
            true,
            false
        ));
    }

    #[tokio::test]
    async fn autonomous_mining_requires_a_selected_wallet_before_connecting() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let error = super::run(
            &store,
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: false,
                threads: None,
                nodes: Vec::new(),
                send_rewards_to: None,
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no wallet is selected"));
    }

    #[tokio::test]
    async fn autonomous_signing_is_refused_on_mainnet_before_wallet_or_rpc_access() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let config = crate::config::AppConfig {
            network: Network::Mainnet,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();
        let error = super::run(
            &store,
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: false,
                threads: None,
                nodes: Vec::new(),
                send_rewards_to: None,
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("disabled outside Injective Testnet")
        );
    }

    #[tokio::test]
    async fn reward_forwarding_flag_is_rejected_before_wallet_or_chain_access() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let destination = Address::with_last_byte(0x42);
        let network = NetworkClient::local_test_client(
            "http://127.0.0.1:1",
            Address::with_last_byte(0x51),
            B256::with_last_byte(0x11),
            Address::with_last_byte(0x61),
            B256::with_last_byte(0x22),
            9,
        )
        .unwrap();
        for compute_only in [false, true] {
            let error = super::run_with_client(
                &store,
                crate::config::AppConfig::default(),
                MineArgs {
                    device: DeviceChoice::Cpu,
                    compute_only,
                    new_session: false,
                    threads: None,
                    nodes: vec![1],
                    send_rewards_to: Some(destination),
                },
                network.clone(),
                None,
                None,
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(AUTOMATIC_REWARD_FORWARDING_DISABLED)
            );
        }
        let cli_error = super::run(
            &store,
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: false,
                threads: None,
                nodes: vec![1],
                send_rewards_to: Some(destination),
            },
        )
        .await
        .unwrap_err();
        assert!(
            cli_error
                .to_string()
                .contains(AUTOMATIC_REWARD_FORWARDING_DISABLED)
        );
        assert!(store.read_transaction_journal().unwrap().is_none());
    }

    #[test]
    fn node_selection_defaults_to_all_and_rejects_duplicates() {
        assert_eq!(
            selected_nodes(&[]).unwrap(),
            (1..=9).collect::<HashSet<_>>()
        );
        assert!(selected_nodes(&[2, 2]).is_err());
    }

    #[tokio::test]
    async fn worker_emits_a_locally_verified_proof_without_submitting_it() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.target = U256::MAX;
        slot.set_work(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
        )
        .unwrap();

        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let total_hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, mut receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&total_hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });

        let proof_result = timeout(Duration::from_secs(2), receiver.recv()).await;
        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
        let proof = proof_result
            .expect("worker should find a proof under the maximum target")
            .expect("worker should report its proof");

        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        assert_eq!(proof.node_id, 1);
        assert!(slots[0].is_generation_current(proof.generation));
        assert_eq!(
            WorkHasher::new(&context).unwrap().hash(proof.nonce),
            proof.hash
        );
        assert!(meets_target(proof.hash, U256::MAX));
        assert!(total_hashes.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn hashrate_returns_to_zero_after_all_scheduled_work_is_invalidated() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let slot = NodeSlot::new(1);
        let mut state = eligible_state();
        state.work.target = U256::ZERO;
        let block = test_block(1, 100);
        slot.set_work(&manifest, miner, contract, Some(&state), &block)
            .unwrap();

        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, _receiver) = proof_inbox(Arc::new(ProofAttemptGuard::default()), false);
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });
        timeout(Duration::from_secs(2), async {
            while hashes.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("active work must produce completed hashes");

        slots[0]
            .set_work(&manifest, miner, contract, None, &block)
            .unwrap();
        *schedule
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
        let stable_hash_count = tokio::time::timeout(Duration::from_secs(2), async {
            let mut previous = hashes.load(Ordering::Relaxed);
            let mut unchanged_samples = 0_u8;
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let current = hashes.load(Ordering::Relaxed);
                if current == previous {
                    unchanged_samples = unchanged_samples.saturating_add(1);
                    if unchanged_samples == 3 {
                        return current;
                    }
                } else {
                    previous = current;
                    unchanged_samples = 0;
                }
            }
        })
        .await
        .expect("hash counter should settle after work invalidation");
        assert!(stable_hash_count > 0);
        assert!(slots[0].current_work().is_none());
        assert_eq!(
            hashes_per_second(stable_hash_count, stable_hash_count, 1.0),
            0.0
        );

        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
    }
}
