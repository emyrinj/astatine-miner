use crate::{
    config::validate_rpc_url,
    contracts::{AstatineMinerRead, IERC20Read},
    deployment::{DeploymentManifest, NodePin, parse_address, parse_hash},
    diagnostics::DiagnosticBuffer,
    history_telemetry::{HistoryCounter, HistoryDuration, HistoryTelemetry},
    protocol::{WorkContext, WorkHasher, meets_target, work_domain_v2},
    startup::StartupProgress,
};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use alloy_sol_types::{SolCall, SolError, SolEvent, SolType, SolValue};
use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(test)]
type TestProofNonceStarts = std::sync::Arc<Mutex<HashMap<(u8, u64, B256), u128>>>;

#[cfg(test)]
use crate::deployment::TokenPin;

const RPC_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RPC_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOG_QUERY_RANGE: u64 = 10_000;
const SUBMISSION_FEE_WEI: u128 = 10_000_000_000_000_000;
const ABI_PROBE_NONCE: u128 = u128::MAX - 7;
const GENESIS_PROBE_CONCURRENCY: usize = 3;

fn rpc_network_label(network: crate::cli::Network) -> &'static str {
    match network {
        crate::cli::Network::Testnet => "Testnet",
        crate::cli::Network::Mainnet => "Mainnet",
    }
}

fn report_archival_unavailable(progress: Option<&StartupProgress>, message: String) {
    if let Some(progress) = progress {
        progress.note(message);
    } else {
        eprintln!("{message}");
    }
}

#[cfg(test)]
fn consume_counter(counter: &AtomicUsize) -> bool {
    let mut remaining = counter.load(Ordering::Acquire);
    loop {
        if remaining == 0 {
            return false;
        }
        match counter.compare_exchange_weak(
            remaining,
            remaining - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => remaining = observed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkInfo {
    pub started: bool,
    pub ended: bool,
    pub window_id: u64,
    pub window_start_time: u64,
    pub window_expiry_time: u64,
    pub seed: B256,
    pub prev_hash: B256,
    pub target: U256,
    pub reward_per_window: U256,
    pub remaining_allocation: U256,
    pub max_header_length: u32,
    pub submission_fee: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateInfo {
    pub miner: Address,
    pub nonce: u128,
    pub work_hash: B256,
    pub submitted_at: u64,
    pub header: Bytes,
    pub first_valid_solve_secs: u64,
}

#[derive(Clone, Debug)]
pub struct MiningInfo {
    pub started: bool,
    pub ended: bool,
    pub window_id: u64,
    pub reward_per_window: U256,
    pub target: U256,
    pub seed: B256,
    pub prev_hash: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeState {
    pub work: WorkInfo,
    pub candidate: Option<CandidateInfo>,
    pub mining_paused: bool,
    pub eligible: bool,
    pub finalizable: bool,
    pub eligibility_reason: &'static str,
}

#[derive(Clone, Debug)]
pub struct FeeQuote {
    pub gas_limit: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: Option<u64>,
    pub block_hash: Option<B256>,
    pub transaction_hash: Option<B256>,
    pub transaction_index: Option<u64>,
    pub log_index: Option<u64>,
    pub removed: bool,
    pub virtual_log: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub status: bool,
    pub gas_used: U256,
    pub cumulative_gas_used: U256,
    pub effective_gas_price: Option<U256>,
    pub transaction_type: Option<u64>,
    pub block_number: u64,
    pub block_hash: B256,
    pub logs: Vec<RpcLog>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionDetails {
    pub hash: B256,
    pub chain_id: Option<u64>,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub input: Bytes,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub transaction_type: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptJson {
    transaction_hash: String,
    transaction_index: String,
    from: String,
    to: Option<String>,
    status: String,
    gas_used: String,
    cumulative_gas_used: String,
    effective_gas_price: Option<String>,
    #[serde(default, rename = "type")]
    transaction_type: Option<String>,
    block_number: String,
    block_hash: String,
    logs: Vec<ReceiptLogJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptLogJson {
    address: String,
    topics: Vec<String>,
    data: String,
    block_number: Option<String>,
    block_hash: Option<String>,
    transaction_hash: Option<String>,
    transaction_index: Option<String>,
    log_index: Option<String>,
    #[serde(default)]
    removed: bool,
    #[serde(default, rename = "virtual")]
    virtual_log: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionJson {
    hash: String,
    chain_id: Option<String>,
    from: String,
    to: Option<String>,
    nonce: String,
    value: String,
    gas: String,
    #[serde(alias = "data")]
    input: String,
    gas_price: Option<String>,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
    #[serde(default, rename = "type")]
    transaction_type: Option<String>,
}

impl TryFrom<ReceiptJson> for TransactionReceipt {
    type Error = anyhow::Error;

    fn try_from(receipt: ReceiptJson) -> Result<Self> {
        let logs = receipt
            .logs
            .into_iter()
            .map(parse_rpc_log)
            .collect::<Result<Vec<_>>>()?;
        let status = parse_hex_quantity(&receipt.status)?;
        if status > 1 {
            bail!("transaction receipt status must be 0 or 1");
        }
        Ok(Self {
            transaction_hash: parse_hash(&receipt.transaction_hash)?,
            transaction_index: parse_hex_quantity(&receipt.transaction_index)?,
            from: parse_address(&receipt.from)?,
            to: receipt.to.as_deref().map(parse_address).transpose()?,
            status: status == 1,
            gas_used: parse_hex_u256(&receipt.gas_used)?,
            cumulative_gas_used: parse_hex_u256(&receipt.cumulative_gas_used)?,
            effective_gas_price: receipt
                .effective_gas_price
                .as_deref()
                .map(parse_hex_u256)
                .transpose()?,
            transaction_type: receipt
                .transaction_type
                .as_deref()
                .map(parse_hex_quantity)
                .transpose()?,
            block_number: parse_hex_quantity(&receipt.block_number)?,
            block_hash: parse_hash(&receipt.block_hash)?,
            logs,
        })
    }
}

impl TryFrom<TransactionJson> for TransactionDetails {
    type Error = anyhow::Error;

    fn try_from(transaction: TransactionJson) -> Result<Self> {
        let input = transaction
            .input
            .strip_prefix("0x")
            .context("transaction input has no 0x prefix")?;
        Ok(Self {
            hash: parse_hash(&transaction.hash)?,
            chain_id: transaction
                .chain_id
                .as_deref()
                .map(parse_hex_quantity)
                .transpose()?,
            from: parse_address(&transaction.from)?,
            to: transaction.to.as_deref().map(parse_address).transpose()?,
            nonce: parse_hex_quantity(&transaction.nonce)?,
            value: parse_hex_u256(&transaction.value)?,
            gas_limit: parse_hex_quantity(&transaction.gas)?,
            input: Bytes::from(hex::decode(input).context("decode transaction input")?),
            gas_price: transaction
                .gas_price
                .as_deref()
                .map(parse_hex_u256)
                .transpose()?,
            max_fee_per_gas: transaction
                .max_fee_per_gas
                .as_deref()
                .map(parse_hex_u256)
                .transpose()?,
            max_priority_fee_per_gas: transaction
                .max_priority_fee_per_gas
                .as_deref()
                .map(parse_hex_u256)
                .transpose()?,
            transaction_type: transaction
                .transaction_type
                .as_deref()
                .map(parse_hex_quantity)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NodeView {
    pub id: u8,
    pub address: Address,
    pub pin: ContractPinStatus,
    pub state: Option<NodeState>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BlockSnapshot {
    pub number: u64,
    pub timestamp: u64,
    pub hash: B256,
}

#[derive(Clone, Debug)]
pub struct ReadSnapshot {
    pub block: BlockSnapshot,
    pub native_balance: Option<U256>,
    pub native_balance_error: Option<String>,
    pub ast_balance: Option<U256>,
    pub ast_balance_error: Option<String>,
    pub nodes: Vec<NodeView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractPinStatus {
    pub runtime_verified: bool,
    pub abi_verified: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
struct RpcEndpoint {
    name: String,
    url: Url,
    client: reqwest::Client,
}

#[derive(Clone, Debug)]
pub struct DeploymentVerification {
    pub token_verified: bool,
    pub reference_snapshot_verified: bool,
    pub nodes: HashMap<u8, ContractPinStatus>,
}

#[derive(Clone, Debug)]
pub struct NetworkClient {
    pub manifest: DeploymentManifest,
    endpoints: Vec<RpcEndpoint>,
    archival_endpoint: Option<RpcEndpoint>,
    custom_primary: bool,
    pub verification: DeploymentVerification,
    /// Nodes whose started work has passed the activation-time runtime/ABI/PoW check.
    /// Entries are cleared when genesis is absent or a canonical reorg is observed.
    activation_work: Arc<Mutex<HashSet<u8>>>,
    diagnostics: Option<DiagnosticBuffer>,
    history_telemetry: Arc<HistoryTelemetry>,
    #[cfg(test)]
    fail_next_finalization_fee_quote: std::sync::Arc<AtomicUsize>,
    #[cfg(test)]
    fail_next_proof_fee_quote: std::sync::Arc<AtomicUsize>,
    #[cfg(test)]
    delay_next_proof_fee_quote_ms: std::sync::Arc<AtomicU64>,
    #[cfg(test)]
    delay_next_finalization_fee_quote_ms: std::sync::Arc<AtomicU64>,
    #[cfg(test)]
    fee_quote_delays_started: std::sync::Arc<AtomicU64>,
    #[cfg(test)]
    proof_nonce_starts: TestProofNonceStarts,
    #[cfg(test)]
    genesis_poll_observations: Arc<Mutex<Vec<GenesisPollObservation>>>,
    #[cfg(test)]
    genesis_poll_inflight: Arc<AtomicUsize>,
    #[cfg(test)]
    genesis_poll_max_inflight: Arc<AtomicUsize>,
    #[cfg(test)]
    genesis_poll_active_calls: Arc<AtomicUsize>,
    #[cfg(test)]
    genesis_poll_delay_ms: Arc<AtomicU64>,
    #[cfg(test)]
    fail_next_genesis_polls: Arc<AtomicUsize>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct GenesisPollObservation {
    pub(crate) started_at: Instant,
    pub(crate) completed_at: Instant,
    pub(crate) node_ids: Vec<u8>,
    pub(crate) max_concurrent_node_reads: usize,
    pub(crate) succeeded: bool,
}

#[cfg(test)]
struct GenesisProbeConcurrencyGuard {
    inflight: Arc<AtomicUsize>,
}

#[cfg(test)]
struct GenesisPollCallGuard(Arc<AtomicUsize>);

#[cfg(test)]
impl GenesisPollCallGuard {
    fn enter(active_calls: Arc<AtomicUsize>) -> Self {
        active_calls.fetch_add(1, Ordering::AcqRel);
        Self(active_calls)
    }
}

#[cfg(test)]
impl Drop for GenesisPollCallGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
impl GenesisProbeConcurrencyGuard {
    fn enter(inflight: Arc<AtomicUsize>, maximum: &AtomicUsize) -> Self {
        let current = inflight.fetch_add(1, Ordering::AcqRel) + 1;
        maximum.fetch_max(current, Ordering::AcqRel);
        Self { inflight }
    }
}

#[cfg(test)]
impl Drop for GenesisProbeConcurrencyGuard {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl NetworkClient {
    pub async fn connect_with_rpc(
        network: crate::cli::Network,
        rpc_override: Option<&str>,
    ) -> Result<Self> {
        Self::connect_with_progress(network, rpc_override, None).await
    }

    pub(crate) async fn connect_with_progress(
        network: crate::cli::Network,
        rpc_override: Option<&str>,
        progress: Option<&StartupProgress>,
    ) -> Result<Self> {
        let manifest = match DeploymentManifest::load(network) {
            Ok(manifest) => manifest,
            Err(error) => {
                if let Some(progress) = progress {
                    progress.fail(format!("Deployment configuration failed: {error:#}"));
                }
                return Err(error);
            }
        };
        let custom_primary = rpc_override.is_some();
        let primary_url = rpc_override.unwrap_or(&manifest.primary_rpc);
        validate_rpc_url(primary_url).context("selected RPC URL is invalid")?;
        if let Some(progress) = progress {
            progress.update("Connecting to selected RPC · validating Chain ID");
        }
        let primary = connect_endpoint("primary", primary_url)
            .await
            .context("connect to the selected RPC endpoint")?;
        let chain_id = rpc_request::<String>(&primary, "eth_chainId", serde_json::json!([]))
            .await
            .and_then(|chain| parse_hex_quantity(&chain))
            .context("read chain ID from the selected RPC endpoint")?;
        if chain_id != manifest.chain_id {
            bail!(
                "selected RPC reports chain ID {chain_id}; expected {} for {}",
                manifest.chain_id,
                rpc_network_label(network)
            );
        }

        let mut archival_endpoint = None;
        if !custom_primary && let Some(archival_url) = manifest.archival_rpc.as_deref() {
            match connect_endpoint("archival", archival_url).await {
                Ok(endpoint) => {
                    let archival_chain =
                        rpc_request::<String>(&endpoint, "eth_chainId", serde_json::json!([]))
                            .await
                            .and_then(|chain| parse_hex_quantity(&chain));
                    match archival_chain {
                        Ok(chain) if chain == manifest.chain_id => {
                            archival_endpoint = Some(endpoint);
                        }
                        Ok(chain) => report_archival_unavailable(
                            progress,
                            format!(
                                "bundled archival RPC reports chain ID {chain}; expected {}",
                                manifest.chain_id
                            ),
                        ),
                        Err(error) => report_archival_unavailable(
                            progress,
                            format!("bundled archival RPC is unavailable: {error:#}"),
                        ),
                    }
                }
                Err(error) => report_archival_unavailable(
                    progress,
                    format!("bundled archival RPC is unavailable: {error:#}"),
                ),
            }
        }
        if let Some(progress) = progress {
            progress.complete(format!("Selected RPC verified · Chain ID {chain_id}"));
            if custom_primary && manifest.archival_rpc.is_some() {
                progress.note("Bundled archival endpoint is not used as a custom-RPC fallback.");
            }
        }

        let mut client = Self {
            manifest,
            endpoints: vec![primary],
            archival_endpoint,
            custom_primary,
            activation_work: Arc::new(Mutex::new(HashSet::new())),
            diagnostics: None,
            history_telemetry: Arc::new(HistoryTelemetry::default()),
            #[cfg(test)]
            fail_next_finalization_fee_quote: std::sync::Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            fail_next_proof_fee_quote: std::sync::Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            delay_next_proof_fee_quote_ms: std::sync::Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            delay_next_finalization_fee_quote_ms: std::sync::Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            fee_quote_delays_started: std::sync::Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            proof_nonce_starts: std::sync::Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            genesis_poll_observations: Arc::new(Mutex::new(Vec::new())),
            #[cfg(test)]
            genesis_poll_inflight: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            genesis_poll_max_inflight: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            genesis_poll_active_calls: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            genesis_poll_delay_ms: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            fail_next_genesis_polls: Arc::new(AtomicUsize::new(0)),
            verification: DeploymentVerification {
                token_verified: false,
                reference_snapshot_verified: false,
                nodes: HashMap::new(),
            },
        };
        client.verify_deployment(progress).await?;
        Ok(client)
    }

    pub async fn validate_rpc_endpoint(network: crate::cli::Network, url: &str) -> Result<()> {
        let manifest = DeploymentManifest::load(network)?;
        validate_rpc_url(url).context("custom RPC URL is invalid")?;
        let endpoint = connect_endpoint("validation", url).await?;
        let chain_id = rpc_request::<String>(&endpoint, "eth_chainId", serde_json::json!([]))
            .await
            .and_then(|chain| parse_hex_quantity(&chain))
            .context("custom RPC did not return a valid chain ID")?;
        if chain_id != manifest.chain_id {
            bail!(
                "custom RPC reports chain ID {chain_id}; expected {} for {}",
                manifest.chain_id,
                rpc_network_label(network)
            );
        }
        Ok(())
    }

    pub fn set_diagnostics(&mut self, diagnostics: DiagnosticBuffer) {
        self.diagnostics = Some(diagnostics);
    }

    pub(crate) fn history_telemetry(&self) -> Arc<HistoryTelemetry> {
        Arc::clone(&self.history_telemetry)
    }

    fn report_diagnostic(&self, message: impl Into<String>) {
        let message = message.into();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.push(message);
        } else {
            eprintln!("{message}");
        }
    }

    pub fn has_mining_deployment(&self) -> bool {
        self.manifest.mining_enabled && self.manifest.nodes.len() == 9
    }

    pub fn can_broadcast(&self) -> bool {
        self.manifest.network == crate::cli::Network::Testnet
            && self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.name == "primary")
    }

    pub async fn verify_node_runtime_at(&self, node_id: u8, block: u64) -> Result<Address> {
        let pin = self
            .manifest
            .nodes
            .iter()
            .find(|pin| pin.id == node_id)
            .with_context(|| format!("node {node_id} is absent from the verified manifest"))?;
        let endpoints = self.trusted_rpc_endpoints()?;
        let address = parse_address(&pin.address)?;
        let expected_hash = parse_hash(&pin.runtime_code_hash)?;
        for endpoint in &endpoints {
            let code = get_code(endpoint, address, block)
                .await
                .with_context(|| format!("read node {node_id} code from {}", endpoint.name))?;
            if code.is_empty() || keccak256(code) != expected_hash {
                bail!(
                    "node {node_id} runtime code from {} no longer matches the approved pin",
                    endpoint.name
                );
            }
        }
        let status = self
            .verification
            .nodes
            .get(&node_id)
            .context("node ABI verification is missing")?;
        if !status.runtime_verified || !status.abi_verified {
            bail!("node {node_id} runtime or ABI verification is not trusted");
        }
        Ok(address)
    }

    pub async fn verify_ast_token_runtime_at(&self, block: u64) -> Result<Address> {
        let pin = self
            .manifest
            .ast_token
            .as_ref()
            .context("AST token is absent from the verified manifest")?;
        let address = parse_address(&pin.address)?;
        let expected_hash = parse_hash(&pin.runtime_code_hash)?;
        let endpoints = self.trusted_rpc_endpoints()?;
        for endpoint in &endpoints {
            let code = get_code(endpoint, address, block)
                .await
                .with_context(|| format!("read AST token code from {}", endpoint.name))?;
            if code.is_empty() || keccak256(code) != expected_hash {
                bail!(
                    "AST token runtime code from {} no longer matches the approved pin",
                    endpoint.name
                );
            }
        }
        if !self.verification.token_verified {
            bail!("AST token runtime or decimals are not verified");
        }
        Ok(address)
    }

    pub async fn verify_broadcast_snapshot(&self, snapshot: &BlockSnapshot) -> Result<()> {
        let endpoints = self.trusted_rpc_endpoints()?;
        for endpoint in &endpoints {
            let (latest_number, _) = endpoint_block(endpoint)
                .await
                .with_context(|| format!("read latest financial head from {}", endpoint.name))?;
            if latest_number < snapshot.number {
                bail!(
                    "RPC {} is behind the verified work snapshot ({} < {})",
                    endpoint.name,
                    latest_number,
                    snapshot.number
                );
            }
            let financial_block = block_at(endpoint, snapshot.number)
                .await
                .with_context(|| format!("read snapshot block from {}", endpoint.name))?;
            if financial_block.hash != snapshot.hash {
                bail!(
                    "RPC {} disagrees with the verified work snapshot; refusing to broadcast",
                    endpoint.name
                );
            }
        }
        Ok(())
    }

    pub async fn pending_balance(&self, address: Address) -> Result<U256> {
        let endpoints = self.trusted_rpc_endpoints()?;
        let mut balances = Vec::with_capacity(endpoints.len());
        for endpoint in &endpoints {
            let result = rpc_request::<String>(
                endpoint,
                "eth_getBalance",
                serde_json::json!([format!("{address:#x}"), "pending"]),
            )
            .await
            .with_context(|| format!("read pending balance from {}", endpoint.name))?;
            balances.push(parse_hex_u256(&result)?);
        }
        let balance = *balances
            .first()
            .context("pending balance endpoint is unavailable")?;
        if balances.iter().any(|other| *other != balance) {
            bail!("selected RPC returned inconsistent pending INJ balance data");
        }
        Ok(balance)
    }

    pub async fn pending_nonce(&self, address: Address) -> Result<u64> {
        self.history_telemetry.add(HistoryCounter::NonceRequests, 1);
        let endpoints = self.trusted_rpc_endpoints()?;
        let mut nonces = Vec::with_capacity(endpoints.len());
        for endpoint in &endpoints {
            let endpoint_started = Instant::now();
            let result = rpc_request::<String>(
                endpoint,
                "eth_getTransactionCount",
                serde_json::json!([format!("{address:#x}"), "pending"]),
            )
            .await;
            self.history_telemetry
                .add_elapsed(HistoryDuration::HistoricalRpc, endpoint_started.elapsed());
            match result {
                Ok(result) => nonces.push(parse_hex_quantity(&result)?),
                Err(error) => {
                    self.history_telemetry.add(HistoryCounter::RpcErrors, 1);
                    return Err(error)
                        .with_context(|| format!("read pending nonce from {}", endpoint.name));
                }
            }
        }
        let nonce = *nonces
            .first()
            .context("pending nonce endpoint is unavailable")?;
        if nonces.iter().any(|other| *other != nonce) {
            bail!("selected RPC returned inconsistent wallet pending nonce data");
        }
        Ok(nonce)
    }

    pub async fn fee_quote(
        &self,
        from: Address,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Result<FeeQuote> {
        #[cfg(test)]
        if data.starts_with(&AstatineMinerRead::finalizeWindowCall::SELECTOR) {
            let delay_ms = self
                .delay_next_finalization_fee_quote_ms
                .swap(0, Ordering::AcqRel);
            if delay_ms > 0 {
                self.fee_quote_delays_started
                    .fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
        #[cfg(test)]
        if data.starts_with(&AstatineMinerRead::submitSolutionCall::SELECTOR) {
            let delay_ms = self.delay_next_proof_fee_quote_ms.swap(0, Ordering::AcqRel);
            if delay_ms > 0 {
                self.fee_quote_delays_started
                    .fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            if consume_counter(&self.fail_next_proof_fee_quote) {
                return Err(anyhow::Error::new(TransientRpcFailure {
                    details: "test-injected HTTP 503 from proof fee quote provider".to_owned(),
                }));
            }
        }
        #[cfg(test)]
        if data.starts_with(&AstatineMinerRead::finalizeWindowCall::SELECTOR)
            && consume_counter(&self.fail_next_finalization_fee_quote)
        {
            return Err(anyhow::Error::new(TransientRpcFailure {
                details: "test-injected HTTP 503 from fee quote provider".to_owned(),
            }));
        }
        let endpoint = self.primary_endpoint()?;
        let transaction = serde_json::json!({
            "from": format!("{from:#x}"),
            "to": format!("{to:#x}"),
            "value": format!("{value:#x}"),
            "data": format!("0x{}", hex::encode(data)),
        });
        let estimate = rpc_request::<String>(
            endpoint,
            "eth_estimateGas",
            serde_json::json!([transaction]),
        )
        .await
        .context("estimate transaction gas")
        .and_then(|value| parse_hex_quantity(&value))?;
        let gas_limit = estimate
            .checked_mul(120)
            .and_then(|value| value.checked_add(99))
            .map(|value| value / 100)
            .context("gas estimate overflow")?;
        if gas_limit == 0 || gas_limit > 10_000_000 {
            bail!("estimated transaction gas is outside the supported 1..=10,000,000 range");
        }

        let block = rpc_request::<serde_json::Value>(
            endpoint,
            "eth_getBlockByNumber",
            serde_json::json!(["latest", false]),
        )
        .await?;
        let base_fee = block
            .get("baseFeePerGas")
            .and_then(serde_json::Value::as_str)
            .context("latest block does not expose EIP-1559 baseFeePerGas")
            .and_then(parse_hex_u256)?;
        let priority = match rpc_request::<String>(
            endpoint,
            "eth_maxPriorityFeePerGas",
            serde_json::json!([]),
        )
        .await
        {
            Ok(value) => parse_hex_u256(&value)?,
            Err(_) => {
                let gas_price =
                    rpc_request::<String>(endpoint, "eth_gasPrice", serde_json::json!([])).await?;
                parse_hex_u256(&gas_price)?
            }
        };
        let max_fee_per_gas = base_fee
            .checked_mul(U256::from(2))
            .and_then(|base| base.checked_add(priority))
            .context("EIP-1559 maximum fee calculation overflow")?;
        Ok(FeeQuote {
            gas_limit,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas,
        })
    }

    pub async fn broadcast_raw_transaction(&self, raw_transaction: &[u8]) -> Result<B256> {
        let result = rpc_request::<String>(
            self.primary_endpoint()?,
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(raw_transaction))]),
        )
        .await?;
        parse_hash(&result).context("RPC returned an invalid transaction hash")
    }

    pub async fn transaction_known(&self, hash: B256) -> Result<bool> {
        Ok(self.transaction_details(hash).await?.is_some())
    }

    pub async fn transaction_sender(&self, hash: B256) -> Result<Option<Address>> {
        Ok(self
            .transaction_details(hash)
            .await?
            .map(|transaction| transaction.from))
    }

    pub async fn transaction_receipt(&self, hash: B256) -> Result<Option<TransactionReceipt>> {
        let endpoint = self.primary_endpoint()?;
        self.history_telemetry
            .add(HistoryCounter::ReceiptRequests, 1);
        let started = Instant::now();
        let result = rpc_request::<Option<ReceiptJson>>(
            endpoint,
            "eth_getTransactionReceipt",
            serde_json::json!([format!("{hash:#x}")]),
        )
        .await;
        self.history_telemetry
            .add_elapsed(HistoryDuration::HistoricalRpc, started.elapsed());
        match result {
            Ok(Some(receipt)) => {
                let receipt = TransactionReceipt::try_from(receipt)
                    .with_context(|| format!("decode receipt reported by {}", endpoint.name))?;
                if receipt.transaction_hash != hash {
                    bail!("selected RPC returned a receipt for a different transaction hash");
                }
                validate_trusted_rpc_receipt(&receipt)
                    .context("validate receipt shape and transaction metadata")?;
                Ok(Some(receipt))
            }
            Ok(None) => Ok(None),
            Err(error) if is_transient_rpc_error(&error) => {
                self.history_telemetry.add(HistoryCounter::RpcErrors, 1);
                Err(anyhow::Error::new(ReceiptStatusUnavailable {
                    details: format!(
                        "selected RPC receipt request is temporarily unavailable: {error:#}"
                    ),
                }))
            }
            Err(error) => {
                self.history_telemetry.add(HistoryCounter::RpcErrors, 1);
                Err(error).context("read transaction receipt from the selected trusted RPC")
            }
        }
    }

    pub async fn transaction_details(&self, hash: B256) -> Result<Option<TransactionDetails>> {
        let endpoint = self.primary_endpoint()?;
        self.history_telemetry
            .add(HistoryCounter::TransactionLookupRequests, 1);
        let started = Instant::now();
        let result = rpc_request::<Option<TransactionJson>>(
            endpoint,
            "eth_getTransactionByHash",
            serde_json::json!([format!("{hash:#x}")]),
        )
        .await;
        self.history_telemetry
            .add_elapsed(HistoryDuration::HistoricalRpc, started.elapsed());
        let transaction = match result {
            Ok(transaction) => transaction,
            Err(error) => {
                self.history_telemetry.add(HistoryCounter::RpcErrors, 1);
                return Err(error)
                    .context("read transaction details from the selected trusted RPC");
            }
        };
        let Some(transaction) = transaction else {
            return Ok(None);
        };
        let transaction = TransactionDetails::try_from(transaction)
            .context("decode transaction details reported by the selected RPC")?;
        if transaction.hash != hash {
            bail!("selected RPC returned transaction details for a different hash");
        }
        Ok(Some(transaction))
    }

    pub(crate) async fn window_finalization_logs_range(
        &self,
        address: Address,
        token: Address,
        window_id: u64,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RpcLog>> {
        if from_block > to_block {
            return Ok(Vec::new());
        }
        if to_block.saturating_sub(from_block) >= MAX_LOG_QUERY_RANGE {
            bail!("reward history range exceeds the bounded RPC log-query size");
        }
        let primary = self.primary_endpoint()?;
        let mut logs = match window_finalization_logs_range_at(
            primary,
            address,
            token,
            window_id,
            from_block,
            to_block,
            &self.history_telemetry,
        )
        .await
        {
            Ok(logs) => logs,
            Err(primary_error) if !self.custom_primary => {
                let Some(archival) = self.archival_endpoint() else {
                    return Err(primary_error)
                        .context("read historical reward logs from selected RPC");
                };
                self.report_diagnostic(format!(
                    "Selected primary RPC could not serve historical reward logs for node {} window {}; reading the bundled archival endpoint as a historical fallback: {primary_error:#}",
                    address, window_id
                ));
                window_finalization_logs_range_at(
                    archival,
                    address,
                    token,
                    window_id,
                    from_block,
                    to_block,
                    &self.history_telemetry,
                )
                .await
                .context("read historical reward logs from bundled archival fallback")?
            }
            Err(error) => {
                return Err(error).context("read historical reward logs from selected custom RPC");
            }
        };
        logs.sort_by_key(|log| {
            (
                log.block_number.unwrap_or(u64::MAX),
                log.transaction_index.unwrap_or(u64::MAX),
                log.log_index.unwrap_or(u64::MAX),
            )
        });
        self.verify_log_receipts(&logs, from_block, to_block)
            .await?;
        Ok(logs)
    }

    async fn verify_log_receipts(
        &self,
        logs: &[RpcLog],
        from_block: u64,
        to_block: u64,
    ) -> Result<()> {
        let mut by_transaction = HashMap::<B256, Vec<&RpcLog>>::new();
        let mut positions = HashSet::new();
        for log in logs {
            let block_number = log
                .block_number
                .context("historical RPC log has no block number")?;
            if !(from_block..=to_block).contains(&block_number) {
                bail!("historical RPC log lies outside the requested canonical block range");
            }
            let block_hash = log
                .block_hash
                .context("historical RPC log has no block hash")?;
            let transaction_hash = log
                .transaction_hash
                .context("historical RPC log has no transaction hash")?;
            let transaction_index = log
                .transaction_index
                .context("historical RPC log has no transaction index")?;
            let log_index = log
                .log_index
                .context("historical RPC log has no log index")?;
            if log.removed || log.virtual_log {
                bail!("historical reward log is removed or virtual rather than EVM-included");
            }
            if !positions.insert((block_hash, transaction_index, log_index)) {
                bail!("historical RPC log set contains a duplicate log position");
            }
            by_transaction
                .entry(transaction_hash)
                .or_default()
                .push(log);
        }
        for (hash, transaction_logs) in by_transaction {
            let receipt = self
                .transaction_receipt(hash)
                .await?
                .context("historical reward log has no matching receipt from the selected RPC")?;
            for log in transaction_logs {
                if receipt.block_number != log.block_number.unwrap_or_default()
                    || receipt.block_hash != log.block_hash.unwrap_or(B256::ZERO)
                    || receipt.transaction_index != log.transaction_index.unwrap_or_default()
                    || !receipt.logs.contains(log)
                {
                    bail!(
                        "historical reward log is not present in the matching selected-RPC receipt"
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn primary_nonce(&self, address: Address, block_tag: &str) -> Result<u64> {
        self.history_telemetry.add(HistoryCounter::NonceRequests, 1);
        let started = Instant::now();
        let result = rpc_request::<String>(
            self.primary_endpoint()?,
            "eth_getTransactionCount",
            serde_json::json!([format!("{address:#x}"), block_tag]),
        )
        .await;
        self.history_telemetry
            .add_elapsed(HistoryDuration::HistoricalRpc, started.elapsed());
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.history_telemetry.add(HistoryCounter::RpcErrors, 1);
                return Err(error);
            }
        };
        parse_hex_quantity(&result)
    }

    pub async fn latest_block_snapshot(&self) -> Result<BlockSnapshot> {
        self.best_block().await.map(|(_, block)| block)
    }

    pub(crate) fn clear_activation_work_verification(&self) {
        self.activation_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Read only the `work()` status of selected nodes known to be awaiting genesis.
    /// The caller must treat an activation candidate as a hint and follow it with
    /// `snapshot()`, which performs the canonical full-state and pin verification.
    pub(crate) async fn poll_genesis(&self, node_ids: &[u8]) -> Result<Vec<u8>> {
        #[cfg(test)]
        let started_at = Instant::now();
        #[cfg(test)]
        let _active_call = GenesisPollCallGuard::enter(Arc::clone(&self.genesis_poll_active_calls));
        #[cfg(test)]
        {
            let delay_ms = self.genesis_poll_delay_ms.swap(0, Ordering::AcqRel);
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
        #[cfg(test)]
        self.genesis_poll_max_inflight.store(0, Ordering::Release);
        let result = self.poll_genesis_inner(node_ids).await;
        #[cfg(test)]
        let succeeded = result.is_ok();
        #[cfg(test)]
        self.genesis_poll_observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(GenesisPollObservation {
                started_at,
                completed_at: Instant::now(),
                node_ids: node_ids.to_vec(),
                max_concurrent_node_reads: self.genesis_poll_max_inflight.load(Ordering::Acquire),
                succeeded,
            });
        result
    }

    async fn poll_genesis_inner(&self, node_ids: &[u8]) -> Result<Vec<u8>> {
        if node_ids.is_empty() {
            return Ok(Vec::new());
        }
        #[cfg(test)]
        if consume_counter(&self.fail_next_genesis_polls) {
            bail!("injected transient genesis status RPC failure");
        }
        let requested = node_ids.iter().copied().collect::<HashSet<_>>();
        if requested.len() != node_ids.len() {
            bail!("genesis poll node selection contains duplicates");
        }
        let mut pins = self
            .manifest
            .nodes
            .iter()
            .filter(|pin| requested.contains(&pin.id))
            .cloned()
            .collect::<Vec<_>>();
        pins.sort_by_key(|pin| pin.id);
        if pins.len() != requested.len() {
            bail!("genesis poll requested a node outside the deployment manifest");
        }

        let (endpoints, block) = self.best_block().await?;
        let mut refresh_nodes = Vec::new();
        for batch in pins.chunks(GENESIS_PROBE_CONCURRENCY) {
            let mut jobs = JoinSet::new();
            for pin in batch.iter().cloned() {
                let endpoints = endpoints.clone();
                let block_number = block.number;
                #[cfg(test)]
                let concurrency = GenesisProbeConcurrencyGuard::enter(
                    Arc::clone(&self.genesis_poll_inflight),
                    &self.genesis_poll_max_inflight,
                );
                jobs.spawn(async move {
                    #[cfg(test)]
                    let _concurrency = concurrency;
                    let address = parse_address(&pin.address)?;
                    let mut last_error = None;
                    for endpoint in endpoints {
                        match call_contract(
                            &endpoint,
                            address,
                            AstatineMinerRead::workCall {},
                            block_number,
                        )
                        .await
                        {
                            Ok(bytes) => {
                                let work = decode_work(&bytes)?;
                                let refresh = work.started
                                    || work.ended
                                    || work.remaining_allocation.is_zero();
                                return Ok::<(u8, bool), anyhow::Error>((pin.id, refresh));
                            }
                            Err(error) => {
                                last_error = Some(format!("{}: {error:#}", endpoint.name));
                            }
                        }
                    }
                    bail!(
                        "could not read genesis status for node {}: {}",
                        pin.id,
                        last_error.unwrap_or_else(|| "no canonical RPC endpoint".to_owned())
                    )
                });
            }
            while let Some(joined) = jobs.join_next().await {
                let (node_id, refresh) = joined.context("genesis status reader task failed")??;
                if refresh {
                    refresh_nodes.push(node_id);
                }
            }
        }
        refresh_nodes.sort_unstable();
        Ok(refresh_nodes)
    }

    #[cfg(test)]
    pub(crate) fn genesis_poll_observations(&self) -> Vec<GenesisPollObservation> {
        self.genesis_poll_observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn clear_genesis_poll_observations(&self) {
        self.genesis_poll_observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    #[cfg(test)]
    pub(crate) fn delay_next_genesis_poll(&self, delay: Duration) {
        self.genesis_poll_delay_ms.store(
            delay.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Release,
        );
    }

    #[cfg(test)]
    pub(crate) fn fail_next_genesis_polls(&self, count: usize) {
        self.fail_next_genesis_polls
            .fetch_add(count, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn genesis_poll_is_active(&self) -> bool {
        self.genesis_poll_active_calls.load(Ordering::Acquire) > 0
    }

    pub async fn canonical_block_hash(&self, block_number: u64) -> Result<B256> {
        let endpoint = self.primary_endpoint()?;
        self.history_telemetry
            .add(HistoryCounter::CanonicalBlockRequests, 1);
        let started = Instant::now();
        let result = block_at(endpoint, block_number).await;
        self.history_telemetry
            .add_elapsed(HistoryDuration::HistoricalRpc, started.elapsed());
        match result {
            Ok(block) => Ok(block.hash),
            Err(error) => {
                self.history_telemetry.add(HistoryCounter::RpcErrors, 1);
                Err(error).with_context(|| {
                    format!("selected trusted RPC cannot read canonical block {block_number}")
                })
            }
        }
    }

    async fn financial_block_hash(&self, block_number: u64) -> Result<B256> {
        self.canonical_block_hash(block_number).await
    }

    pub async fn receipt_confirmations(
        &self,
        block_number: u64,
        block_hash: B256,
        latest_block_number: u64,
    ) -> Result<Option<u64>> {
        if latest_block_number < block_number {
            return Ok(Some(0));
        }
        self.financial_block_hash(latest_block_number).await?;
        let canonical_hash = self.financial_block_hash(block_number).await?;
        if canonical_hash != block_hash {
            return Ok(None);
        }
        Ok(Some(
            latest_block_number
                .saturating_sub(block_number)
                .saturating_add(1),
        ))
    }

    pub(crate) async fn receipt_confirmations_at_snapshot(
        &self,
        block_number: u64,
        block_hash: B256,
        snapshot: &BlockSnapshot,
        canonical_blocks: &mut HashMap<u64, B256>,
    ) -> Result<Option<u64>> {
        if snapshot.number < block_number {
            return Ok(Some(0));
        }
        let snapshot_hash = if let Some(hash) = canonical_blocks.get(&snapshot.number) {
            *hash
        } else {
            let hash = self.financial_block_hash(snapshot.number).await?;
            if hash != snapshot.hash {
                bail!("selected trusted RPC no longer agrees with the monitoring snapshot");
            }
            canonical_blocks.insert(snapshot.number, hash);
            hash
        };
        if snapshot_hash != snapshot.hash {
            bail!("cached snapshot hash disagrees with the current monitoring snapshot");
        }
        let canonical_hash = if let Some(hash) = canonical_blocks.get(&block_number) {
            *hash
        } else {
            let hash = self.financial_block_hash(block_number).await?;
            canonical_blocks.insert(block_number, hash);
            hash
        };
        if canonical_hash != block_hash {
            return Ok(None);
        }
        Ok(Some(
            snapshot
                .number
                .saturating_sub(block_number)
                .saturating_add(1),
        ))
    }

    fn primary_endpoint(&self) -> Result<&RpcEndpoint> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.name == "primary")
            .context("configured primary RPC is unavailable; refusing to broadcast")
    }

    fn archival_endpoint(&self) -> Option<&RpcEndpoint> {
        self.archival_endpoint.as_ref()
    }

    fn trusted_rpc_endpoints(&self) -> Result<Vec<RpcEndpoint>> {
        Ok(vec![self.primary_endpoint()?.clone()])
    }

    #[cfg(test)]
    pub(crate) fn local_test_client(
        url: &str,
        miner: Address,
        miner_runtime_hash: B256,
        token: Address,
        token_runtime_hash: B256,
        token_decimals: u8,
    ) -> Result<Self> {
        Self::local_test_client_with_nodes(
            url,
            &[(1, miner, miner_runtime_hash)],
            token,
            token_runtime_hash,
            token_decimals,
        )
    }

    #[cfg(test)]
    pub(crate) fn local_test_client_with_nodes(
        url: &str,
        miners: &[(u8, Address, B256)],
        token: Address,
        token_runtime_hash: B256,
        token_decimals: u8,
    ) -> Result<Self> {
        let endpoint = RpcEndpoint {
            name: "primary".to_owned(),
            url: Url::parse(url).context("parse local Anvil URL")?,
            client: reqwest::Client::builder()
                .timeout(RPC_TIMEOUT)
                .build()
                .context("create local Anvil RPC client")?,
        };
        let manifest = DeploymentManifest {
            schema_version: 1,
            network: crate::cli::Network::Testnet,
            chain_id: 1439,
            native_symbol: "INJ".to_owned(),
            native_decimals: 18,
            primary_rpc: url.to_owned(),
            archival_rpc: None,
            mining_enabled: true,
            solidity_source: None,
            reference_snapshot: None,
            ast_token: Some(TokenPin {
                address: format!("{token:#x}"),
                decimals: token_decimals,
                runtime_code_hash: format!("{token_runtime_hash:#x}"),
            }),
            nodes: miners
                .iter()
                .map(|(id, address, runtime_hash)| NodePin {
                    id: *id,
                    address: format!("{address:#x}"),
                    runtime_code_hash: format!("{runtime_hash:#x}"),
                })
                .collect(),
        };
        Ok(Self {
            manifest,
            endpoints: vec![endpoint],
            archival_endpoint: None,
            custom_primary: false,
            activation_work: Arc::new(Mutex::new(HashSet::new())),
            diagnostics: None,
            history_telemetry: Arc::new(HistoryTelemetry::default()),
            #[cfg(test)]
            fail_next_finalization_fee_quote: std::sync::Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            fail_next_proof_fee_quote: std::sync::Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            delay_next_proof_fee_quote_ms: std::sync::Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            delay_next_finalization_fee_quote_ms: std::sync::Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            fee_quote_delays_started: std::sync::Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            proof_nonce_starts: std::sync::Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            genesis_poll_observations: Arc::new(Mutex::new(Vec::new())),
            #[cfg(test)]
            genesis_poll_inflight: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            genesis_poll_max_inflight: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            genesis_poll_active_calls: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            genesis_poll_delay_ms: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            fail_next_genesis_polls: Arc::new(AtomicUsize::new(0)),
            verification: DeploymentVerification {
                token_verified: true,
                reference_snapshot_verified: false,
                nodes: miners
                    .iter()
                    .map(|(id, _, _)| {
                        (
                            *id,
                            ContractPinStatus {
                                runtime_verified: true,
                                abi_verified: true,
                                error: None,
                            },
                        )
                    })
                    .collect(),
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_finalization_fee_quote_once(&self) {
        self.fail_next_finalization_fee_quote
            .fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_proof_fee_quote_once(&self) {
        self.fail_next_proof_fee_quote
            .fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn delay_next_proof_fee_quote(&self, delay: Duration) {
        self.delay_next_proof_fee_quote_ms.store(
            delay.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Release,
        );
    }

    #[cfg(test)]
    pub(crate) fn delay_next_finalization_fee_quote(&self, delay: Duration) {
        self.delay_next_finalization_fee_quote_ms.store(
            delay.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Release,
        );
    }

    #[cfg(test)]
    pub(crate) fn fee_quote_delays_started(&self) -> u64 {
        self.fee_quote_delays_started.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn set_test_proof_nonce_start(
        &self,
        node_id: u8,
        window_id: u64,
        seed: B256,
        nonce: u128,
    ) {
        self.proof_nonce_starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((node_id, window_id, seed), nonce);
    }

    #[cfg(test)]
    pub(crate) fn take_test_proof_nonce_start(
        &self,
        node_id: u8,
        window_id: u64,
        seed: B256,
    ) -> Option<u128> {
        self.proof_nonce_starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(node_id, window_id, seed))
    }

    async fn verify_deployment(&mut self, progress: Option<&StartupProgress>) -> Result<()> {
        if let Some(progress) = progress {
            progress.begin("Selecting a consistent deployment block");
        }
        let (endpoints, block) = match self.best_block().await {
            Ok(result) => result,
            Err(error) => {
                if let Some(progress) = progress {
                    progress.fail(format!(
                        "Could not select a verified deployment block: {error:#}"
                    ));
                }
                return Err(error).context("select a consistent deployment verification block");
            }
        };
        if let Some(progress) = progress {
            progress.complete(format!("Deployment block selected · #{}", block.number));
            progress.begin("Verifying deployment reference snapshot");
        }
        if self.manifest.reference_snapshot.is_some() {
            self.verification.reference_snapshot_verified = self.verify_reference_snapshot().await;
            if !self.verification.reference_snapshot_verified {
                let message = "Historical reference block was unavailable or did not match; live runtime pins are still required.";
                if let Some(progress) = progress {
                    progress.warn(message);
                } else {
                    self.report_diagnostic(message.to_owned());
                }
            } else if let Some(progress) = progress {
                progress.complete("Deployment reference snapshot verified");
            }
        } else {
            self.verification.reference_snapshot_verified = false;
            if let Some(progress) = progress {
                progress.complete("No pinned reference snapshot configured");
            }
        }

        if let Some(token) = &self.manifest.ast_token {
            if let Some(progress) = progress {
                progress.begin("Verifying AST token");
            }
            let mut token_errors = Vec::new();
            for source in &endpoints {
                if let Err(error) = self.verify_token_pin(source, block.number, token).await {
                    token_errors.push(format!("{}: {error:#}", source.name));
                }
            }
            if token_errors.is_empty() {
                self.verification.token_verified = true;
                if let Some(progress) = progress {
                    progress.complete("AST token verified");
                }
            } else {
                self.verification.token_verified = false;
                let message = format!(
                    "AST token is unverified because provider checks did not all succeed: {}",
                    token_errors.join("; ")
                );
                if let Some(progress) = progress {
                    progress.warn(&message);
                } else {
                    self.report_diagnostic(message);
                }
            }
        }

        let total = self.manifest.nodes.len();
        if total == 0 {
            if let Some(progress) = progress {
                progress.complete("No mining contracts configured for this network");
            }
        } else {
            if let Some(progress) = progress {
                progress.begin(format!("Verifying mining contracts · 0/{total}"));
            }
            let mut verified = 0;
            for (index, pin) in self.manifest.nodes.clone().into_iter().enumerate() {
                let status = self
                    .verify_node_pin_for_snapshot(&endpoints, &block, &pin)
                    .await;
                if status.runtime_verified && status.abi_verified {
                    verified += 1;
                } else {
                    let message = format!(
                        "Node {} verification failed: {}",
                        pin.id,
                        status
                            .error
                            .as_deref()
                            .unwrap_or("runtime or ABI pin did not verify")
                    );
                    if let Some(progress) = progress {
                        progress.note(message);
                    } else {
                        self.report_diagnostic(message);
                    }
                }
                self.verification.nodes.insert(pin.id, status);
                if let Some(progress) = progress {
                    progress.update(format!(
                        "Verifying mining contracts · {}/{}",
                        index + 1,
                        total
                    ));
                }
            }
            if let Some(progress) = progress {
                if verified == total {
                    progress.complete(format!("Mining contracts verified · {verified}/{total}"));
                } else {
                    progress.warn(format!(
                        "Mining contracts checked · {verified}/{total} verified"
                    ));
                }
            }
        }
        Ok(())
    }

    async fn verify_reference_snapshot(&self) -> bool {
        let Some(snapshot) = &self.manifest.reference_snapshot else {
            return false;
        };
        let Ok(expected_hash) = parse_hash(&snapshot.block_hash) else {
            return false;
        };
        let endpoints = self.endpoints.clone();
        if endpoints.is_empty() {
            return false;
        }
        for endpoint in &endpoints {
            match block_at(endpoint, snapshot.block_number).await {
                Ok(block) if block.hash == expected_hash => {}
                _ => return false,
            }
        }
        true
    }

    async fn verify_token_pin(
        &self,
        endpoint: &RpcEndpoint,
        block: u64,
        token: &crate::deployment::TokenPin,
    ) -> Result<()> {
        async {
            let address = parse_address(&token.address)?;
            let expected_hash = parse_hash(&token.runtime_code_hash)?;
            let code = get_code(endpoint, address, block).await?;
            if code.is_empty() || keccak256(code) != expected_hash {
                bail!("AST token runtime hash does not match the deployment pin");
            }
            let decimals =
                call_contract(endpoint, address, IERC20Read::decimalsCall {}, block).await?;
            if decode_return::<u64>(&decimals)? != u64::from(token.decimals) {
                bail!("AST token decimals do not match the deployment pin");
            }
            Ok::<(), anyhow::Error>(())
        }
        .await
    }

    async fn verify_node_pin(
        &self,
        endpoint: &RpcEndpoint,
        block: &BlockSnapshot,
        pin: &NodePin,
    ) -> ContractPinStatus {
        self.activation_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&pin.id);
        let runtime_check = async {
            let address = parse_address(&pin.address)?;
            let expected_hash = parse_hash(&pin.runtime_code_hash)?;
            let code = get_code(endpoint, address, block.number)
                .await
                .with_context(|| format!("eth_getCode(node {})", pin.id))?;
            if code.is_empty() || keccak256(code) != expected_hash {
                bail!("runtime code hash does not match the deployment pin");
            }
            Ok::<Address, anyhow::Error>(address)
        }
        .await;
        let address = match runtime_check {
            Ok(address) => address,
            Err(error) => {
                return ContractPinStatus {
                    runtime_verified: false,
                    abi_verified: false,
                    error: Some(format!("{error:#}")),
                };
            }
        };

        let mut verified_work = false;
        let abi_check = async {
            let state = fetch_node(endpoint, &self.manifest, address, block).await?;
            let has_best_bytes = call_contract(
                endpoint,
                address,
                AstatineMinerRead::hasBestCall {},
                block.number,
            )
            .await?;
            if decode_return::<bool>(&has_best_bytes)? != state.candidate.is_some() {
                bail!("candidateSummary and hasBest disagree");
            }
            if let Some(token) = &self.manifest.ast_token {
                let token_bytes = call_contract(
                    endpoint,
                    address,
                    AstatineMinerRead::astTokenCall {},
                    block.number,
                )
                .await?;
                if decode_return::<Address>(&token_bytes)? != parse_address(&token.address)? {
                    bail!("miner AST token does not match its deployment manifest");
                }
            }
            let domain_bytes = call_contract(
                endpoint,
                address,
                AstatineMinerRead::WORK_DOMAIN_V2Call {},
                block.number,
            )
            .await?;
            if decode_return::<B256>(&domain_bytes)? != work_domain_v2() {
                bail!("WORK_DOMAIN_V2 does not match the canonical Rust codec");
            }
            if state.work.started && !state.work.ended {
                let context = WorkContext {
                    chain_id: self.manifest.chain_id,
                    contract: address,
                    window_id: state.work.window_id,
                    seed: state.work.seed,
                    miner: Address::ZERO,
                    header: Vec::new(),
                };
                let nonce = ABI_PROBE_NONCE;
                let local_hash = WorkHasher::new(&context)?.hash(nonce);
                let remote_bytes = call_contract(
                    endpoint,
                    address,
                    AstatineMinerRead::computeWorkHashCall {
                        miner: Address::ZERO,
                        nonce,
                        header: Bytes::new(),
                    },
                    block.number,
                )
                .await?;
                if decode_return::<B256>(&remote_bytes)? != local_hash {
                    bail!("computeWorkHash disagrees with the canonical Rust implementation");
                }
                verified_work = true;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        match abi_check {
            Ok(()) => {
                if verified_work {
                    self.activation_work
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(pin.id);
                }
                ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                }
            }
            Err(error) => ContractPinStatus {
                runtime_verified: true,
                abi_verified: false,
                error: Some(format!("ABI/protocol verification failed: {error:#}")),
            },
        }
    }

    async fn verify_node_pin_for_snapshot(
        &self,
        endpoints: &[RpcEndpoint],
        block: &BlockSnapshot,
        pin: &NodePin,
    ) -> ContractPinStatus {
        let mut results = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            results.push((
                endpoint.name.clone(),
                self.verify_node_pin(endpoint, block, pin).await,
            ));
        }
        let Some((_, status)) = results.first() else {
            return ContractPinStatus {
                runtime_verified: false,
                abi_verified: false,
                error: Some("no RPC endpoint verified the deployment pin".to_owned()),
            };
        };
        let failures = results
            .iter()
            .filter(|(_, result)| !result.runtime_verified || !result.abi_verified)
            .map(|(name, result)| {
                format!(
                    "{name}: {}",
                    result
                        .error
                        .as_deref()
                        .unwrap_or("deployment pin verification failed")
                )
            })
            .collect::<Vec<_>>();
        if !failures.is_empty() {
            self.activation_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&pin.id);
            return ContractPinStatus {
                runtime_verified: false,
                abi_verified: false,
                error: Some(format!(
                    "selected RPC did not verify node {}: {}",
                    pin.id,
                    failures.join("; ")
                )),
            };
        }
        status.clone()
    }

    pub async fn snapshot(&self, wallet: Option<Address>) -> Result<ReadSnapshot> {
        let (endpoints, block) = self.best_block().await?;
        let primary = endpoints
            .first()
            .cloned()
            .context("selected primary RPC is unavailable")?;
        let mut node_jobs = JoinSet::new();
        for pin in self.manifest.nodes.clone() {
            let primary = primary.clone();
            let pin_status = self
                .verification
                .nodes
                .get(&pin.id)
                .cloned()
                .unwrap_or_else(|| ContractPinStatus {
                    runtime_verified: false,
                    abi_verified: false,
                    error: Some("runtime verification did not complete".to_owned()),
                });
            let manifest = self.manifest.clone();
            let block = block.clone();
            node_jobs.spawn(async move {
                fetch_node_from_rpc(&primary, &manifest, pin, pin_status, block).await
            });
        }

        let mut nodes = Vec::with_capacity(self.manifest.nodes.len());
        while let Some(joined) = node_jobs.join_next().await {
            match joined {
                Ok(node) => nodes.push(node),
                Err(error) => self.report_diagnostic(format!("node reader task failed: {error}")),
            }
        }
        nodes.sort_by_key(|node| node.id);
        self.verify_active_nodes(&endpoints, &block, &mut nodes, false)
            .await?;

        let (native_balance, native_balance_error) = if let Some(address) = wallet {
            let mut balances = Vec::with_capacity(endpoints.len());
            let mut errors = Vec::new();
            for endpoint in &endpoints {
                match get_balance(endpoint, address, block.number).await {
                    Ok(balance) => balances.push((endpoint.name.as_str(), balance)),
                    Err(error) => errors.push(format!("{}: {error:#}", endpoint.name)),
                }
            }
            if !errors.is_empty() {
                (
                    None,
                    Some(format!(
                        "selected RPC confirmed-balance request failed: {}",
                        errors.join("; ")
                    )),
                )
            } else if balances
                .iter()
                .any(|(_, balance)| *balance != balances[0].1)
            {
                (
                    None,
                    Some(
                        "selected RPC returned inconsistent confirmed INJ balance values"
                            .to_owned(),
                    ),
                )
            } else {
                (Some(balances[0].1), None)
            }
        } else {
            (None, None)
        };
        let (ast_balance, ast_balance_error) = match (&self.manifest.ast_token, wallet) {
            (Some(token), Some(address)) if self.verification.token_verified => {
                let token_address = parse_address(&token.address)?;
                let mut balances = Vec::with_capacity(endpoints.len());
                let mut errors = Vec::new();
                for endpoint in &endpoints {
                    match call_contract(
                        endpoint,
                        token_address,
                        IERC20Read::balanceOfCall { account: address },
                        block.number,
                    )
                    .await
                    .and_then(|value| decode_return::<U256>(&value))
                    {
                        Ok(balance) => balances.push(balance),
                        Err(error) => errors.push(format!("{}: {error:#}", endpoint.name)),
                    }
                }
                if !errors.is_empty() {
                    (
                        None,
                        Some(format!(
                            "selected RPC AST-balance request failed: {}",
                            errors.join("; ")
                        )),
                    )
                } else if balances.iter().any(|balance| *balance != balances[0]) {
                    (
                        None,
                        Some("selected RPC returned inconsistent AST balance values".to_owned()),
                    )
                } else {
                    (Some(balances[0]), None)
                }
            }
            (Some(_), Some(_)) => (
                None,
                Some("AST token runtime pin is not verified".to_owned()),
            ),
            _ => (None, None),
        };

        for source in &endpoints {
            let current = block_at(source, block.number).await?;
            if current.hash != block.hash {
                bail!(
                    "RPC {} changed block {} while reading; discarding stale snapshot",
                    source.name,
                    block.number
                );
            }
        }

        Ok(ReadSnapshot {
            block,
            native_balance,
            native_balance_error,
            ast_balance,
            ast_balance_error,
            nodes,
        })
    }

    async fn verify_active_nodes(
        &self,
        endpoints: &[RpcEndpoint],
        block: &BlockSnapshot,
        nodes: &mut [NodeView],
        force: bool,
    ) -> Result<()> {
        if force {
            self.activation_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
        let mut candidates = Vec::new();
        {
            let mut verified = self
                .activation_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for node in nodes.iter() {
                let Some(state) = node.state.as_ref() else {
                    verified.remove(&node.id);
                    continue;
                };
                if !state.work.started || state.work.ended {
                    verified.remove(&node.id);
                    continue;
                }
                // The node's runtime pin fixes the hash algorithm; verify once per genesis
                // activation rather than repeating code/ABI/hash probes on every work window.
                if !force && verified.contains(&node.id) {
                    continue;
                }
                let pin = self
                    .manifest
                    .nodes
                    .iter()
                    .find(|pin| pin.id == node.id)
                    .cloned()
                    .context("active snapshot node is absent from the deployment manifest")?;
                candidates.push((node.id, pin));
            }
        }
        if candidates.is_empty() {
            return Ok(());
        }

        let endpoint = endpoints
            .first()
            .context("active-node activation verification has no canonical RPC endpoint")?;
        let chain_id = rpc_request::<String>(endpoint, "eth_chainId", serde_json::json!([]))
            .await
            .and_then(|value| parse_hex_quantity(&value))
            .context("verify chain ID during genesis activation")?;
        if chain_id != self.manifest.chain_id {
            bail!(
                "RPC {} changed chain ID during genesis activation: expected {}, observed {}",
                endpoint.name,
                self.manifest.chain_id,
                chain_id
            );
        }

        for batch in candidates.chunks(GENESIS_PROBE_CONCURRENCY) {
            let mut jobs = JoinSet::new();
            for (node_id, pin) in batch.iter().cloned() {
                let client = self.clone();
                let endpoints = endpoints.to_vec();
                let block = block.clone();
                jobs.spawn(async move {
                    let status = client
                        .verify_node_pin_for_snapshot(&endpoints, &block, &pin)
                        .await;
                    (node_id, status)
                });
            }
            while let Some(joined) = jobs.join_next().await {
                let (node_id, mut status) =
                    joined.context("genesis activation verifier task failed")?;
                let work_hash_verified = self
                    .activation_work
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&node_id);
                if status.runtime_verified && status.abi_verified && !work_hash_verified {
                    status.abi_verified = false;
                    status.error = Some(
                        "activation verification did not confirm canonical PoW compatibility"
                            .to_owned(),
                    );
                    self.activation_work
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&node_id);
                }
                if let Some(node) = nodes.iter_mut().find(|node| node.id == node_id) {
                    node.error = status.error.clone();
                    node.pin = status;
                }
            }
        }
        Ok(())
    }

    /// Recheck activation compatibility after a canonical-chain reorganization.
    /// The original snapshot is verified again at its block before any work is published.
    pub(crate) async fn reverify_activated_nodes_after_reorg(
        &self,
        snapshot: &mut ReadSnapshot,
    ) -> Result<()> {
        let (endpoints, head) = self.best_block().await?;
        if head.number < snapshot.block.number {
            bail!("RPC head is behind the snapshot during activation revalidation");
        }
        let mut matching_endpoints = Vec::new();
        for endpoint in endpoints {
            if let Ok(block) = block_at(&endpoint, snapshot.block.number).await
                && block.hash == snapshot.block.hash
            {
                matching_endpoints.push(endpoint);
            }
        }
        if matching_endpoints.is_empty() {
            bail!("selected RPC no longer reports the activation snapshot on its canonical chain");
        }
        self.verify_active_nodes(
            &matching_endpoints,
            &snapshot.block,
            &mut snapshot.nodes,
            true,
        )
        .await
    }

    async fn best_block(&self) -> Result<(Vec<RpcEndpoint>, BlockSnapshot)> {
        let endpoint = self.primary_endpoint()?.clone();
        let (_, block) = endpoint_block(&endpoint)
            .await
            .context("read the selected trusted RPC head")?;
        Ok((vec![endpoint], block))
    }
}

fn validate_trusted_rpc_receipt(receipt: &TransactionReceipt) -> Result<()> {
    if receipt.from.is_zero() || receipt.to.is_none() {
        bail!("receipt does not describe a signed contract transaction");
    }
    if receipt.block_hash.is_zero() || receipt.block_number == 0 {
        bail!("receipt has no valid block association");
    }
    if receipt.gas_used.is_zero() {
        bail!("receipt reports zero gas for a fee-paying EVM transaction");
    }
    if receipt.cumulative_gas_used < receipt.gas_used {
        bail!("receipt cumulative gas is lower than its gas usage");
    }
    if receipt
        .effective_gas_price
        .is_some_and(|price| price.is_zero())
    {
        bail!("receipt reports a zero effective gas price");
    }
    if !receipt.status && !receipt.logs.is_empty() {
        bail!("reverted EVM receipt unexpectedly contains logs");
    }
    for log in &receipt.logs {
        if log.removed || log.virtual_log {
            bail!("transaction receipt contains a removed or virtual log");
        }
        if log.block_number != Some(receipt.block_number)
            || log.block_hash != Some(receipt.block_hash)
            || log.transaction_hash != Some(receipt.transaction_hash)
            || log.transaction_index != Some(receipt.transaction_index)
            || log.log_index.is_none()
        {
            bail!("receipt log metadata does not match its enclosing transaction receipt");
        }
    }
    Ok(())
}

fn parse_rpc_log(log: ReceiptLogJson) -> Result<RpcLog> {
    let topics = log
        .topics
        .iter()
        .map(|topic| parse_hash(topic))
        .collect::<Result<Vec<_>>>()?;
    let data = log
        .data
        .strip_prefix("0x")
        .context("receipt log data has no 0x prefix")?;
    Ok(RpcLog {
        address: parse_address(&log.address)?,
        topics,
        data: Bytes::from(hex::decode(data).context("decode receipt log data")?),
        block_number: log
            .block_number
            .as_deref()
            .map(parse_hex_quantity)
            .transpose()?,
        block_hash: log.block_hash.as_deref().map(parse_hash).transpose()?,
        transaction_hash: log
            .transaction_hash
            .as_deref()
            .map(parse_hash)
            .transpose()?,
        transaction_index: log
            .transaction_index
            .as_deref()
            .map(parse_hex_quantity)
            .transpose()?,
        log_index: log
            .log_index
            .as_deref()
            .map(parse_hex_quantity)
            .transpose()?,
        removed: log.removed,
        virtual_log: log.virtual_log,
    })
}

async fn window_finalization_logs_range_at(
    endpoint: &RpcEndpoint,
    address: Address,
    token: Address,
    window_id: u64,
    from_block: u64,
    to_block: u64,
    telemetry: &HistoryTelemetry,
) -> Result<Vec<RpcLog>> {
    if from_block > to_block || to_block.saturating_sub(from_block) >= MAX_LOG_QUERY_RANGE {
        bail!("reward history range is outside the bounded RPC log-query size");
    }
    let window_topic = B256::from(U256::from(window_id).to_be_bytes::<32>());
    let topics = serde_json::json!([
        [
            format!("{:#x}", AstatineMinerRead::WindowFinalized::SIGNATURE_HASH),
            format!("{:#x}", AstatineMinerRead::RewardPaid::SIGNATURE_HASH),
        ],
        format!("{window_topic:#x}"),
    ]);
    let mut from_topic = [0_u8; 32];
    from_topic[12..].copy_from_slice(address.as_slice());
    let transfer_topics = serde_json::json!([
        format!("{:#x}", IERC20Read::Transfer::SIGNATURE_HASH),
        format!("{:#x}", B256::from(from_topic)),
    ]);
    telemetry.add(HistoryCounter::BlockRangesScanned, 1);
    let mut results = Vec::new();
    telemetry.add(HistoryCounter::GetLogsRequests, 1);
    let logs_started = Instant::now();
    let logs_result = rpc_request::<Vec<ReceiptLogJson>>(
        endpoint,
        "eth_getLogs",
        serde_json::json!([{
            "address": format!("{address:#x}"),
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{to_block:x}"),
            "topics": topics,
        }]),
    )
    .await
    .with_context(|| format!("query finalization logs for node window {window_id}"));
    telemetry.add_elapsed(HistoryDuration::HistoricalRpc, logs_started.elapsed());
    let logs = match logs_result {
        Ok(logs) => logs,
        Err(error) => {
            telemetry.add(HistoryCounter::RpcErrors, 1);
            return Err(error);
        }
    };
    results.extend(
        logs.into_iter()
            .map(parse_rpc_log)
            .collect::<Result<Vec<_>>>()?,
    );
    telemetry.add(HistoryCounter::GetLogsRequests, 1);
    let transfers_started = Instant::now();
    let transfers_result = rpc_request::<Vec<ReceiptLogJson>>(
        endpoint,
        "eth_getLogs",
        serde_json::json!([{
            "address": format!("{token:#x}"),
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{to_block:x}"),
            "topics": transfer_topics,
        }]),
    )
    .await
    .with_context(|| format!("query AST Transfer logs for node window {window_id}"));
    telemetry.add_elapsed(HistoryDuration::HistoricalRpc, transfers_started.elapsed());
    let transfers = match transfers_result {
        Ok(transfers) => transfers,
        Err(error) => {
            telemetry.add(HistoryCounter::RpcErrors, 1);
            return Err(error);
        }
    };
    results.extend(
        transfers
            .into_iter()
            .map(parse_rpc_log)
            .collect::<Result<Vec<_>>>()?,
    );
    Ok(results)
}

async fn connect_endpoint(name: &str, url: &str) -> Result<RpcEndpoint> {
    let url = validate_rpc_url(url).context("validate RPC endpoint URL")?;
    let client = reqwest::Client::builder()
        .timeout(RPC_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("create HTTPS JSON-RPC client")?;
    Ok(RpcEndpoint {
        name: name.to_owned(),
        url,
        client,
    })
}

async fn endpoint_block(endpoint: &RpcEndpoint) -> Result<(u64, BlockSnapshot)> {
    let number = rpc_request::<String>(endpoint, "eth_blockNumber", serde_json::json!([]))
        .await
        .and_then(|value| parse_hex_quantity(&value))
        .with_context(|| format!("read latest block from {}", endpoint.name))?;
    Ok((number, block_at(endpoint, number).await?))
}

async fn block_at(endpoint: &RpcEndpoint, number: u64) -> Result<BlockSnapshot> {
    let tag = format!("0x{number:x}");
    let block = rpc_request::<serde_json::Value>(
        endpoint,
        "eth_getBlockByNumber",
        serde_json::json!([tag, false]),
    )
    .await?;
    let timestamp = parse_hex_quantity(
        block
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .context("block response has no timestamp")?,
    )?;
    let observed_number = parse_hex_quantity(
        block
            .get("number")
            .and_then(serde_json::Value::as_str)
            .context("block response has no number")?,
    )?;
    if observed_number != number {
        bail!("RPC returned block {observed_number} for requested block {number}");
    }
    let hash = parse_hash(
        block
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .context("block response has no hash")?,
    )?;
    Ok(BlockSnapshot {
        number,
        timestamp,
        hash,
    })
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct RpcResponse<T> {
    #[serde(default)]
    result: RpcResult<T>,
    error: Option<RpcError>,
}

#[derive(Default)]
enum RpcResult<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for RpcResult<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

impl<T> RpcResponse<T> {
    fn result(self) -> Option<T> {
        match self.result {
            RpcResult::Missing => None,
            RpcResult::Present(result) => Some(result),
        }
    }
}

#[derive(Debug)]
struct ReceiptStatusUnavailable {
    details: String,
}

#[derive(Debug)]
struct TransientRpcFailure {
    details: String,
}

impl std::fmt::Display for TransientRpcFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "transient RPC failure: {}", self.details)
    }
}

impl std::error::Error for TransientRpcFailure {}

#[derive(Debug)]
struct RpcServerError {
    code: i64,
    message: String,
}

impl std::fmt::Display for RpcServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcServerError {}

impl std::fmt::Display for ReceiptStatusUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "receipt status unavailable: {}", self.details)
    }
}

impl std::error::Error for ReceiptStatusUnavailable {}

pub fn is_transient_receipt_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<ReceiptStatusUnavailable>().is_some())
}

pub fn is_transient_rpc_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<TransientRpcFailure>().is_some()
            || cause.downcast_ref::<reqwest::Error>().is_some_and(|rpc| {
                rpc.is_timeout()
                    || rpc.is_connect()
                    || rpc
                        .status()
                        .is_some_and(|status| status.is_server_error() || status.as_u16() == 429)
            })
            || cause
                .downcast_ref::<RpcServerError>()
                .is_some_and(|rpc| transient_json_rpc_error(rpc.code, &rpc.message))
    })
}

pub fn is_window_expired_revert(error: &anyhow::Error) -> bool {
    rpc_error_matches_contract_selector(error, AstatineMinerRead::WindowExpired::SELECTOR)
        || format!("{error:#}").contains("WindowExpired")
}

pub fn is_window_not_expired_revert(error: &anyhow::Error) -> bool {
    rpc_error_matches_contract_selector(error, AstatineMinerRead::WindowNotExpired::SELECTOR)
        || format!("{error:#}").contains("WindowNotExpired")
}

fn rpc_error_matches_contract_selector(error: &anyhow::Error, selector: [u8; 4]) -> bool {
    let selector = format!("0x{}", hex::encode(selector));
    error.chain().any(|cause| {
        cause
            .downcast_ref::<RpcServerError>()
            .is_some_and(|rpc| rpc.message.contains(&selector))
    })
}

fn transient_json_rpc_error(code: i64, message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    if message.contains("execution reverted") || message.contains("revert") {
        return false;
    }
    code == -32603
        || code == -32005
        || [
            "temporar",
            "unavailable",
            "rate limit",
            "too many requests",
            "timed out",
            "try again",
        ]
        .iter()
        .any(|marker| message.contains(marker))
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

async fn rpc_request<T: DeserializeOwned>(
    endpoint: &RpcEndpoint,
    method: &str,
    params: serde_json::Value,
) -> Result<T> {
    let mut response = endpoint
        .client
        .post(endpoint.url.clone())
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .map_err(|error| {
            anyhow::Error::new(error.without_url()).context(format!(
                "send {method} JSON-RPC request to {}",
                endpoint.name
            ))
        })?
        .error_for_status()
        .map_err(|error| {
            anyhow::Error::new(error.without_url()).context(format!(
                "{method} returned an HTTP error from {}",
                endpoint.name
            ))
        })?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
    {
        bail!(
            "{method} response from {} exceeds the 2 MiB limit",
            endpoint.name
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        anyhow::Error::new(error.without_url()).context(format!(
            "read {method} JSON-RPC response from {}",
            endpoint.name
        ))
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
            bail!(
                "{method} response from {} exceeds the 2 MiB limit",
                endpoint.name
            );
        }
        body.extend_from_slice(&chunk);
    }
    let response: RpcResponse<T> = serde_json::from_slice(&body)
        .with_context(|| format!("decode {method} JSON-RPC response from {}", endpoint.name))?;
    if let Some(error) = response.error {
        return Err(anyhow::Error::new(RpcServerError {
            code: error.code,
            message: redact_rpc_message(endpoint, &error.message),
        }))
        .with_context(|| format!("{method} JSON-RPC request to {}", endpoint.name));
    }
    response
        .result()
        .with_context(|| format!("{method} JSON-RPC response has no result"))
}

fn redact_rpc_message(endpoint: &RpcEndpoint, message: &str) -> String {
    let mut redacted = message.replace(endpoint.url.as_str(), "<rpc-url>");
    if let Some(query) = endpoint.url.query().filter(|query| !query.is_empty()) {
        redacted = redacted.replace(query, "<redacted-query>");
    }
    let path = endpoint.url.path();
    if path != "/" {
        redacted = redacted.replace(path, "/<redacted-path>");
    }
    redacted
}

async fn get_code(endpoint: &RpcEndpoint, address: Address, block: u64) -> Result<Bytes> {
    let result = rpc_request::<String>(
        endpoint,
        "eth_getCode",
        serde_json::json!([format!("{address:#x}"), format!("0x{block:x}")]),
    )
    .await?;
    let digits = result
        .strip_prefix("0x")
        .context("eth_getCode returned a value without a 0x prefix")?;
    Ok(Bytes::from(
        hex::decode(digits).context("eth_getCode returned malformed hex")?,
    ))
}

async fn get_balance(endpoint: &RpcEndpoint, address: Address, block: u64) -> Result<U256> {
    let result = rpc_request::<String>(
        endpoint,
        "eth_getBalance",
        serde_json::json!([format!("{address:#x}"), format!("0x{block:x}")]),
    )
    .await?;
    parse_hex_u256(&result)
}

async fn fetch_node_from_rpc(
    endpoint: &RpcEndpoint,
    manifest: &DeploymentManifest,
    pin: NodePin,
    pin_status: ContractPinStatus,
    block: BlockSnapshot,
) -> NodeView {
    let address = match parse_address(&pin.address) {
        Ok(address) => address,
        Err(error) => {
            return NodeView::unavailable(pin.id, Address::ZERO, pin_status, error.to_string());
        }
    };
    if !pin_status.runtime_verified || !pin_status.abi_verified {
        return NodeView::unavailable(
            pin.id,
            address,
            pin_status.clone(),
            pin_status
                .error
                .clone()
                .unwrap_or_else(|| "runtime or ABI pin is not trusted".to_owned()),
        );
    }

    let state = match fetch_node(endpoint, manifest, address, &block).await {
        Ok(state) => state,
        Err(error) => {
            return NodeView::unavailable(
                pin.id,
                address,
                pin_status,
                format!("selected RPC could not verify node state: {error:#}"),
            );
        }
    };
    NodeView {
        id: pin.id,
        address,
        pin: pin_status,
        state: Some(state),
        error: None,
    }
}

impl NodeView {
    fn unavailable(id: u8, address: Address, pin: ContractPinStatus, error: String) -> Self {
        Self {
            id,
            address,
            pin,
            state: None,
            error: Some(error),
        }
    }
}

async fn fetch_node(
    endpoint: &RpcEndpoint,
    manifest: &DeploymentManifest,
    address: Address,
    block: &BlockSnapshot,
) -> Result<NodeState> {
    let (work_bytes, candidate_bytes, mining_bytes, paused_bytes) = tokio::try_join!(
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::workCall {},
            block.number
        ),
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::candidateSummaryCall {},
            block.number
        ),
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::miningStateCall {},
            block.number
        ),
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::miningPausedCall {},
            block.number
        ),
    )?;
    let work = decode_work(&work_bytes)?;
    let candidate = decode_candidate(&candidate_bytes)?;
    let mining = decode_mining(&mining_bytes)?;
    let mining_paused = decode_return::<bool>(&paused_bytes)?;
    validate_coherent_state(&work, &mining)?;
    if work.submission_fee != U256::from(SUBMISSION_FEE_WEI) {
        bail!("on-chain submission fee does not match the 0.01 INJ protocol constant");
    }
    if let Some(candidate) = &candidate {
        if candidate.header.len() > work.max_header_length as usize {
            bail!("incumbent header exceeds the on-chain maximum header length");
        }
        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract: address,
            window_id: work.window_id,
            seed: work.seed,
            miner: candidate.miner,
            header: candidate.header.to_vec(),
        };
        let local_hash = WorkHasher::new(&context)?.hash(candidate.nonce);
        if local_hash != candidate.work_hash || !meets_target(local_hash, work.target) {
            bail!("incumbent candidate does not match the current seed/target state");
        }
    }
    let eligible = work.started
        && !work.ended
        && !mining_paused
        && block.timestamp <= work.window_expiry_time
        && !work.remaining_allocation.is_zero();
    let finalizable =
        work.started && !work.ended && !mining_paused && block.timestamp > work.window_expiry_time;
    let eligibility_reason = if !work.started {
        "not started"
    } else if work.ended || work.remaining_allocation.is_zero() {
        "ended or allocation exhausted"
    } else if mining_paused {
        "paused"
    } else if block.timestamp > work.window_expiry_time {
        "window expired; awaiting permissionless finalization"
    } else {
        "eligible"
    };
    Ok(NodeState {
        work,
        candidate,
        mining_paused,
        eligible,
        finalizable,
        eligibility_reason,
    })
}

fn validate_coherent_state(work: &WorkInfo, mining: &MiningInfo) -> Result<()> {
    if work.started != mining.started
        || work.ended != mining.ended
        || work.window_id != mining.window_id
        || work.seed != mining.seed
        || work.prev_hash != mining.prev_hash
        || work.target != mining.target
        || work.reward_per_window != mining.reward_per_window
    {
        bail!("work() and miningState() disagree at the same block");
    }
    if work.window_expiry_time < work.window_start_time
        || work.max_header_length == 0
        || work.max_header_length as usize > crate::protocol::MAX_HEADER_LENGTH
    {
        bail!("miner returned invalid window/header bounds");
    }
    Ok(())
}

async fn call_contract<C: SolCall>(
    endpoint: &RpcEndpoint,
    address: Address,
    call: C,
    block: u64,
) -> Result<Bytes> {
    let input = format!("0x{}", hex::encode(call.abi_encode()));
    let output = rpc_request::<String>(
        endpoint,
        "eth_call",
        serde_json::json!([
            { "to": format!("{address:#x}"), "data": input },
            format!("0x{block:x}")
        ]),
    )
    .await
    .with_context(|| format!("read contract {address:#x}"))?;
    let digits = output
        .strip_prefix("0x")
        .context("eth_call returned a value without a 0x prefix")?;
    Ok(Bytes::from(
        hex::decode(digits).context("eth_call returned malformed hex")?,
    ))
}

fn decode_work(data: &[u8]) -> Result<WorkInfo> {
    type Return = (
        bool,
        bool,
        u64,
        u64,
        u64,
        B256,
        B256,
        U256,
        U256,
        U256,
        u32,
        U256,
    );
    let (
        started,
        ended,
        window_id,
        window_start_time,
        window_expiry_time,
        seed,
        prev_hash,
        target,
        reward_per_window,
        remaining_allocation,
        max_header_length,
        submission_fee,
    ) = <Return as SolValue>::abi_decode_validate(data).context("decode work() ABI return")?;
    Ok(WorkInfo {
        started,
        ended,
        window_id,
        window_start_time,
        window_expiry_time,
        seed,
        prev_hash,
        target,
        reward_per_window,
        remaining_allocation,
        max_header_length,
        submission_fee,
    })
}

fn decode_candidate(data: &[u8]) -> Result<Option<CandidateInfo>> {
    let summary = AstatineMinerRead::candidateSummaryCall::abi_decode_returns_validate(data)
        .context("decode candidateSummary() ABI return")?;
    if !summary.exists {
        if summary.header.is_empty() {
            return Ok(None);
        }
        bail!("empty candidate state contains a nonempty header");
    }
    Ok(Some(CandidateInfo {
        miner: summary.miner,
        nonce: summary.nonce,
        work_hash: summary.workHash,
        submitted_at: summary.submittedAt,
        header: summary.header,
        first_valid_solve_secs: summary.firstValidSolveSecs,
    }))
}

fn decode_mining(data: &[u8]) -> Result<MiningInfo> {
    type Return = (
        bool,
        bool,
        u64,
        u64,
        u64,
        u16,
        U256,
        U256,
        U256,
        U256,
        B256,
        B256,
    );
    let (
        started,
        ended,
        window_id,
        _last_retarget_window_id,
        _ema_solve_secs,
        _halving_index,
        reward_per_window,
        _total_distributed,
        _next_halving_threshold,
        target,
        seed,
        prev_hash,
    ) = <Return as SolValue>::abi_decode_validate(data)
        .context("decode miningState() ABI return")?;
    Ok(MiningInfo {
        started,
        ended,
        window_id,
        reward_per_window,
        target,
        seed,
        prev_hash,
    })
}

fn decode_return<T>(data: &[u8]) -> Result<T>
where
    T: SolValue + From<<T::SolType as SolType>::RustType>,
{
    T::abi_decode_validate(data).context("decode Solidity view return")
}

fn parse_hex_quantity(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .context("RPC quantity has no 0x prefix")?;
    u64::from_str_radix(digits, 16).context("RPC quantity is outside uint64")
}

fn parse_hex_u256(value: &str) -> Result<U256> {
    let digits = value
        .strip_prefix("0x")
        .context("RPC quantity has no 0x prefix")?;
    U256::from_str_radix(digits, 16).context("RPC quantity is outside uint256")
}

#[cfg(test)]
mod tests {
    use super::{
        MiningInfo, NetworkClient, RpcEndpoint, RpcResponse, RpcResult, SUBMISSION_FEE_WEI,
        WorkInfo, decode_candidate, decode_mining, decode_work, is_transient_receipt_error,
        is_transient_rpc_error, is_window_expired_revert, is_window_not_expired_revert,
        rpc_request, validate_coherent_state, validate_trusted_rpc_receipt,
    };
    use crate::deployment::NodePin;
    use alloy_primitives::{Address, B256, Bytes, U256, hex};
    use alloy_sol_types::{SolCall, SolValue};
    use reqwest::Url;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
        time::Duration,
    };

    fn mock_endpoint(name: &str, responses: Vec<(u16, String)>) -> (RpcEndpoint, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                read_http_request(&mut stream);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let endpoint = RpcEndpoint {
            name: name.to_owned(),
            url: Url::parse(&format!("http://{address}")).unwrap(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
        };
        (endpoint, server)
    }

    fn unreachable_endpoint(name: &str) -> RpcEndpoint {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        RpcEndpoint {
            name: name.to_owned(),
            url: Url::parse(&format!("http://{address}")).unwrap(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn slow_rpc_chain_id_request_times_out_and_remains_retryable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_http_request(&mut stream);
            thread::sleep(Duration::from_millis(1_500));
            let body = rpc_result(serde_json::json!("0x59f"));
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        let endpoint = RpcEndpoint {
            name: "delayed-primary".to_owned(),
            url: Url::parse(&format!("http://{address}")).unwrap(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap(),
        };

        let error = rpc_request::<String>(&endpoint, "eth_chainId", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_transient_rpc_error(&error));
        server.join().unwrap();
    }

    fn read_http_request(stream: &mut TcpStream) {
        let mut received = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "RPC client closed before sending its request");
            received.extend_from_slice(&chunk[..count]);
            let Some(header_end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&received[..header_end]);
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if received.len() >= header_end + 4 + content_length {
                return;
            }
        }
    }

    fn rpc_result(result: serde_json::Value) -> String {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
    }

    fn receipt_result(hash: B256, block_hash: B256) -> String {
        rpc_result(serde_json::json!({
            "transactionHash": format!("{hash:#x}"),
            "transactionIndex": "0x0",
            "from": format!("{:#x}", Address::with_last_byte(0x11)),
            "to": format!("{:#x}", Address::with_last_byte(0x22)),
            "status": "0x1",
            "gasUsed": "0x5208",
            "cumulativeGasUsed": "0x5208",
            "effectiveGasPrice": "0x2",
            "type": "0x2",
            "blockNumber": "0x10",
            "blockHash": format!("{block_hash:#x}"),
            "logs": [],
        }))
    }

    fn transaction_result(hash: B256) -> String {
        rpc_result(serde_json::json!({
            "hash": format!("{hash:#x}"),
            "chainId": "0x59f",
            "from": format!("{:#x}", Address::with_last_byte(0x11)),
            "to": format!("{:#x}", Address::with_last_byte(0x22)),
            "nonce": "0x0",
            "value": "0x0",
            "gas": "0x5208",
            "input": "0x",
            "gasPrice": "0x2",
            "maxFeePerGas": "0x2",
            "maxPriorityFeePerGas": "0x1",
            "type": "0x2",
        }))
    }

    #[tokio::test]
    async fn transaction_details_decode_signed_intent_fields_from_rpc() {
        let hash = B256::with_last_byte(0x91);
        let (endpoint, server) = mock_endpoint("primary", vec![(200, transaction_result(hash))]);
        let client = network_client(vec![endpoint]);

        let transaction = client.transaction_details(hash).await.unwrap().unwrap();
        assert_eq!(transaction.hash, hash);
        assert_eq!(transaction.chain_id, Some(1439));
        assert_eq!(transaction.from, Address::with_last_byte(0x11));
        assert_eq!(transaction.to, Some(Address::with_last_byte(0x22)));
        assert_eq!(transaction.nonce, 0);
        assert_eq!(transaction.value, U256::ZERO);
        assert_eq!(transaction.gas_limit, 21_000);
        assert!(transaction.input.is_empty());
        assert_eq!(transaction.gas_price, Some(U256::from(2)));
        assert_eq!(transaction.max_fee_per_gas, Some(U256::from(2)));
        assert_eq!(transaction.max_priority_fee_per_gas, Some(U256::from(1)));
        assert_eq!(transaction.transaction_type, Some(2));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn custom_rpc_validation_requires_the_selected_network_chain_id() {
        let (endpoint, server) = mock_endpoint(
            "custom",
            vec![(200, rpc_result(serde_json::json!("0x59f")))],
        );
        let url = endpoint.url.to_string();
        NetworkClient::validate_rpc_endpoint(crate::cli::Network::Testnet, &url)
            .await
            .unwrap();
        server.join().unwrap();

        let (endpoint, server) = mock_endpoint(
            "wrong-chain",
            vec![(200, rpc_result(serde_json::json!("0x6f0")))],
        );
        let url = endpoint.url.to_string();
        let error = NetworkClient::validate_rpc_endpoint(crate::cli::Network::Testnet, &url)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("expected 1439"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn custom_primary_with_wrong_chain_is_rejected_without_fallback() {
        let (endpoint, server) = mock_endpoint(
            "custom",
            vec![(200, rpc_result(serde_json::json!("0x6f0")))],
        );
        let url = endpoint.url.to_string();
        let error = NetworkClient::connect_with_rpc(crate::cli::Network::Testnet, Some(&url))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("expected 1439"));
        server.join().unwrap();
    }

    #[test]
    fn node_work_and_mining_state_must_match_at_selected_block() {
        let work = WorkInfo {
            started: true,
            ended: false,
            window_id: 7,
            window_start_time: 100,
            window_expiry_time: 160,
            seed: B256::with_last_byte(1),
            prev_hash: B256::with_last_byte(2),
            target: U256::MAX,
            reward_per_window: U256::from(3),
            remaining_allocation: U256::from(4),
            max_header_length: 64,
            submission_fee: U256::from(SUBMISSION_FEE_WEI),
        };
        let mining = MiningInfo {
            started: true,
            ended: false,
            window_id: 7,
            reward_per_window: U256::from(3),
            target: U256::MAX,
            seed: B256::with_last_byte(1),
            prev_hash: B256::with_last_byte(2),
        };
        assert!(validate_coherent_state(&work, &mining).is_ok());

        let mut inconsistent = mining;
        inconsistent.target = U256::from(1);
        let error = validate_coherent_state(&work, &inconsistent).unwrap_err();
        assert!(format!("{error:#}").contains("work() and miningState() disagree"));
    }

    #[test]
    fn trusted_rpc_receipt_rejects_logs_not_bound_to_its_inclusion_metadata() {
        let hash = B256::with_last_byte(0x91);
        let block_hash = B256::with_last_byte(0x92);
        let log = super::RpcLog {
            address: Address::with_last_byte(0x93),
            topics: Vec::new(),
            data: Bytes::new(),
            block_number: Some(10),
            block_hash: Some(block_hash),
            transaction_hash: Some(hash),
            transaction_index: Some(2),
            log_index: Some(7),
            removed: false,
            virtual_log: false,
        };
        let receipt = super::TransactionReceipt {
            transaction_hash: hash,
            transaction_index: 2,
            from: Address::with_last_byte(0x94),
            to: Some(Address::with_last_byte(0x95)),
            status: true,
            gas_used: U256::from(21_000),
            cumulative_gas_used: U256::from(42_000),
            effective_gas_price: Some(U256::from(1)),
            transaction_type: Some(2),
            block_number: 10,
            block_hash,
            logs: vec![log],
        };
        assert!(validate_trusted_rpc_receipt(&receipt).is_ok());

        let mut forged = receipt.clone();
        forged.logs[0].transaction_hash = Some(B256::with_last_byte(0x96));
        assert!(validate_trusted_rpc_receipt(&forged).is_err());

        let mut virtual_event = receipt;
        virtual_event.logs[0].virtual_log = true;
        assert!(validate_trusted_rpc_receipt(&virtual_event).is_err());
    }

    fn block_result(number: u64, timestamp: u64, hash: B256) -> String {
        rpc_result(serde_json::json!({
            "number": format!("0x{number:x}"),
            "timestamp": format!("0x{timestamp:x}"),
            "hash": format!("{hash:#x}"),
        }))
    }

    fn work_result(started: bool, ended: bool, remaining_allocation: U256) -> String {
        let work = (
            started,
            ended,
            0_u64,
            100_u64,
            160_u64,
            B256::with_last_byte(1),
            B256::ZERO,
            U256::MAX,
            U256::from(1_000_u64),
            remaining_allocation,
            64_u32,
            U256::from(SUBMISSION_FEE_WEI),
        )
            .abi_encode();
        rpc_result(serde_json::json!(format!("0x{}", hex::encode(work))))
    }

    fn genesis_probe_responses(node_count: usize, started: bool) -> Vec<(u16, String)> {
        let mut responses = vec![
            (200, rpc_result(serde_json::json!("0x1"))),
            (200, block_result(1, 100, B256::with_last_byte(1))),
        ];
        responses.extend(
            (0..node_count).map(|_| (200, work_result(started, false, U256::from(100_u64)))),
        );
        responses
    }

    fn network_client(endpoints: Vec<RpcEndpoint>) -> NetworkClient {
        let primary_url = endpoints
            .iter()
            .find(|endpoint| endpoint.name == "primary")
            .unwrap()
            .url
            .as_str();
        let mut client = NetworkClient::local_test_client(
            primary_url,
            Address::with_last_byte(1),
            B256::with_last_byte(2),
            Address::with_last_byte(3),
            B256::with_last_byte(4),
            9,
        )
        .unwrap();
        client.archival_endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.name == "archival")
            .cloned();
        client.endpoints = vec![
            endpoints
                .into_iter()
                .find(|endpoint| endpoint.name == "primary")
                .unwrap(),
        ];
        client
    }

    #[tokio::test]
    async fn trusted_snapshot_uses_only_the_selected_primary_rpc() {
        let block_hash = B256::with_last_byte(0x31);
        let (primary, primary_server) = mock_endpoint(
            "primary",
            vec![
                (200, rpc_result(serde_json::json!("0x10"))),
                (200, block_result(16, 100, block_hash)),
            ],
        );
        let archival = unreachable_endpoint("archival");
        let client = network_client(vec![primary, archival]);

        let (endpoints, block) = client.best_block().await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "primary");
        assert_eq!(block.hash, block_hash);
        primary_server.join().unwrap();
    }

    #[tokio::test]
    async fn genesis_probe_reads_only_selected_nodes_with_bounded_concurrency() {
        let (endpoint, server) = mock_endpoint("primary", genesis_probe_responses(3, false));
        let mut client = network_client(vec![endpoint]);
        client.manifest.nodes = (1..=9)
            .map(|id| NodePin {
                id,
                address: format!("{:#x}", Address::with_last_byte(id)),
                runtime_code_hash: format!("{:#x}", B256::with_last_byte(id)),
            })
            .collect();

        let refresh = client.poll_genesis(&[1, 3, 5]).await.unwrap();
        assert!(
            refresh.is_empty(),
            "unstarted nodes are not activation candidates"
        );
        let observations = client.genesis_poll_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].node_ids, [1, 3, 5]);
        assert!(
            observations[0].max_concurrent_node_reads <= 3,
            "genesis probe must cap node reads at its configured concurrency"
        );
        assert!(observations[0].completed_at >= observations[0].started_at);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn genesis_probe_only_signals_activation_candidates_for_full_refresh() {
        let (endpoint, server) = mock_endpoint("primary", genesis_probe_responses(1, true));
        let client = network_client(vec![endpoint]);

        assert_eq!(client.poll_genesis(&[1]).await.unwrap(), [1]);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn genesis_poll_recovers_after_a_transient_rpc_failure() {
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![
                (200, rpc_result(serde_json::json!("0x1"))),
                (200, block_result(1, 100, B256::with_last_byte(1))),
                (503, "{}".to_owned()),
                (200, rpc_result(serde_json::json!("0x1"))),
                (200, block_result(1, 100, B256::with_last_byte(1))),
                (200, work_result(false, false, U256::from(100_u64))),
            ],
        );
        let client = network_client(vec![endpoint]);

        assert!(client.poll_genesis(&[1]).await.is_err());
        assert!(client.poll_genesis(&[1]).await.unwrap().is_empty());
        let observations = client.genesis_poll_observations();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].node_ids, [1]);
        assert_eq!(observations[1].node_ids, [1]);
        server.join().unwrap();
    }

    #[test]
    fn optional_result_distinguishes_explicit_null_from_missing_field() {
        let pending: RpcResponse<Option<serde_json::Value>> =
            serde_json::from_str(r#"{"result":null}"#).unwrap();
        assert!(matches!(pending.result, RpcResult::Present(None)));

        let missing: RpcResponse<Option<serde_json::Value>> = serde_json::from_str("{}").unwrap();
        assert!(matches!(missing.result, RpcResult::Missing));
    }

    #[tokio::test]
    async fn null_receipt_and_transaction_results_are_valid_pending_responses() {
        let hash = B256::with_last_byte(0x51);
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![(200, rpc_result(serde_json::Value::Null)); 2],
        );
        let client = network_client(vec![endpoint]);

        assert!(client.transaction_receipt(hash).await.unwrap().is_none());
        assert!(!client.transaction_known(hash).await.unwrap());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn pending_receipt_transitions_to_confirmed_receipt() {
        let hash = B256::with_last_byte(0x61);
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![
                (200, rpc_result(serde_json::Value::Null)),
                (200, receipt_result(hash, B256::with_last_byte(0x71))),
            ],
        );
        let client = network_client(vec![endpoint]);

        assert!(client.transaction_receipt(hash).await.unwrap().is_none());
        let receipt = client.transaction_receipt(hash).await.unwrap().unwrap();
        assert_eq!(receipt.transaction_hash, hash);
        assert_eq!(receipt.block_hash, B256::with_last_byte(0x71));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn custom_primary_receipt_lookup_never_substitutes_the_archival_endpoint() {
        let hash = B256::with_last_byte(0x62);
        let (primary, primary_server) =
            mock_endpoint("primary", vec![(200, rpc_result(serde_json::Value::Null))]);
        let archival = unreachable_endpoint("archival");
        let mut client = network_client(vec![primary, archival]);
        client.custom_primary = true;

        assert!(client.transaction_receipt(hash).await.unwrap().is_none());
        primary_server.join().unwrap();
    }

    #[tokio::test]
    async fn custom_primary_historical_reads_do_not_silently_fall_back_to_archival() {
        let (primary, primary_server) = mock_endpoint("primary", vec![(503, "{}".to_owned())]);
        let archival = unreachable_endpoint("archival");
        let mut client = network_client(vec![primary, archival]);
        client.custom_primary = true;

        let error = client
            .window_finalization_logs_range(
                Address::with_last_byte(1),
                Address::with_last_byte(2),
                0,
                10,
                10,
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("selected custom RPC"));
        primary_server.join().unwrap();
    }

    #[tokio::test]
    async fn transaction_lookup_follows_the_selected_primary_rpc() {
        let hash = B256::with_last_byte(0x63);
        let transaction = transaction_result(hash);
        let (primary, primary_server) = mock_endpoint(
            "primary",
            vec![
                (200, rpc_result(serde_json::Value::Null)),
                (200, transaction.clone()),
            ],
        );
        let archival = unreachable_endpoint("archival");
        let client = network_client(vec![primary, archival]);

        assert!(client.transaction_details(hash).await.unwrap().is_none());
        assert_eq!(
            client
                .transaction_details(hash)
                .await
                .unwrap()
                .unwrap()
                .hash,
            hash
        );
        primary_server.join().unwrap();
    }

    #[tokio::test]
    async fn absent_result_is_an_error_and_json_rpc_errors_are_preserved() {
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![(200, r#"{"jsonrpc":"2.0","id":1}"#.to_owned())],
        );
        let error = rpc_request::<Option<serde_json::Value>>(
            &endpoint,
            "eth_getTransactionReceipt",
            serde_json::json!([format!("{:#x}", B256::with_last_byte(0x81))]),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("response has no result"));
        server.join().unwrap();

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "temporary provider failure"},
        })
        .to_string();
        let (endpoint, server) = mock_endpoint("primary", vec![(200, body)]);
        let error = rpc_request::<Option<serde_json::Value>>(
            &endpoint,
            "eth_getTransactionByHash",
            serde_json::json!([format!("{:#x}", B256::with_last_byte(0x82))]),
        )
        .await
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("JSON-RPC error -32000"));
        assert!(message.contains("temporary provider failure"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn all_transient_receipt_endpoint_errors_are_retryable() {
        let (primary, primary_server) = mock_endpoint("primary", vec![(503, "{}".to_owned())]);
        let client = network_client(vec![primary]);
        let error = client
            .transaction_receipt(B256::with_last_byte(0xa1))
            .await
            .unwrap_err();

        assert!(is_transient_receipt_error(&error));
        assert!(
            format!("{error:#}")
                .contains("selected RPC receipt request is temporarily unavailable")
        );
        primary_server.join().unwrap();
    }

    #[tokio::test]
    async fn transient_rpc_failures_are_retryable_but_contract_reverts_are_not() {
        let (endpoint, server) = mock_endpoint("primary", vec![(503, "{}".to_owned())]);
        let error = rpc_request::<String>(&endpoint, "eth_blockNumber", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_transient_rpc_error(&error));
        server.join().unwrap();

        let rate_limit = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32005, "message": "rate limit exceeded"},
        })
        .to_string();
        let (endpoint, server) = mock_endpoint("primary", vec![(200, rate_limit)]);
        let error = rpc_request::<String>(&endpoint, "eth_estimateGas", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_transient_rpc_error(&error));
        server.join().unwrap();

        let revert = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "execution reverted: WindowNotExpired"},
        })
        .to_string();
        let (endpoint, server) = mock_endpoint("primary", vec![(200, revert)]);
        let error = rpc_request::<String>(&endpoint, "eth_estimateGas", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(!is_transient_rpc_error(&error));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn canonical_expiry_reverts_are_distinguished_from_provider_failures() {
        let expired = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": 3, "message": "execution reverted: custom error 0x7bbfb6fe"},
        })
        .to_string();
        let (endpoint, server) = mock_endpoint("primary", vec![(200, expired)]);
        let error = rpc_request::<String>(&endpoint, "eth_estimateGas", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_window_expired_revert(&error));
        assert!(!is_transient_rpc_error(&error));
        server.join().unwrap();

        let not_expired = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": 3, "message": "execution reverted: custom error 0xd5bd6e95"},
        })
        .to_string();
        let (endpoint, server) = mock_endpoint("primary", vec![(200, not_expired)]);
        let error = rpc_request::<String>(&endpoint, "eth_estimateGas", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_window_not_expired_revert(&error));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_content_from_the_selected_primary_is_used_as_trusted_input() {
        let hash = B256::with_last_byte(0xb1);
        let (primary, primary_server) = mock_endpoint(
            "primary",
            vec![(200, receipt_result(hash, B256::with_last_byte(0xb2)))],
        );
        let archival = unreachable_endpoint("archival");
        let client = network_client(vec![primary, archival]);
        let receipt = client.transaction_receipt(hash).await.unwrap().unwrap();

        assert_eq!(receipt.block_hash, B256::with_last_byte(0xb2));
        primary_server.join().unwrap();
    }

    #[test]
    fn decodes_source_shaped_work_and_mining_tuples() {
        let work = (
            true,
            false,
            7_u64,
            100_u64,
            160_u64,
            B256::with_last_byte(1),
            B256::with_last_byte(2),
            U256::MAX,
            U256::from(3),
            U256::from(4),
            64_u32,
            U256::from(SUBMISSION_FEE_WEI),
        )
            .abi_encode();
        let decoded_work = decode_work(&work).unwrap();
        assert_eq!(decoded_work.window_id, 7);
        assert_eq!(decoded_work.window_expiry_time, 160);
        assert_eq!(decoded_work.target, U256::MAX);

        let mining = (
            true,
            false,
            7_u64,
            0_u64,
            12_u64,
            0_u16,
            U256::from(3),
            U256::from(4),
            U256::from(5),
            U256::MAX,
            B256::with_last_byte(1),
            B256::with_last_byte(2),
        )
            .abi_encode();
        let decoded_mining = decode_mining(&mining).unwrap();
        assert_eq!(decoded_mining.window_id, decoded_work.window_id);
        assert_eq!(decoded_mining.seed, decoded_work.seed);
    }

    #[test]
    fn decodes_dynamic_candidate_summary_return_shape() {
        use crate::contracts::AstatineMinerRead;

        let candidate = AstatineMinerRead::CandidateInfo {
            exists: true,
            miner: Address::with_last_byte(1),
            nonce: u128::MAX,
            workHash: B256::with_last_byte(2),
            submittedAt: 3,
            header: Bytes::from_static(b"abc"),
            firstValidSolveSecs: 4,
        };
        let encoded = AstatineMinerRead::candidateSummaryCall::abi_encode_returns(&candidate);
        let decoded = decode_candidate(&encoded).unwrap().unwrap();
        assert_eq!(decoded.nonce, u128::MAX);
        assert_eq!(decoded.header.as_ref(), b"abc");

        let empty = AstatineMinerRead::CandidateInfo {
            exists: false,
            miner: Address::ZERO,
            nonce: 0,
            workHash: B256::ZERO,
            submittedAt: 0,
            header: Bytes::new(),
            firstValidSolveSecs: 0,
        };
        let empty = AstatineMinerRead::candidateSummaryCall::abi_encode_returns(&empty);
        assert!(decode_candidate(&empty).unwrap().is_none());
    }
}
