# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on CPUs or compatible GPUs; Injective contracts verify submissions and settle each work window on-chain. GPU acceleration does not change the canonical SHA-256d work algorithm.

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nodes or select specific nodes.

## Install

Testnet.13 candidate installers verify the signed release manifest and the platform archive digest before installation. No root or administrator access is required. The installer replaces only the executable and license notices; configuration, wallets, and transaction journals are left untouched. The manifest is signed with the RSA release key pinned in the client and installer scripts.

### macOS and Linux

Requires `curl`, `openssl`, `tar`, and `install`. Supported targets are Apple Silicon and Intel macOS, plus x86_64 and aarch64 Linux (glibc 2.35 or later).

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.13/support/install-unix.sh | sh
```

To download and review the installer before executing it:

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.13/support/install-unix.sh -o "$HOME/astatine-install-unix.sh"
less "$HOME/astatine-install-unix.sh"
sh "$HOME/astatine-install-unix.sh"
```

Apple Silicon requires macOS 11 or later; Intel requires macOS 10.12 or later. The executable and license notices are installed under `~/.local/bin`; add that directory to `PATH` if needed. Linux configuration, wallets, and transaction journals use `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`.

### Windows PowerShell

Supported target: Windows 10 or later, x86_64. The executable is installed under your user profile.

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.13/support/install-windows.ps1' -OutFile $Installer; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

To download and review the PowerShell installer before executing it:

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.13/support/install-windows.ps1' -OutFile $Installer
Get-Content -LiteralPath $Installer -Raw
# After reviewing the script:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Add `$HOME\bin` to your user `Path`, then open a new PowerShell window and verify with `astatine.exe --version`. Configuration, wallets, and transaction journals remain in `%APPDATA%\Astatine`.

### Authenticated updates

`astatine update --check` verifies the signed release manifest and reports whether a newer Testnet release is available without downloading an executable. `astatine update` checks the signed manifest, downloads the matching executable and license notices, validates sizes and SHA-256 digests, smoke-tests the new executable, then replaces the installed files with rollback on failure. Windows uses a helper that waits for the updater process to exit before replacing the running executable. Mining checks for newer signed releases in a background task and adds a dashboard notification; it never updates or restarts a running miner automatically. Updates do not modify configuration, wallets, or transaction journals.

### GPU mining

CPU remains the default and requires no GPU driver:

```sh
astatine mine --device cpu
```

Use a validated physical GPU explicitly, or request GPU preference with automatic CPU fallback:

```sh
astatine mine --device gpu
astatine mine --device auto
astatine mine --device gpu --nodes 1,3,5
astatine mine --device gpu --compute-only
```

Explicit `gpu` mode stops with an actionable error if no physical adapter passes the actual WGSL SHA-256d self-test. It never silently becomes CPU mining. `auto` performs a short canonical-work comparison and chooses GPU only when its measured throughput is more than 10% faster than CPU; otherwise it chooses CPU. Auto mode also falls back to CPU if GPU operation later fails. Any in-flight GPU nonce range is abandoned on failure, not reassigned. `--threads` controls CPU mining workers; GPU mode uses a dedicated controller and does not start the full CPU mining pool.

Every GPU candidate is rehashed with the canonical Rust `WorkHasher` before it enters the existing bounded proof inbox. The existing proof preflight, journal, signing, submission, finalization, and reward-reconciliation paths remain authoritative. The GPU module does not own wallets, RPC connections, or transaction signing.

### Starting before genesis

Testnet.12 can be started before selected mining contracts activate. Verified, inactive nodes show `WAIT GENESIS`; when all selected nodes are inactive the dashboard shows `WAITING FOR GENESIS`. The observer checks selected inactive nodes approximately once per second with read-only `work()` calls and a bounded three-node concurrency limit. Active nodes keep the normal observer cadence.

An activation candidate triggers the existing canonical full-snapshot path. The miner rechecks the chain ID, pinned runtime code, ABI coherence and canonical Rust/Solidity `computeWorkHash` parity before publishing eligible work to the existing node scheduler. Partial activation is handled independently per node; nine-node atomic Coordinator activation is discovered by the same mechanism. The CLI never calls `activateGenesis()` or the Coordinator, never asks the user to restart, and does not create mining nonce ranges or paid transactions for unstarted nodes. There is no new init configuration.

```sh
astatine mine --device gpu --nodes 1,2,3,4,5,6,7,8,9
```

The existing proof verification, spending cap, minimum reserve, transaction journal, recovery, and reorganization handling remain in force after activation. Automatic AST reward forwarding is disabled in Testnet.13 because the selected RPC can fabricate reward evidence.

Inspect local compute adapters and run their real shader self-test without connecting to RPC or unlocking a wallet:

```sh
astatine devices
```

The wgpu backends target Metal on macOS, Direct3D 12 or Vulkan on Windows, and Vulkan on Linux. Driver and hardware support varies:

| Platform / GPU | Preferred backend | Testnet.12 evidence |
|---|---|---|
| Apple Silicon · Apple M4 | Metal | Physical shader parity, three-window mining/reward reconciliation, 1/3/9-node genesis activation, and one-second pre-genesis polling tested |
| Intel macOS GPU | Metal | Native target CI passes; physical GPU runtime not tested |
| NVIDIA / AMD Windows GPU | Direct3D 12 or Vulkan | Native Windows CI passes; physical GPU runtime not tested |
| NVIDIA / AMD Linux GPU | Vulkan | Native Linux CI passes; physical GPU runtime not tested |

Adapter enumeration or a successful native build is not itself a GPU correctness test.

Run a local, read-only CPU/GPU benchmark on identical canonical work (no wallet or RPC required):

```sh
astatine benchmark
astatine benchmark --seconds 10 --threads 4
```

The report includes three repeated CPU/GPU samples by default, compares results with the supplied Testnet.11 M4/Metal reference and historical Testnet.10 reference, separates initialization/self-test time from timed throughput, and records host-stage timings and JSON output when requested. GPU compute timestamps are reported only where supported; otherwise dispatch-to-readback is identified as wall latency. `--profile` sweeps all supported batch and workgroup sizes; `--compare-full-sha` compares full SHA-256 with the cached-midstate path, and `--serial` disables the bounded two-batch overlap for comparison. Example:

```sh
astatine benchmark --seconds 10 --threads 4 --batch-size 262144 --workgroup-size 32 --compare-full-sha --output-json gpu-ab.json
```

Use measured results for the installed hardware. The GPU shader implements SHA-256d only; it does not alter the PoW protocol.

The Testnet.11 M4/Metal reference supplied for this release is `69.102 MH/s` GPU median and `23.284 MH/s` CPU median (four CPU workers). A fresh comparable Testnet.12 run measured GPU `68.689 MH/s` median (`68.689`, `68.677`, `68.738 MH/s`) and CPU `22.304 MH/s` median (`22.727`, `22.304`, `22.126 MH/s`). Across fifteen local Testnet.12 samples, the combined GPU median is `68.568 MH/s`. The GPU shader and compute pipeline were not changed. Full per-run samples, methodology, genesis activation latencies, and timing limitations are in [the Testnet.12 performance report](support/testnet12-performance.md). Metal exposes no wgpu GPU timestamp queries on this adapter, so dispatch-to-readback is wall latency, not isolated shader time. These are measured results, not a guarantee across devices; run `astatine benchmark` on the target hardware.

Release manifests are authenticated by a pinned RSA-3072 key in addition to
HTTPS. The currently embedded key's SHA-256 SubjectPublicKeyInfo fingerprint is
`7a89234d5b269bb5372eab957e66307e321f4d9de9a550f7a2d7a6783cc50650`. This
owner-supplied key is integrated across the Rust updater, Unix/Windows
installers, and release validators; `support/release-key-fingerprint.txt`
contains the matching active fingerprint. Before signing, the offline signer
requires the selected private key to derive this exact public anchor. Replacing
the pin means existing Testnet.12 clients with the legacy key cannot verify
releases signed only by the new key. This candidate does not include a
backward-compatible bridge; clients that require automatic updates from
Testnet.12 need a migration path before release. macOS binaries are not
Developer ID signed or notarized, and Windows binaries are not Authenticode
signed.

GitHub Actions only builds/tests unsigned artifacts and creates provenance for
the exact source commit. Creating a tag does not publish a release. The owner
downloads and independently verifies the asset attestations, signs the manifest
offline, then explicitly publishes the signed 15-asset inventory with
`support/publish_signed_release.py`. See
[`support/OFFLINE_RELEASE_PROCESS.md`](support/OFFLINE_RELEASE_PROCESS.md) for
the owner commands and recovery behavior. To inspect build provenance for an
unsigned package, use:

```sh
gh attestation verify astatine-linux-x86_64.tar.gz \
  --repo "$(tr -d '\n' < support/release-repository.txt)"
```

## Use

```sh
astatine init
astatine mine
astatine mine --device cpu
astatine mine --device gpu --nodes 1,2,3,4,5,6,7,8,9
astatine mine --device auto --nodes 1,3,5
astatine mine --device gpu --compute-only
astatine devices
astatine benchmark
astatine update
astatine update --check
```

`astatine init` configures the wallet, network, RPC, CPU budget, reserve, authorization cap, and confirmation depth. Startup shows configuration, RPC/deployment checks, transaction recovery, wallet unlock, initial work, worker preparation and when historical reward reconciliation is scheduled; detailed history counters are hidden during ordinary startup. Historical reward reconciliation runs in the background so live proof work can continue while older events are checked against the selected RPC. Interactive terminals use a subtle spinner, while redirected output uses plain-text progress. The mining dashboard shows live node state, RPC-reported INJ and AST balances, RPC-reported rewards for the current invocation, hashrate, transaction state, cumulative maximum authorization, remaining authorization budget, and RPC-reported actual cost. It distinguishes proof checking, signed-but-not-yet-broadcast, broadcast/confirmation, chain waiting, required/retrying finalization, and policy-blocked finalization. Autonomous mining retains the best queued proof per node in a bounded inbox, revalidates it against current work, and reports bounded per-node proof-pipeline counters on exit. `--compute-only` hashes locally without unlocking a wallet or sending transactions. Use `--nodes 1,3,5` to restrict mining to selected nodes.

Automatic AST reward forwarding is disabled in Testnet.13. Passing `--send-rewards-to ADDRESS` is rejected with an explanation: a selected RPC can fabricate a mutually consistent proof receipt, payout events, balances, and confirmations, which could otherwise authorize a real AST transfer from the mining wallet. Reward reconciliation and the `MINED` display remain available, but they are based on selected-RPC data and are not independent proof of payout. Verify a reward through an independent trusted source before making any manual transfer.

Set `ASTATINE_HISTORY_PROFILE=1` before `astatine mine` (or `$env:ASTATINE_HISTORY_PROFILE='1'` in PowerShell) to print aggregate history profiling at startup and shutdown for developer diagnostics. The profile contains counters and timings only. Normal startup continues to display actionable transaction/RPC warnings and the background reward-verification status without the aggregate dump.

New encrypted Ethereum V3 keystores require passwords of at least 12 Unicode characters and at most 1024 bytes. Input is hidden and confirmed. A brief, non-blocking warning recommends a longer unique passphrase when fewer than 16 characters are chosen. This applies to new wallets and mnemonic imports; importing an existing V3 keystore continues to use its original password without a new minimum.

**Transaction costs and authorization cap:** Each proof submission pays a `0.01 INJ` fee. Finalizing a window consumes INJ gas, including when the window is empty or another miner wins. For every signed transaction, Astatine durably charges `gas_limit × max_fee_per_gas + transaction_value` against the session cap before producing the signature. That maximum authorization is cumulative and is never refunded or reduced by RPC receipts, reported gas usage, or a completed transaction. The dashboard separates maximum authorized exposure from RPC-reported actual costs. A positive cap authorizes spending; the default zero cap disables signing. Use `astatine mine --new-session` to explicitly start a separate session after a prior spending session has been closed. It is refused while transactions are unresolved. Mainnet transaction signing is disabled.

The spending journal is stored locally with private file permissions, atomic writes, and archive checks. The cap's integrity assumes that the local journal and archives have not been intentionally rewritten: Astatine does not have an independent cryptographic or hardware-backed monotonic anchor for them. A process running as the same OS account (or an administrator/root user) can rewrite valid journal data, so the cap is not a defense against a compromised same-account environment. It is a per-session cap, not a lifetime spending limit; explicitly starting a new session authorizes a separate cap.

## RPC Configuration & Trust

Astatine uses the selected network’s RPC URL from the bundled deployment manifest by default. The bundled Testnet primary is `https://k8s.testnet.json-rpc.injective.network/`. You do not need to operate an RPC node. `astatine init` displays the active network’s bundled default and lets you enter a custom RPC; pressing Enter keeps the current selection. Re-running setup keeps an existing custom RPC unless you change it.

View or change the current network’s selection:

```sh
astatine get rpc
astatine set rpc
astatine set rpc https://my-trusted-rpc.example.com
astatine set rpc default
```

PowerShell uses the same commands with `astatine.exe`:

```powershell
astatine.exe get rpc
astatine.exe set rpc
astatine.exe set rpc https://my-trusted-rpc.example.com
astatine.exe set rpc default
```

Use `--network testnet` or `--network mainnet` on `get rpc` and `set rpc` to
inspect or change that network’s override without changing the selected network.
`astatine init --rpc https://my-trusted-rpc.example.com` validates and saves an
override for the selected network. `astatine set rpc` without a URL is
interactive; type `default` to restore the bundled endpoint. A remote endpoint
must use HTTPS and return the selected network’s expected chain ID. HTTP is
accepted only for local loopback development endpoints. URL credentials are not
accepted; paths and query parameters are redacted in CLI output because some
providers use them for API tokens.

Astatine trusts the selected RPC provider for blockchain state, receipts and
reward evidence; it does not cryptographically authenticate all RPC data. A
malicious or compromised provider can return false work, transaction, receipt or
reward information. Automatic AST reward forwarding is disabled because such
false reward evidence must not authorize a transfer. The bundled archival
endpoint is only a historical-log fallback with the bundled primary. It is not
silently substituted when a custom primary is selected. The local session
authorization cap does not depend on receipt correctness: receipts never
replenish signing authority. Cap integrity assumes the same-account local
journal and archives have not been intentionally rewritten.

## License

The miner is licensed under [MIT](LICENSE-MIT). Third-party dependency notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
