## Astatine Miner v0.1.0-testnet.13

Testnet.13 is an RC1 security-remediation candidate for the Rust miner.

### Highlights

- Configure a network-specific RPC with `astatine get rpc`, `astatine set rpc`,
  or `astatine init`. Remote endpoints require HTTPS and the expected chain ID.
  The selected RPC is trusted input; custom endpoints do not silently fall back
  to another provider.
- The transaction journal durably counts each session's maximum transaction
  authorization before signing. Receipts, gas reports, and reorgs never refund
  the authorization budget; RPC-reported actual costs remain separate.
- Automatic AST reward forwarding is disabled because a selected RPC can
  fabricate payout evidence. `--send-rewards-to` is rejected; rewards remain
  visible as selected-RPC reports and should be independently verified.
- Unix and Windows installers fail closed on unsupported versions and reject
  downgrades, including stable/prerelease ordering.
- New encrypted wallets require 12-character passwords; existing V3 keystores
  remain import-compatible.
- GitHub Actions builds/tests unsigned release assets and creates source
  provenance. The release owner verifies and signs the manifest offline, then
  manually publishes the signed inventory; a tag alone never publishes.

The protocol, proof algorithm, GPU pipeline, rewards, node pins, and 0.01 INJ
submission fee remain unchanged. RPC state, receipts, and reward evidence are
not cryptographically authenticated by the miner. The local authorization cap
is per session and assumes its private journal and archives have not been
intentionally rewritten by a process running under the same OS account.

Commit-pinned source: https://github.com/__RELEASE_REPOSITORY__/tree/__RELEASE_COMMIT__
