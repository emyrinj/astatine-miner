# Dependency advisory policy

`Cargo.lock` currently retains `crypto-bigint 0.5.5`, which is reported by
`RUSTSEC-2026-0387`. The locked package is an optional transitive dependency of
`alloy-primitives 1.7.3` through `k256 0.13.4` and `elliptic-curve 0.13.8`.
The miner enables only `alloy-primitives`' `std` feature; the optional `k256`
feature is not in the resolved build graph. The active target graph uses
`crypto-bigint 0.7.9`.

The advisory's fixed release is `crypto-bigint >=0.7.6`; there is no patched
0.5.x release to select within the locked `k256 0.13` dependency line. A
targeted attempt to update the optional lock entry to `0.5.6` found no such
package version. Manually removing an optional transitive package from
`Cargo.lock` is not compatible with the repository's `--locked` build policy.
The optional dependency is therefore retained until its upstream dependency
line can be safely removed or upgraded.

CI keeps the existing `cargo audit --ignore RUSTSEC-2026-0387` exception and
adds an all-features/all-targets reverse-dependency check that fails if
`crypto-bigint 0.5.5` enters the active graph. The exception must be removed if
that graph check ever finds the package, and revisited when `alloy-primitives`
updates its optional cryptography dependencies. `derivative 2.2.0` is also
reported as unmaintained by `cargo audit`, but is not a vulnerability advisory.
