# Owner-operated offline release process

GitHub Actions builds/tests the Testnet release, validates the unsigned package
inventory, and emits provenance attestations. It has **no production signing
key** and no publication job. Pushing a release tag can build and attest
unsigned artifacts, but cannot publish a release.

The workflow isolation test is a source-controlled regression tripwire, not a
replacement for GitHub token-permission controls or keeping the production
signing key outside GitHub and online build hosts. Repository/environment
secret-name metadata was checked after removal; no values were requested.

The release owner downloads one successful tag run, verifies its exact source
commit and all asset attestations while online, then disconnects from the
network and signs the local manifest. After signing, the owner reconnects,
verifies and manually publishes the signed artifact set. The signing tool has no
network client and fails closed unless every verifier pin matches the active
owner public key.

## 0. Active release verification key

The owner-supplied RSA-3072 public key is integrated across the Rust updater,
Unix and Windows installers, PEM/XML verifier files, release validator, and
fingerprint check. Its SHA-256 SubjectPublicKeyInfo fingerprint is
`7a89234d5b269bb5372eab957e66307e321f4d9de9a550f7a2d7a6783cc50650`; the
checked-in `support/release-key-fingerprint.txt` must contain that fingerprint,
as one lowercase 64-character SHA-256 value. CI runs the strict pin check, which
rejects a missing, malformed, or inconsistent fingerprint marker.

For a future explicit public-key rotation, provide **only** an RSA-3072 public
PEM (`-----BEGIN PUBLIC KEY-----`). Never send a private key or passphrase.
Synchronize every checked-in verifier pin with:

```sh
python3 support/release_public_key.py sync --public-key /path/to/OWNER_SUPPLIED_PUBLIC_KEY.pem
python3 support/release_public_key.py check
```

Review the resulting diff in Rust, Unix, Windows, canonical PEM/XML, fingerprint
and documentation. Run all tests and obtain the independent RC1 audit. The sync
operation reads a **public** key only; it does not find, inspect, or copy any
private key. The offline signer separately requires the selected private key to
derive exactly this integrated public key before signing.

**Key-transition consequence:** existing Testnet.12 clients trust the current
legacy key and will reject a release signed only by the new key. This process
does not implement a bridge release or dual-key transition. If compatibility
with an existing Testnet.12 client is required, design that migration before
release; do not silently reuse the legacy key.

## Nonpublishing release-path rehearsal (no tag)

The workflow supports an explicit `workflow_dispatch` rehearsal input. It runs
the unsigned package assembly, raw-binary and package attestations, branch-ref
provenance verification, and native Windows package/archive smoke test. It has no
signing key or publishing job, and it does not create or move a Git tag.

From a clean checkout at the commit to rehearse:

```sh
REPOSITORY="$(tr -d '\n' < support/release-repository.txt)"
BRANCH="feature/testnet13-rc1-remediation"
TAG="v0.1.0-testnet.13"
gh workflow run ci.yml --repo "$REPOSITORY" --ref "$BRANCH" \
  -f release_rehearsal=true -f release_tag="$TAG"
```

Wait for the run to complete, then use that run's ID and head SHA to download
and verify its unsigned artifact from a directory outside the repository:

```sh
RUN_ID="<completed-workflow-dispatch-run-id>"
SOURCE_COMMIT="<40-character-head-SHA-from-that-run>"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/astatine-rehearsal.XXXXXX")"
gh run download "$RUN_ID" --repo "$REPOSITORY" \
  --name "astatine-${TAG}-unsigned-release-packages" \
  --dir "$WORK/unsigned"
python3 support/verify_release_provenance.py --rehearsal \
  --artifact-dir "$WORK/unsigned" --tag "$TAG" --branch "$BRANCH" \
  --run-id "$RUN_ID" --source-commit "$SOURCE_COMMIT" \
  --report "$WORK/rehearsal-preflight.json"
```

Rehearsal provenance is checked against `refs/heads/$BRANCH`, the exact
workflow-dispatch run, and source commit. The report uses a separate
`astatine-owner-preflight-rehearsal-v1` schema and is deliberately rejected by
both offline signing and publication tools. This verifies the build,
attestation/provenance, and Windows package paths without exercising release-tag
resolution, production signing, or publication.

## 1. Download and verify an unsigned CI artifact (online; no key involved)

Use the successful tag-push workflow run ID and exact 40-character source SHA
shown by GitHub. Keep the working directory outside the repository:

```sh
REPOSITORY="$(tr -d '\n' < support/release-repository.txt)"
TAG="v0.1.0-testnet.13"
RUN_ID="<successful-tag-workflow-run-id>"
SOURCE_COMMIT="<40-character-source-commit-from-that-run>"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/astatine-release.XXXXXX")"

gh run download "$RUN_ID" \
  --repo "$REPOSITORY" \
  --name "astatine-${TAG}-unsigned-release-packages" \
  --dir "$WORK/unsigned"

python3 support/verify_release_provenance.py \
  --artifact-dir "$WORK/unsigned" \
  --tag "$TAG" \
  --run-id "$RUN_ID" \
  --source-commit "$SOURCE_COMMIT" \
  --report "$WORK/provenance-preflight.json"
```

The preflight requires a clean local checkout whose `HEAD` exactly matches
`SOURCE_COMMIT`; it also rejects Git `assume-unchanged` and `skip-worktree`
index flags on tracked files. It checks the exact tag/run/commit/repository and CI workflow
path, confirms the remote tag resolves to the attested source commit, verifies
the exact 13-file unsigned inventory, checks hashes/sizes/package members/licenses, and runs
`gh attestation verify` for every asset. Review the command output and the
preflight report. Record the reported SHA-256 of that report through the
offline transfer; it binds the owner confirmation to this exact preflight result.
Do not continue if any check fails.

## 2. Sign offline (no network access)

Disconnect networking before running the signing command. The signer again
requires the clean checkout at `SOURCE_COMMIT`. Substitute the
existing owner-controlled private-key path locally; do not print, copy, upload,
or transmit it. The script prompts for an exact confirmation containing the
tag, source commit, and pinned public-key fingerprint, then checks that the
private key derives the integrated public pin. It writes a new signed directory
atomically and leaves the unsigned source directory untouched.

```sh
python3 support/offline_sign_release.py \
  --input-dir "$WORK/unsigned" \
  --output-dir "$WORK/signed" \
  --tag "$TAG" \
  --source-commit "$SOURCE_COMMIT" \
  --preflight-report "$WORK/provenance-preflight.json" \
  --verified-preflight-sha256 "<SHA-256 recorded during online verification>" \
  --private-key /path/to/OWNER_EXISTING_PRIVATE_KEY.pem \
  --public-key support/release-signing-public.pem
```

The tool makes no network requests. It rechecks the preflight asset hashes,
requires the preflight report SHA-256 recorded while online, includes that hash
in the explicit interactive confirmation, checks key correspondence without
printing key material, creates the RSA-3072 manifest signature and
`SHA256SUMS`, and validates the exact 15-file signed inventory before
atomically exposing the output directory. `--self-test` uses only disposable
synthetic keys and does not sign with the owner key.

## 3. Reconnect and manually publish the signed set

After the offline signer exits successfully, reconnect. The publisher also
requires the clean checkout to remain at `SOURCE_COMMIT` and has no private-key
input. It revalidates the signed manifest, hashes, allowlist,
package contents, preflight report and source tag, creates a **draft** release,
checks all uploaded asset digests, and only then makes the draft a prerelease.
It refuses to overwrite an existing release. An interrupted upload remains a
draft and a retry refuses to mutate it; inspect and resolve that draft manually.

```sh
python3 support/publish_signed_release.py \
  --release-dir "$WORK/signed" \
  --preflight-report "$WORK/provenance-preflight.json" \
  --tag "$TAG" \
  --source-commit "$SOURCE_COMMIT" \
  --verified-preflight-sha256 "<same SHA-256 recorded during online verification>" \
  --public-key support/release-signing-public.pem \
  --notes-file support/release-notes-v0.1.0-testnet.13.md
```

The script prompts for `PUBLISH <tag> <source-commit> PREFLIGHT <report-sha256>`.
Publishing uses the owner's authenticated GitHub CLI session and the exact
repository from `support/release-repository.txt`. Verify the public release
assets and run the public installer smoke only after the release appears with
the expected signed inventory.

## Future GitHub organization migration

`support/release-repository.txt` is the exact release identity for the updater,
package validator, build script, and workflow checks. Standalone installers and
documentation embed the same exact current identity and are checked against
that file. A migration must update the canonical identity and every client,
installer URL, workflow attestation expectation, README/release-note link, and
test in one reviewed change. Wildcards or accepting multiple repository names
are not supported. The owner must rebuild and re-attest the migrated source; old
release artifacts must not be relabeled as coming from the new repository.
