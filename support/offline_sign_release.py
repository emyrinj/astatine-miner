#!/usr/bin/env python3
"""Offline owner signing for a preflight-verified unsigned release directory.

This program contains no HTTP/GitHub client and never copies or prints the
private key. Run it with networking disabled after
verify_release_provenance.py has written the preflight report.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable

from release_artifacts import (
    LICENSES,
    REPOSITORY,
    TARGETS,
    expected_names,
    parse_tag,
    sha256,
    validate_release,
    write_checksums,
)
from release_public_key import verify_public_key_pins
from verify_release_provenance import validate_local_source_checkout


class OfflineSigningError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OfflineSigningError(message)


def asset_fingerprints(root: pathlib.Path) -> dict[str, dict[str, int | str]]:
    return {
        filename: {"sha256": sha256(root / filename), "size": (root / filename).stat().st_size}
        for filename in sorted(expected_names(signed=False))
    }


def validate_preflight_report(
    report_path: pathlib.Path,
    input_dir: pathlib.Path,
    tag: str,
    source_commit: str,
    expected_report_sha256: str,
) -> dict:
    require(re.fullmatch(r"[0-9a-f]{64}", expected_report_sha256) is not None, "owner-recorded preflight report SHA-256 is malformed")
    require(sha256(report_path) == expected_report_sha256, "preflight report differs from the SHA-256 recorded during online verification")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OfflineSigningError(f"cannot read owner provenance preflight report: {error}") from error
    require(report.get("schema") == "astatine-owner-preflight-v1", "unsupported owner provenance report schema")
    require(report.get("repository") == REPOSITORY, "preflight repository identity does not match the pinned release identity")
    require(report.get("tag") == tag and tag == f"v{parse_tag(tag)}", "preflight tag does not match the requested canonical tag")
    require(report.get("source_commit") == source_commit, "preflight source commit differs from the explicit owner-selected commit")
    require(report.get("tag_commit") == source_commit, "preflight tag ref does not point to the selected source commit")
    require(report.get("workflow") == ".github/workflows/ci.yml", "preflight report names an unexpected workflow")
    require(report.get("run_id"), "preflight report has no GitHub Actions run identity")
    require(report.get("run_url"), "preflight report has no GitHub Actions run URL")
    artifact_path = input_dir.resolve()
    report_resolved = report_path.resolve()
    require(not report_resolved.is_relative_to(artifact_path), "provenance report must be stored outside the artifact inventory")
    require(report.get("attested_assets") == asset_fingerprints(input_dir), "unsigned artifact bytes differ from the provenance-verified report")
    return report


def openssl_private_operation(
    arguments: list[str],
    passphrase: str,
) -> subprocess.CompletedProcess[bytes]:
    passin = ["-passin", "stdin" if passphrase else "pass:"]
    if not passphrase:
        return subprocess.run(
            ["openssl", arguments[0], *passin, *arguments[1:]],
            check=False,
            capture_output=True,
        )
    return subprocess.run(
        ["openssl", arguments[0], *passin, *arguments[1:]],
        input=passphrase.encode("utf-8") + b"\n",
        check=False,
        capture_output=True,
    )


def validate_private_key_path(private_key: pathlib.Path, repo_root: pathlib.Path) -> None:
    require(not private_key.is_symlink(), "private key path must not be a symbolic link")
    metadata = private_key.lstat()
    require(stat.S_ISREG(metadata.st_mode), "private key path must identify a regular file")
    if os.name == "posix":
        require(stat.S_IMODE(metadata.st_mode) & 0o077 == 0, "private key file permissions must not grant group/other access")
    require(
        not private_key.resolve().is_relative_to(repo_root.resolve()),
        "private signing key must remain outside the repository",
    )


def sign_release(
    *,
    input_dir: pathlib.Path,
    output_dir: pathlib.Path,
    tag: str,
    source_commit: str,
    report_path: pathlib.Path,
    expected_report_sha256: str,
    private_key: pathlib.Path,
    public_key: pathlib.Path,
    confirmation: str,
    passphrase: str,
    repo_root: pathlib.Path,
    after_signature: Callable[[], None] | None = None,
) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None, "source commit must be a full lowercase Git SHA")
    report = validate_preflight_report(report_path, input_dir, tag, source_commit, expected_report_sha256)
    validate_release(input_dir, tag, repo_root, None, signed=False)

    fingerprint = verify_public_key_pins(repo_root, public_key)
    confirmation_phrase = f"SIGN {tag} {source_commit} PREFLIGHT {expected_report_sha256} WITH {fingerprint}"
    require(
        confirmation == confirmation_phrase,
        "owner confirmation did not exactly match tag, source commit, preflight report digest, and public-key fingerprint",
    )

    validate_private_key_path(private_key, repo_root)
    require(output_dir.resolve() != input_dir.resolve(), "signed output directory must differ from unsigned input")
    repo_path = repo_root.resolve()
    require(not input_dir.resolve().is_relative_to(repo_path), "unsigned release artifacts must be staged outside the repository")
    require(not output_dir.resolve().is_relative_to(repo_path), "signed release output must remain outside the repository")
    require(not report_path.resolve().is_relative_to(repo_path), "provenance report must remain outside the repository")
    require(not private_key.resolve().is_relative_to(repo_path), "private signing key must remain outside the repository")
    require(not output_dir.exists(), "signed output directory already exists; refusing overwrite/re-sign")
    output_dir.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".astatine-offline-sign-", dir=output_dir.parent) as temp_name:
        temporary_root = pathlib.Path(temp_name)
        staged = temporary_root / "signed-release"
        staged.mkdir()
        for filename in expected_names(signed=False):
            shutil.copy2(input_dir / filename, staged / filename)
        require(
            asset_fingerprints(staged) == report["attested_assets"],
            "staged bytes changed after provenance preflight; refusing to sign",
        )

        public_der = temporary_root / "signer-public.der"
        key_check = openssl_private_operation(
            ["pkey", "-in", str(private_key), "-pubout", "-outform", "DER", "-out", str(public_der)],
            passphrase,
        )
        require(key_check.returncode == 0, "private-key public-component derivation failed; key not logged")
        expected_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
            check=False,
            capture_output=True,
        )
        require(expected_der.returncode == 0, "could not read owner-supplied public key")
        require(public_der.read_bytes() == expected_der.stdout, "private key does not match the pinned owner public key")

        temporary_signature = temporary_root / "update-manifest.sig"
        signed = openssl_private_operation(
            [
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(temporary_signature),
                str(staged / "update-manifest.txt"),
            ],
            passphrase,
        )
        require(signed.returncode == 0 and temporary_signature.is_file(), "manifest signing failed; temporary output will be discarded")
        shutil.copyfile(temporary_signature, staged / "update-manifest.sig")
        write_checksums(staged)
        if after_signature is not None:
            after_signature()
        validate_release(staged, tag, repo_root, public_key, signed=True)
        validate_preflight_report(report_path, input_dir, tag, source_commit, expected_report_sha256)

        # Publish a complete verified directory atomically. The temporary staging
        # tree is on the same filesystem as output_dir, and output_dir must be new.
        os.replace(staged, output_dir)

    return report


def self_test(repo_root: pathlib.Path) -> None:
    import release_artifacts
    import release_public_key

    tag = "v0.1.0-testnet.13"
    source_commit = "a" * 40
    with tempfile.TemporaryDirectory(prefix="astatine-offline-sign-test-") as temporary:
        temp = pathlib.Path(temporary)
        test_repo = temp / "repo"
        incomplete_repo = temp / "repo-incomplete-key"
        test_repo.mkdir()
        incomplete_repo.mkdir()
        for relative in (
            "README.md",
            "src/update.rs",
            "support/install-unix.sh",
            "support/install-windows.ps1",
            "support/release-signing-public.pem",
            "support/release-signing-public.xml",
            "support/release-key-fingerprint.txt",
            "support/release-repository.txt",
            "LICENSE-MIT",
            "THIRD_PARTY_LICENSES.md",
        ):
            destination = test_repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo_root / relative, destination)
            incomplete_destination = incomplete_repo / relative
            incomplete_destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo_root / relative, incomplete_destination)
        (incomplete_repo / "support/release-key-fingerprint.txt").write_text(
            "INCOMPLETE_PUBLIC_KEY_CONFIGURATION\n",
            encoding="ascii",
        )

        private_key = temp / "synthetic-signing-key.pem"
        public_key = temp / "synthetic-signing-public.pem"
        wrong_private_key = temp / "wrong-synthetic-signing-key.pem"
        wrong_public_key = temp / "wrong-synthetic-signing-public.pem"
        for path in (private_key, wrong_private_key):
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            path.chmod(0o600)
        encrypted_private_key = temp / "synthetic-encrypted-signing-key.pem"
        encrypted_public_key = temp / "synthetic-encrypted-signing-public.pem"
        passphrase = "synthetic-test-passphrase"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-aes-256-cbc",
                "-pass",
                f"pass:{passphrase}",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                str(encrypted_private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        encrypted_private_key.chmod(0o600)
        subprocess.run(
            ["openssl", "pkey", "-in", str(encrypted_private_key), "-passin", f"pass:{passphrase}", "-pubout", "-out", str(encrypted_public_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(wrong_private_key), "-pubout", "-out", str(wrong_public_key)], check=True, capture_output=True)
        release_public_key.sync_public_key(test_repo, public_key)

        unsigned = temp / "unsigned"
        unsigned.mkdir()
        release_artifacts.build_synthetic_unsigned(unsigned, tag, repo_root)
        report_path = temp / "preflight.json"
        preflight = {
            "schema": "astatine-owner-preflight-v1",
            "repository": release_artifacts.REPOSITORY,
            "tag": tag,
            "source_commit": source_commit,
            "run_id": "synthetic-run",
            "run_url": "synthetic://workflow-run",
            "tag_commit": source_commit,
            "workflow": ".github/workflows/ci.yml",
            "attested_assets": asset_fingerprints(unsigned),
        }
        report_path.write_text(json.dumps(preflight), encoding="utf-8")
        preflight_sha256 = sha256(report_path)

        rehearsal_report = temp / "rehearsal-preflight.json"
        rehearsal_report.write_text(
            json.dumps({**preflight, "schema": "astatine-owner-preflight-rehearsal-v1", "source_ref": "refs/heads/main"}),
            encoding="utf-8",
        )
        rehearsal_output = temp / "rehearsal-must-not-sign"
        try:
            sign_release(
                input_dir=unsigned,
                output_dir=rehearsal_output,
                tag=tag,
                source_commit=source_commit,
                report_path=rehearsal_report,
                expected_report_sha256=sha256(rehearsal_report),
                private_key=private_key,
                public_key=public_key,
                confirmation="",
                passphrase="",
                repo_root=test_repo,
            )
        except OfflineSigningError:
            pass
        else:
            raise AssertionError("offline signer accepted a non-signable workflow-dispatch rehearsal report")
        require(not rehearsal_output.exists(), "rehearsal report refusal left a signed output directory")

        incomplete_output = temp / "incomplete-key-output"
        try:
            sign_release(
                input_dir=unsigned,
                output_dir=incomplete_output,
                tag=tag,
                source_commit=source_commit,
                report_path=report_path,
                expected_report_sha256=preflight_sha256,
                private_key=private_key,
                public_key=public_key,
                confirmation="",
                passphrase="",
                repo_root=incomplete_repo,
            )
        except (OfflineSigningError, release_public_key.PublicKeyError):
            pass
        else:
            raise AssertionError("offline signer accepted an incomplete public-key fingerprint marker")
        require(not incomplete_output.exists(), "incomplete-key refusal left a signed output directory")

        tampered_report = temp / "tampered-preflight.json"
        tampered_report.write_bytes(report_path.read_bytes() + b"\n")
        tampered_report_output = temp / "tampered-report-output"
        try:
            sign_release(
                input_dir=unsigned,
                output_dir=tampered_report_output,
                tag=tag,
                source_commit=source_commit,
                report_path=tampered_report,
                expected_report_sha256=preflight_sha256,
                private_key=private_key,
                public_key=public_key,
                confirmation="",
                passphrase="",
                repo_root=test_repo,
            )
        except OfflineSigningError:
            pass
        else:
            raise AssertionError("offline signer accepted a preflight report changed after online verification")
        require(not tampered_report_output.exists(), "preflight digest refusal left a signed output directory")

        output = temp / "signed"
        phrase = (
            f"SIGN {tag} {source_commit} PREFLIGHT {preflight_sha256} WITH "
            f"{release_public_key.verify_public_key_pins(test_repo, public_key)}"
        )
        sign_release(
            input_dir=unsigned,
            output_dir=output,
            tag=tag,
            source_commit=source_commit,
            report_path=report_path,
            expected_report_sha256=preflight_sha256,
            private_key=private_key,
            public_key=public_key,
            confirmation=phrase,
            passphrase="",
            repo_root=test_repo,
        )
        release_artifacts.validate_release(output, tag, repo_root, public_key, signed=True)

        encrypted_output = temp / "encrypted-signed"
        # The encrypted synthetic key is expected not to match the synchronized
        # key; synchronize a separate temporary source tree for its public pin.
        encrypted_repo = temp / "encrypted-repo"
        shutil.copytree(test_repo, encrypted_repo)
        release_public_key.sync_public_key(encrypted_repo, encrypted_public_key)
        encrypted_phrase = (
            f"SIGN {tag} {source_commit} PREFLIGHT {preflight_sha256} WITH "
            f"{release_public_key.verify_public_key_pins(encrypted_repo, encrypted_public_key)}"
        )
        sign_release(
            input_dir=unsigned,
            output_dir=encrypted_output,
            tag=tag,
            source_commit=source_commit,
            report_path=report_path,
            expected_report_sha256=preflight_sha256,
            private_key=encrypted_private_key,
            public_key=encrypted_public_key,
            confirmation=encrypted_phrase,
            passphrase=passphrase,
            repo_root=encrypted_repo,
        )
        release_artifacts.validate_release(encrypted_output, tag, encrypted_repo, encrypted_public_key, signed=True)

        interrupted_output = temp / "sign-interrupted-output"

        def interrupt_after_signature() -> None:
            raise RuntimeError("synthetic interruption after signature generation")

        try:
            sign_release(
                input_dir=unsigned,
                output_dir=interrupted_output,
                tag=tag,
                source_commit=source_commit,
                report_path=report_path,
                expected_report_sha256=preflight_sha256,
                private_key=private_key,
                public_key=public_key,
                confirmation=phrase,
                passphrase="",
                repo_root=test_repo,
                after_signature=interrupt_after_signature,
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError("synthetic interruption did not stop signing")
        require(not interrupted_output.exists(), "interrupted signing exposed a partial output directory")

        wrong_output = temp / "wrong-key-output"
        try:
            sign_release(
                input_dir=unsigned,
                output_dir=wrong_output,
                tag=tag,
                source_commit=source_commit,
                report_path=report_path,
                expected_report_sha256=preflight_sha256,
                private_key=wrong_private_key,
                public_key=public_key,
                confirmation=phrase,
                passphrase="",
                repo_root=test_repo,
            )
        except OfflineSigningError:
            pass
        else:
            raise AssertionError("offline signer accepted a private key that differs from the pinned public key")
        require(not wrong_output.exists(), "wrong-key test left a publishable output directory")

        interrupted_key = temp / "interrupted-key.pem"
        interrupted_key.write_text("not a private key\n", encoding="ascii")
        interrupted_key.chmod(0o600)
        interrupted_output = temp / "interrupted-output"
        try:
            sign_release(
                input_dir=unsigned,
                output_dir=interrupted_output,
                tag=tag,
                source_commit=source_commit,
                report_path=report_path,
                expected_report_sha256=preflight_sha256,
                private_key=interrupted_key,
                public_key=public_key,
                confirmation=phrase,
                passphrase="",
                repo_root=test_repo,
            )
        except OfflineSigningError:
            pass
        else:
            raise AssertionError("offline signer accepted an invalid synthetic key")
        require(not interrupted_output.exists(), "interrupted signing left a publishable output directory")


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--input-dir", type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path)
    parser.add_argument("--tag")
    parser.add_argument("--source-commit")
    parser.add_argument("--preflight-report", type=pathlib.Path)
    parser.add_argument("--verified-preflight-sha256")
    parser.add_argument("--private-key", type=pathlib.Path)
    parser.add_argument("--public-key", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(repo_root)
            print("Synthetic offline RSA-3072 signing, wrong-key, and interrupted-signing tests passed")
            return
        for name in (
            "input_dir",
            "output_dir",
            "tag",
            "source_commit",
            "preflight_report",
            "verified_preflight_sha256",
            "private_key",
            "public_key",
        ):
            require(getattr(args, name) is not None, f"--{name.replace('_', '-')} is required")
        validate_local_source_checkout(repo_root, args.source_commit)
        report = validate_preflight_report(
            args.preflight_report,
            args.input_dir,
            args.tag,
            args.source_commit,
            args.verified_preflight_sha256,
        )
        validate_release(args.input_dir, args.tag, repo_root, None, signed=False)
        fingerprint = verify_public_key_pins(repo_root, args.public_key)
        print("Offline signing preflight passed; no network call is made by this tool.")
        print(f"Repository: {report['repository']} · Tag: {args.tag} · Commit: {args.source_commit}")
        print(f"Verified owner preflight run: {report['run_id']} · {report['run_url']}")
        print(f"Exact unsigned asset count: {len(report['attested_assets'])}")
        print(f"Preflight report SHA-256: {args.verified_preflight_sha256}")
        print(f"Pinned public-key SHA-256 fingerprint: {fingerprint}")
        phrase = f"SIGN {args.tag} {args.source_commit} PREFLIGHT {args.verified_preflight_sha256} WITH {fingerprint}"
        supplied = input(f"To authorize signing, type exactly: {phrase}\n> ")
        require(
            supplied == phrase,
            "owner confirmation did not exactly match tag, source commit, preflight report digest, and public-key fingerprint",
        )
        validate_private_key_path(args.private_key, repo_root)
        passphrase = getpass.getpass("Private-key passphrase (leave blank if unencrypted): ")
        sign_release(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            tag=args.tag,
            source_commit=args.source_commit,
            report_path=args.preflight_report,
            expected_report_sha256=args.verified_preflight_sha256,
            private_key=args.private_key,
            public_key=args.public_key,
            confirmation=supplied,
            passphrase=passphrase,
            repo_root=repo_root,
        )
        print(f"Signed release artifact set created at {args.output_dir}; verify it before publication.")
    except (OSError, subprocess.SubprocessError, OfflineSigningError, ValueError) as error:
        parser.exit(1, f"offline release signing failed: {error}\n")


if __name__ == "__main__":
    main()
