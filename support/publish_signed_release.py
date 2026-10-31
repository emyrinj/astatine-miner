#!/usr/bin/env python3
"""Owner-invoked, signature-gated GitHub draft publication; never reads a private key."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable

from offline_sign_release import OfflineSigningError, validate_preflight_report
from release_artifacts import REPOSITORY, expected_names, parse_tag, sha256, validate_release
from release_public_key import verify_public_key_pins
from verify_release_provenance import validate_local_source_checkout


class PublicationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationError(message)


def run_gh(arguments: list[str], runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> subprocess.CompletedProcess:
    return runner(["gh", *arguments], check=False, capture_output=True, text=True)


def gh_json(arguments: list[str], runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict:
    result = run_gh(arguments, runner)
    require(result.returncode == 0, f"GitHub CLI request failed: {result.stderr.strip()}")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PublicationError(f"GitHub CLI returned malformed JSON: {error}") from error
    require(isinstance(response, dict), "GitHub CLI response must be a JSON object")
    return response


def ensure_release_absent(tag: str, runner: Callable[..., subprocess.CompletedProcess]) -> None:
    result = run_gh(["api", f"repos/{REPOSITORY}/releases/tags/{tag}"], runner)
    if result.returncode == 0:
        raise PublicationError(f"release {tag} already exists; repeated publication is refused")
    error = result.stderr.lower()
    require("404" in error or "not found" in error, f"could not verify release absence: {result.stderr.strip()}")


def resolve_tag_commit(
    repository: str,
    tag: str,
    runner: Callable[..., subprocess.CompletedProcess],
) -> str:
    reference = gh_json(["api", f"repos/{repository}/git/ref/tags/{tag}"], runner)
    target = reference.get("object", {})
    for _ in range(4):
        object_type = target.get("type")
        object_sha = target.get("sha")
        require(isinstance(object_sha, str), "remote tag ref has no object SHA")
        if object_type == "commit":
            return object_sha
        require(object_type == "tag", "remote tag ref does not resolve to a commit or annotated tag")
        annotated = gh_json(["api", f"repos/{repository}/git/tags/{object_sha}"], runner)
        target = annotated.get("object", {})
    raise PublicationError("remote tag nesting exceeds the supported resolution depth")


def remote_assets_match(release: dict, signed_dir: pathlib.Path) -> None:
    assets = release.get("assets")
    require(isinstance(assets, list), "GitHub release response has no asset list")
    local_names = expected_names(signed=True)
    remote_names = {asset.get("name") for asset in assets if isinstance(asset, dict)}
    require(len(assets) == len(local_names) and remote_names == local_names, "remote release asset inventory differs from signed allowlist")
    for asset in assets:
        name = asset["name"]
        local = signed_dir / name
        require(asset.get("size") == local.stat().st_size, f"remote asset size differs from signed local asset: {name}")
        digest = asset.get("digest")
        require(digest == f"sha256:{sha256(local)}", f"remote asset digest differs from signed local asset: {name}")


def prepare_publication(
    signed_dir: pathlib.Path,
    preflight_report: pathlib.Path,
    tag: str,
    source_commit: str,
    expected_report_sha256: str,
    public_key: pathlib.Path,
    repo_root: pathlib.Path,
) -> dict:
    parse_tag(tag)
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None, "source commit must be a full lowercase Git SHA")
    report = validate_preflight_report(preflight_report, signed_dir, tag, source_commit, expected_report_sha256)
    verify_public_key_pins(repo_root, public_key)
    validate_release(signed_dir, tag, repo_root, public_key, signed=True)
    return report


def publish_release(
    *,
    signed_dir: pathlib.Path,
    preflight_report: pathlib.Path,
    tag: str,
    source_commit: str,
    expected_report_sha256: str,
    public_key: pathlib.Path,
    notes_template: pathlib.Path,
    confirmation: str,
    repo_root: pathlib.Path,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    report = prepare_publication(
        signed_dir,
        preflight_report,
        tag,
        source_commit,
        expected_report_sha256,
        public_key,
        repo_root,
    )
    tag_commit = resolve_tag_commit(REPOSITORY, tag, runner)
    require(tag_commit == source_commit, "remote release tag does not point to the provenance-verified source commit")
    ensure_release_absent(tag, runner)

    expected_confirmation = f"PUBLISH {tag} {source_commit} PREFLIGHT {expected_report_sha256}"
    require(confirmation == expected_confirmation, "owner publication confirmation does not match the exact tag and source commit")

    try:
        template = notes_template.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PublicationError(f"cannot read release notes template: {error}") from error
    notes = template.replace("__RELEASE_REPOSITORY__", REPOSITORY).replace("__RELEASE_COMMIT__", source_commit)
    require("__RELEASE_REPOSITORY__" not in notes and "__RELEASE_COMMIT__" not in notes, "release notes contain unresolved source placeholders")

    with tempfile.TemporaryDirectory(prefix="astatine-release-notes-") as temporary:
        notes_path = pathlib.Path(temporary) / "release-notes.md"
        notes_path.write_text(notes, encoding="utf-8")
        assets = [str(signed_dir / name) for name in sorted(expected_names(signed=True))]
        create = run_gh(
            [
                "release",
                "create",
                tag,
                *assets,
                "--repo",
                REPOSITORY,
                "--title",
                f"Astatine {tag} — Injective Testnet",
                "--notes-file",
                str(notes_path),
                "--prerelease",
                "--draft",
                "--verify-tag",
            ],
            runner,
        )
        require(create.returncode == 0, f"draft upload failed; no publication attempted: {create.stderr.strip()}")

        # Recheck the exact locally signed bytes after upload. If a local file
        # changed during transfer, the release remains a draft and is not made
        # public.
        prepare_publication(
            signed_dir,
            preflight_report,
            tag,
            source_commit,
            expected_report_sha256,
            public_key,
            repo_root,
        )
        draft = gh_json(["api", f"repos/{REPOSITORY}/releases/tags/{tag}"], runner)
        require(draft.get("draft") is True and draft.get("prerelease") is True, "uploaded release is not a draft prerelease")
        require(draft.get("tag_name") == tag, "uploaded draft tag differs from the requested release tag")
        remote_assets_match(draft, signed_dir)
        release_id = draft.get("id")
        require(isinstance(release_id, int), "draft release response has no numeric ID")

        # A failed or interrupted PATCH leaves the already-verified release as a
        # draft. A retry refuses to mutate it; the owner must inspect it manually.
        publish = run_gh(
            ["api", f"repos/{REPOSITORY}/releases/{release_id}", "--method", "PATCH", "-F", "draft=false"],
            runner,
        )
        require(publish.returncode == 0, f"release remains a draft; publication transition failed: {publish.stderr.strip()}")
        prepare_publication(
            signed_dir,
            preflight_report,
            tag,
            source_commit,
            expected_report_sha256,
            public_key,
            repo_root,
        )
        final = gh_json(["api", f"repos/{REPOSITORY}/releases/tags/{tag}"], runner)
        require(final.get("draft") is False and final.get("prerelease") is True, "release publication state is unexpected")
        remote_assets_match(final, signed_dir)
    print(f"Published signed prerelease {tag} from {source_commit}; provenance run {report['run_id']}")


class FakeGitHub:
    """Small deterministic GitHub API double used only by the synthetic test."""

    def __init__(self, tag: str, source_commit: str, fail_publish: bool = False, existing: bool = False):
        self.tag = tag
        self.source_commit = source_commit
        self.fail_publish = fail_publish
        self.existing = existing
        self.created = existing
        self.draft = existing
        self.create_count = 0
        self.publish_count = 0
        self.assets: list[dict] = []
        self.local_dir: pathlib.Path | None = None

    def __call__(self, arguments: list[str], **kwargs) -> subprocess.CompletedProcess:
        args = arguments[1:]
        if args[:2] == ["api", f"repos/{REPOSITORY}/git/ref/tags/{self.tag}"]:
            response = {"object": {"type": "commit", "sha": self.source_commit}}
            return subprocess.CompletedProcess(arguments, 0, json.dumps(response), "")
        if args[:2] == ["api", f"repos/{REPOSITORY}/releases/tags/{self.tag}"]:
            if not self.created:
                return subprocess.CompletedProcess(arguments, 1, "", "Not Found (HTTP 404)")
            response = {
                "id": 42,
                "tag_name": self.tag,
                "draft": self.draft,
                "prerelease": True,
                "assets": self.assets,
            }
            return subprocess.CompletedProcess(arguments, 0, json.dumps(response), "")
        if args[:2] == ["release", "create"]:
            self.create_count += 1
            self.created = True
            self.draft = True
            self.local_dir = pathlib.Path(args[3]).parent
            self.assets = [
                {
                    "name": path.name,
                    "size": path.stat().st_size,
                    "digest": f"sha256:{sha256(path)}",
                }
                for path in (self.local_dir / name for name in sorted(expected_names(signed=True)))
            ]
            return subprocess.CompletedProcess(arguments, 0, "created draft", "")
        if args[:3] == ["api", f"repos/{REPOSITORY}/releases/42", "--method"]:
            self.publish_count += 1
            if self.fail_publish:
                return subprocess.CompletedProcess(arguments, 1, "", "simulated interrupted publication")
            self.draft = False
            return subprocess.CompletedProcess(arguments, 0, "{}", "")
        return subprocess.CompletedProcess(arguments, 1, "", f"unexpected synthetic gh command: {args}")


def self_test(repo_root: pathlib.Path) -> None:
    import release_artifacts
    import release_public_key

    tag = "v0.1.0-testnet.13"
    source_commit = "b" * 40
    with tempfile.TemporaryDirectory(prefix="astatine-publish-test-") as temporary:
        temp = pathlib.Path(temporary)
        test_repo = temp / "repo"
        test_repo.mkdir()
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
        key = temp / "synthetic-private.pem"
        public_key = temp / "synthetic-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        key.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
        release_public_key.sync_public_key(test_repo, public_key)

        unsigned = temp / "unsigned"
        unsigned.mkdir()
        release_artifacts.build_synthetic_unsigned(unsigned, tag, repo_root)
        preflight = {
            "schema": "astatine-owner-preflight-v1",
            "repository": REPOSITORY,
            "tag": tag,
            "source_commit": source_commit,
            "run_id": "synthetic-run",
            "run_url": "synthetic://workflow-run",
            "tag_commit": source_commit,
            "workflow": ".github/workflows/ci.yml",
            "attested_assets": {
                name: {"sha256": sha256(unsigned / name), "size": (unsigned / name).stat().st_size}
                for name in sorted(expected_names(signed=False))
            },
        }
        preflight_path = temp / "preflight.json"
        preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
        preflight_sha256 = sha256(preflight_path)
        phrase = (
            f"SIGN {tag} {source_commit} PREFLIGHT {preflight_sha256} WITH "
            f"{release_public_key.verify_public_key_pins(test_repo, public_key)}"
        )
        signed = temp / "signed"
        from offline_sign_release import sign_release

        sign_release(
            input_dir=unsigned,
            output_dir=signed,
            tag=tag,
            source_commit=source_commit,
            report_path=preflight_path,
            expected_report_sha256=preflight_sha256,
            private_key=key,
            public_key=public_key,
            confirmation=phrase,
            passphrase="",
            repo_root=test_repo,
        )
        notes = repo_root / "support/release-notes-v0.1.0-testnet.13.md"
        confirmation = f"PUBLISH {tag} {source_commit} PREFLIGHT {preflight_sha256}"

        rehearsal_preflight_path = temp / "rehearsal-preflight.json"
        rehearsal_preflight_path.write_text(
            json.dumps({**preflight, "schema": "astatine-owner-preflight-rehearsal-v1", "source_ref": "refs/heads/main"}),
            encoding="utf-8",
        )
        try:
            prepare_publication(
                signed,
                rehearsal_preflight_path,
                tag,
                source_commit,
                sha256(rehearsal_preflight_path),
                public_key,
                test_repo,
            )
        except OfflineSigningError:
            pass
        else:
            raise AssertionError("publisher accepted a non-signable workflow-dispatch rehearsal report")

        incomplete_repo = temp / "repo-incomplete-key"
        shutil.copytree(test_repo, incomplete_repo)
        (incomplete_repo / "support/release-key-fingerprint.txt").write_text(
            "INCOMPLETE_PUBLIC_KEY_CONFIGURATION\n",
            encoding="ascii",
        )
        try:
            prepare_publication(
                signed,
                preflight_path,
                tag,
                source_commit,
                preflight_sha256,
                public_key,
                incomplete_repo,
            )
        except release_public_key.PublicKeyError:
            pass
        else:
            raise AssertionError("publisher accepted an incomplete public-key fingerprint marker")

        unsigned_fake = FakeGitHub(tag, source_commit)
        try:
            publish_release(
                signed_dir=unsigned,
                preflight_report=preflight_path,
                tag=tag,
                source_commit=source_commit,
                expected_report_sha256=preflight_sha256,
                public_key=public_key,
                notes_template=notes,
                confirmation=confirmation,
                repo_root=test_repo,
                runner=unsigned_fake,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("publisher accepted an unsigned artifact set")
        require(unsigned_fake.create_count == 0, "publisher attempted an upload without a valid owner signature")

        mismatched_report = FakeGitHub(tag, source_commit)
        try:
            publish_release(
                signed_dir=signed,
                preflight_report=preflight_path,
                tag=tag,
                source_commit=source_commit,
                expected_report_sha256="0" * 64,
                public_key=public_key,
                notes_template=notes,
                confirmation=confirmation,
                repo_root=test_repo,
                runner=mismatched_report,
            )
        except (PublicationError, OfflineSigningError):
            pass
        else:
            raise AssertionError("publisher accepted a preflight report with an unrecorded digest")
        require(mismatched_report.create_count == 0, "publisher uploaded assets after preflight digest mismatch")

        interrupted = FakeGitHub(tag, source_commit, fail_publish=True)
        try:
            publish_release(
                signed_dir=signed,
                preflight_report=preflight_path,
                tag=tag,
                source_commit=source_commit,
                expected_report_sha256=preflight_sha256,
                public_key=public_key,
                notes_template=notes,
                confirmation=confirmation,
                repo_root=test_repo,
                runner=interrupted,
            )
        except PublicationError:
            pass
        else:
            raise AssertionError("publisher did not surface simulated interrupted publication")
        require(interrupted.created and interrupted.draft and interrupted.publish_count == 1, "interrupted publication must remain an unpublished draft")

        repeated = FakeGitHub(tag, source_commit, existing=True)
        try:
            publish_release(
                signed_dir=signed,
                preflight_report=preflight_path,
                tag=tag,
                source_commit=source_commit,
                expected_report_sha256=preflight_sha256,
                public_key=public_key,
                notes_template=notes,
                confirmation=confirmation,
                repo_root=test_repo,
                runner=repeated,
            )
        except PublicationError:
            pass
        else:
            raise AssertionError("publisher accepted a repeated publication attempt")
        require(repeated.create_count == 0, "repeated publication mutated the existing release")


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--release-dir", type=pathlib.Path)
    parser.add_argument("--preflight-report", type=pathlib.Path)
    parser.add_argument("--tag")
    parser.add_argument("--source-commit")
    parser.add_argument("--verified-preflight-sha256")
    parser.add_argument("--public-key", type=pathlib.Path, default=repo_root / "support/release-signing-public.pem")
    parser.add_argument("--notes-file", type=pathlib.Path, required=False)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(repo_root)
            print("Synthetic signed-publication, unsigned refusal, interrupted-draft, and repeat refusal tests passed")
            return
        for name in ("release_dir", "preflight_report", "tag", "source_commit", "verified_preflight_sha256"):
            require(getattr(args, name) is not None, f"--{name.replace('_', '-')} is required")
        validate_local_source_checkout(repo_root, args.source_commit)
        notes_file = args.notes_file or repo_root / "support/release-notes-v0.1.0-testnet.13.md"
        report = prepare_publication(
            args.release_dir,
            args.preflight_report,
            args.tag,
            args.source_commit,
            args.verified_preflight_sha256,
            args.public_key,
            repo_root,
        )
        remote_tag_commit = resolve_tag_commit(REPOSITORY, args.tag, subprocess.run)
        require(remote_tag_commit == args.source_commit, "remote release tag does not point to the verified source commit")
        ensure_release_absent(args.tag, subprocess.run)
        phrase = f"PUBLISH {args.tag} {args.source_commit} PREFLIGHT {args.verified_preflight_sha256}"
        print(f"Verified signed candidate: {args.tag} from {args.source_commit}")
        print(f"Verified provenance run: {report['run_id']} · {report['run_url']}")
        print(f"Preflight report SHA-256: {args.verified_preflight_sha256}")
        confirmation = input(f"Type exactly to create a draft and publish after asset re-verification: {phrase}\n> ")
        publish_release(
            signed_dir=args.release_dir,
            preflight_report=args.preflight_report,
            tag=args.tag,
            source_commit=args.source_commit,
            expected_report_sha256=args.verified_preflight_sha256,
            public_key=args.public_key,
            notes_template=notes_file,
            confirmation=confirmation,
            repo_root=repo_root,
        )
    except (OSError, subprocess.SubprocessError, PublicationError, OfflineSigningError, ValueError) as error:
        parser.exit(1, f"signed release publication failed: {error}\n")


if __name__ == "__main__":
    main()
