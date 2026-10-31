#!/usr/bin/env python3
"""Network preflight for tag artifacts or non-signable rehearsals; never opens a key."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
from datetime import datetime, timezone

from release_artifacts import REPOSITORY, TARGETS, LICENSES, parse_tag, sha256, validate_release


WORKFLOW = ".github/workflows/ci.yml"
UNSIGNED_FILES = {
    *(binary for binary, _ in TARGETS.values()),
    *(package for _, package in TARGETS.values()),
    *LICENSES,
    "update-manifest.txt",
}


class PreflightError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def gh_json(arguments: list[str]) -> dict:
    result = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    require(result.returncode == 0, f"GitHub CLI request failed: {result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PreflightError(f"GitHub CLI returned malformed JSON: {error}") from error
    require(isinstance(value, dict), "GitHub CLI response must be a JSON object")
    return value


def gh_success(arguments: list[str]) -> None:
    result = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    require(result.returncode == 0, f"GitHub attestation verification failed: {result.stderr.strip()}")


def validate_local_source_checkout(repo_root: pathlib.Path, expected_commit: str) -> None:
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None, "source commit must be a full lowercase Git SHA")
    head = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    require(head.returncode == 0, f"cannot inspect local source checkout: {head.stderr.strip()}")
    require(head.stdout.strip() == expected_commit, "local source checkout HEAD differs from the selected release commit")
    status = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
    )
    require(status.returncode == 0, f"cannot inspect local source checkout status: {status.stderr.strip()}")
    require(not status.stdout, "local source checkout has uncommitted or untracked files")

    validate_tracked_index_flags(repo_root)


def validate_tracked_index_flags(repo_root: pathlib.Path) -> None:
    indexed = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-v", "-z"],
        check=False,
        capture_output=True,
    )
    require(indexed.returncode == 0, "cannot inspect local Git index flags")
    entries = [entry for entry in indexed.stdout.split(b"\0") if entry]
    require(bool(entries), "local Git index contains no tracked source files")
    require(
        all(entry.startswith(b"H ") for entry in entries),
        "local source checkout has assume-unchanged, skip-worktree, or nonstandard tracked index flags",
    )


def validate_run_context(run: dict, repository: str, tag: str, expected_commit: str) -> None:
    run_repository = run.get("repository")
    if isinstance(run_repository, dict):
        run_repository = run_repository.get("full_name")
    require(run_repository == repository, "source workflow run belongs to a different repository")
    require(run.get("conclusion") == "success", "source workflow run did not succeed")
    require(run.get("event") == "push", "source run must be an automatic tag push, not a manual/PR run")
    require(run.get("head_sha") == expected_commit, "source workflow run commit differs from the requested commit")
    require(run.get("head_branch") == tag, "source workflow run was not triggered by the requested tag")
    workflow_path = run.get("path")
    require(isinstance(workflow_path, str), "source workflow run has no workflow file identity")
    workflow_file, separator, workflow_ref = workflow_path.partition("@")
    require(workflow_file == WORKFLOW, "source workflow run was not executed by the pinned CI workflow")
    require(
        not separator or workflow_ref == f"refs/tags/{tag}",
        "source workflow run path does not identify the requested tag ref",
    )
    require(repository == REPOSITORY, "requested repository differs from the exact pinned release identity")
    require(tag == f"v{parse_tag(tag)}", "release tag is not canonical")
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None, "source commit must be a full lowercase Git SHA")


def validate_rehearsal_run_context(run: dict, repository: str, branch: str, expected_commit: str) -> None:
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch) is not None
        and all(part not in ("", ".", "..") for part in branch.split("/")),
        "rehearsal source branch name is malformed",
    )
    run_repository = run.get("repository")
    if isinstance(run_repository, dict):
        run_repository = run_repository.get("full_name")
    require(run_repository == repository, "rehearsal workflow run belongs to a different repository")
    require(run.get("conclusion") == "success", "rehearsal workflow run did not succeed")
    require(run.get("event") == "workflow_dispatch", "rehearsal run must be an explicit manual dispatch")
    require(run.get("head_sha") == expected_commit, "rehearsal workflow commit differs from the selected commit")
    require(run.get("head_branch") == branch, "rehearsal workflow run belongs to a different branch")
    require(
        run.get("path") in (WORKFLOW, f"{WORKFLOW}@refs/heads/{branch}"),
        "rehearsal workflow path does not identify the selected branch and CI workflow",
    )
    require(repository == REPOSITORY, "requested repository differs from the exact pinned release identity")
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None, "source commit must be a full lowercase Git SHA")


def resolve_tag_commit(repository: str, tag: str) -> str:
    reference = gh_json(["api", f"repos/{repository}/git/ref/tags/{tag}"])
    target = reference.get("object", {})
    for _ in range(4):
        object_type = target.get("type")
        object_sha = target.get("sha")
        require(isinstance(object_sha, str), "tag reference has no object SHA")
        if object_type == "commit":
            return object_sha
        require(object_type == "tag", "tag reference does not resolve to a commit or annotated tag")
        tag_object = gh_json(["api", f"repos/{repository}/git/tags/{object_sha}"])
        target = tag_object.get("object", {})
    raise PreflightError("annotated tag nesting exceeds the supported resolution depth")


def attested_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [root / filename for filename in sorted(UNSIGNED_FILES)]


def verify_asset_attestations(
    root: pathlib.Path,
    repository: str,
    source_ref: str,
    expected_commit: str,
) -> None:
    signer_workflow = f"{repository}/{WORKFLOW}"
    for asset in attested_files(root):
        gh_success(
            [
                "attestation",
                "verify",
                str(asset),
                "--repo",
                repository,
                "--source-ref",
                source_ref,
                "--source-digest",
                expected_commit,
                "--signer-workflow",
                signer_workflow,
                "--deny-self-hosted-runners",
            ]
        )


def verify_preflight(
    root: pathlib.Path,
    tag: str,
    run_id: str,
    expected_commit: str,
    repository: str = REPOSITORY,
) -> dict:
    parse_tag(tag)
    validate_local_source_checkout(pathlib.Path(__file__).resolve().parent.parent, expected_commit)
    validate_release(root, tag, pathlib.Path(__file__).resolve().parent.parent, None, signed=False)
    require(re.fullmatch(r"[0-9]+", str(run_id)) is not None, "GitHub Actions run ID must be numeric")
    run = gh_json(["api", f"repos/{repository}/actions/runs/{run_id}"])
    validate_run_context(run, repository, tag, expected_commit)
    tag_commit = resolve_tag_commit(repository, tag)
    require(tag_commit == expected_commit, "remote tag does not identify the attested source commit")

    source_ref = f"refs/tags/{tag}"
    verify_asset_attestations(root, repository, source_ref, expected_commit)

    return {
        "schema": "astatine-owner-preflight-v1",
        "repository": repository,
        "tag": tag,
        "source_commit": expected_commit,
        "run_id": str(run_id),
        "run_url": run.get("html_url", ""),
        "tag_commit": tag_commit,
        "workflow": WORKFLOW,
        "attested_assets": {
            path.name: {"sha256": sha256(path), "size": path.stat().st_size}
            for path in attested_files(root)
        },
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def verify_rehearsal_preflight(
    root: pathlib.Path,
    tag: str,
    run_id: str,
    expected_commit: str,
    branch: str,
    repository: str = REPOSITORY,
) -> dict:
    parse_tag(tag)
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    validate_local_source_checkout(repo_root, expected_commit)
    validate_release(root, tag, repo_root, None, signed=False)
    require(re.fullmatch(r"[0-9]+", str(run_id)) is not None, "GitHub Actions run ID must be numeric")
    run = gh_json(["api", f"repos/{repository}/actions/runs/{run_id}"])
    validate_rehearsal_run_context(run, repository, branch, expected_commit)

    source_ref = f"refs/heads/{branch}"
    verify_asset_attestations(root, repository, source_ref, expected_commit)
    return {
        "schema": "astatine-owner-preflight-rehearsal-v1",
        "repository": repository,
        "tag": tag,
        "source_commit": expected_commit,
        "source_ref": source_ref,
        "run_id": str(run_id),
        "run_url": run.get("html_url", ""),
        "workflow": WORKFLOW,
        "attested_assets": {
            path.name: {"sha256": sha256(path), "size": path.stat().st_size}
            for path in attested_files(root)
        },
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def write_report(path: pathlib.Path, report: dict) -> None:
    require(not path.exists(), "refusing to overwrite an existing provenance report")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as temporary:
            temporary_path = pathlib.Path(temporary.name)
            json.dump(report, temporary, sort_keys=True, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def self_test() -> None:
    valid = {
        "conclusion": "success",
        "event": "push",
        "head_sha": "a" * 40,
        "head_branch": "v0.1.0-testnet.13",
        "path": f"{WORKFLOW}@refs/tags/v0.1.0-testnet.13",
        "repository": {"full_name": REPOSITORY},
    }
    validate_run_context(valid, REPOSITORY, "v0.1.0-testnet.13", "a" * 40)
    for mutated, repository, tag, commit in (
        ({**valid, "head_sha": "b" * 40}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "head_branch": "v0.1.0-testnet.14"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "conclusion": "failure"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "path": ".github/workflows/untrusted.yml@refs/tags/v0.1.0-testnet.13"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "path": f"{WORKFLOW}@refs/heads/main"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "repository": {"full_name": "attacker.invalid/astatine-miner"}}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        (valid, "attacker.invalid/astatine-miner", "v0.1.0-testnet.13", "a" * 40),
        (valid, REPOSITORY, "v0.1.0-testnet.13", "b" * 40),
    ):
        try:
            validate_run_context(mutated, repository, tag, commit)
        except PreflightError:
            continue
        raise AssertionError("synthetic preflight accepted incorrect repository/tag/commit provenance")

    branch = "feature/testnet13-rc1-remediation"
    rehearsal = {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_sha": "c" * 40,
        "head_branch": branch,
        "path": WORKFLOW,
        "repository": {"full_name": REPOSITORY},
    }
    validate_rehearsal_run_context(rehearsal, REPOSITORY, branch, "c" * 40)
    validate_rehearsal_run_context(
        {**rehearsal, "path": f"{WORKFLOW}@refs/heads/{branch}"},
        REPOSITORY,
        branch,
        "c" * 40,
    )
    for mutated, repository, source_branch, commit in (
        ({**rehearsal, "event": "push"}, REPOSITORY, branch, "c" * 40),
        ({**rehearsal, "head_branch": "other-branch"}, REPOSITORY, branch, "c" * 40),
        ({**rehearsal, "head_sha": "d" * 40}, REPOSITORY, branch, "c" * 40),
        ({**rehearsal, "conclusion": "failure"}, REPOSITORY, branch, "c" * 40),
        ({**rehearsal, "path": f"{WORKFLOW}@refs/tags/v0.1.0-testnet.13"}, REPOSITORY, branch, "c" * 40),
        ({**rehearsal, "path": ".github/workflows/other.yml@refs/heads/feature/testnet13-rc1-remediation"}, REPOSITORY, branch, "c" * 40),
        ({**rehearsal, "repository": {"full_name": "attacker.invalid/astatine-miner"}}, REPOSITORY, branch, "c" * 40),
        (rehearsal, REPOSITORY, "../untrusted", "c" * 40),
    ):
        try:
            validate_rehearsal_run_context(mutated, repository, source_branch, commit)
        except PreflightError:
            continue
        raise AssertionError("synthetic rehearsal accepted incorrect workflow-dispatch provenance")

    with tempfile.TemporaryDirectory(prefix="astatine-provenance-checkout-test-") as temporary:
        checkout = pathlib.Path(temporary)
        subprocess.run(["git", "-C", str(checkout), "init", "-q", "-b", "main"], check=True, capture_output=True)
        (checkout / "source.txt").write_text("synthetic source\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(checkout), "add", "source.txt"], check=True, capture_output=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "-c",
                "user.name=synthetic test",
                "-c",
                "user.email=synthetic@example.invalid",
                "commit",
                "-q",
                "-m",
                "synthetic source",
            ],
            check=True,
            capture_output=True,
        )
        commit = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        validate_local_source_checkout(checkout, commit)
        try:
            validate_local_source_checkout(checkout, "b" * 40)
        except PreflightError:
            pass
        else:
            raise AssertionError("synthetic preflight accepted a local checkout at a different commit")

        source_file = checkout / "source.txt"
        for set_flag, clear_flag in (
            ("--assume-unchanged", "--no-assume-unchanged"),
            ("--skip-worktree", "--no-skip-worktree"),
        ):
            subprocess.run(
                ["git", "-C", str(checkout), "update-index", set_flag, "source.txt"],
                check=True,
                capture_output=True,
            )
            source_file.write_text("modified while index flag is active\n", encoding="utf-8")
            if set_flag == "--assume-unchanged":
                status = subprocess.run(
                    ["git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=all"],
                    check=True,
                    capture_output=True,
                )
                require(not status.stdout, "synthetic assume-unchanged fixture did not hide the modified source")
            for validate in (
                lambda: validate_tracked_index_flags(checkout),
                lambda: validate_local_source_checkout(checkout, commit),
            ):
                try:
                    validate()
                except PreflightError:
                    continue
                raise AssertionError(f"synthetic preflight accepted a tracked file with {set_flag}")
            subprocess.run(
                ["git", "-C", str(checkout), "update-index", clear_flag, "source.txt"],
                check=True,
                capture_output=True,
            )
            source_file.write_text("synthetic source\n", encoding="utf-8")
            validate_local_source_checkout(checkout, commit)

        (checkout / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        try:
            validate_local_source_checkout(checkout, commit)
        except PreflightError:
            pass
        else:
            raise AssertionError("synthetic preflight accepted a dirty local source checkout")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--rehearsal", action="store_true", help="verify a non-signable workflow-dispatch rehearsal")
    parser.add_argument("--artifact-dir", type=pathlib.Path)
    parser.add_argument("--tag")
    parser.add_argument("--run-id")
    parser.add_argument("--source-commit")
    parser.add_argument("--branch", help="exact branch used for a workflow-dispatch rehearsal")
    parser.add_argument("--report", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            self_test()
            print("Synthetic release provenance metadata tests passed")
            return
        for name in ("artifact_dir", "tag", "run_id", "source_commit", "report"):
            require(getattr(arguments, name) is not None, f"--{name.replace('_', '-')} is required")
        if arguments.rehearsal:
            require(arguments.branch is not None, "--branch is required for a workflow-dispatch rehearsal")
            report = verify_rehearsal_preflight(
                arguments.artifact_dir,
                arguments.tag,
                arguments.run_id,
                arguments.source_commit,
                arguments.branch,
            )
        else:
            require(arguments.branch is None, "--branch is only valid with --rehearsal")
            report = verify_preflight(
                arguments.artifact_dir,
                arguments.tag,
                arguments.run_id,
                arguments.source_commit,
            )
        write_report(arguments.report, report)
        report_digest = sha256(arguments.report)
        label = "non-signable rehearsal" if arguments.rehearsal else "release preflight"
        print(f"Verified {len(report['attested_assets'])} unsigned assets for {label}: {report['repository']}@{report['source_commit']} ({report['tag']}); report: {arguments.report}")
        if arguments.rehearsal:
            print(f"Rehearsal report SHA-256 (not accepted for signing/publication): {report_digest}")
        else:
            print(f"Record this preflight report SHA-256 for offline signing/publication: {report_digest}")
    except (OSError, subprocess.SubprocessError, PreflightError, ValueError) as error:
        parser.exit(1, f"release provenance preflight failed: {error}\n")


if __name__ == "__main__":
    main()
