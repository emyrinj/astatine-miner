#!/usr/bin/env python3
"""Keep exact repository identity pins aligned without accepting wildcards."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parent.parent
REPOSITORY = (ROOT / "support/release-repository.txt").read_text(encoding="ascii").splitlines()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    require(len(REPOSITORY) == 1, "release-repository.txt must contain exactly one line")
    repository = REPOSITORY[0]
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", repository) is not None,
        "release identity must be an exact OWNER/REPOSITORY value",
    )
    require(
        'env!("ASTATINE_RELEASE_REPOSITORY")' in (ROOT / "src/update.rs").read_text(encoding="utf-8"),
        "Rust updater must compile the exact release identity from build.rs",
    )
    require(
        'support/release-repository.txt' in (ROOT / "build.rs").read_text(encoding="utf-8"),
        "build.rs must use the canonical release identity file",
    )
    for filename, expected in (
        ("support/install-unix.sh", f'REPOSITORY="{repository}"'),
        ("support/install-windows.ps1", f"$Repository = '{repository}'"),
        ("support/verify-public-install-windows.ps1", f"$Repository = '{repository}'"),
    ):
        contents = (ROOT / filename).read_text(encoding="utf-8")
        require(expected in contents, f"{filename} is not pinned to canonical release identity {repository}")
    helper = (ROOT / "support/release_artifacts.py").read_text(encoding="utf-8")
    require('with_name("release-repository.txt")' in helper, "release validator must use the canonical exact repository identity")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("$GITHUB_REPOSITORY" in workflow, "workflow provenance checks must bind the GitHub repository context")
    require("--repo emyrinj/astatine-miner" not in workflow, "workflow must not retain a stale hardcoded GitHub owner/repository")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require(f"raw.githubusercontent.com/{repository}/" in readme, "README installer URLs differ from the canonical release identity")
    require("support/release-repository.txt" in readme, "README provenance command must use the canonical release identity")
    print(f"Release repository identity is exact and aligned: {repository}")


if __name__ == "__main__":
    main()
