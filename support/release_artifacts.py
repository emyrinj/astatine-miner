#!/usr/bin/env python3
"""Validate the exact Astatine release inventory, package contents, and signature."""

from __future__ import annotations

import argparse
import hashlib
import io
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Callable


_REPOSITORY_LINES = pathlib.Path(__file__).with_name("release-repository.txt").read_text(encoding="ascii").splitlines()
if (
    len(_REPOSITORY_LINES) != 1
    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", _REPOSITORY_LINES[0]) is None
):
    raise RuntimeError("support/release-repository.txt must contain one exact owner/repository identity")
REPOSITORY = _REPOSITORY_LINES[0]
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_CONTROL_FILE_BYTES = 2 * 1024 * 1024
TARGETS = {
    "macos-aarch64": ("astatine-macos-aarch64", "astatine-macos-aarch64.tar.gz"),
    "macos-x86_64": ("astatine-macos-x86_64", "astatine-macos-x86_64.tar.gz"),
    "linux-x86_64": ("astatine-linux-x86_64", "astatine-linux-x86_64.tar.gz"),
    "linux-aarch64": ("astatine-linux-aarch64", "astatine-linux-aarch64.tar.gz"),
    "windows-x86_64": ("astatine-windows-x86_64.exe", "astatine-windows-x86_64.zip"),
}
LICENSES = ("LICENSE-MIT", "THIRD_PARTY_LICENSES.md")
EXPECTED_KEYS = {
    *(f"binary.{target}" for target in TARGETS),
    *(f"package.{target}" for target in TARGETS),
    *(f"license.{name}" for name in LICENSES),
}
CHECKSUM_FILES = tuple(package for _, package in TARGETS.values()) + tuple(
    binary for binary, _ in TARGETS.values()
) + LICENSES + ("update-manifest.txt", "update-manifest.sig")


class ValidationError(ValueError):
    """A release artifact violates the expected inventory or provenance binding."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_names(signed: bool) -> set[str]:
    names = {
        *(binary for binary, _ in TARGETS.values()),
        *(package for _, package in TARGETS.values()),
        *LICENSES,
        "update-manifest.txt",
    }
    if signed:
        names.update(("update-manifest.sig", "SHA256SUMS"))
    return names


def parse_tag(tag: str) -> str:
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-testnet\.(0|[1-9][0-9]*)", tag)
    require(match is not None, f"unsupported Testnet release tag: {tag}")
    require(all(int(component) <= 2_147_483_647 for component in match.groups()), "release tag exceeds supported SemVer ranges")
    return tag[1:]


def check_regular_asset(path: pathlib.Path) -> None:
    require(not path.is_symlink(), f"release asset is a symbolic link: {path.name}")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), f"release asset is not a regular file: {path.name}")
    require(0 < metadata.st_size <= MAX_ASSET_BYTES, f"release asset has an invalid size: {path.name}")


def read_manifest(path: pathlib.Path, version: str, tag: str) -> dict[str, tuple[str, str, int]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValidationError(f"cannot read UTF-8 release manifest: {error}") from error
    require(
        len(lines) >= 4
        and lines[:4]
        == [
            "astatine-update-manifest-v1",
            f"repository={REPOSITORY}",
            "channel=testnet",
            f"version={version}",
        ],
        "release manifest header, repository, channel, or version does not match",
    )
    require(tag == f"v{version}", f"release tag {tag} does not match package version {version}")
    records: dict[str, tuple[str, str, int]] = {}
    for line in lines[4:]:
        require("=" in line, f"malformed release manifest line: {line!r}")
        key, value = line.split("=", 1)
        require(key.startswith("asset.") and key not in records, f"invalid or duplicate manifest record: {key}")
        fields = value.split("|")
        require(len(fields) == 3, f"malformed release manifest asset record: {key}")
        filename, digest, size_text = fields
        require(filename == pathlib.PurePosixPath(filename).name and "\\" not in filename, f"unsafe manifest filename: {filename}")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"invalid manifest SHA-256: {key}")
        require(re.fullmatch(r"[1-9][0-9]*", size_text) is not None, f"invalid manifest asset size: {key}")
        records[key.removeprefix("asset.")] = (filename, digest, int(size_text))
    require(set(records) == EXPECTED_KEYS, "manifest asset set differs from the release allowlist")
    return records


def verify_manifest_assets(
    root: pathlib.Path,
    records: dict[str, tuple[str, str, int]],
    license_root: pathlib.Path,
) -> None:
    expected = {
        **{f"binary.{target}": binary for target, (binary, _) in TARGETS.items()},
        **{f"package.{target}": package for target, (_, package) in TARGETS.items()},
        **{f"license.{name}": name for name in LICENSES},
    }
    for key, expected_filename in expected.items():
        recorded_filename, digest, size = records[key]
        require(recorded_filename == expected_filename, f"manifest has an unexpected filename for {key}")
        path = root / expected_filename
        check_regular_asset(path)
        require(path.stat().st_size == size and sha256(path) == digest, f"manifest integrity mismatch: {key}")
    for name in LICENSES:
        require((root / name).read_bytes() == (license_root / name).read_bytes(), f"license asset differs from source: {name}")


def compare_archive_members(root: pathlib.Path, target: str) -> None:
    binary, package = TARGETS[target]
    expected_members = {"astatine.exe" if target == "windows-x86_64" else "astatine", *LICENSES}
    package_path = root / package
    if target == "windows-x86_64":
        with zipfile.ZipFile(package_path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            require(len(names) == len(expected_members) and set(names) == expected_members, f"Windows archive inventory is invalid: {package}")
            for info in infos:
                mode = (info.external_attr >> 16) & 0o170000
                require(not info.is_dir() and mode in (0, stat.S_IFREG), f"Windows archive contains a non-file member: {info.filename}")
                expected_data = (root / (binary if info.filename == "astatine.exe" else info.filename)).read_bytes()
                require(info.file_size == len(expected_data), f"Windows archive member size differs from signed asset: {info.filename}")
                require(archive.read(info) == expected_data, f"Windows archive member differs from signed asset: {info.filename}")
        return

    with tarfile.open(package_path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(expected_members) and set(names) == expected_members, f"archive inventory is invalid: {package}")
        for member in members:
            require(member.isfile() and member.name == pathlib.PurePosixPath(member.name).name, f"archive contains an unsafe or non-file member: {member.name}")
            expected_data = (root / (binary if member.name == "astatine" else member.name)).read_bytes()
            require(member.size == len(expected_data), f"archive member size differs from signed asset: {member.name}")
            source = archive.extractfile(member)
            require(source is not None and source.read(len(expected_data) + 1) == expected_data, f"archive member differs from signed asset: {member.name}")


def verify_checksums(root: pathlib.Path) -> None:
    checksum_path = root / "SHA256SUMS"
    try:
        lines = checksum_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValidationError(f"cannot read SHA256SUMS: {error}") from error
    records: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\s]+)", line)
        require(match is not None, f"malformed SHA256SUMS record: {line!r}")
        digest, filename = match.groups()
        require(filename not in records, f"duplicate SHA256SUMS entry: {filename}")
        records[filename] = digest
    require(set(records) == set(CHECKSUM_FILES), "SHA256SUMS inventory differs from the release allowlist")
    for filename, digest in records.items():
        path = root / filename
        check_regular_asset(path)
        require(sha256(path) == digest, f"SHA256SUMS mismatch: {filename}")


def verify_signature(root: pathlib.Path, public_key: pathlib.Path) -> None:
    signature = root / "update-manifest.sig"
    check_regular_asset(signature)
    require(signature.stat().st_size == 384, "RSA-3072 manifest signature has an invalid length")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(root / "update-manifest.txt")],
        check=False,
        capture_output=True,
        text=True,
    )
    require(result.returncode == 0, f"release manifest signature verification failed: {result.stderr.strip()}")


def validate_release(
    root: pathlib.Path,
    tag: str,
    license_root: pathlib.Path,
    public_key: pathlib.Path | None,
    signed: bool,
) -> None:
    require(root.is_dir() and not root.is_symlink(), "release artifact root is not a real directory")
    names = {path.name for path in root.iterdir()}
    require(names == expected_names(signed), "release artifact inventory contains missing or unexpected files")
    for path in root.iterdir():
        check_regular_asset(path)
        if path.name in ("update-manifest.txt", "SHA256SUMS"):
            require(path.stat().st_size <= MAX_CONTROL_FILE_BYTES, f"release control file exceeds 2 MiB: {path.name}")
    version = parse_tag(tag)
    records = read_manifest(root / "update-manifest.txt", version, tag)
    verify_manifest_assets(root, records, license_root)
    for target in TARGETS:
        compare_archive_members(root, target)
    if signed:
        require(public_key is not None, "signed release validation requires the pinned public key")
        verify_signature(root, public_key)
        verify_checksums(root)


def write_manifest(root: pathlib.Path, tag: str) -> None:
    version = parse_tag(tag)
    lines = ["astatine-update-manifest-v1", f"repository={REPOSITORY}", "channel=testnet", f"version={version}"]
    records: list[tuple[str, str]] = []
    records.extend((f"binary.{target}", binary) for target, (binary, _) in TARGETS.items())
    records.extend((f"package.{target}", package) for target, (_, package) in TARGETS.items())
    records.extend((f"license.{name}", name) for name in LICENSES)
    for key, filename in records:
        path = root / filename
        lines.append(f"asset.{key}={filename}|{sha256(path)}|{path.stat().st_size}")
    (root / "update-manifest.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_checksums(root: pathlib.Path) -> None:
    lines = [f"{sha256(root / filename)}  {filename}" for filename in CHECKSUM_FILES]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")


def build_synthetic_unsigned(root: pathlib.Path, tag: str, license_root: pathlib.Path) -> None:
    for filename in LICENSES:
        shutil.copyfile(license_root / filename, root / filename)
    for target, (binary, package) in TARGETS.items():
        (root / binary).write_bytes(f"synthetic executable for {target}\n".encode())
        if target == "windows-x86_64":
            with zipfile.ZipFile(root / package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, source_name in (("astatine.exe", binary), *[(name, name) for name in LICENSES]):
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, (root / source_name).read_bytes())
        else:
            with tarfile.open(root / package, "w:gz") as archive:
                for name, source_name in (("astatine", binary), *[(name, name) for name in LICENSES]):
                    data = (root / source_name).read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name == "astatine" else 0o644
                    archive.addfile(info, io.BytesIO(data))
    write_manifest(root, tag)


def synthetic_rehearsal(repo_root: pathlib.Path) -> None:
    tag = "v0.1.0-testnet.13"
    with tempfile.TemporaryDirectory(prefix="astatine-release-rehearsal-") as temporary:
        temporary_root = pathlib.Path(temporary)
        good = temporary_root / "release"
        good.mkdir()
        build_synthetic_unsigned(good, tag, repo_root)
        validate_release(good, tag, repo_root, None, signed=False)

        private_key = temporary_root / "synthetic-signing-key.pem"
        public_key = temporary_root / "synthetic-signing-public.pem"
        wrong_private_key = temporary_root / "wrong-synthetic-signing-key.pem"
        wrong_public_key = temporary_root / "wrong-synthetic-signing-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(private_key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(wrong_private_key)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(wrong_private_key), "-pubout", "-out", str(wrong_public_key)], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(good / "update-manifest.sig"), str(good / "update-manifest.txt")],
            check=True,
            capture_output=True,
        )
        write_checksums(good)
        validate_release(good, tag, repo_root, public_key, signed=True)

        cases: list[tuple[str, Callable[[], None]]] = []

        cases.append(("wrong public key", lambda: validate_release(good, tag, repo_root, wrong_public_key, signed=True)))

        def copy_release(label: str) -> pathlib.Path:
            destination = temporary_root / label
            shutil.copytree(good, destination)
            return destination

        raw_substitution = copy_release("raw-substitution")
        with (raw_substitution / TARGETS["linux-x86_64"][0]).open("ab") as modified:
            modified.write(b"substituted executable")
        cases.append(("raw binary substitution", lambda: validate_release(raw_substitution, tag, repo_root, public_key, signed=True)))

        manifest_substitution = copy_release("manifest-substitution")
        with (manifest_substitution / "update-manifest.txt").open("ab") as modified:
            modified.write(b"tampered=true\n")
        cases.append(("unsigned manifest substitution", lambda: validate_release(manifest_substitution, tag, repo_root, public_key, signed=True)))

        def re_sign(directory: pathlib.Path) -> None:
            manifest_path = directory / "update-manifest.txt"
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(directory / "update-manifest.sig"), str(manifest_path)],
                check=True,
                capture_output=True,
            )
            write_checksums(directory)

        wrong_repository = copy_release("wrong-repository")
        wrong_repository_manifest = wrong_repository / "update-manifest.txt"
        wrong_repository_manifest.write_text(
            wrong_repository_manifest.read_text(encoding="utf-8").replace(
                f"repository={REPOSITORY}", "repository=attacker.invalid/astatine-miner"
            ),
            encoding="utf-8",
        )
        re_sign(wrong_repository)
        cases.append(("repository identity mismatch", lambda: validate_release(wrong_repository, tag, repo_root, public_key, signed=True)))

        wrong_version = copy_release("wrong-version")
        wrong_version_manifest = wrong_version / "update-manifest.txt"
        wrong_version_manifest.write_text(
            wrong_version_manifest.read_text(encoding="utf-8").replace(
                "version=0.1.0-testnet.13", "version=0.1.0-testnet.14"
            ),
            encoding="utf-8",
        )
        re_sign(wrong_version)
        cases.append(("incorrect release version", lambda: validate_release(wrong_version, tag, repo_root, public_key, signed=True)))

        package_substitution = copy_release("package-substitution")
        package_name = TARGETS["linux-x86_64"][1]
        with tarfile.open(package_substitution / package_name, "w:gz") as archive:
            for name, source_name in (("astatine", TARGETS["linux-x86_64"][0]), *[(name, name) for name in LICENSES]):
                data = (package_substitution / source_name).read_bytes()
                if name == "astatine":
                    data += b"substituted package member"
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if name == "astatine" else 0o644
                archive.addfile(info, io.BytesIO(data))
        # Simulate a package signed by a synthetic signer after changing its digest.
        # The package-to-attested-binary binding must still reject the member change.
        manifest_lines = (package_substitution / "update-manifest.txt").read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(manifest_lines):
            if line.startswith("asset.package.linux-x86_64="):
                package_path = package_substitution / package_name
                manifest_lines[index] = f"asset.package.linux-x86_64={package_name}|{sha256(package_path)}|{package_path.stat().st_size}"
                break
        manifest_path = package_substitution / "update-manifest.txt"
        manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(package_substitution / "update-manifest.sig"), str(manifest_path)],
            check=True,
            capture_output=True,
        )
        write_checksums(package_substitution)
        cases.append(("re-signed package member substitution", lambda: validate_release(package_substitution, tag, repo_root, public_key, signed=True)))

        extra_asset = copy_release("extra-asset")
        (extra_asset / "unexpected.bin").write_bytes(b"extra")
        cases.append(("unexpected release asset", lambda: validate_release(extra_asset, tag, repo_root, public_key, signed=True)))

        missing_asset = copy_release("missing-asset")
        (missing_asset / TARGETS["macos-aarch64"][1]).unlink()
        cases.append(("missing release asset", lambda: validate_release(missing_asset, tag, repo_root, public_key, signed=True)))

        checksum_substitution = copy_release("checksum-substitution")
        with (checksum_substitution / "SHA256SUMS").open("a", encoding="ascii") as checksums:
            checksums.write("0" * 64 + "  update-manifest.txt\n")
        cases.append(("duplicate or forged checksum", lambda: validate_release(checksum_substitution, tag, repo_root, public_key, signed=True)))

        for label, attempt in cases:
            try:
                attempt()
            except (AssertionError, OSError, tarfile.TarError, zipfile.BadZipFile, ValidationError):
                continue
            raise AssertionError(f"synthetic release rehearsal accepted {label}")
    print("Synthetic RSA-3072 release rehearsal passed: inventory, package binding, signature, checksums, and substitution cases")


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    unsigned = subparsers.add_parser("verify-unsigned")
    unsigned.add_argument("--root", type=pathlib.Path, required=True)
    unsigned.add_argument("--tag", required=True)
    unsigned.add_argument("--license-root", type=pathlib.Path, default=repo_root)
    signed = subparsers.add_parser("verify-release")
    signed.add_argument("--root", type=pathlib.Path, required=True)
    signed.add_argument("--tag", required=True)
    signed.add_argument("--license-root", type=pathlib.Path, default=repo_root)
    signed.add_argument("--public-key", type=pathlib.Path, required=True)
    subparsers.add_parser("self-test")
    arguments = parser.parse_args()
    try:
        if arguments.command == "self-test":
            synthetic_rehearsal(repo_root)
        else:
            validate_release(
                arguments.root,
                arguments.tag,
                arguments.license_root,
                getattr(arguments, "public_key", None),
                signed=arguments.command == "verify-release",
            )
            print(f"{arguments.command}: {arguments.tag} artifact inventory and integrity checks passed")
    except (OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile, ValidationError) as error:
        parser.exit(1, f"release artifact validation failed: {error}\n")


if __name__ == "__main__":
    main()
