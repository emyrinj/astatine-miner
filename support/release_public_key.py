#!/usr/bin/env python3
"""Validate/synchronize release *public* key pins; never accepts a private-key input."""

from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import re
import shutil
import subprocess
import tempfile


RUST_MODULUS = re.compile(r'(?m)^const RSA_MODULUS_BASE64: &str = "([^"]+)";$')
RUST_EXPONENT = re.compile(r'(?m)^const RSA_EXPONENT_BASE64: &str = "([^"]+)";$')
WINDOWS_KEY_XML = re.compile(r"(?m)^(\s*\$KeyXml = ')([^']+)('\s*)$")
README_FINGERPRINT = re.compile(
    r"(SHA-256 SubjectPublicKeyInfo\s+fingerprint is\s+`)[0-9a-f]{64}(`)"
)


class PublicKeyError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicKeyError(message)


def run_openssl(arguments: list[str]) -> bytes:
    result = subprocess.run(
        ["openssl", *arguments],
        check=False,
        capture_output=True,
    )
    require(result.returncode == 0, "OpenSSL public-key operation failed")
    return result.stdout


def inspect_public_key(public_key: pathlib.Path) -> tuple[bytes, bytes, str, str, str]:
    require(public_key.is_file() and not public_key.is_symlink(), "public key must be a regular, non-symlink PEM file")
    pem = run_openssl(["pkey", "-pubin", "-in", str(public_key), "-pubout"])
    der = run_openssl(["pkey", "-pubin", "-in", str(public_key), "-outform", "DER"])
    modulus_text = run_openssl(["rsa", "-pubin", "-in", str(public_key), "-noout", "-modulus"]).decode("ascii")
    match = re.fullmatch(r"Modulus=([0-9A-Fa-f]+)\s*", modulus_text)
    require(match is not None, "public key does not contain a readable RSA modulus")
    modulus = bytes.fromhex(match.group(1)).lstrip(b"\0")
    exponent_text = run_openssl(["pkey", "-pubin", "-in", str(public_key), "-text", "-noout"]).decode(
        "ascii", errors="strict"
    )
    exponent_match = re.search(r"(?m)^Exponent: ([0-9]+) \(0x([0-9a-fA-F]+)\)$", exponent_text)
    bit_match = re.search(r"(?m)^Public-Key: \(([0-9]+) bit\)$", exponent_text)
    require(bit_match is not None and bit_match.group(1) == "3072", "release trust anchor must be RSA-3072")
    require(exponent_match is not None and int(exponent_match.group(1)) == 65537, "release key exponent must be 65537")
    require(len(modulus) == 384 and modulus[0] & 0x80, "RSA-3072 modulus has an invalid encoded length")
    modulus_b64 = base64.b64encode(modulus).decode("ascii")
    exponent = int(exponent_match.group(1))
    exponent_bytes = exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")
    exponent_b64 = base64.b64encode(exponent_bytes).decode("ascii")
    fingerprint = hashlib.sha256(der).hexdigest()
    return pem, der, modulus_b64, exponent_b64, fingerprint


def replace_once(contents: str, pattern: re.Pattern[str], replacement: str, label: str) -> str:
    updated, count = pattern.subn(replacement, contents)
    require(count == 1, f"expected exactly one {label} pin; found {count}")
    return updated


def pem_from_unix_installer(contents: str) -> str:
    start_marker = "cat > \"$PUBLIC_KEY\" <<'PUBLIC_KEY_EOF'\n"
    end_marker = "\nPUBLIC_KEY_EOF"
    require(contents.count(start_marker) == 1 and contents.count(end_marker) == 1, "Unix installer public-key block is not unique")
    start = contents.index(start_marker) + len(start_marker)
    end = contents.index(end_marker, start)
    return contents[start:end] + "\n"


def xml_components(xml: str) -> tuple[str, str]:
    match = re.fullmatch(r"<RSAKeyValue><Modulus>([^<]+)</Modulus><Exponent>([^<]+)</Exponent></RSAKeyValue>", xml)
    require(match is not None, "Windows XML public key is malformed")
    return match.group(1), match.group(2)


def verify_public_key_pins(root: pathlib.Path, expected_public_key: pathlib.Path | None = None) -> str:
    canonical_path = root / "support/release-signing-public.pem"
    _canonical_pem, canonical_der, modulus_b64, exponent_b64, fingerprint = inspect_public_key(canonical_path)
    marker = (root / "support/release-key-fingerprint.txt").read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{64}", marker) is not None, "release key fingerprint marker is missing or malformed")
    require(marker == fingerprint, "release key fingerprint marker differs from canonical public key")

    if expected_public_key is not None:
        _, expected_der, _, _, expected_fingerprint = inspect_public_key(expected_public_key)
        require(expected_der == canonical_der, "supplied public key differs from the checked-in release trust anchor")
        require(expected_fingerprint == fingerprint, "supplied public key fingerprint differs from release trust anchor")

    rust = (root / "src/update.rs").read_text(encoding="utf-8")
    require(RUST_MODULUS.search(rust) is not None and RUST_EXPONENT.search(rust) is not None, "Rust updater key constants are missing")
    require(RUST_MODULUS.search(rust).group(1) == modulus_b64, "Rust updater modulus differs from canonical public key")
    require(RUST_EXPONENT.search(rust).group(1) == exponent_b64, "Rust updater exponent differs from canonical public key")

    unix = (root / "support/install-unix.sh").read_text(encoding="utf-8")
    require(inspect_public_key_bytes(pem_from_unix_installer(unix)) == canonical_der, "Unix installer PEM differs from canonical public key")

    windows = (root / "support/install-windows.ps1").read_text(encoding="utf-8")
    windows_match = WINDOWS_KEY_XML.search(windows)
    require(windows_match is not None, "Windows installer XML public key is missing")
    require(xml_components(windows_match.group(2)) == (modulus_b64, exponent_b64), "Windows installer XML differs from canonical public key")
    canonical_xml = (root / "support/release-signing-public.xml").read_text(encoding="utf-8").strip()
    require(xml_components(canonical_xml) == (modulus_b64, exponent_b64), "canonical Windows XML differs from canonical PEM")

    readme = (root / "README.md").read_text(encoding="utf-8")
    readme_match = README_FINGERPRINT.search(readme)
    require(readme_match is not None and readme_match.group(0).endswith(f"`{fingerprint}`"), "README fingerprint differs from canonical public key")
    return fingerprint


def inspect_public_key_bytes(pem: str) -> bytes:
    with tempfile.NamedTemporaryFile(prefix="astatine-public-key-", suffix=".pem") as temporary:
        temporary.write(pem.encode("ascii"))
        temporary.flush()
        return run_openssl(["pkey", "-pubin", "-in", temporary.name, "-outform", "DER"])


def sync_public_key(root: pathlib.Path, public_key: pathlib.Path) -> str:
    pem, _der, modulus_b64, exponent_b64, fingerprint = inspect_public_key(public_key)
    pem_text = pem.decode("ascii")

    canonical_pem_path = root / "support/release-signing-public.pem"
    canonical_pem_path.write_text(pem_text, encoding="ascii")

    rust_path = root / "src/update.rs"
    rust = rust_path.read_text(encoding="utf-8")
    rust = replace_once(rust, RUST_MODULUS, f'const RSA_MODULUS_BASE64: &str = "{modulus_b64}";', "Rust modulus")
    rust = replace_once(rust, RUST_EXPONENT, f'const RSA_EXPONENT_BASE64: &str = "{exponent_b64}";', "Rust exponent")
    rust_path.write_text(rust, encoding="utf-8")

    unix_path = root / "support/install-unix.sh"
    unix = unix_path.read_text(encoding="utf-8")
    start_marker = "cat > \"$PUBLIC_KEY\" <<'PUBLIC_KEY_EOF'\n"
    end_marker = "\nPUBLIC_KEY_EOF"
    require(unix.count(start_marker) == 1 and unix.count(end_marker) == 1, "Unix installer public-key block is not unique")
    start = unix.index(start_marker) + len(start_marker)
    end = unix.index(end_marker, start)
    unix_path.write_text(unix[:start] + pem_text.rstrip("\n") + unix[end:], encoding="utf-8")

    xml = f"<RSAKeyValue><Modulus>{modulus_b64}</Modulus><Exponent>{exponent_b64}</Exponent></RSAKeyValue>"
    xml_path = root / "support/release-signing-public.xml"
    xml_path.write_text(xml + "\n", encoding="ascii")

    windows_path = root / "support/install-windows.ps1"
    windows = windows_path.read_text(encoding="utf-8")
    windows = replace_once(windows, WINDOWS_KEY_XML, rf"\g<1>{xml}\g<3>", "Windows XML")
    windows_path.write_text(windows, encoding="utf-8")

    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    readme = replace_once(readme, README_FINGERPRINT, rf"\g<1>{fingerprint}\g<2>", "README fingerprint")
    readme_path.write_text(readme, encoding="utf-8")
    (root / "support/release-key-fingerprint.txt").write_text(fingerprint + "\n", encoding="ascii")
    verify_public_key_pins(root, public_key)
    return fingerprint


def self_test(root: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="astatine-key-sync-test-") as temporary:
        temp = pathlib.Path(temporary)
        test_root = temp / "repo"
        test_root.mkdir()
        for relative in (
            "README.md",
            "src/update.rs",
            "support/install-unix.sh",
            "support/install-windows.ps1",
            "support/release-signing-public.pem",
            "support/release-signing-public.xml",
            "support/release-key-fingerprint.txt",
        ):
            destination = test_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, destination)

        (test_root / "support/release-key-fingerprint.txt").write_text(
            "INCOMPLETE_PUBLIC_KEY_CONFIGURATION\n",
            encoding="ascii",
        )
        try:
            verify_public_key_pins(test_root)
        except PublicKeyError:
            pass
        else:
            raise AssertionError("public-key verifier accepted an incomplete fingerprint marker")

        private_key = temp / "synthetic-private.pem"
        public_key = temp / "synthetic-public.pem"
        other_private = temp / "other-synthetic-private.pem"
        other_public = temp / "other-synthetic-public.pem"
        for path in (private_key, other_private):
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(other_private), "-pubout", "-out", str(other_public)], check=True, capture_output=True)
        fingerprint = sync_public_key(test_root, public_key)
        require(verify_public_key_pins(test_root, public_key) == fingerprint, "synthetic public key sync did not verify")
        try:
            verify_public_key_pins(test_root, other_public)
        except PublicKeyError:
            pass
        else:
            raise AssertionError("public key verifier accepted a different synthetic key")


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--public-key", type=pathlib.Path)
    sync = commands.add_parser("sync")
    sync.add_argument("--public-key", type=pathlib.Path, required=True)
    commands.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "check":
            fingerprint = verify_public_key_pins(root, args.public_key)
            print(f"Release public-key pins are consistent: {fingerprint}")
        elif args.command == "sync":
            fingerprint = sync_public_key(root, args.public_key)
            print(f"Synchronized public-key pins to owner-supplied key fingerprint {fingerprint}")
        else:
            self_test(root)
            print("Synthetic RSA-3072 public-key synchronization and wrong-key tests passed")
    except (OSError, subprocess.SubprocessError, PublicKeyError) as error:
        parser.exit(1, f"release public-key operation failed: {error}\n")


if __name__ == "__main__":
    main()
