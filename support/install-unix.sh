#!/bin/sh
set -eu

VERSION="0.1.0-testnet.13"
REPOSITORY="emyrinj/astatine-miner"

compare_testnet_versions() {
  awk -v current="$1" -v candidate="$2" '
    function parse_version(version, values, core, suffix, dash, has_prerelease, count, parts, i, sequence) {
      dash = index(version, "-")
      has_prerelease = dash > 0
      if (has_prerelease) {
        core = substr(version, 1, dash - 1)
        suffix = substr(version, dash + 1)
      } else {
        core = version
        suffix = ""
      }
      count = split(core, parts, ".")
      if (count != 3) return 0
      for (i = 1; i <= 3; i++) {
        if (parts[i] !~ /^(0|[1-9][0-9]*)$/ || length(parts[i]) > 10 || parts[i] + 0 > 2147483647) return 0
        values[i] = parts[i] + 0
      }
      values[4] = has_prerelease
      values[5] = 0
      if (has_prerelease) {
        if (suffix !~ /^testnet\.(0|[1-9][0-9]*)$/) return 0
        sequence = substr(suffix, 9)
        if (length(sequence) > 10 || sequence + 0 > 2147483647) return 0
        values[5] = sequence + 0
      }
      return 1
    }
    BEGIN {
      if (!parse_version(current, a) || !parse_version(candidate, b)) exit 2
      for (i = 1; i <= 3; i++) {
        if (a[i] < b[i]) { print -1; exit }
        if (a[i] > b[i]) { print 1; exit }
      }
      if (a[4] != b[4]) { print (a[4] ? -1 : 1); exit }
      if (a[4] && a[5] != b[5]) { print (a[5] < b[5] ? -1 : 1); exit }
      print 0
    }
  '
}

read_executable_version() {
  executable=$1
  output_file=$(mktemp) || return 1
  if ! "$executable" --version > "$output_file"; then
    rm -f "$output_file"
    return 1
  fi
  line_count=$(awk 'END { print NR + 0 }' "$output_file")
  if [ "$line_count" -ne 1 ] || ! IFS= read -r output_line < "$output_file"; then
    rm -f "$output_file"
    return 1
  fi
  rm -f "$output_file"
  case "$output_line" in
    "astatine "*) reported_version=${output_line#astatine } ;;
    *) return 1 ;;
  esac
  if ! compare_testnet_versions "$reported_version" "$reported_version" >/dev/null; then
    return 1
  fi
  printf '%s\n' "$reported_version"
}

verify_executable_version() {
  executable=$1
  expected=$2
  if ! reported_version=$(read_executable_version "$executable"); then
    return 1
  fi
  [ "$(compare_testnet_versions "$reported_version" "$expected")" = 0 ]
}

if [ "${1:-}" = "--compare-testnet-versions" ]; then
  if [ "$#" -ne 3 ]; then
    printf '%s\n' 'Usage: install-unix.sh --compare-testnet-versions CURRENT CANDIDATE' >&2
    exit 2
  fi
  compare_testnet_versions "$2" "$3"
  exit $?
fi

if [ "${1:-}" = "--verify-executable-version" ]; then
  if [ "$#" -ne 3 ]; then
    printf '%s\n' 'Usage: install-unix.sh --verify-executable-version EXPECTED EXECUTABLE' >&2
    exit 2
  fi
  verify_executable_version "$3" "$2"
  exit $?
fi

if [ "${1:-}" = "--read-executable-version" ]; then
  if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: install-unix.sh --read-executable-version EXECUTABLE' >&2
    exit 2
  fi
  read_executable_version "$2"
  exit $?
fi

case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) TARGET="macos-aarch64" ;;
      x86_64|amd64) TARGET="macos-x86_64" ;;
      *) printf '%s\n' 'Unsupported macOS architecture' >&2; exit 1 ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      aarch64|arm64) TARGET="linux-aarch64" ;;
      x86_64|amd64) TARGET="linux-x86_64" ;;
      *) printf '%s\n' 'Unsupported Linux architecture' >&2; exit 1 ;;
    esac
    ;;
  *) printf '%s\n' 'This installer supports macOS and Linux' >&2; exit 1 ;;
esac

BASE="https://github.com/${REPOSITORY}/releases/download/v${VERSION}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
MANIFEST="$TEMP_DIR/update-manifest.txt"
SIGNATURE="$TEMP_DIR/update-manifest.sig"
PUBLIC_KEY="$TEMP_DIR/release-signing-public.pem"
ASSET_LINE="$TEMP_DIR/asset-line"

curl --fail --show-error --location --connect-timeout 10 --max-time 60 --max-filesize 2097152 "$BASE/update-manifest.txt" -o "$MANIFEST"
curl --fail --show-error --location --connect-timeout 10 --max-time 60 --max-filesize 4096 "$BASE/update-manifest.sig" -o "$SIGNATURE"
cat > "$PUBLIC_KEY" <<'PUBLIC_KEY_EOF'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1Qxetx4KvnfuhGEP17i0
9JKEg2WYQ5ExtGc8ioSsVi4zsghLCaDL2WKs0ibGyTa2Gju2x0UTGHRuUBHEaDta
As4oirYtVwwvj5Jca14zc2ggL1ZcwBiN+B3GvTwOot+kd/QBcp+yFiGj2YdUtt9P
ZcIweIi0LZnbJGyl+khfWQ3iHa+1bpCzin5KLGcPFD2UevErRx/WbKJzg2qdxkGK
ESDLQc9panAqZTbEkYzKQhrIJBJPBuOGJZc+K+KzeLd+iLNx31UUUaRcUtJ0g3NO
gIA8z3EVM6dRnbVmT1Wk5UV5RFNAujfb7ptVx7q3fzxkV7d5Fuk0VFlSU4WddWyN
sGHFpZj/U/n3yh0vRzyt08yLVsYRKpKqKFvZSN/Ad4ARYto7POee4Alu6kWHALdq
IwWqR9TT5IYyiCze37ZwZcU3Mqq1t6VytWdP9GMHlWVw87v7/BglcSgb+h7e7+YN
9ok5BTW/eZYqd5B1/xljaiUUHanhzQ6dX2vPnCwF5jz7AgMBAAE=
-----END PUBLIC KEY-----
PUBLIC_KEY_EOF

openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$MANIFEST" >/dev/null
manifest_repository="$(awk -F= '$1 == "repository" { print $2 }' "$MANIFEST")"
manifest_channel="$(awk -F= '$1 == "channel" { print $2 }' "$MANIFEST")"
manifest_version="$(awk -F= '$1 == "version" { print $2 }' "$MANIFEST")"
test "$manifest_repository" = "$REPOSITORY"
test "$manifest_channel" = "testnet"
test "$manifest_version" = "$VERSION"
asset_key="asset.package.${TARGET}="
awk -F= -v key="$asset_key" '$1 == substr(key, 1, length(key) - 1) { print $2 }' "$MANIFEST" > "$ASSET_LINE"
IFS='|' read -r ASSET EXPECTED_SHA256 EXPECTED_SIZE < "$ASSET_LINE"
if [ -z "${ASSET:-}" ] || [ -z "${EXPECTED_SHA256:-}" ] || [ -z "${EXPECTED_SIZE:-}" ]; then
  printf '%s\n' 'Signed manifest has no package for this platform' >&2
  exit 1
fi
test "$ASSET" = "astatine-${TARGET}.tar.gz"

ARCHIVE="$TEMP_DIR/$ASSET"
curl --fail --show-error --location --connect-timeout 10 --max-time 180 --max-filesize "$EXPECTED_SIZE" --retry 2 --retry-max-time 240 --progress-bar "$BASE/$ASSET" -o "$ARCHIVE"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | awk '{ print $1 }')"
else
  ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE" | awk '{ print $1 }')"
fi
ACTUAL_SIZE="$(wc -c < "$ARCHIVE" | tr -d '[:space:]')"
test "$ACTUAL_SHA256" = "$EXPECTED_SHA256"
test "$ACTUAL_SIZE" = "$EXPECTED_SIZE"

tar_entries="$(tar -tzf "$ARCHIVE")"
expected_entries="$(printf '%s\n' astatine LICENSE-MIT THIRD_PARTY_LICENSES.md)"
test "$tar_entries" = "$expected_entries"
tar -xzf "$ARCHIVE" -C "$TEMP_DIR"
if ! verify_executable_version "$TEMP_DIR/astatine" "$VERSION"; then
  printf '%s\n' 'Downloaded executable did not report the exact signed Testnet version' >&2
  exit 1
fi

INSTALL_DIR="${HOME:?HOME is required}/.local/bin"
LICENSE_DIR="$INSTALL_DIR/licenses"
if [ -e "$INSTALL_DIR/astatine" ]; then
  if [ ! -x "$INSTALL_DIR/astatine" ]; then
    printf '%s\n' 'Refusing to replace an existing Astatine executable that cannot be run for version verification' >&2
    exit 1
  fi
  if ! installed_version="$(read_executable_version "$INSTALL_DIR/astatine" 2>/dev/null)"; then
    printf '%s\n' 'Refusing to replace an existing executable with malformed or multiline version output' >&2
    exit 1
  fi
  version_order="$(compare_testnet_versions "$installed_version" "$VERSION")" || {
    printf '%s\n' "Refusing to replace an existing executable with an unsupported version: $installed_version" >&2
    exit 1
  }
  if [ "$version_order" -gt 0 ]; then
    printf '%s\n' "Refusing to replace newer Astatine $installed_version with $VERSION" >&2
    exit 1
  fi
fi
mkdir -p "$LICENSE_DIR"
install -m 0755 "$TEMP_DIR/astatine" "$INSTALL_DIR/.astatine.update"
install -m 0644 "$TEMP_DIR/LICENSE-MIT" "$LICENSE_DIR/.LICENSE-MIT.update"
install -m 0644 "$TEMP_DIR/THIRD_PARTY_LICENSES.md" "$LICENSE_DIR/.THIRD_PARTY_LICENSES.md.update"
mv -f "$INSTALL_DIR/.astatine.update" "$INSTALL_DIR/astatine"
mv -f "$LICENSE_DIR/.LICENSE-MIT.update" "$LICENSE_DIR/LICENSE-MIT"
mv -f "$LICENSE_DIR/.THIRD_PARTY_LICENSES.md.update" "$LICENSE_DIR/THIRD_PARTY_LICENSES.md"
"$INSTALL_DIR/astatine" --version
printf '%s\n' "Installed authenticated Astatine $VERSION in $INSTALL_DIR"
