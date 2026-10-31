#!/bin/sh
set -eu

INSTALLER="$(dirname "$0")/install-unix.sh"

assert_order() {
  actual="$(sh "$INSTALLER" --compare-testnet-versions "$1" "$2")"
  if [ "$actual" != "$3" ]; then
    printf '%s\n' "Expected version order $1 vs $2 to be $3, got $actual" >&2
    exit 1
  fi
}

assert_order 0.1.0-testnet.12 0.1.0-testnet.13 -1
assert_order 0.1.0-testnet.13 0.1.0-testnet.13 0
assert_order 0.1.0-testnet.14 0.1.0-testnet.13 1
assert_order 0.1.0-testnet.0 0.1.0-testnet.1 -1
assert_order 0.1.0-testnet.2147483647 0.1.0-testnet.2147483646 1
assert_order 0.1.1-testnet.1 0.1.0-testnet.99 1
assert_order 0.1.1 0.1.0 1
assert_order 0.1.0 0.2.0 -1
assert_order 1.0.0 0.99.99 1
assert_order 0.1.0-testnet.99 0.1.1-testnet.0 -1
assert_order 0.1.0-testnet.99 0.1.0  -1
assert_order 0.1.0 0.1.0-testnet.99 1

assert_invalid() {
  if sh "$INSTALLER" --compare-testnet-versions "$1" 0.1.0-testnet.13 >/dev/null 2>&1; then
    printf '%s\n' "Invalid installed version must be rejected: $1" >&2
    exit 1
  fi
  if sh "$INSTALLER" --compare-testnet-versions 0.1.0-testnet.12 "$1" >/dev/null 2>&1; then
    printf '%s\n' "Invalid candidate version must be rejected: $1" >&2
    exit 1
  fi
}

for invalid in \
  0.1 \
  v0.1.0 \
  0.1.0-preview.1 \
  0.1.0-testnet.foo \
  00.1.0 \
  0.01.0 \
  0.1.00 \
  0.1.0-testnet.013 \
  2147483648.0.0 \
  0.1.0-testnet.2147483648 \
  18446744073709551616.0.0; do
  assert_invalid "$invalid"
done

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
FAKE_EXECUTABLE="$TEMP_DIR/astatine"
assert_executable_version() {
  output=$1
  should_pass=$2
  {
    printf '%s\n' '#!/bin/sh'
    printf "printf '%%b' '%s'\n" "$output"
  } > "$FAKE_EXECUTABLE"
  chmod +x "$FAKE_EXECUTABLE"
  if [ "$should_pass" = true ]; then
    sh "$INSTALLER" --verify-executable-version 0.1.0-testnet.13 "$FAKE_EXECUTABLE"
  elif sh "$INSTALLER" --verify-executable-version 0.1.0-testnet.13 "$FAKE_EXECUTABLE" >/dev/null 2>&1; then
    printf '%s\n' "Malformed or mismatched executable version output was accepted: $output" >&2
    exit 1
  fi
}

assert_executable_version 'astatine 0.1.0-testnet.13\n' true
assert_executable_version 'astatine 0.1.0-testnet.130\n' false
assert_executable_version 'astatine 0.1.0-testnet.foo\n' false
assert_executable_version 'astatine 0.1.0-testnet.12\n' false
assert_executable_version 'astatine 0.1.0-testnet.13 \n' false
assert_executable_version '0.1.0-testnet.13\n' false
assert_executable_version 'not a version\n' false
assert_executable_version 'astatine 0.1.0-testnet.13\nextra output\n' false
assert_executable_version 'astatine 0.1.0-testnet.13' false

assert_existing_version() {
  output=$1
  should_pass=$2
  expected_version=${3:-}
  {
    printf '%s\n' '#!/bin/sh'
    printf "printf '%%b' '%s'\n" "$output"
  } > "$FAKE_EXECUTABLE"
  chmod +x "$FAKE_EXECUTABLE"
  if [ "$should_pass" = true ]; then
    actual_version=$(sh "$INSTALLER" --read-executable-version "$FAKE_EXECUTABLE")
    if [ "$actual_version" != "$expected_version" ]; then
      printf '%s\n' "Expected existing version $expected_version, got $actual_version" >&2
      exit 1
    fi
  elif sh "$INSTALLER" --read-executable-version "$FAKE_EXECUTABLE" >/dev/null 2>&1; then
    printf '%s\n' "Malformed or multiline existing version output was accepted: $output" >&2
    exit 1
  fi
}

assert_existing_version 'astatine 0.1.0-testnet.12\n' true '0.1.0-testnet.12'
assert_existing_version 'astatine 0.1.0-testnet.14\n' true '0.1.0-testnet.14'
assert_existing_version 'astatine 0.1.0-testnet.12\nastatine 0.1.0-testnet.14\n' false
assert_existing_version 'astatine 0.1.0-testnet.12\nextra output\n' false
assert_existing_version 'astatine 0.1.0-testnet.foo\n' false
assert_existing_version 'astatine 0.1.0-testnet.12' false

printf '%s\n' 'Unix installer SemVer ordering, executable matching, and fail-closed checks passed'
