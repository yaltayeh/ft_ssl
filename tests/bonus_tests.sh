#!/bin/bash
# Test suite for ft_ssl bonus hash algorithms: sha224, sha384, sha512
#
# Usage: bash tests/test_ft_ssl_bonus.sh [path/to/ft_ssl]
# Defaults to ./ft_ssl if no path is given.
#
# Requires: sha224sum/openssl (for sha224), sha384sum/openssl (for sha384),
# sha512sum/openssl (for sha512). Falls back to `openssl dgst -shaNNN` if the
# *sum binary isn't available (e.g. on macOS without coreutils installed).

set -u

FT_SSL="${1:-./ft_ssl}"
PASS=0
FAIL=0
FAILED_NAMES=()

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "=== ft_ssl bonus test suite (sha224 / sha384 / sha512) ==="
echo "binary under test: $FT_SSL"
echo

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# reference_digest <algo> <content>
# prints the hex digest of <content> using the best available reference tool
reference_digest() {
    local algo="$1"
    local content="$2"
    case "$algo" in
        sha224)
            if command -v sha224sum >/dev/null 2>&1; then
                printf '%s' "$content" | sha224sum | cut -d' ' -f1
            else
                printf '%s' "$content" | openssl dgst -sha224 -r | cut -d' ' -f1
            fi
            ;;
        sha384)
            if command -v sha384sum >/dev/null 2>&1; then
                printf '%s' "$content" | sha384sum | cut -d' ' -f1
            else
                printf '%s' "$content" | openssl dgst -sha384 -r | cut -d' ' -f1
            fi
            ;;
        sha512)
            if command -v sha512sum >/dev/null 2>&1; then
                printf '%s' "$content" | sha512sum | cut -d' ' -f1
            else
                printf '%s' "$content" | openssl dgst -sha512 -r | cut -d' ' -f1
            fi
            ;;
    esac
}

# reference_digest_file <algo> <path>
reference_digest_file() {
    local algo="$1"
    local path="$2"
    case "$algo" in
        sha224)
            if command -v sha224sum >/dev/null 2>&1; then
                sha224sum "$path" | cut -d' ' -f1
            else
                openssl dgst -sha224 -r "$path" | cut -d' ' -f1
            fi
            ;;
        sha384)
            if command -v sha384sum >/dev/null 2>&1; then
                sha384sum "$path" | cut -d' ' -f1
            else
                openssl dgst -sha384 -r "$path" | cut -d' ' -f1
            fi
            ;;
        sha512)
            if command -v sha512sum >/dev/null 2>&1; then
                sha512sum "$path" | cut -d' ' -f1
            else
                openssl dgst -sha512 -r "$path" | cut -d' ' -f1
            fi
            ;;
    esac
}

expected_hex_len() {
    case "$1" in
        sha224) echo 56 ;;
        sha384) echo 96 ;;
        sha512) echo 128 ;;
    esac
}

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
        echo "PASS  $desc"
    else
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$desc")
        echo "FAIL  $desc"
        echo "      expected: $expected"
        echo "      actual:   $actual"
    fi
}

check_exit() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
        echo "PASS  $desc (exit $actual)"
    else
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$desc")
        echo "FAIL  $desc"
        echo "      expected exit: $expected"
        echo "      actual exit:   $actual"
    fi
}

# ---------------------------------------------------------------------------
# per-algorithm digest correctness: empty / short / boundary lengths / files
# ---------------------------------------------------------------------------

for algo in sha224 sha384 sha512; do
    echo "--- $algo: digest correctness ---"

    # empty input
    exp=$(reference_digest "$algo" "")
    act=$(printf "" | "$FT_SSL" "$algo" -q)
    check "$algo: empty stdin" "$exp" "$act"

    # single byte
    exp=$(reference_digest "$algo" "a")
    act=$(printf "a" | "$FT_SSL" "$algo" -q)
    check "$algo: single byte 'a'" "$exp" "$act"

    # known short string
    exp=$(reference_digest "$algo" "abc")
    act=$(printf "abc" | "$FT_SSL" "$algo" -q)
    check "$algo: 'abc'" "$exp" "$act"

    # sanity: digest is the right length in hex chars
    want_len=$(expected_hex_len "$algo")
    got_len=${#act}
    check "$algo: digest length is $want_len hex chars" "$want_len" "$got_len"

    # padding boundary lengths differ per algorithm:
    #   sha224/sha256-family block=64,  boundary around 56 (BLOCK_SIZE-8)
    #   sha384/sha512-family block=128, boundary around 112 (BLOCK_SIZE-16)
    if [ "$algo" = "sha224" ]; then
        lengths="54 55 56 57 63 64 65 120 128"
    else
        lengths="110 111 112 113 127 128 129 200 256"
    fi

    for n in $lengths; do
        content=$(python3 -c "import sys; sys.stdout.write('a'*$n)")
        exp=$(reference_digest "$algo" "$content")
        act=$(printf '%s' "$content" | "$FT_SSL" "$algo" -q)
        check "$algo: boundary length n=$n" "$exp" "$act"
    done

    # multi-block, non-repetitive content
    content=$(python3 -c "print('The quick brown fox jumps over the lazy dog' * 5, end='')")
    exp=$(reference_digest "$algo" "$content")
    act=$(printf '%s' "$content" | "$FT_SSL" "$algo" -q)
    check "$algo: multi-block non-repetitive string" "$exp" "$act"

    # binary file (100KB, not just text)
    head -c 100000 /dev/urandom > "$TMPDIR/bigfile.bin"
    exp=$(reference_digest_file "$algo" "$TMPDIR/bigfile.bin")
    act=$("$FT_SSL" "$algo" -q "$TMPDIR/bigfile.bin")
    check "$algo: 100KB binary file" "$exp" "$act"

    echo
done

# ---------------------------------------------------------------------------
# flags / output formatting (same rules as md5/sha256: -p -q -r -s)
# ---------------------------------------------------------------------------

for algo in sha224 sha384 sha512; do
    echo "--- $algo: flags and formatting ---"
    display_name=$(echo "$algo" | tr '[:lower:]' '[:upper:]')

    # bare stdin -> (stdin)= form
    out=$(printf "hello" | "$FT_SSL" "$algo")
    case "$out" in
        "(stdin)="*) PASS=$((PASS+1)); echo "PASS  $algo: bare stdin -> (stdin)= form" ;;
        *) FAIL=$((FAIL+1)); FAILED_NAMES+=("$algo: bare stdin format"); echo "FAIL  $algo: bare stdin format -> got: $out" ;;
    esac

    # -s string -> DISPLAYNAME ("string") = hash
    exp_hash=$(reference_digest "$algo" "foo")
    out=$("$FT_SSL" "$algo" -s "foo")
    expected_line="$display_name (\"foo\") = $exp_hash"
    check "$algo: -s string display name and format" "$expected_line" "$out"

    # file -> DISPLAYNAME (file) = hash
    echo "test content" > "$TMPDIR/file.txt"
    exp_hash=$(reference_digest_file "$algo" "$TMPDIR/file.txt")
    out=$("$FT_SSL" "$algo" "$TMPDIR/file.txt")
    expected_line="$display_name ($TMPDIR/file.txt) = $exp_hash"
    check "$algo: file display name and format" "$expected_line" "$out"

    # -q -> digest only
    out=$(printf "hello" | "$FT_SSL" "$algo" -q)
    check "$algo: -q digest-only length" "$(expected_hex_len "$algo")" "${#out}"

    # -r file -> "hash filename"
    out=$("$FT_SSL" "$algo" -r "$TMPDIR/file.txt")
    expected_line="$exp_hash $TMPDIR/file.txt"
    check "$algo: -r file format" "$expected_line" "$out"

    # -p echoes stdin content then appends digest, no trailing-newline leak
    exp_hash=$(reference_digest "$algo" "42 is nice")
    out=$(printf "42 is nice" | "$FT_SSL" "$algo" -p)
    expected_line="(\"42 is nice\")= $exp_hash"
    check "$algo: -p quoting, no name/paren prefix, no space before =" "$expected_line" "$out"

    # missing file -> non-zero exit, doesn't crash
    "$FT_SSL" "$algo" "$TMPDIR/does_not_exist_$$.txt" >/dev/null 2>/dev/null
    check_exit "$algo: missing file -> non-zero exit" "1" "$?"

    echo
done

# ---------------------------------------------------------------------------
# command dispatch / registration sanity
# ---------------------------------------------------------------------------

echo "--- command registration ---"

out=$("$FT_SSL" foobar 2>&1)
for algo in sha224 sha384 sha512; do
    case "$out" in
        *"$algo"*) PASS=$((PASS+1)); echo "PASS  invalid-command listing mentions $algo" ;;
        *) FAIL=$((FAIL+1)); FAILED_NAMES+=("invalid-command listing mentions $algo"); echo "FAIL  invalid-command listing does not mention $algo" ;;
    esac
done
echo

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

echo "=== $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    echo "failed cases:"
    for name in "${FAILED_NAMES[@]}"; do
        echo "  - $name"
    done
    exit 1
fi
exit 0