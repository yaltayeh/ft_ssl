#!/usr/bin/env bash
# Test suite for the mandatory part of ft_ssl (md5 / sha256).
#
# Every expected digest is computed live from md5sum / sha256sum / openssl,
# never hard-coded, so the suite cross-checks ft_ssl against the reference tools.
#
# Usage: tests/test_ft_ssl.sh [path-to-ft_ssl]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSL="${1:-$ROOT/ft_ssl}"

if [ ! -x "$SSL" ]; then
	echo "error: $SSL not found or not executable (run make first)" >&2
	exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ft_ssl_tests.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 2

PASS=0
FAIL=0
FAILED_NAMES=()

# --- reference helpers -------------------------------------------------------

# md5 of a string given exactly (no trailing newline added)
md5_s()    { printf '%s' "$1" | md5sum    | cut -d' ' -f1; }
sha256_s() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
md5_f()    { md5sum    < "$1" | cut -d' ' -f1; }
sha256_f() { sha256sum < "$1" | cut -d' ' -f1; }

# dispatch by command name so md5/sha256 cases can share one body
ref_s() { if [ "$1" = md5 ]; then md5_s "$2"; else sha256_s "$2"; fi; }
ref_f() { if [ "$1" = md5 ]; then md5_f "$2"; else sha256_f "$2"; fi; }
disp()  { if [ "$1" = md5 ]; then echo MD5; else echo SHA256; fi; }

# --- test driver -------------------------------------------------------------
#
# check <name> <expected_exit> <expected_output> <stdin_content> <args...>
# expected_output is compared against stdout+stderr merged, exactly as the
# subject's transcripts show them interleaved in a terminal.
# Pass the literal string __NOSTDIN__ as stdin_content to attach </dev/null.

check() {
	local name="$1" exp_code="$2" exp_out="$3" stdin="$4"
	shift 4

	local actual actual_code
	if [ "$stdin" = "__NOSTDIN__" ]; then
		actual="$("$SSL" "$@" </dev/null 2>&1)"
	else
		actual="$(printf '%s' "$stdin" | "$SSL" "$@" 2>&1)"
	fi
	actual_code=$?

	if [ "$actual" = "$exp_out" ] && [ "$actual_code" = "$exp_code" ]; then
		PASS=$((PASS + 1))
		printf 'PASS  %s\n' "$name"
	else
		FAIL=$((FAIL + 1))
		FAILED_NAMES+=("$name")
		printf 'FAIL  %s\n' "$name"
		printf '        args: %s\n' "$*"
		printf '        expected exit %s, got %s\n' "$exp_code" "$actual_code"
		printf '        --- expected ---\n'
		printf '%s\n' "$exp_out" | sed 's/^/        | /'
		printf '        --- actual ---\n'
		printf '%s\n' "$actual" | sed 's/^/        | /'
	fi
}

# --- fixtures ----------------------------------------------------------------

printf 'And above all,\n'      > file
printf 'https://www.42.fr/\n'  > website
printf ''                      > empty
printf 'no trailing newline'   > nonl
head -c 100000 /dev/urandom    > big
mkdir -p adir
printf 'secret\n'              > noperm && chmod 000 noperm

FILE_NOT_FOUND="No such file or directory"

echo "=== ft_ssl test suite ==="
echo

# =============================================================================
# 1. Usage / invalid command
# =============================================================================

check "no arguments -> usage, exit 1" 1 \
	"usage: ft_ssl command [flags] [file/string]" "__NOSTDIN__"

INVALID_OUT="ft_ssl: Error: 'foobar' is an invalid command.

Commands:
md5
sha256

Flags:
-p -q -r -s"
check "invalid command -> command/flag listing, exit 1" 1 "$INVALID_OUT" "__NOSTDIN__" foobar

check "invalid command (uppercase MD5 is not a command)" 1 \
	"${INVALID_OUT//foobar/MD5}" "__NOSTDIN__" MD5

# =============================================================================
# 2..N. Per-algorithm behaviour: everything below runs for both md5 and sha256
# =============================================================================

for cmd in md5 sha256; do
	D="$(disp "$cmd")"

	FILE_H="$(ref_f "$cmd" file)"
	WEB_H="$(ref_f "$cmd" website)"
	EMPTY_H="$(ref_f "$cmd" empty)"
	NONL_H="$(ref_f "$cmd" nonl)"
	BIG_H="$(ref_f "$cmd" big)"
	FOO_H="$(ref_s "$cmd" foo)"
	BAR_H="$(ref_s "$cmd" bar)"

	echo "--- $cmd: stdin ---"

	# --- rule 12: no flags, no operand -> read stdin, "(stdin)= <hash>"
	S='42 is nice
'
	H="$(ref_s "$cmd" "$S")"
	check "$cmd: bare stdin -> (stdin)= form" 0 "(stdin)= $H" "$S" "$cmd"

	check "$cmd: bare stdin digest equals openssl $cmd" 0 \
		"(stdin)= $(printf '%s' "$S" | openssl "$cmd" | sed 's/^.*= //')" "$S" "$cmd"

	check "$cmd: empty stdin" 0 "(stdin)= $EMPTY_H" "" "$cmd"

	# --- rule 4: -r alone does not change the stdin line
	check "$cmd: -r alone on stdin is ignored (still (stdin)= )" 0 \
		"(stdin)= $H" "$S" "$cmd" -r

	# --- -q alone on stdin: digest only
	check "$cmd: -q alone on stdin -> digest only" 0 "$H" "$S" "$cmd" -q

	# --- subject transcript: echo "Pity the living." | ft_ssl md5 -q -r
	S2='Pity the living.
'
	H2="$(ref_s "$cmd" "$S2")"
	check "$cmd: -q -r on stdin -> digest only" 0 "$H2" "$S2" "$cmd" -q -r
	check "$cmd: -r -q on stdin (order swapped)" 0 "$H2" "$S2" "$cmd" -r -q

	# --- rule: -p echoes stdin in quoted form, trailing newline stripped
	check "$cmd: -p on stdin -> (\"content\")= hash" 0 \
		"(\"42 is nice\")= $H" "$S" "$cmd" -p

	# --- rule 4: -r must not alter the -p stdin line either
	check "$cmd: -p -r on stdin ignores -r" 0 \
		"(\"42 is nice\")= $H" "$S" "$cmd" -p -r

	# --- rule 5: -p -q -> raw content line, then bare digest
	check "$cmd: -p -q on stdin -> raw echo then digest" 0 \
		"42 is nice
$H" "$S" "$cmd" -p -q

	check "$cmd: -q -p on stdin (order swapped)" 0 \
		"42 is nice
$H" "$S" "$cmd" -q -p

	check "$cmd: -p -q -r on stdin -> raw echo then digest" 0 \
		"42 is nice
$H" "$S" "$cmd" -p -q -r

	# --- -p with stdin that has no trailing newline
	NN='no trailing newline'
	NNH="$(ref_s "$cmd" "$NN")"
	check "$cmd: -p stdin without trailing newline" 0 \
		"(\"$NN\")= $NNH" "$NN" "$cmd" -p
	check "$cmd: -p -q stdin without trailing newline" 0 \
		"$NN
$NNH" "$NN" "$cmd" -p -q

	# --- -p with empty stdin
	check "$cmd: -p on empty stdin" 0 "(\"\")= $EMPTY_H" "" "$cmd" -p
	check "$cmd: -p -q on empty stdin" 0 "
$EMPTY_H" "" "$cmd" -p -q

	echo "--- $cmd: files ---"

	check "$cmd: single file" 0 "$D (file) = $FILE_H" "__NOSTDIN__" "$cmd" file
	check "$cmd: -q file -> digest only" 0 "$WEB_H" "__NOSTDIN__" "$cmd" -q website
	check "$cmd: -r file -> hash then name" 0 "$FILE_H file" "__NOSTDIN__" "$cmd" -r file
	check "$cmd: -q -r file (rule 6: -q wins)" 0 "$FILE_H" "__NOSTDIN__" "$cmd" -q -r file
	check "$cmd: -r -q file (rule 6, order swapped)" 0 "$FILE_H" "__NOSTDIN__" "$cmd" -r -q file
	check "$cmd: empty file" 0 "$D (empty) = $EMPTY_H" "__NOSTDIN__" "$cmd" empty
	check "$cmd: 100KB binary file (multi-block)" 0 "$D (big) = $BIG_H" "__NOSTDIN__" "$cmd" big
	check "$cmd: several files, argv order preserved" 0 \
		"$D (file) = $FILE_H
$D (website) = $WEB_H
$D (empty) = $EMPTY_H" "__NOSTDIN__" "$cmd" file website empty
	# Option parsing stops at the first bare filename operand: -r after it is
	# a filename, and website is hashed with the default (non-reversed) format.
	check "$cmd: -r after the first operand is a filename, not a flag" 1 \
		"$D (file) = $FILE_H
ft_ssl: $cmd: -r: $FILE_NOT_FOUND
$D (website) = $WEB_H" "__NOSTDIN__" "$cmd" file -r website

	echo "--- $cmd: -s strings ---"

	check "$cmd: -s string" 0 "$D (\"foo\") = $FOO_H" "__NOSTDIN__" "$cmd" -s foo
	check "$cmd: -s with spaces and apostrophe" 0 \
		"$D (\"pity those that aren't following baerista on spotify.\") = $(ref_s "$cmd" "pity those that aren't following baerista on spotify.")" \
		"__NOSTDIN__" "$cmd" -s "pity those that aren't following baerista on spotify."
	check "$cmd: -s empty string" 0 "$D (\"\") = $EMPTY_H" "__NOSTDIN__" "$cmd" -s ""
	check "$cmd: -q -s string -> digest only" 0 "$FOO_H" "__NOSTDIN__" "$cmd" -q -s foo
	check "$cmd: -r -s string -> hash then quoted string" 0 "$FOO_H \"foo\"" "__NOSTDIN__" "$cmd" -r -s foo
	check "$cmd: -q -r -s string (-q wins)" 0 "$FOO_H" "__NOSTDIN__" "$cmd" -q -r -s foo
	check "$cmd: several -s strings in order" 0 \
		"$D (\"foo\") = $FOO_H
$D (\"bar\") = $BAR_H" "__NOSTDIN__" "$cmd" -s foo -s bar
	check "$cmd: -s string that looks like a flag is taken literally" 0 \
		"$D (\"-r\") = $(ref_s "$cmd" "-r")" \
		"__NOSTDIN__" "$cmd" -s "-r"
	check "$cmd: mixed files and strings keep argv order" 0 \
		"$D (\"foo\") = $FOO_H
$D (\"bar\") = $BAR_H
$D (file) = $FILE_H" "__NOSTDIN__" "$cmd" -s foo -s bar file
	# Option parsing stops at the first bare filename operand: the subject's
	# "md5 -r -p -s foo file -s bar" transcript shows the trailing -s and its
	# argument both failing as filenames even though -s has an argument there.
	check "$cmd: -s after a file operand is a plain filename" 1 \
		"$D (file) = $FILE_H
ft_ssl: $cmd: -s: $FILE_NOT_FOUND
ft_ssl: $cmd: bar: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" file -s bar
	check "$cmd: -q before the first operand is a flag" 0 \
		"$FILE_H" "__NOSTDIN__" "$cmd" -q file
	check "$cmd: -q after the first operand is a filename that fails" 1 \
		"$D (file) = $FILE_H
ft_ssl: $cmd: -q: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" file -q
	check "$cmd: -p after the first operand does not enable stdin echo" 1 \
		"$D (file) = $FILE_H
ft_ssl: $cmd: -p: $FILE_NOT_FOUND" "42 is nice
" "$cmd" file -p
	check "$cmd: -s before any operand still works after other flags" 0 \
		"$FOO_H \"foo\"
$BAR_H \"bar\"" "__NOSTDIN__" "$cmd" -r -s foo -s bar

	echo "--- $cmd: stdin combined with operands ---"

	# --- rule 3: a file operand suppresses stdin unless -p is given
	check "$cmd: file operand alone does not read stdin" 0 \
		"$D (file) = $FILE_H" "some of this will not make sense at first
" "$cmd" file

	# --- rule 2/3: -p reads stdin in addition, and stdin always prints first
	P='be sure to handle edge cases carefully
'
	PH="$(ref_s "$cmd" "$P")"
	check "$cmd: -p with a file -> stdin first, then file" 0 \
		"(\"be sure to handle edge cases carefully\")= $PH
$D (file) = $FILE_H" "$P" "$cmd" -p file

	# -p may sit anywhere in the option section; STDIN is still processed first
	check "$cmd: -p after a -s string still prints stdin first" 0 \
		"(\"be sure to handle edge cases carefully\")= $PH
$D (\"foo\") = $FOO_H
$D (file) = $FILE_H" "$P" "$cmd" -s foo -p file

	P2='but eventually you will understand
'
	P2H="$(ref_s "$cmd" "$P2")"
	check "$cmd: -p -r with a file (stdin ignores -r, file does not)" 0 \
		"(\"but eventually you will understand\")= $P2H
$FILE_H file" "$P2" "$cmd" -p -r file

	P3="GL HF let's go
"
	P3H="$(ref_s "$cmd" "$P3")"
	check "$cmd: -p -s foo file (subject transcript)" 0 \
		"(\"GL HF let's go\")= $P3H
$D (\"foo\") = $FOO_H
$D (file) = $FILE_H" "$P3" "$cmd" -p -s foo file

	# --- rule 10: trailing -s with no argument becomes a (failing) filename
	P4='one more thing
'
	P4H="$(ref_s "$cmd" "$P4")"
	check "$cmd: -r -p -s foo file -s bar (trailing -s becomes a bad file)" 1 \
		"(\"one more thing\")= $P4H
$FOO_H \"foo\"
$FILE_H file
ft_ssl: $cmd: -s: $FILE_NOT_FOUND
ft_ssl: $cmd: bar: $FILE_NOT_FOUND" "$P4" "$cmd" -r -p -s foo file -s bar

	# --- rule 5 + operands: -p -q prints raw stdin, then bare digests
	P5='just to be extra clear
'
	P5H="$(ref_s "$cmd" "$P5")"
	check "$cmd: -r -q -p -s foo file (subject transcript)" 0 \
		"just to be extra clear
$P5H
$FOO_H
$FILE_H" "$P5" "$cmd" -r -q -p -s foo file

	# --- full four-flag combination
	check "$cmd: -p -q -r -s foo file (all four flags)" 0 \
		"just to be extra clear
$P5H
$FOO_H
$FILE_H" "$P5" "$cmd" -p -q -r -s foo file

	echo "--- $cmd: errors and exit codes ---"

	check "$cmd: missing file -> stderr message, exit 1" 1 \
		"ft_ssl: $cmd: nope.txt: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" nope.txt

	check "$cmd: missing file does not abort the rest of the run" 1 \
		"$D (file) = $FILE_H
ft_ssl: $cmd: nope.txt: $FILE_NOT_FOUND
$D (website) = $WEB_H" "__NOSTDIN__" "$cmd" file nope.txt website

	check "$cmd: several failures all reported, exit still 1" 1 \
		"$D (\"foo\") = $FOO_H
ft_ssl: $cmd: a.txt: $FILE_NOT_FOUND
ft_ssl: $cmd: b.txt: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" -s foo a.txt b.txt

	check "$cmd: directory operand -> error, exit 1" 1 \
		"ft_ssl: $cmd: adir: Is a directory" "__NOSTDIN__" "$cmd" adir

	if [ "$(id -u)" != "0" ]; then
		check "$cmd: unreadable file -> error, exit 1" 1 \
			"ft_ssl: $cmd: noperm: Permission denied" "__NOSTDIN__" "$cmd" noperm
	fi

	check "$cmd: all entries succeed -> exit 0" 0 \
		"$D (\"foo\") = $FOO_H
$D (file) = $FILE_H" "__NOSTDIN__" "$cmd" -s foo file

	check "$cmd: -q -r with a failing file keeps going" 1 \
		"$FILE_H
ft_ssl: $cmd: nope.txt: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" -q -r file nope.txt

	check "$cmd: -p plus a failing file (stdin still first, exit 1)" 1 \
		"(\"42 is nice\")= $H
ft_ssl: $cmd: nope.txt: $FILE_NOT_FOUND" "$S" "$cmd" -p nope.txt

	echo "--- $cmd: robustness ---"

	check "$cmd: unknown flag is treated as a filename" 1 \
		"ft_ssl: $cmd: -z: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" -z

	check "$cmd: lone dash is treated as a filename" 1 \
		"ft_ssl: $cmd: -: $FILE_NOT_FOUND" "__NOSTDIN__" "$cmd" -

	check "$cmd: repeated flags are idempotent" 0 \
		"$FILE_H" "__NOSTDIN__" "$cmd" -q -q -q file

	check "$cmd: same file twice hashes twice" 0 \
		"$D (file) = $FILE_H
$D (file) = $FILE_H" "__NOSTDIN__" "$cmd" file file
done

# =============================================================================
# Subject transcripts, verbatim
# =============================================================================

echo "--- subject transcripts (literal digests from the subject) ---"

check "transcript: echo '42 is nice' | ft_ssl md5" 0 \
	"(stdin)= 35f1d6de0302e2086a4e472266efb3a9" '42 is nice
' md5
check "transcript: echo '42 is nice' | ft_ssl md5 -p" 0 \
	'("42 is nice")= 35f1d6de0302e2086a4e472266efb3a9' '42 is nice
' md5 -p
check "transcript: echo 'Pity the living.' | ft_ssl md5 -q -r" 0 \
	"e20c3b973f63482a778f3fd1869b7f25" 'Pity the living.
' md5 -q -r
check "transcript: ft_ssl md5 file" 0 \
	"MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a" "__NOSTDIN__" md5 file
check "transcript: ft_ssl md5 -r file" 0 \
	"53d53ea94217b259c11a5a2d104ec58a file" "__NOSTDIN__" md5 -r file
check "transcript: ft_ssl md5 -s \"pity those...\"" 0 \
	'MD5 ("pity those that aren'"'"'t following baerista on spotify.") = a3c990a1964705d9bf0e602f44572f5f' \
	"__NOSTDIN__" md5 -s "pity those that aren't following baerista on spotify."
check "transcript: md5 -p file" 0 \
	'("be sure to handle edge cases carefully")= 3553dc7dc5963b583c056d1b9fa3349c
MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a' 'be sure to handle edge cases carefully
' md5 -p file
check "transcript: md5 file (stdin ignored)" 0 \
	"MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a" 'some of this will not make sense at first
' md5 file
check "transcript: md5 -p -r file" 0 \
	'("but eventually you will understand")= dcdd84e0f635694d2a943fa8d3905281
53d53ea94217b259c11a5a2d104ec58a file' 'but eventually you will understand
' md5 -p -r file
check "transcript: md5 -p -s foo file" 0 \
	'("GL HF let'"'"'s go")= d1e3cc342b6da09480b27ec57ff243e2
MD5 ("foo") = acbd18db4cc2f85cedef654fccc4a4d8
MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a' 'GL HF let'"'"'s go
' md5 -p -s foo file
check "transcript: md5 -r -p -s foo file -s bar" 1 \
	'("one more thing")= a0bd1876c6f011dd50fae52827f445f5
acbd18db4cc2f85cedef654fccc4a4d8 "foo"
53d53ea94217b259c11a5a2d104ec58a file
ft_ssl: md5: -s: No such file or directory
ft_ssl: md5: bar: No such file or directory' 'one more thing
' md5 -r -p -s foo file -s bar
check "transcript: md5 -r -q -p -s foo file" 0 \
	'just to be extra clear
3ba35f1ea0d170cb3b9a752e3360286c
acbd18db4cc2f85cedef654fccc4a4d8
53d53ea94217b259c11a5a2d104ec58a' 'just to be extra clear
' md5 -r -q -p -s foo file
check "transcript: sha256 -q website" 0 \
	"1ceb55d2845d9dd98557b50488db12bbf51aaca5aa9c1199eb795607a2457daf" "__NOSTDIN__" sha256 -q website
check "transcript: sha256 -s '42 is nice'" 0 \
	'SHA256 ("42 is nice") = b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f' \
	"__NOSTDIN__" sha256 -s "42 is nice"

# =============================================================================
# Digest correctness sweep: padding boundaries, against md5sum / sha256sum
# =============================================================================

echo "--- digest correctness sweep (padding boundaries) ---"

SWEEP_FAIL=0
for len in 0 1 2 31 32 54 55 56 57 63 64 65 119 120 127 128 129 255 256 1000 4096; do
	head -c "$len" /dev/urandom > sweep.bin
	for cmd in md5 sha256; do
		exp="$(ref_f "$cmd" sweep.bin)"
		got="$("$SSL" "$cmd" -q sweep.bin)"
		if [ "$exp" != "$got" ]; then
			echo "FAIL  $cmd digest of $len-byte file: expected $exp got $got"
			SWEEP_FAIL=$((SWEEP_FAIL + 1))
		fi
	done
done
if [ "$SWEEP_FAIL" = 0 ]; then
	PASS=$((PASS + 1))
	echo "PASS  digest sweep over 21 lengths x 2 algorithms matches md5sum/sha256sum"
else
	FAIL=$((FAIL + 1))
	FAILED_NAMES+=("digest sweep")
fi

# =============================================================================
# Summary
# =============================================================================

echo
echo "=== $PASS passed, $FAIL failed ==="
if [ "$FAIL" != 0 ]; then
	printf 'failed cases:\n'
	printf '  - %s\n' "${FAILED_NAMES[@]}"
	exit 1
fi
exit 0
