#!/bin/bash
# Regression suite for skills/secrets, in the shape of the workload one: one
# line per case, then the tally.
#
#   ./scripts/tests/run.sh                 everything
#   ./scripts/tests/run.sh keychain        only cases whose name matches
#   ./scripts/tests/run.sh --mutate        soften one literal at a time, demand red
#
# The suite never reaches a real secret store. A guard in tests/conftest.py
# raises if a test tries to exec security, keepassxc-cli, az, op, secret-tool,
# ssh, scp or sudo, because the developer running this has real credentials in
# all of them. The single exception is the macOS tier, which creates its own
# throwaway keychain, names itself, and is skipped everywhere else.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$DIR/../.." && pwd)"
cd "$SKILL" || exit 2

PATTERN="${1:-}"

if [ "$PATTERN" = "--mutate" ]; then
  # The proof over the proof. Each entry in tests/mutations.py softens ONE
  # literal in an engine source and names the ONE test that must go red for it.
  # A mutation that stays green means the suite does not examine that behaviour,
  # whatever its name promises.
  #
  # Every mutation is applied to a SCRATCH COPY, never to the working tree, and
  # the copy is thrown away afterwards.
  exec python3 "$DIR/mutate.py"
fi

# The template carries its own X's and the whole path is given, because the
# two mktemp implementations disagree about `-t` with a bare name: BSD
# appends a suffix, GNU refuses with "too few X's in template". A suite
# written on one of them collected zero tests on the other and said so in a
# line nobody would connect to a temporary file. CI found this; a macOS run
# never could.
RAW="$(mktemp "${TMPDIR:-/tmp}/secrets-tests.XXXXXXXX")"
trap 'rm -f "$RAW"' EXIT

if [ -n "$PATTERN" ]; then
  python3 -m unittest discover -v -s tests -t . -k "$PATTERN" >"$RAW" 2>&1
else
  python3 -m unittest discover -v -s tests -t . >"$RAW" 2>&1
fi

awk -f "$DIR/tally.awk" "$RAW"
status=$?

if [ "$status" -ne 0 ]; then
  # A red verdict is not always a traceback: "everything was skipped" and
  # "nothing was collected" both fail with no failure block to show.
  detail="$(sed -n '/^======/,$p' "$RAW" | head -60)"
  if [ -n "$detail" ]; then
    echo
    echo "first failures in detail:"
    printf '%s\n' "$detail"
  fi
fi

exit "$status"
