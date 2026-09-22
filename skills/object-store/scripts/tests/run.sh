#!/bin/bash
# Regression suite for skills/object-store: one line per case, then the verdict.
#
#   ./scripts/tests/run.sh                 everything
#   ./scripts/tests/run.sh cache           only cases whose name matches
#   ./scripts/tests/run.sh --mutate        soften one literal at a time, demand red
#
# The suite never reaches a real store. tests/support.py lets a socket connect
# to loopback only and lets no program start, because whoever runs this may
# have a live bucket and live credentials configured. S3 is played by an
# in-memory fake on 127.0.0.1.
#
# The verdicts come from runner.py, which reads them from unittest's result
# object and writes them to STDOUT. Warnings and all other output go to stderr,
# kept apart, because a verdict parsed out of a shared stream was lost on CI
# when a ResourceWarning landed in the middle of its line (see runner.py).
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$DIR/../.." && pwd)"
cd "$SKILL" || exit 2

PATTERN="${1:-}"

if [ "$PATTERN" = "--mutate" ]; then
  # Each entry in tests/mutations.py softens ONE literal and names the ONE test
  # that must go red for it, applied to a scratch copy of the skill, never to
  # the working tree.
  exec python3 "$DIR/mutate.py"
fi

ERR="$(mktemp "${TMPDIR:-/tmp}/objstore-tests.XXXXXXXX")"
trap 'rm -f "$ERR"' EXIT

python3 "$DIR/runner.py" "$PATTERN" 2>"$ERR"
status=$?

# Leaks are not failures, but they are worth seeing: they were the cause of the
# lost verdict, and a new one is a resource somebody forgot to close.
if grep -q "ResourceWarning" "$ERR"; then
  echo
  echo "resource warnings on stderr (not a failure, but a resource was left open):"
  grep -A1 "ResourceWarning" "$ERR" | head -12
fi
if [ "$status" -ne 0 ] && [ -s "$ERR" ]; then
  echo
  echo "stderr:"
  tail -30 "$ERR"
fi

exit "$status"
