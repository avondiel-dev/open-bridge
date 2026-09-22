#!/bin/sh
# Entry point of the object-store skill.
#
# The skill is reached through the discovery symlink, so $0 is usually a link.
# Resolve it step by step: readlink -f is not portable, and this loop is.
set -eu

target="$0"
while [ -L "$target" ]; do
    link="$(readlink "$target")"
    case "$link" in
        /*) target="$link" ;;
        *)  target="$(dirname "$target")/$link" ;;
    esac
done
SKILL_DIR="$(cd "$(dirname "$target")" && pwd -P)"

# WHICH python3 runs this, and why it is not simply the first one on PATH.
#
# This engine imports nothing but the standard library, except PyYAML for the
# store declarations, which it names when it is missing. What can happen is the
# other half of the same scar, measured on 2026-08-25 on the machine this
# fleet watches: a non interactive PATH resolves `python3` to an interpreter
# that is too old for the syntax, and the failure arrives as a SyntaxError from
# the middle of an import chain, which says nothing about the actual problem.
#
# So the candidates are PROBED, and the probe measures the requirement itself:
# it imports the skill. A version number would be a second derivation of "can
# this run" and drifts the day the code uses something newer.
can_run() {
    PYTHONPATH="$SKILL_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$1" -c 'import objstore.cli' >/dev/null 2>&1
}

CANDIDATES="python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3"

refuse() {
    echo "object-store: no python3 here can run this skill." >&2
    echo >&2
    if [ -n "${BRIDGE_PYTHON:-}" ]; then
        echo "  BRIDGE_PYTHON names $BRIDGE_PYTHON, and it cannot." >&2
    fi
    echo "  Each candidate has to import the skill; it needs only the standard library." >&2
    echo "  What was found:" >&2
    for cand in $CANDIDATES; do
        full="$(command -v "$cand" 2>/dev/null || true)"
        if [ -z "$full" ]; then
            echo "    $cand: not there" >&2
            continue
        fi
        version="$("$full" -V 2>&1 || echo '?')"
        echo "    $full: $version, cannot import the skill" >&2
    done
    echo >&2
    echo "  Set BRIDGE_PYTHON to name an interpreter that can." >&2
    exit 78
}

if [ -n "${BRIDGE_PYTHON:-}" ]; then
    # Named outright wins, because a machine with an unusual layout needs a way
    # to say what to run. It is still probed, so a wrong one is answered with
    # the report above instead of an import error out of nowhere.
    can_run "$BRIDGE_PYTHON" || refuse
    PYTHON="$BRIDGE_PYTHON"
else
    PYTHON=""
    for cand in $CANDIDATES; do
        command -v "$cand" >/dev/null 2>&1 || continue
        if can_run "$cand"; then PYTHON="$cand"; break; fi
    done
    [ -n "$PYTHON" ] || refuse
fi

PYTHONPATH="$SKILL_DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$PYTHON" -m objstore.cli "$@"
