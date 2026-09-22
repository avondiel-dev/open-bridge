#!/bin/bash
# Regression suite for infra/object-stores/_schema.yaml.
#
#   run.sh            every valid/ file must pass, every invalid/ file must
#                     fail AND name the reason it was written for. A control
#                     that fails for the wrong reason proves nothing.
#   run.sh --mutate   soften ONE rule in a scratch copy of the schema and prove
#                     that exactly the controls belonging to that rule go
#                     hollow. A control that stays red while its own rule is
#                     gone was never testing that rule.
#
# Shaped after infra/remotes/_tests/run.sh, because it answers the same
# question about a different schema. The controls are the shapes the ADR
# (docs/object-store.md) rules out: a declaration without its tripwire, a store
# with no placement policy, a store that hides whether its bytes exist twice, a
# credential written as a value.
#
# The `_`-prefix keeps this folder out of `infra/object-stores/*.yaml`, which is
# what validate-bridge.py globs, so these deliberately invalid files never
# reach it.

set -uo pipefail
cd "$(dirname "$0")/../../.." || exit 2

SCHEMA="infra/object-stores/_schema.yaml"
DIR="infra/object-stores/_tests"
FAILED=0

if ! command -v check-jsonschema >/dev/null 2>&1; then
    echo "check-jsonschema not on PATH (pipx install check-jsonschema), skipping"
    exit 0
fi

# file | needle its error must contain | sed removing the rule | controls that
# rule owns (space separated; more than one means the rule is shared)
CONTROLS=(
  "no-scope.yaml|'scope' is a required property|s/\[name, scope, /[name, /|no-scope.yaml"
  "scope-core.yaml|'core' is not one of|s/enum: \[org, user, private\]/enum: [core, org, user, private]/|scope-core.yaml"
  "no-holds.yaml|'holds' is a required property|s/addresses, holds, /addresses, /|no-holds.yaml"
  "empty-holds.yaml|should be non-empty|/# holds: an empty policy answers nothing/d|empty-holds.yaml"
  "no-replicated.yaml|'replicated' is a required property|s/, replicated, recovery\]/, recovery]/|no-replicated.yaml"
  "recovery-without-backed-up.yaml|'backed_up' is a required property|s/required: \[backed_up\]/required: []/|recovery-without-backed-up.yaml"
  "unknown-backend.yaml|'ftp' is not one of|s/enum: \[local, s3\]/enum: [local, s3, ftp]/|unknown-backend.yaml"
  "local-without-path.yaml|'path' is a required property|s/required: \[path\]/required: []/|local-without-path.yaml"
  "s3-without-bucket.yaml|'bucket' is a required property|s/required: \[endpoint, bucket\]/required: [endpoint]/|s3-without-bucket.yaml"
  "raw-secret-in-credentials.yaml|'secret_key' was unexpected|s/additionalProperties: false   # credentials: references only/additionalProperties: true/|raw-secret-in-credentials.yaml"
  "top-level-unknown-key.yaml|'secret_access_key' was unexpected|s/additionalProperties: false   # top level: a field nobody declared is a typo, or a value/additionalProperties: true/|top-level-unknown-key.yaml"
  "location-unknown-key.yaml|'pth' was unexpected|s/additionalProperties: false   # location: one set of keys per backend/additionalProperties: true/|location-unknown-key.yaml"
  "s3-without-credentials.yaml|'credentials' is a required property|s/required: \[location, credentials\]/required: [location]/|s3-without-credentials.yaml"
  "local-relative-path.yaml|does not match '^[~/]'|/# local path: absolute or ~, never relative/d|local-relative-path.yaml"
  "credential-not-a-reference.yaml|does not match|/# a locator, never a value/d|credential-not-a-reference.yaml"
)

field() { echo "$1" | cut -d'|' -f"$2"; }

check() {  # schema, file -> 0 when the file validates
    check-jsonschema --schemafile "$1" "$2" >/dev/null 2>&1
}

# `pipefail` turns a matched grep into a failed pipeline whenever the producer
# exits non-zero, and check-jsonschema always does on an invalid file. So the
# output is captured first and matched afterwards.
reason_matches() {  # schema, file, needle
    local out
    out="$(check-jsonschema --schemafile "$1" "$2" 2>&1)"
    case "$out" in (*"$3"*) return 0 ;; (*) return 1 ;; esac
}

# ---------------------------------------------------------------- the suite --
if [ "${1:-}" != "--mutate" ]; then
    if [ ! -f "$SCHEMA" ]; then
        echo "FAIL  $SCHEMA does not exist, so nothing below can be measured"
        exit 1
    fi
    echo "== valid cases (must pass)"
    for f in "$DIR"/valid/*.yaml; do
        if check "$SCHEMA" "$f"; then
            printf "  ok    %s\n" "$(basename "$f")"
        else
            printf "  FAIL  %s  (a legitimate shape is refused)\n" "$(basename "$f")"
            check-jsonschema --schemafile "$SCHEMA" "$f" 2>&1 | sed -n '2,4p' | sed 's/^/        /'
            FAILED=1
        fi
    done

    echo "== negative controls (must fail, for their own reason)"
    for entry in "${CONTROLS[@]}"; do
        name="$(field "$entry" 1)"; needle="$(field "$entry" 2)"
        f="$DIR/invalid/$name"
        if check "$SCHEMA" "$f"; then
            printf "  FAIL  %-34s accepted; the rule is not enforced\n" "$name"
            FAILED=1
        elif reason_matches "$SCHEMA" "$f" "$needle"; then
            printf "  ok    %-34s refused for \"%s\"\n" "$name" "$needle"
        else
            printf "  FAIL  %-34s refused, but NOT for \"%s\"\n" "$name" "$needle"
            check-jsonschema --schemafile "$SCHEMA" "$f" 2>&1 | sed -n '2,4p' | sed 's/^/        /'
            FAILED=1
        fi
    done

    # Nothing in invalid/ may be left out of the table above: a fixture nobody
    # runs is a fixture nobody proved.
    for f in "$DIR"/invalid/*.yaml; do
        b="$(basename "$f")"
        printf '%s\n' "${CONTROLS[@]}" | cut -d'|' -f1 | grep -qx "$b" \
            || { printf "  FAIL  %-34s lies in invalid/ but no control claims it\n" "$b"; FAILED=1; }
    done

    [ "$FAILED" -eq 0 ] && echo "suite green" || echo "suite RED"
    exit "$FAILED"
fi

# ------------------------------------------------------------ the mutations --
echo "== mutation battery: each rule removed in turn"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

for entry in "${CONTROLS[@]}"; do
    rule="$(field "$entry" 1)"; mutation="$(field "$entry" 3)"; owned="$(field "$entry" 4)"
    cp "$SCHEMA" "$SCRATCH/schema.yaml"
    sed -i '' -e "$mutation" "$SCRATCH/schema.yaml" 2>/dev/null \
        || sed -i -e "$mutation" "$SCRATCH/schema.yaml"

    if ! diff -q "$SCHEMA" "$SCRATCH/schema.yaml" >/dev/null; then
        hollow=""
        for f in "$DIR"/invalid/*.yaml; do
            check "$SCRATCH/schema.yaml" "$f" && hollow="$hollow $(basename "$f")"
        done
        hollow="$(echo "$hollow" | tr ' ' '\n' | sort | xargs)"
        expect="$(echo "$owned" | tr ' ' '\n' | sort | xargs)"
        if [ "$hollow" = "$expect" ]; then
            printf "  ok    rule of %-34s gone -> hollow: %s\n" "$rule" "$hollow"
        else
            printf "  FAIL  rule of %-34s gone -> expected [%s], got [%s]\n" "$rule" "$expect" "${hollow:-nothing}"
            FAILED=1
        fi
        # The SOFTENED schema must still accept what was always legitimate,
        # otherwise the battery would be measuring a broken schema rather than
        # a missing rule. Checked against the scratch copy, inside the loop: the
        # copy of this suite in infra/remotes/_tests/ checks the ORIGINAL
        # schema after the loop, which proves nothing about any mutation.
        for f in "$DIR"/valid/*.yaml; do
            check "$SCRATCH/schema.yaml" "$f" \
                || { printf "  FAIL  rule of %-34s gone -> a valid case broke: %s\n" "$rule" "$(basename "$f")"; FAILED=1; }
        done
    else
        printf "  FAIL  the mutation for %s changed nothing in the schema\n" "$rule"
        FAILED=1
    fi
done

[ "$FAILED" -eq 0 ] && echo "battery green: every control proved" || echo "battery RED"
exit "$FAILED"
