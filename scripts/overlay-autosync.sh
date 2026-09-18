#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# overlay-autosync.sh — unattended sync of every subscribed org overlay.
#
# The companion to upstream-autoupdate.sh. That one keeps CORE current; this one
# keeps the ORG layer current. Without it, staying current is a thing somebody
# has to remember, and the failure is silent: an overlay drifts for weeks while
# every session keeps using the copy it happens to hold. Measured on the
# instance this comes from: 71 days stale, 124 overlay commits behind, 6 of 26
# org skills present — and the skill somebody was looking for was in the other 20.
#
# WHY THIS CAN RUN UNATTENDED AT ALL. `overlay.py sync --yes` splits the work
# exactly where the trust boundary sits:
#   · config, contexts, projects, mandants, accounts   → applied
#   · updates to behavioural files ALREADY accepted    → applied (the [y] gate
#     is first-materialize only: `first_time = dest not in prev_files`)
#   · behavioural files arriving for the FIRST time    → SKIPPED, listed, never
#     silently installed
# So the publisher stays responsible for what it ships, the consumer keeps one
# decision per genuinely new tool, and nothing in between needs a human.
# A new skill is therefore REPORTED, not applied — that is the point, not a gap.
#
# Guards: only on a user/* branch (the engine refuses otherwise; this fails
# early with a readable reason). Local edits are never clobbered — the engine
# 3-way-merges them and prompts, which under --yes means it keeps the local file.
#
# AND: an unattended run APPLIES and UPDATES, it never DELETES. It plans first
# (--dry-run), and if the plan contains even ONE prune it reports and stops
# without touching anything.
#
# That bar is deliberately stricter than the engine's own. The engine blocks a
# prune batch only above LARGE_PRUNE_THRESHOLD (5) — at or below it, a
# non-interactive --yes run removes the files. Measured here at the moment this
# was written: exactly 5 clean orphans, one keystroke under the guard, and one of
# them (skills/meeting-transcription/scripts/anchor_transcript.py) is a TRACKED
# file that upstream CORE ships — it became an orphan because the overlay stopped
# shipping that skill, not because anyone decided the file should go. A daily job
# that quietly deletes a CORE file is not a thing to own. A deletion is a human's
# call, so it escalates to one.
#
# Env (optional): SIGNAL_ACCOUNT + SIGNAL_RECIPIENT (both set → Signal push).
set -uo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)" || exit 1

REPORT="work/overlay-status.md"
LOG=/tmp/ob-overlay-autosync.log

notify() {
  { [ -n "${SIGNAL_ACCOUNT:-}" ] && [ -n "${SIGNAL_RECIPIENT:-}" ] \
    && command -v signal-cli >/dev/null 2>&1 \
    && signal-cli -a "$SIGNAL_ACCOUNT" send -m "$1" "$SIGNAL_RECIPIENT" >/dev/null 2>&1; } || true
}
report() { mkdir -p work; { echo "# Overlay Auto-Sync — $(date '+%F %T')"; echo; printf '%s\n' "$@"; } > "$REPORT"; }

branch=$(git branch --show-current 2>/dev/null || echo "")
case "$branch" in
  user/*) ;;
  *) report "- ⚠ skipped: not on a user/* branch (on '${branch:-detached}')" \
            "- the overlay engine only materializes on a user/* branch"
     echo "overlay-autosync: skipped — branch '${branch:-detached}'"; exit 0 ;;
esac

# Nothing subscribed → say so once and stay quiet. Not an error.
if ! python3 scripts/overlay.py list 2>/dev/null | grep -q .; then
  report "- ✓ no overlays subscribed"; echo "overlay-autosync: no overlays"; exit 0
fi

# LC_ALL=C throughout: this output is parsed, and a localized git underneath
# would move the strings. Same lesson as the merge-tree guard in
# upstream-autoupdate.sh, where grepping localized prose failed OPEN.
PLAN=/tmp/ob-overlay-autosync-plan.log
LC_ALL=C python3 scripts/overlay.py sync --yes --dry-run >"$PLAN" 2>&1 || true

# PRE-FLIGHT: refuse to apply a plan that deletes anything.
prunes=$(grep -cE '^[[:space:]]*⌫' "$PLAN" 2>/dev/null) || prunes=0
case "$prunes" in ''|*[!0-9]*) prunes=0 ;; esac
if [ "$prunes" -gt 0 ]; then
  plist=$(grep -E '^[[:space:]]*⌫' "$PLAN" 2>/dev/null | awk '{print $NF}' \
          | sed 's|^|  - `|; s|$|`|' | head -20)
  extra=$([ "$prunes" -gt 20 ] && echo "  - … and $((prunes - 20)) more" || true)
  report "- ⚠ overlay sync NOT applied: the plan would delete $prunes file(s)" \
         "- an unattended run applies and updates, it never deletes — a removal is a human's call" \
         "$plist" "$extra" \
         "" "- review with \`/overlay diff\`, then run \`/overlay sync\` interactively"
  notify "⚠ overlay auto-sync HELD: plan would delete $prunes file(s). Needs review."
  echo "overlay-autosync: held — $prunes deletion(s) planned"; exit 0
fi

LC_ALL=C python3 scripts/overlay.py sync --yes >"$LOG" 2>&1
rc=$?

# Behavioural files the engine deliberately did NOT install — the one thing a
# human still owns. Parsed from the engine's own SKIP lines, not guessed.
pending=$(grep -cE '^[[:space:]]*SKIP[[:space:]]' "$LOG" 2>/dev/null) || pending=0
case "$pending" in ''|*[!0-9]*) pending=0 ;; esac
names=$(grep -E '^[[:space:]]*SKIP[[:space:]]' "$LOG" 2>/dev/null \
        | sed 's/^[[:space:]]*SKIP[[:space:]]*//; s/:.*//' | sed 's|^|  - `|; s|$|`|')

if [ "$rc" -ne 0 ]; then
  report "- 🔴 overlay sync FAILED (exit $rc) — see \`$LOG\`" \
          "- nothing was left half-applied: the engine writes atomically per file"
  notify "🔴 overlay auto-sync FAILED (exit $rc). See $LOG"
  echo "overlay-autosync: failed (exit $rc)"; exit 1
fi

status=$(LC_ALL=C python3 scripts/overlay.py status 2>/dev/null | sed 's/^/  /')
if [ "$pending" -gt 0 ]; then
  report "- ✅ overlay sync applied" \
          "- ⚠ $pending behavioural file(s) await an explicit \`[y]\` — run \`/overlay sync\` interactively:" \
          "$names" \
          "" "\`\`\`" "$status" "\`\`\`"
  notify "✅ overlay auto-sync applied · ⚠ $pending new behavioural file(s) need your [y]"
  echo "overlay-autosync: applied · $pending behavioural pending"
else
  report "- ✅ overlay sync applied · nothing awaiting confirmation" \
          "" "\`\`\`" "$status" "\`\`\`"
  echo "overlay-autosync: applied · 0 pending"
fi
