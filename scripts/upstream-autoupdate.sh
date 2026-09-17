#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# upstream-autoupdate.sh — GUARDED daily auto-merge of upstream CORE updates.
#
# Auto-merges the upstream ref into the current user/* branch ONLY when it is
# provably safe. Otherwise it does NOT merge — it writes a status report and
# (optionally) notifies. Every guard FAILS CLOSED: any error or unknown state
# skips the merge rather than risking a bad one.
#
# Authoritative safety gate = `git merge-tree` (content-based conflict
# prediction). The name-based divergence sentinel is used only for the
# informational report, never as the merge decision (it can flag files that are
# byte-identical after a prior contribution).
#
# Guards (ALL must pass):
#   1. on a user/* branch
#   2. no uncommitted TRACKED changes
#   3. git merge-tree predicts 0 conflicts (read from its EXIT CODE — never
#      from its localized output; see the note at the guard itself)
#
# After a successful merge it also FAST-FORWARDS the mirror's core branch, so the
# private origin keeps a copy of the CORE history this job just merged. Without
# that step the mirror falls behind by exactly the commits this job consumes, and
# the next `git push user/<name>` has to carry all of them: measured 1317 objects
# against a 24-day-stale mirror, 83 once it was current. The count also makes the
# user branch LOOK enormous — 161 commits ahead, of which 6 were the user's — and
# that reading has cost real debugging time twice.
#
# Env (optional): UPSTREAM_REMOTE (default upstream) · UPSTREAM_REF (default
# upstream/main) · MIRROR_REMOTE (default origin) · MIRROR_CORE=0 disables the
# mirror step · SIGNAL_ACCOUNT + SIGNAL_RECIPIENT (both set → Signal push).
set -uo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)" || exit 1

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_REF="${UPSTREAM_REF:-upstream/main}"
REPORT="work/upstream-status.md"

notify() {  # $1 = message
  { [ -n "${SIGNAL_ACCOUNT:-}" ] && [ -n "${SIGNAL_RECIPIENT:-}" ] \
    && command -v signal-cli >/dev/null 2>&1 \
    && signal-cli -a "$SIGNAL_ACCOUNT" send -m "$1" "$SIGNAL_RECIPIENT" >/dev/null 2>&1; } || true
}
report() { mkdir -p work; { echo "# Upstream Auto-Update — $(date '+%F %T')"; echo; printf '%s\n' "$@"; } > "$REPORT"; }
is_int() { case "$1" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }

# mirror_core_branch — fast-forward the mirror's CORE branch to $UPSTREAM_REF.
#
# Echoes ONE report line and always returns 0: the merge already succeeded, so a
# mirror that cannot be updated is a note, never a failure that masks it.
#
# Deliberately NOT a second push-guard. The push runs with the repo's hooks
# ACTIVE (no core.hooksPath override), so scripts/hooks/pre-push classifies the
# target with the one classifier there is — config push_guard.*, then the
# .bridge-origin marker — and refuses a target it cannot vouch for. Re-deriving
# that judgement here would be a copy that drifts.
#
# Three conditions, all conservative:
#   · the mirror remote exists
#   · the core branch ALREADY exists there — this step keeps an existing mirror
#     current, it never creates a branch on somebody's remote
#   · the update is a true fast-forward, checked before pushing, so no mirror
#     history is ever rewritten
# It pushes $UPSTREAM_REF, never HEAD and never the user branch, so only CORE
# commits travel; USER content is not in the pushed ref by construction.
mirror_core_branch() {
  [ "${MIRROR_CORE:-1}" = 0 ] && { echo "- mirror: skipped (MIRROR_CORE=0)"; return 0; }
  local remote="${MIRROR_REMOTE:-origin}" branch cur
  git remote get-url "$remote" >/dev/null 2>&1 || { echo "- mirror: skipped (no \`$remote\` remote)"; return 0; }

  # Target branch = the mirror's OWN default, never hardcoded; fall back to the
  # branch part of UPSTREAM_REF when the remote publishes no HEAD.
  branch=$(git symbolic-ref --quiet "refs/remotes/${remote}/HEAD" 2>/dev/null | sed "s|^refs/remotes/${remote}/||")
  [ -n "$branch" ] || branch="${UPSTREAM_REF##*/}"

  git fetch "$remote" -q "$branch" 2>/dev/null || true
  cur=$(git rev-parse --verify --quiet "refs/remotes/${remote}/${branch}") \
    || { echo "- mirror: skipped (\`$remote/$branch\` does not exist yet — push it once by hand)"; return 0; }

  [ "$cur" = "$(git rev-parse "$UPSTREAM_REF")" ] && { echo "- mirror: \`$remote/$branch\` already current"; return 0; }
  git merge-base --is-ancestor "$cur" "$UPSTREAM_REF" 2>/dev/null \
    || { echo "- ⚠ mirror: \`$remote/$branch\` has diverged from \`$UPSTREAM_REF\` — NOT fast-forwardable, left alone"; return 0; }

  local n; n=$(git rev-list --count "${cur}..${UPSTREAM_REF}" 2>/dev/null || echo "?")
  if git push "$remote" "${UPSTREAM_REF}:refs/heads/${branch}" >/tmp/ob-autoupdate-mirror.log 2>&1; then
    echo "- ✅ mirror: \`$remote/$branch\` fast-forwarded $n commit(s) ($(git rev-parse --short "$cur") → $(git rev-parse --short "$UPSTREAM_REF"))"
  else
    echo "- ⚠ mirror: push to \`$remote/$branch\` failed (see /tmp/ob-autoupdate-mirror.log) — merge itself is fine"
  fi
  return 0
}

git fetch "$UPSTREAM_REMOTE" -q 2>/dev/null || true

behind=$(git rev-list --count "HEAD..$UPSTREAM_REF" 2>/dev/null || echo x)
is_int "$behind" || { report "- 🔴 cannot resolve \`$UPSTREAM_REF\` (fetch failed?)"; echo "autoupdate: no upstream ref"; exit 1; }
if [ "$behind" -eq 0 ]; then
  report "- ✓ up to date (0 behind \`$UPSTREAM_REF\`)"; echo "autoupdate: up to date"; exit 0
fi

# informational divergence count for the report (NOT a gate; unknown → '?')
risk=$(python3 scripts/bridge-divergence-check.py --upstream "$UPSTREAM_REF" --json 2>/dev/null \
       | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("conflict_risk",[])))' 2>/dev/null)
is_int "$risk" || risk="?"

# ---- GUARDS (fail closed) ----
reason=""
branch=$(git branch --show-current 2>/dev/null || echo "")
case "$branch" in user/*) ;; *) reason="not on a user/* branch (on '${branch:-detached}')";; esac

if [ -z "$reason" ] && ! { git diff --quiet && git diff --cached --quiet; }; then
  reason="working tree has uncommitted tracked changes"
fi

if [ -z "$reason" ]; then
  # Authoritative signal is merge-tree's EXIT CODE, not its prose:
  #   0 = clean · 1 = conflicts · >1 = the command itself failed.
  # This used to grep the output for "conflict", which is a LOCALE-DEPENDENT
  # string and silently returned 0 on any non-English git. On de_DE the output
  # reads "KONFLIKT (Inhalt): Merge-Konflikt in <file>" — no match, so the
  # gate that exists to fail closed reported "safe" and the merge went ahead
  # and failed. That is exactly what happened on 2026-09-07 (.gitignore).
  # LC_ALL=C is belt-and-braces: it pins any output we or a human read.
  mt=$(LC_ALL=C git merge-tree --write-tree HEAD "$UPSTREAM_REF" 2>/dev/null)
  mt_rc=$?
  case "$mt_rc" in
    0) : ;;                                                    # provably clean
    1) files=$(printf '%s\n' "$mt" | sed -n 's/^[0-7]\{6\} [0-9a-f]\{40\} [123]\t//p' \
               | sort -u | tr '\n' ' ' | sed 's/ $//')
       reason="merge conflict(s) predicted${files:+ in: $files}" ;;
    *) reason="merge-tree could not verify safety (exit $mt_rc, failing closed)" ;;
  esac
fi

if [ -n "$reason" ]; then
  report "- ⚠ auto-update SKIPPED: $reason" \
         "- $behind commit(s) behind \`$UPSTREAM_REF\` · sentinel conflict-risk: $risk" \
         "- resolve/\`/promote\` diverged CORE files, then merge manually"
  notify "⚠ open-bridge auto-update SKIPPED: $reason ($behind behind). Manual merge needed."
  echo "autoupdate: skipped — $reason"; exit 0
fi

# ---- SAFE → auto-merge (skip the local pre-commit hook for the headless merge) ----
before=$(git rev-parse --short HEAD)
if git -c core.hooksPath=/dev/null merge --no-edit "$UPSTREAM_REF" >/tmp/ob-autoupdate-merge.log 2>&1; then
  after=$(git rev-parse --short HEAD)
  mirror_line=$(mirror_core_branch)
  report "- ✅ auto-updated \`$before\` → \`$after\` ($behind commit(s) merged from \`$UPSTREAM_REF\`)" \
         "$mirror_line"
  notify "✅ open-bridge auto-updated: $behind commit(s) merged ($before→$after)"
  echo "autoupdate: merged $behind commit(s) ($before→$after)"
  echo "autoupdate: mirror — ${mirror_line#- }"
else
  git merge --abort 2>/dev/null || true
  report "- 🔴 auto-update merge FAILED and was aborted — $behind behind, manual merge needed"
  notify "🔴 open-bridge auto-update merge FAILED (aborted). Manual merge needed."
  echo "autoupdate: merge failed, aborted"; exit 1
fi
