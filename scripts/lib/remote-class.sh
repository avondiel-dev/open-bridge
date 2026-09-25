#!/bin/sh
# SPDX-License-Identifier: MIT
#
# remote-class.sh: is this remote a safe home for USER data?
#
# ONE answer, three states: private | public | unknown. Two callers need it and
# must never disagree:
#   scripts/hooks/pre-push   blocks USER content to anything not private
#   scripts/user-data.py     keeps USER data out of git on a clone whose origin
#                            is not private, and lets a private one back it up
# Before this file the logic lived inline in pre-push, and a second copy would
# have been the drift that decides whether a persona file gets backed up or
# published.
#
# Offline first, in this order (the first that answers wins):
#   1. bridge-config.yaml push_guard.private_remotes              → private
#   2. bks-lab/open-bridge + push_guard.public_upstreams          → public
#   3. .bridge-origin, ONLY when its repo: slug matches the target,
#      so a stale marker cannot vouch for a re-homed remote       → is_public
#   4. gh repo view --json visibility (best effort)               → PUBLIC/PRIVATE
# Anything else stays unknown, and every caller treats unknown like public.
#
# Two ways in:
#   sh scripts/lib/remote-class.sh [<remote-url>]   prints the state (default: origin)
#   REMOTE_CLASS_LIB=1 . scripts/lib/remote-class.sh
#                                   defines the functions, runs nothing

# normalize any git remote URL to a lowercase owner/repo slug
slug_of() {
  printf '%s' "$1" \
    | sed -E 's#^git@[^:]+:##; s#^ssh://git@[^/]+/##; s#^https?://[^/]+/##; s#/$##; s#\.git$##' \
    | tr '[:upper:]' '[:lower:]'
}

# read a space-separated list under push_guard.<key> from a YAML file
# (supports inline `key: [a, b]` and block `- a` forms; best-effort, optional)
yaml_list() {
  _file="$1"; _key="$2"
  [ -f "$_file" ] || return 0
  awk -v key="$_key" '
    /^push_guard:/ { inpg=1; next }
    inpg && /^[^[:space:]#]/ { inpg=0 }
    inpg && $0 ~ "^[[:space:]]+" key ":" {
      l=$0; sub(/^[[:space:]]*[^:]+:[[:space:]]*/, "", l)
      if (l ~ /^\[/) { gsub(/[][,]/, " ", l); print l; ink=0; next }
      ink=1; next
    }
    ink && /^[[:space:]]*-[[:space:]]*/ { v=$0; sub(/^[[:space:]]*-[[:space:]]*/, "", v); printf "%s ", v; next }
    ink && /^[[:space:]]*[^[:space:]-]/ { ink=0 }
  ' "$_file" | tr -d "\"'" | tr '[:upper:]' '[:lower:]'
}

# classify_remote <slug> <repo-root>  → prints private | public | unknown
classify_remote() {
  _target="$1"; _root="$2"; _cfg="$_root/bridge-config.yaml"
  [ -n "$_target" ] || { echo unknown; return 0; }

  for _p in $(yaml_list "$_cfg" private_remotes); do
    [ "$_target" = "$_p" ] && { echo private; return 0; }
  done

  for _u in bks-lab/open-bridge $(yaml_list "$_cfg" public_upstreams); do
    [ "$_target" = "$_u" ] && { echo public; return 0; }
  done

  if [ -f "$_root/.bridge-origin" ]; then
    _ob_repo=$(sed -n 's/^repo:[[:space:]]*//p' "$_root/.bridge-origin" | head -1 | tr -d "\"' " | tr '[:upper:]' '[:lower:]')
    _ob_pub=$(sed -n 's/^is_public:[[:space:]]*//p' "$_root/.bridge-origin" | head -1 | tr -d " ")
    if [ -n "$_ob_repo" ] && [ "$_ob_repo" = "$_target" ]; then
      case "$_ob_pub" in
        true)  echo public;  return 0 ;;
        false) echo private; return 0 ;;
      esac
    fi
  fi

  # Only an EXPLICIT answer moves it off unknown; INTERNAL and any other value
  # stay unknown, escapable via push_guard.private_remotes.
  # REMOTE_CLASS_OFFLINE=1 skips this step: a per-commit check must not wait on
  # the network, and an offline answer can only ever be less private.
  if [ "${REMOTE_CLASS_OFFLINE:-}" != 1 ] && command -v gh >/dev/null 2>&1; then
    case "$(gh repo view "$_target" --json visibility -q .visibility 2>/dev/null)" in
      PUBLIC)  echo public;  return 0 ;;
      PRIVATE) echo private; return 0 ;;
    esac
  fi
  echo unknown
}

if [ "${REMOTE_CLASS_LIB:-}" != 1 ]; then
  _root=$(git rev-parse --show-toplevel 2>/dev/null) || _root=$(pwd)
  _url="${1:-$(git remote get-url origin 2>/dev/null)}"
  classify_remote "$(slug_of "$_url")" "$_root"
fi
