#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# onboard-sim — build a leak-SAFE sandbox reproducing a fresh PUBLIC-origin clone
# of open-bridge with the push guard armed.
#
# The sandbox's "public upstream" is a LOCAL bare repo. The newcomer clone's
# `origin` is set to the public URL (so the guard's slug detection sees the real
# public slug) but ALL transport is redirected to the local bare repo via
# insteadOf — so even if the guard fails, a simulated leaky push lands in the
# local bare repo, never on the real public internet. Testing for a leak can
# never cause one.
#
# Prints the sandbox dir on stdout.
set -euo pipefail

CORE_SRC="${1:?usage: build-sandbox.sh <open-bridge-checkout> [sandbox-dir]}"
SANDBOX="${2:-$(mktemp -d "${TMPDIR:-/tmp}/obsim.XXXXXX")}"
rm -rf "$SANDBOX"; mkdir -p "$SANDBOX"
PUBLIC_BARE="$SANDBOX/public-open-bridge.git"
NEWCOMER="$SANDBOX/newcomer"
PUBLIC_URL="https://github.com/bks-lab/open-bridge.git"

slug_of() {
  printf '%s' "$1" \
    | sed -E 's#^git@[^:]+:##; s#^ssh://git@[^/]+/##; s#^https?://[^/]+/##; s#/$##; s#\.git$##' \
    | tr '[:upper:]' '[:lower:]'
}

# 1) fake "public" upstream = a local bare repo
git init -q --bare "$PUBLIC_BARE"

# 2) newcomer working copy = the live CORE (tracked + new-untracked, minus ignored)
mkdir -p "$NEWCOMER"
# A public open-bridge clone contains CORE ONLY. Taking the host tree verbatim is
# correct upstream and wrong in every downstream instance, where `git ls-files`
# also yields work/, identity/, bridge-config.yaml and the rest. The baseline
# commit then carries USER content, the CORE-only `ci/probe` branch inherits it
# through main, the guard blocks the probe exactly as designed, and
# assert-no-leak.sh reports BROKEN SANDBOX without a single real leak having
# happened. Observed in a downstream instance's CI, 06.09.2026.
#
# The USER definition is SOURCED from the guard itself rather than copied: the
# regex already exists in four places and has drifted between them, and a fifth
# copy in the very sandbox that is supposed to prove the guard would be the worst
# of the five. A file is kept when it is a CORE companion, or when it is not USER.
eval "$(grep -E '^(USER_PATHS|CORE_EXEMPT)=' "$CORE_SRC/scripts/hooks/pre-push")"
if [ -z "${USER_PATHS:-}" ] || [ -z "${CORE_EXEMPT:-}" ]; then
  echo "build-sandbox: cannot read USER_PATHS/CORE_EXEMPT from $CORE_SRC/scripts/hooks/pre-push" >&2
  exit 1
fi
( cd "$CORE_SRC" && git ls-files -co --exclude-standard ) > "$SANDBOX/.filelist.all"
{ grep -E  "$CORE_EXEMPT" "$SANDBOX/.filelist.all" || true
  grep -Ev "$USER_PATHS"  "$SANDBOX/.filelist.all" || true
} | sort -u > "$SANDBOX/.filelist"
rsync -a --files-from="$SANDBOX/.filelist" "$CORE_SRC"/ "$NEWCOMER"/
cd "$NEWCOMER"
git init -q -b main
git add -A
git -c user.email=sim@example.com -c user.name="OB Sim" commit -q -m "open-bridge CORE baseline (sim)"

# 3) origin LOOKS like the public repo; transport redirected to the local bare (leak-safe)
git remote add origin "$PUBLIC_URL"
git config "url.${PUBLIC_BARE}.insteadOf" "$PUBLIC_URL"
git config "url.${PUBLIC_BARE}.pushInsteadOf" "$PUBLIC_URL"

# 4) arm the guard exactly as bin/setup would
git config core.hooksPath scripts/hooks
[ -f scripts/hooks/pre-push ] && chmod +x scripts/hooks/pre-push

# 5) belt-and-suspenders: the guard must recognize the target as public whether git
#    hands the hook the spoof URL or the rewritten bare path
cat > bridge-config.yaml <<YAML
# sandbox-only (gitignored in real clones)
push_guard:
  public_upstreams: ["bks-lab/open-bridge", "$(slug_of "$PUBLIC_BARE")"]
  private_remotes: []
YAML

echo "$SANDBOX"
