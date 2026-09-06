#!/usr/bin/env bash
# debrief_sync.sh — bridge between the transcription pipeline and the /debrief
# skill. It implements the sync-script contract of docs/transcription-worker.md.
# Two directions:
#
#   pull               fetch: bring finished transcripts into the bridge imports
#                      dir, where /debrief Phase 1 finds them. Pulled files are
#                      moved to <transcripts>/<ctx>/_debriefed/ so they're pulled
#                      exactly once.
#
#   push <audio> [ctx] deliver: send an audio file to the pipeline inbox for
#                      transcription. Returns immediately; the transcript shows
#                      up in a later `pull` (transcription is async, minutes).
#
#   voiceprints pull   back up: fetch the per-context speaker-library/*.npy into
#                      the bridge under identity/voiceprints/<ctx>/.
#   voiceprints push   restore: send the bridge's voiceprints back onto a (fresh)
#                      worker — rebuild the library after a worker wipe.
#
# TRANSPORT is chosen by the topology mode (infra/transcriptions/topology.yaml):
#   remote — the pipeline lives on a worker host; every pull/push/voiceprints
#            operation runs over ssh + rsync to worker.host. An unreachable worker
#            exits non-zero and /debrief degrades to its manual path.
#   local  — bridge and worker are the SAME machine; every operation is a plain
#            local filesystem cp/mv against the worker's conventional dirs, and
#            the SSH reachability probe is skipped (no sshd / Remote Login needed).
#   Resolution: TRANSCRIBE_MODE env > topology.yaml `mode` > inferred (a worker
#   host resolves ⇒ remote, else local — legacy fallback for pre-topology instances).
#
#   NOTE on voiceprints: these are biometric voice embeddings (GDPR Art. 9), so
#   identity/voiceprints/ is scope:user and NEVER promotes upstream. Git tracking
#   is decided by the bridge's .gitignore, NOT by this script: each context dir
#   is opt-in via a whitelist. This script pulls ALL contexts uniformly; what
#   gets committed is the bridge's policy. A customer-facing instance would
#   route customer voiceprints to that customer's own repo instead of tracking
#   them here.
#
# Config resolution: environment first, then infra/transcriptions/topology.yaml
# (PLACEMENT: mode, worker host, local paths) + bridge-config.yaml (REGISTRATION:
# contexts, default_context), then fail with a clear message. Imports dir defaults
# to this repo's work/imports; override with BRIDGE_IMPORTS. Voiceprint dir:
# BRIDGE_VOICEPRINTS.
#
# Usage:
#   debrief_sync.sh pull
#   debrief_sync.sh push ~/Recordings/foo.m4a customer-x
#   debrief_sync.sh voiceprints pull | voiceprints push

set -euo pipefail

# Repo root resolved from this script's location (scripts/ → skill → skills/ → repo).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CONFIG="$REPO_ROOT/bridge-config.yaml"
TOPO="$REPO_ROOT/infra/transcriptions/topology.yaml"

# Read a dotted key from a YAML file. Prints the scalar value, dict keys
# space-joined for mappings, or nothing when the key (or the file) is absent.
yaml_get() {
  [[ -f "$1" ]] || return 0
  python3 -c '
import sys
try:
    import yaml
    data = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    sys.exit(0)
node = data
for part in sys.argv[2].split("."):
    if not isinstance(node, dict) or part not in node:
        sys.exit(0)
    node = node[part]
if isinstance(node, dict):
    print(" ".join(str(k) for k in node))
elif isinstance(node, bool):
    print(str(node).lower())   # YAML wants lowercase true/false; the Python bool default prints capitalized
elif node is not None:
    print(node)
' "$1" "$2" 2>/dev/null || true
}
cfg_get()  { yaml_get "$CONFIG" "$1"; }   # bridge-config.yaml — registration axis
topo_get() { yaml_get "$TOPO"   "$1"; }   # infra/transcriptions/topology.yaml — placement axis

# Expand a leading ~ to $HOME (topo_get returns the literal string).
_tilde() { printf '%s' "${1/#\~/$HOME}"; }

# --- Topology mode ---------------------------------------------------------
MODE="${TRANSCRIBE_MODE:-$(topo_get mode)}"
if [[ -z "$MODE" ]]; then
  # Legacy fallback (no topology.yaml — pre-2026-07 instances): infer from a host.
  if [[ -n "${TRANSCRIBE_WORKER:-}" || -n "$(cfg_get integrations.transcription.worker.host)" ]]; then
    MODE=remote
  else
    MODE=local
  fi
fi
case "$MODE" in
  local|remote) ;;
  *) echo "invalid transcription mode '$MODE' — set 'mode: local|remote' in infra/transcriptions/topology.yaml (or TRANSCRIBE_MODE)"; exit 1 ;;
esac

# --- Worker host (required only in remote mode) ----------------------------
WORKER="${TRANSCRIBE_WORKER:-$(topo_get worker.host)}"
[[ -z "$WORKER" ]] && WORKER="$(cfg_get integrations.transcription.worker.host)"   # legacy location
if [[ "$MODE" == remote && -z "$WORKER" ]]; then
  echo "mode 'remote' but no worker host — set worker.host in infra/transcriptions/topology.yaml or TRANSCRIBE_WORKER"; exit 1
fi

# Imports dir: BRIDGE_IMPORTS env > bridge-config.yaml work.imports_dir > the
# work/imports fallback. Resolving only against the hardcoded fallback (and
# ignoring work.imports_dir) let this script silently desync from /debrief,
# which scans work.imports_dir — see issue #104.
_imports_cfg="$(cfg_get work.imports_dir)"
if [[ -n "${BRIDGE_IMPORTS:-}" ]]; then
  IMPORTS="$BRIDGE_IMPORTS"
elif [[ -n "$_imports_cfg" ]]; then
  case "$_imports_cfg" in
    /*) IMPORTS="$_imports_cfg" ;;
    ~*) IMPORTS="$(_tilde "$_imports_cfg")" ;;
    *)  IMPORTS="$REPO_ROOT/$_imports_cfg" ;;
  esac
else
  IMPORTS="$REPO_ROOT/work/imports"
fi
CONTEXTS="${TRANSCRIBE_CONTEXTS:-$(cfg_get integrations.transcription.contexts)}"
if [[ -z "$CONTEXTS" ]]; then
  echo "no contexts configured — set TRANSCRIBE_CONTEXTS or add integrations.transcription.contexts to bridge-config.yaml"; exit 1
fi

# launchd label of the worker job — kicked after a push (remote: worker.*, local: local.*).
if [[ "$MODE" == remote ]]; then KICK_LABEL="$(topo_get worker.launchd_label)"; else KICK_LABEL="$(topo_get local.launchd_label)"; fi
[[ -z "$KICK_LABEL" ]] && KICK_LABEL="$(cfg_get integrations.transcription.worker.launchd_label)"   # legacy
KICK_LABEL="${KICK_LABEL:-com.openbridge.transcribe-worker}"

# Voiceprint dir defaults to <repo-root>/identity/voiceprints.
VOICEPRINTS="${BRIDGE_VOICEPRINTS:-$REPO_ROOT/identity/voiceprints}"

# Local worker dirs (mode: local only; defaults = the worker's own conventions).
L_TRANSCRIPTS="$(_tilde "$(topo_get local.transcripts_dir)")"; L_TRANSCRIPTS="${L_TRANSCRIPTS:-$HOME/Transcripts}"
L_INBOX="$(_tilde "$(topo_get local.inbox_dir)")";             L_INBOX="${L_INBOX:-$HOME/transcribe-inbox}"
L_LIBRARY="$(_tilde "$(topo_get local.library_dir)")";         L_LIBRARY="${L_LIBRARY:-$HOME/transcribe-pipeline/speaker-library}"

cmd="${1:-}"; case "$cmd" in pull|push|voiceprints) ;; *)
  echo "usage: debrief_sync.sh pull | push <audio> [context] | voiceprints pull|push"; exit 2 ;; esac

# --- Recording provenance --------------------------------------------------
# A handoff manifest must describe the RECORDING, not the moment of the push.
# Writing `date` + `duration_s: 0` here makes every derived transcript claim the
# meeting happened when it was uploaded, for one minute — wrong in the frontmatter
# AND in every wall-clock timestamp the worker derives from it. Both values are
# knowable from the audio file itself, so derive them.

probe_duration_s() {
  # Seconds (integer) of an audio file. ffprobe where available, afinfo on macOS.
  # 0 means "unknown" — the worker treats it as it did before.
  local f="$1" d=""
  if command -v ffprobe >/dev/null 2>&1; then
    d="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$f" 2>/dev/null)"
  fi
  if [[ -z "$d" ]] && command -v afinfo >/dev/null 2>&1; then
    d="$(afinfo "$f" 2>/dev/null | sed -n 's/.*estimated duration: *\([0-9.]*\).*/\1/p' | head -1)"
  fi
  [[ -z "$d" ]] && { printf '0'; return; }
  _round_seconds "$d"
}

_round_seconds() {
  # Float seconds -> integer seconds. Kept separate from the probe so it can be
  # tested directly; the bug it guards is invisible unless the fractional part
  # is >= 0.5, which no committed fixture guarantees.
  #
  # LC_ALL=C is load-bearing. Under a locale whose decimal separator is ',',
  # printf rejects "3491.030204" — but it still writes the part it managed to
  # parse to stdout AND returns non-zero, so a `|| printf 0` fallback APPENDS a
  # zero instead of replacing the value (3491 -> 34900), and even without the
  # fallback the value is truncated rather than rounded. Convert under C, then
  # validate the result instead of trusting the exit code.
  #
  # awk, NOT printf. An `LC_ALL=C` prefix does not reach the printf BUILTIN under
  # /bin/bash 3.2 (the macOS default, and the shebang target on any machine whose
  # PATH has no newer bash): there it returns 0. A duration of 0 then makes
  # derive_recorded_at fall back to mtime, which is when the recording ENDED, so
  # every transcript would claim the meeting started when it stopped. awk is an
  # EXTERNAL command, so the prefix lands in its environment and the point stays a
  # decimal point. Homebrew bash 5.x hides this difference — test with /bin/bash.
  local v
  v="$(LC_ALL=C awk -v x="$1" 'BEGIN { printf "%.0f", x + 0 }' 2>/dev/null)"
  [[ "$v" =~ ^[0-9]+$ ]] || v=0
  printf '%s' "$v"
}

_epoch_to_utc() {
  # Epoch seconds -> ISO-8601 UTC. BSD and GNU date disagree on the flag.
  date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ
}

_file_mtime() {
  # Epoch mtime. BSD and GNU disagree on the flag, and the naive
  # `stat -f %m "$1" || stat -c %Y "$1"` is NOT a clean fallback: under GNU
  # coreutils `-f` means --file-system, so `%m` becomes a second FILE operand.
  # That operand fails (stderr only) while the real file still gets its
  # FILESYSTEM BLOCK printed to stdout, and the non-zero exit then runs the
  # fallback, which APPENDS the real epoch underneath. The caller receives a
  # multi-line blob instead of a number, and every consumer downstream chokes on
  # it. Measured on CI 06.09.2026:
  #   date: invalid date '@  File: "…/sample.mp3"\n ID: … Type: ext2/ext3\n…\n1788678830'
  # `push` then died with rc=1 under `set -e`, before writing anything, and the
  # designed "duration unknown" fallback was never reached.
  #
  # Same lesson as _round_seconds below: validate the RESULT, never trust the
  # exit code of a tool whose flags mean different things per platform. GNU form
  # first, BSD second, and a numeric check as the only acceptance criterion.
  local v
  v="$(stat -c %Y "$1" 2>/dev/null || true)"
  [[ "$v" =~ ^[0-9]+$ ]] || v="$(stat -f %m "$1" 2>/dev/null || true)"
  [[ "$v" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$v"
}

derive_recorded_at() {
  # When did this recording START? Three sources, most trustworthy first:
  #   1. a timestamp in the filename (recorders name files by start time)
  #   2. file mtime minus duration (mtime is the moment recording STOPPED)
  #   3. now — last resort, and no better than the old behaviour
  local f="$1" dur="${2:-0}" base ymd hm epoch
  base="$(basename "$f")"
  # YYYYMMDD<sep>HHMM[SS]  or  YYYY-MM-DD<sep>HH-MM[-SS]
  ymd="$(printf '%s' "$base" | sed -n 's/.*\([0-9]\{4\}\)-\{0,1\}\([0-9]\{2\}\)-\{0,1\}\([0-9]\{2\}\)[ _T-]\{1,\}\([0-9]\{2\}\)-\{0,1\}\([0-9]\{2\}\).*/\1\2\3\4\5/p' | head -1)"
  if [[ ${#ymd} -eq 12 ]]; then
    # Interpret as LOCAL time, convert to UTC. BSD then GNU.
    # Seconds are appended explicitly: BSD `date -j` fills fields the format does
    # not name from the CURRENT time, so %Y%m%d%H%M alone would stamp each run
    # with a different second.
    epoch="$(date -j -f %Y%m%d%H%M%S "${ymd}00" +%s 2>/dev/null)" \
      || epoch="$(date -d "${ymd:0:4}-${ymd:4:2}-${ymd:6:2} ${ymd:8:2}:${ymd:10:2}:00" +%s 2>/dev/null)"
    if [[ -n "$epoch" ]]; then _epoch_to_utc "$epoch"; return; fi
  fi
  epoch="$(_file_mtime "$f")"
  if [[ -n "$epoch" ]]; then
    [[ "$dur" -gt 0 ]] 2>/dev/null && epoch=$(( epoch - dur ))
    _epoch_to_utc "$epoch"; return
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ
}

# --- Capability registry (opt-in, checked on every pull/push) --------------
# Publishes "a transcription worker exists on this machine and how to reach
# it" to ~/.bridge-capabilities/transcription.yaml so a SIBLING Bridge
# instance can discover it without reading this instance's own files (see
# docs/capability-registry.md). Default OFF: only fires when this instance
# opted in via integrations.transcription.share_capability: true. Runs
# EVERY invocation (not a one-off manual step) so the flag stays wired once
# set, and self-heals when the flag is later turned back off — flipping it
# to false (or leaving it unset) removes this instance's own prior entry on
# the very next pull/push, no separate teardown step to remember. Warns,
# never fails: a registry hiccup must never break the actual sync.
publish_capability() {
  local share instance reg
  share="$(cfg_get integrations.transcription.share_capability)"
  instance="$(cfg_get identity.name)"
  reg="$REPO_ROOT/scripts/capability_registry.py"
  [[ -f "$reg" && -n "$instance" ]] || return 0   # no registry / no instance identity yet — nothing to do
  if [[ "$share" == "true" ]]; then
    local ctxdir host_args=()
    if [[ "$MODE" == remote ]]; then
      ctxdir="~/transcribe-pipeline/contexts"     # fixed worker-side convention, not locally overridable
      host_args=(--host "$WORKER")
    else
      ctxdir="$(topo_get local.contexts_dir)"; ctxdir="${ctxdir:-~/transcribe-pipeline/contexts}"
    fi
    python3 "$reg" publish transcription --provider meeting-transcription \
      --registered-by "$instance" "${host_args[@]}" --launchd-label "$KICK_LABEL" \
      --contexts-dir "$ctxdir" >/dev/null 2>&1 \
      || echo "WARN could not publish to the capability registry (non-fatal)"
  else
    python3 "$reg" remove transcription --registered-by "$instance" \
      --provider meeting-transcription >/dev/null 2>&1 \
      || echo "WARN could not clean up the capability registry (non-fatal)"
  fi
}

# Remote reachability probe — skipped entirely in local mode.
if [[ "$MODE" == remote ]]; then
  if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "$WORKER" 'true' 2>/dev/null; then
    echo "worker $WORKER unreachable"; exit 1
  fi
fi

case "$cmd" in
  pull)
    mkdir -p "$IMPORTS"
    pulled=0
    for ctx in $CONTEXTS; do
      if [[ "$MODE" == remote ]]; then
        ssh -o BatchMode=yes "$WORKER" "mkdir -p ~/Transcripts/$ctx/_debriefed" 2>/dev/null || true
        # find (not a glob) avoids the remote zsh "no matches found" on empty dirs
        mapfile -t files < <(ssh -o BatchMode=yes "$WORKER" "find ~/Transcripts/$ctx -maxdepth 1 -name '*.md' 2>/dev/null" || true)
      else
        mkdir -p "$L_TRANSCRIPTS/$ctx/_debriefed" 2>/dev/null || true
        mapfile -t files < <(find "$L_TRANSCRIPTS/$ctx" -maxdepth 1 -name '*.md' 2>/dev/null || true)
      fi
      for f in "${files[@]}"; do
        [[ -n "$f" ]] || continue
        bn="$(basename "$f")"
        # Context-prefix so /debrief can route (e.g. customer-x-* → that
        # customer's own Bridge instance).
        if [[ "$MODE" == remote ]]; then
          if rsync -av "$WORKER:$f" "$IMPORTS/${ctx}-${bn}" >/dev/null 2>&1; then
            ssh -o BatchMode=yes "$WORKER" "mv ~/Transcripts/$ctx/$bn ~/Transcripts/$ctx/_debriefed/" 2>/dev/null || true
            echo "pulled ${ctx}-${bn}"
            pulled=$((pulled+1))
          fi
        else
          if cp "$f" "$IMPORTS/${ctx}-${bn}" 2>/dev/null; then
            mv "$L_TRANSCRIPTS/$ctx/$bn" "$L_TRANSCRIPTS/$ctx/_debriefed/" 2>/dev/null || true
            echo "pulled ${ctx}-${bn}"
            pulled=$((pulled+1))
          fi
        fi
      done
    done
    publish_capability
    echo "pull done — $pulled new transcript(s) into $IMPORTS"
    ;;

  push)
    audio="${2:?push needs an audio file path}"
    ctx="${3:-}"
    if [[ -z "$ctx" ]]; then
      ctx="$(cfg_get integrations.transcription.default_context)"
    fi
    if [[ -z "$ctx" ]]; then
      echo "no context given and no integrations.transcription.default_context in bridge-config.yaml — pass one: debrief_sync.sh push <audio> <context>"; exit 1
    fi
    [[ -f "$audio" ]] || { echo "audio not found: $audio"; exit 1; }
    ts="$(date +%Y-%m-%d-%H%M%S)"
    # Derived from the AUDIO, not from now — see § Recording provenance above.
    dur_s="$(probe_duration_s "$audio")"
    rec_at="$(derive_recorded_at "$audio" "$dur_s")"
    echo "recording: $rec_at (${dur_s}s)"
    # Duplikat-Sperre. Ohne sie legt push bedingungslos ein neues Bundle an, und
    # dieselbe Aufnahme wird ein zweites Mal gerechnet. Am 2026-08-27 ist genau das
    # passiert: 47 Minuten Audio waren schon seit einer Stunde in Arbeit, der zweite
    # Push haette sie verdoppelt und das dahinter wartende Weekly um rund 17 Minuten
    # verzoegert. Aufgefallen ist es nur, weil jemand die Manifeste von Hand verglichen
    # hat. `recorded_at` wird aus dem AUDIO abgeleitet, nicht aus der Uhr des Pushs,
    # und ist damit fuer dieselbe Aufnahme stabil.
    if [[ "${FORCE:-}" != "1" ]]; then
      if [[ "$MODE" == remote ]]; then
        dup="$(ssh -o BatchMode=yes "$WORKER" \
                 "grep -l 'recorded_at: $rec_at' ~/transcribe-inbox/$ctx/*/manifest.yaml 2>/dev/null" || true)"
      else
        dup="$(grep -l "recorded_at: $rec_at" "$L_INBOX/$ctx"/*/manifest.yaml 2>/dev/null || true)"
      fi
      if [[ -n "$dup" ]]; then
        echo "SCHON IN DER WARTESCHLANGE, push abgebrochen:"
        echo "$dup" | sed 's/^/  /'
        echo "  gleiche Aufnahme (recorded_at=$rec_at, ${dur_s}s)."
        echo "  Trotzdem einreichen: FORCE=1 $0 push \"$audio\" $ctx"
        exit 2
      fi
    fi
    # tracks: single — a debrief handoff is always ONE mixed recording, never a
    # real 2-track Audio-Hijack bundle. Without this the worker defaults to dual
    # and runs an ffmpeg channel-split that fails on single-file audio.
    if [[ "$MODE" == remote ]]; then
      if ! ssh -o BatchMode=yes "$WORKER" "test -d ~/transcribe-inbox/$ctx" 2>/dev/null; then
        echo "context '$ctx' not provisioned on $WORKER — run add_context.sh $ctx first"; exit 1
      fi
      ssh -o BatchMode=yes "$WORKER" "mkdir -p ~/transcribe-inbox/$ctx/$ts"
      rsync -av "$audio" "$WORKER:~/transcribe-inbox/$ctx/$ts/meeting.mp3" >/dev/null
      ssh -o BatchMode=yes "$WORKER" "printf 'recorded_at: %s\nduration_s: %s\ncontext: %s\ntracks: single\nsource: debrief-handoff\n' \
          \"$rec_at\" \"$dur_s\" \"$ctx\" > ~/transcribe-inbox/$ctx/$ts/manifest.yaml; \
          touch ~/transcribe-inbox/$ctx/$ts/.READY"
      # Kick the worker explicitly. The launchd WatchPath on ~/transcribe-inbox
      # only fires for changes to that dir's DIRECT entries — a bundle created
      # inside an already-existing context subfolder (main/<ts>) does NOT trigger
      # it, so the very first push to a new context worked but later ones silently
      # never got processed. kickstart (not -k, so a running transcription isn't
      # killed) makes the handoff reliable regardless of the watch.
      ssh -o BatchMode=yes "$WORKER" "launchctl kickstart gui/\$(id -u)/$KICK_LABEL" >/dev/null 2>&1 \
        && echo "worker kicked" || echo "WARN could not kickstart worker (will rely on WatchPath / next run)"
      echo "pushed → $WORKER:~/transcribe-inbox/$ctx/$ts (context=$ctx)"
    else
      if [[ ! -d "$L_INBOX/$ctx" ]]; then
        echo "context '$ctx' not provisioned — run add_context.sh $ctx first"; exit 1
      fi
      mkdir -p "$L_INBOX/$ctx/$ts"
      cp "$audio" "$L_INBOX/$ctx/$ts/meeting.mp3"
      printf 'recorded_at: %s\nduration_s: %s\ncontext: %s\ntracks: single\nsource: debrief-handoff\n' \
          "$rec_at" "$dur_s" "$ctx" > "$L_INBOX/$ctx/$ts/manifest.yaml"
      touch "$L_INBOX/$ctx/$ts/.READY"
      launchctl kickstart "gui/$(id -u)/$KICK_LABEL" >/dev/null 2>&1 \
        && echo "worker kicked" || echo "WARN could not kickstart worker (will rely on WatchPath / next run)"
      echo "pushed → $L_INBOX/$ctx/$ts (context=$ctx)"
    fi
    publish_capability
    echo "transcription is async — run 'debrief_sync.sh pull' (or /debrief) in a few minutes to collect it"
    ;;

  voiceprints)
    dir="${2:-}"; case "$dir" in
      pull)
        # worker → bridge. Pull each context's .npy embeddings. Only *.npy is
        # synced (the speaker-library/raw/ bootstrap audio is deliberately left
        # in place — it's large + not needed for matching).
        synced=0
        for ctx in $CONTEXTS; do
          if [[ "$MODE" == remote ]]; then
            if ! ssh -o BatchMode=yes "$WORKER" "test -d ~/transcribe-pipeline/speaker-library/$ctx" 2>/dev/null; then
              continue   # context has no library on the worker yet
            fi
            mkdir -p "$VOICEPRINTS/$ctx"
            n=$(rsync -av --include='*.npy' --exclude='*' \
                  "$WORKER:transcribe-pipeline/speaker-library/$ctx/" "$VOICEPRINTS/$ctx/" \
                  2>/dev/null | grep -c '\.npy$' || true)
          else
            [[ -d "$L_LIBRARY/$ctx" ]] || continue   # context has no local library yet
            mkdir -p "$VOICEPRINTS/$ctx"
            n=$(rsync -av --include='*.npy' --exclude='*' \
                  "$L_LIBRARY/$ctx/" "$VOICEPRINTS/$ctx/" \
                  2>/dev/null | grep -c '\.npy$' || true)
          fi
          echo "pulled ${ctx}: ${n} voiceprint(s) → $VOICEPRINTS/$ctx/"
          synced=$((synced + n))
        done
        echo "voiceprints pull done — $synced file(s) into $VOICEPRINTS"
        echo "git tracks only whitelisted contexts (see .gitignore); the rest is offsite-only via your backup pipeline."
        ;;
      push)
        # bridge → worker (restore after a worker wipe). Additive, no --delete.
        [[ -d "$VOICEPRINTS" ]] || { echo "no local voiceprints at $VOICEPRINTS"; exit 1; }
        restored=0
        for ctx in $CONTEXTS; do
          [[ -d "$VOICEPRINTS/$ctx" ]] || continue
          if [[ "$MODE" == remote ]]; then
            ssh -o BatchMode=yes "$WORKER" "mkdir -p ~/transcribe-pipeline/speaker-library/$ctx" 2>/dev/null || true
            n=$(rsync -av --include='*.npy' --exclude='*' \
                  "$VOICEPRINTS/$ctx/" "$WORKER:transcribe-pipeline/speaker-library/$ctx/" \
                  2>/dev/null | grep -c '\.npy$' || true)
          else
            mkdir -p "$L_LIBRARY/$ctx" 2>/dev/null || true
            n=$(rsync -av --include='*.npy' --exclude='*' \
                  "$VOICEPRINTS/$ctx/" "$L_LIBRARY/$ctx/" \
                  2>/dev/null | grep -c '\.npy$' || true)
          fi
          echo "restored ${ctx}: ${n} voiceprint(s)"
          restored=$((restored + n))
        done
        echo "voiceprints push done — $restored file(s) restored"
        ;;
      *) echo "usage: debrief_sync.sh voiceprints pull|push"; exit 2 ;;
    esac
    ;;
esac
