---
summary: "File-based memory model — one fact per file, MEMORY.md as a lean index"
type: guide
last_updated: 2026-09-13
related:
  - ../rules/knowledge-growth.md
---

# Memory

The Bridge keeps a persistent, file-based memory base — the experience store that
survives across sessions. It is **not** a session log; it holds durable facts the
agent should recall later.

## Where memories come from

Two routes, both human-gated:

1. **In-session** — you or the agent notice a durable fact and save it.
2. **Distilled at archive time** — `/archive` Phase 5 reads the period's
   `work/log.md` rows before resetting them and proposes the few that carry
   lasting knowledge (a decision *and its why*, a costly diagnosis, a
   discovered constraint). Bookkeeping rows are dropped: git already records
   commits and PRs permanently.

Route 2 exists because `work/archive/` has **no reader** — no skill loads an
archived summary back into context. The memory base is the only layer that is
read every session, so distilling into it is what lets a short archive cadence
stay safe instead of amnesiac. Neither route writes without confirmation
(see [`../rules/learning-autonomy.md`](../rules/learning-autonomy.md)); a
deferred candidate becomes a `work/_learning/proposals/` entry with
`source.type: archive-distill` and `target.type: memory`, reviewed via
`/bridge-learn`.

## Model

- **One fact = one file.** Each memory is a single Markdown file
  `<type>_<underscore_slug>.md` in the memory directory, with frontmatter
  (`name:` = kebab slug, `description:` = one-line summary used for recall,
  `metadata.type`).
- **`MEMORY.md` is the INDEX, not the store.** It is loaded into context at the
  start of every session, so it must stay small. One line per memory, grouped by
  section. **Never put fact content directly in `MEMORY.md`** — only a pointer.
- **`[[wikilink]]`** links memory-to-memory and resolves to the other memory's
  `name:` slug. Cross-system references (config YAML, skill dirs, a wiki) use
  plain backtick paths, not `[[ ]]`.

## Filesystem location

Two states exist, and both are legitimate:

- **Default (harness-managed):** the memory base lives **outside the repo**,
  in a tool-specific path, not committed alongside the Bridge files.
  For Claude Code it sits under `~/.claude/projects/<project-hash>/memory/`,
  where `MEMORY.md` is the index and each `<type>_<slug>.md` is one fact.
  Other harnesses use their own location.
- **Recommended: inside the repo.** A Bridge can instead keep its memory base
  at `work/memory/`, versioned like the rest of `work/`. Claude Code reads the
  setting `autoMemoryDirectory` from any settings scope; run
  `python3 scripts/memory-location.py enable` to write it as an absolute path
  into the gitignored `.claude/settings.local.json`. See
  [Keeping memory inside the repo](#keeping-memory-inside-the-repo) below.

A fresh clone, either way, therefore has **no memory base yet**: it is
created as you work (the first fact you save creates the directory and
index). An empty or missing memory base on a new clone is expected, not a
broken setup.

## Keeping memory inside the repo

**Why:** a memory base under `work/memory/` is versioned (git history shows
who changed a fact and when), reviewable (a diff in a PR instead of an
invisible edit under `~/.claude`), revertable (`git checkout` undoes a bad
write the same way it undoes any other mistake), survives a repo move or a
re-clone on a new machine, and is checkable by the same tooling that already
reads the rest of the tree instead of only by the harness itself.

**One-time setup:**

1. `python3 scripts/memory-location.py enable`: writes
   `{"autoMemoryDirectory": "<repo>/work/memory"}` into the gitignored
   `.claude/settings.local.json`, preserving every other key already in that
   file.
2. `python3 scripts/memory-location.py migrate`, right away: copies facts
   from the old (legacy) location into `work/memory/`, without touching or
   deleting the legacy copy. Run it before any session restarts, otherwise a
   fresh session writes a new `MEMORY.md` into the empty directory first and
   `migrate` reports that index as a conflict.
3. **Restart every running Claude Code session on this repo**, then run
   `migrate` once more. A session that was already running can keep writing
   to the old directory; the second run picks up what it wrote in between.
4. Once every session that predates step 1 has ended,
   `python3 scripts/memory-location.py stub-legacy --yes` replaces the legacy
   `MEMORY.md` with a short pointer to the new location, so a stray old
   session (or a human) never keeps reading a frozen, increasingly-stale
   index.

**Harness facts** (Claude Code; probed live with `claude -p`, or quoted from
https://code.claude.com/docs/en/memory):

- A **relative** `autoMemoryDirectory` value is silently ignored: the
  harness falls back to its default directory with no warning. The value
  must be absolute, or start with `~/`.
- The setting is keyed to the **git project**, not the working directory: one
  setting in the main checkout's `.claude/settings.local.json` also applies
  to every linked worktree and every subdirectory.
- When both `.claude/settings.local.json` and `.claude/settings.json` set it,
  the **local file wins**.
- `MEMORY.md` loads only its first **200 lines or 25 KB**, whichever comes
  first, regardless of where the directory lives.
- **Sub-agents do not load** the main session's auto memory, in either
  location.

**Privacy:** `work/memory/` is tracked **only on a private instance**. The
public `.gitignore` ignores `/work/memory/` by default, and the pre-push
content net (`scripts/hooks/pre-push`) blocks `work/memory/` from reaching a
public or unknown remote, the same protection every other personal-data
family under `work/` already gets. Confirm both are in place before relying
on them (`git check-ignore work/memory/`; the `memory/` alternation in
`scripts/hooks/pre-push`'s `USER_PATHS`).

**Trap:** because `work/memory/` is *gitignored*, `git clean -x` (or `-fdx`)
deletes it like any other ignored directory, with no separate warning that
you are about to delete your memory base rather than build artifacts. Run
`git clean -n` first, or exclude it explicitly (`git clean -fdx -e
work/memory`).

## Index-line contract (load-bearing)

Every index entry is exactly:

```
- [Title](type_slug.md) — <one hook saying WHEN to reach for it>
```

- **Hook ≤ 120 characters.** The hook is a *recall trigger*, not a summary — it
  must carry the distinguishing symptom/keyword that makes the agent open the
  fact file (e.g. a precise error phrase), never just a restated title.
- Detail (repro steps, commands, exception strings, incident dates) lives in the
  fact file, never in the index line. If the index line is richer than its fact
  file, move the surplus **into the fact file first**, then trim the index.
- A lean index is the whole point: an oversized `MEMORY.md` overflows its
  context budget and silently drops its tail — the facts then exist on disk but
  become unreachable at session start.

## Memory types

| Type | Holds |
|------|-------|
| `user` | Who the user is — role, expertise, durable preferences |
| `feedback` | How the agent should work — corrections and confirmed approaches; include the *why* and *how to apply* |
| `project` | Ongoing work, goals, constraints not derivable from code or git history; convert relative dates to absolute |
| `reference` | Pointers to external resources (URLs, dashboards, tickets) |

## Discipline (prune, don't accumulate)

- **Write when:** a mistake cost time, a non-obvious workaround was found, the
  user corrected you, a new tool/endpoint/pattern appeared, or a decision was
  made (record the *why*).
- **Don't write when:** it is already in `CLAUDE.md`/`AGENTS.md`, it is general
  knowledge, or it is one-off session-specific state (current branch, current bug).
- Before saving, check whether an existing file already covers the fact — update
  it instead of duplicating. **Delete** memories that turn out to be wrong or
  obsolete rather than letting them accumulate.
- Cold or closed facts can move to a sibling archive index
  (`MEMORY-ARCHIVE.md`), keeping `MEMORY.md` to hot recall — but a behavioural
  **guardrail** (a never-/always-/only-on-explicit-OK rule) is never "cold": it
  fires rarely *by design*, so it stays in the live index regardless of age.

## Enforcement

The ≤120-char index-line cap and the 200-line/25 KB load limit are checked by
`python3 scripts/memory-location.py check`, which `bridge-audit`'s memory pass
runs against whichever directory the memory base actually resolves to
(in-repo or legacy). Treat the audit as the backstop, not a substitute for
keeping lines lean as you write them.
