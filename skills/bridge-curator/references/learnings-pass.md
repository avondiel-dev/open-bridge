---
summary: "Learnings-Pass procedure: promote matured entries of one skill's LEARNINGS.md into its references/, and propose moving skill-specific traps out of global memory into that journal."
type: reference
last_updated: 2026-09-24
---

# Learnings Pass: Procedure

Runs over **one skill** at a time: `/bridge-curator --pass learnings <skill>`.
The model and templates are in [`docs/skill-learnings.md`](../../../docs/skill-learnings.md).
Like every curator pass it writes proposals only; `/bridge-learn` applies them.

## Inputs

- `skills/<skill>/LEARNINGS.md` (the journal; absent means source 1 is empty)
- `skills/<skill>/SKILL.md` and `skills/<skill>/references/*.md` (where a
  matured entry could land)
- The global memory base, resolved with
  `python3 scripts/memory-location.py status --json` (field `memory_dir`)
- `work/_learning/proposals/rejected/` via step 0 below

## Step 0: prior rejections

Before writing any proposal, run
`python3 scripts/learning-ledger.py prior-rejections <target.path>` for the path
it would target. On a hit, cite it as `prior_rejections:` and say in the body
what is different now, or write nothing.

## Source 1: matured journal entries

An entry has **matured** when at least one of these holds, and the pass names
which in the proposal body:

- it is older than 14 days and nothing since contradicts it (no later entry or
  commit reverses it);
- two or more entries say the same thing in different words;
- the user explicitly says it is settled.

For each matured entry (or cluster), pick the `references/*.md` it belongs in
by what that file already covers; if none fits, propose a new reference file
with `target.action: create`. Write one proposal per target file:

```yaml
source:
  type: curator-suggestion
  evidence:
    - "skills/<skill>/LEARNINGS.md#<date>-<lesson-slug>"
severity: P3
status: pending
scope: <the skill's metadata.scope>
target:
  type: skill
  path: skills/<skill>/references/<file>.md
  action: edit
proposal_type: structured
diff_preview: |
  <the text as it should read in the reference file>
```

The body quotes the journal entry and ends with: **"On accept, delete this
entry from `skills/<skill>/LEARNINGS.md` in the same commit."** That is the
trim step; the journal only keeps what has not moved.

Entries that have not matured are left alone. Entries that turned out wrong
get one `target.action: edit` proposal against `LEARNINGS.md` that removes
them, with the reason.

## Source 2: skill traps sitting in global memory

A trap learned before the skill had a journal lives in global memory, where the
next run of the skill (and any sub-agent running it) never reads it.

1. List the memory facts, excluding `MEMORY.md` and other index files.
2. A fact **concerns this skill** when its body or `description:` names the
   skill (`<skill>`, `skills/<skill>/`, or its slash command) and the lesson is
   about using the skill, not about the world in general.
3. For each, write one proposal: `target.path: skills/<skill>/LEARNINGS.md`,
   `target.action: edit` (or `create` if the journal does not exist yet, then
   also the routing block, see `docs/skill-learnings.md` § Templates), with the
   entry text in `diff_preview` and the memory file in `source.evidence`.
4. **The memory fact is not touched.** It stays until the proposal is accepted;
   removing it afterwards is the user's call, stated in the proposal body.

## Output

Append to the curator report:

```
Learnings pass (<skill>): <N> journal entries, <M> matured → <K> proposals
                          <P> memory facts about this skill → <Q> proposals
  • <date>: <lesson> → references/<file>.md
  • memory/<file> → LEARNINGS.md
```

With `--dry-run`, report "would write" and touch nothing.

## Does not

- Edit `LEARNINGS.md`, `references/` or memory directly.
- Run over every skill by default. The pass is per skill; a sweep over all
  skills with a journal is `--pass learnings --all`, still one proposal per
  target file.
- Load `LEARNINGS.md` into anything that runs on every skill invocation.
