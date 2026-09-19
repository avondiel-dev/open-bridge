# Roadmap

**Honest status:** open-bridge is built and used day to day by its two
maintainers, each on their own instances: **N=2**, and no external users yet.
This roadmap is a *direction*, not a set of dated promises. Priorities move with
what people actually need. **Every open item below links to its issue: react 👍
on the issues you want most**; that's the signal ordering gets decided by.
Discuss use-cases in [Discussions](https://github.com/bks-lab/open-bridge/discussions).

Nothing below is a commitment to a date, and "Later, exploring" means exactly that.

## Shipped

- **Persistent project memory**: context that survives across sessions, in plain
  markdown + YAML in git.
- **Cross-tool skill discovery**: the same `SKILL.md` skills are found by Claude
  Code, GitHub Copilot, Codex, Gemini and Cursor via standard discovery paths.
- **Structured work-system**: a generated board + an append-only work log, with
  a closed status model.
- **Guided onboarding**: a four-lane front door (see it run, describe your
  goal, go private first, or bind a workspace) that takes a fresh clone to a
  running instance; hardened first-run (push-guard, scope consent, goal
  clarity) ([#51](https://github.com/bks-lab/open-bridge/issues/51),
  [#46](https://github.com/bks-lab/open-bridge/issues/46)).
- **Organization overlays**: subscribe to an organization's config by git URL
  and provision it onto a vanilla open-bridge, no fork
  ([#48](https://github.com/bks-lab/open-bridge/issues/48), `docs/org-overlays.md`).
- **Meeting transcription**: a bring-your-own-worker contract for `/debrief`
  plus a full reference pipeline (whisper.cpp + pyannote speaker naming) as a
  CORE skill (`docs/transcription-worker.md`, `skills/meeting-transcription/`).
- **One-command health check**: `/bridge-status` reports whether an instance
  is wired up correctly: configs resolve, the board generates from the task
  dirs, and docs + links are healthy
  ([#44](https://github.com/bks-lab/open-bridge/issues/44)).
- **Mirror-aware install**: a clone commits to your own private repo, never a
  silent push upstream: the armed `pre-push` guard, the private-template setup,
  and the `git fetch upstream && git merge upstream/main` update path keep you
  current without a public fork
  ([#52](https://github.com/bks-lab/open-bridge/issues/52), `rules/push-guard.md`).
- **Representative agent (Bridge-Agent) runtime**: a persistent, addressable
  A2A endpoint that fronts a persona to the world and to peer bridges under
  human gates; generic runtime + template in `agents/`, guide in
  `docs/representative-agent.md`
  ([#49](https://github.com/bks-lab/open-bridge/issues/49),
  [#126](https://github.com/bks-lab/open-bridge/pull/126)).
- **MCP→A2A gateway**: a thin, stateless gateway (`agents/_gateway/`) that
  lets MCP-only frontends (Claude connectors, ChatGPT developer mode, Gemini)
  talk to a bridge's A2A agent; anonymous access is standard, a bearer token
  unlocks more
  ([#125](https://github.com/bks-lab/open-bridge/pull/125), discovery closed
  in [#124](https://github.com/bks-lab/open-bridge/issues/124)).
- **Data-model guardrails: which data lives where**
  ([#53](https://github.com/bks-lab/open-bridge/issues/53)): CORE/org/user
  data boundaries explicit and enforceable, so instances stay clean by
  construction.
- **Staying current, unattended**: a daily job merges CORE updates into your
  branch behind guards that fail closed on local edits or a predicted conflict
  ([#187](https://github.com/bks-lab/open-bridge/pull/187),
  [#213](https://github.com/bks-lab/open-bridge/pull/213)), and a companion job
  keeps every subscribed org overlay current: it applies updates, reports a new
  tool for one explicit yes, and never deletes anything unattended
  ([#214](https://github.com/bks-lab/open-bridge/pull/214)).
- **Workloads, declared runs on your machines**: one file per scheduled job,
  daemon or watcher; the `workload` skill provisions it and reconciles the
  declaration against the live service manager, never against a status field
  ([#161](https://github.com/bks-lab/open-bridge/pull/161),
  [#178](https://github.com/bks-lab/open-bridge/pull/178),
  [#180](https://github.com/bks-lab/open-bridge/pull/180)).
- **A measured session context**: what every session loads has a declared
  budget that CI enforces, registries are read as a table of contents with one
  entry fetched on demand, and the skill and sub-agent listing is measured too
  ([#165](https://github.com/bks-lab/open-bridge/pull/165),
  [#166](https://github.com/bks-lab/open-bridge/pull/166),
  [#167](https://github.com/bks-lab/open-bridge/pull/167)).
- **Memory in the repo**: Claude Code's auto memory can live under
  `work/memory/`, versioned with the rest of the instance
  ([#208](https://github.com/bks-lab/open-bridge/pull/208)), and archiving a
  period distils its durable facts into it
  ([#158](https://github.com/bks-lab/open-bridge/pull/158)).

## Next

- **A secrets skill**
  ([#215](https://github.com/bks-lab/open-bridge/issues/215)): one broker that
  resolves a secret reference against Keychain, KeePass, Azure Key Vault or
  1Password, declares where each kind of new secret goes, and finds plaintext
  tokens that landed anywhere else.
- **One picture of the data model**
  ([#217](https://github.com/bks-lab/open-bridge/issues/217)): which data is
  core, per user and per organisation, which objects live there, how they
  reference each other and in which kind of store; the rings on the site are
  regenerated from the same source.
- **Storage beyond git**
  ([#216](https://github.com/bks-lab/open-bridge/issues/216)): a discovery and
  a decision record for an object store beside git, for content that must not
  live in a repository. Follows the data model.
- **Overlay auto-sync, finished**
  ([#218](https://github.com/bks-lab/open-bridge/issues/218)): scheduling,
  tests and a status line for the job shipped in #214.

## Later, exploring

- **More worked examples**
  ([#45](https://github.com/bks-lab/open-bridge/issues/45)): additional
  end-to-end example setups beyond `examples/agency`. Waiting for a signal on
  which archetype people want first.
- **Deployment & structured-feedback story**
  ([#56](https://github.com/bks-lab/open-bridge/issues/56)): a repeatable way
  to roll an instance out to someone else and learn from how it behaves.
- **A learning loop that checks itself**
  ([#203](https://github.com/bks-lab/open-bridge/issues/203),
  [#204](https://github.com/bks-lab/open-bridge/issues/204),
  [#205](https://github.com/bks-lab/open-bridge/issues/205),
  [#202](https://github.com/bks-lab/open-bridge/issues/202),
  [#163](https://github.com/bks-lab/open-bridge/issues/163)): an audit trail
  written from git, proposals that cite earlier rejections, per-skill
  provenance, optional before and after evidence, and a home for a lesson
  inside the skill it is about.
- **Memory across harnesses**
  ([#209](https://github.com/bks-lab/open-bridge/issues/209),
  [#201](https://github.com/bks-lab/open-bridge/issues/201)): the memory index
  read the same way on every harness, and a stated retention window for the
  session links that facts carry.
- **Finding answers, writing skills**
  ([#164](https://github.com/bks-lab/open-bridge/issues/164),
  [#206](https://github.com/bks-lab/open-bridge/issues/206)): a map from a
  question to where its answer lives, and authoring guidance that marks
  model-specific workarounds.

## Ecosystem: companion projects

open-bridge is the substrate; these optional, independently usable projects sit
around it. Take only what you need.

- **Bridge Deck**: a pixel-art, real-time dashboard that renders a bridge's
  live state (services, crew, calendar, channels). Separate repo,
  **Apache-2.0**, read-only, config-driven.
  → [`bks-lab/bridge-deck`](https://github.com/bks-lab/bridge-deck)
- **Representative agent**: the CORE `agents/` runtime + template, plus the
  MCP→A2A gateway that fronts it to MCP-only clients; see *Shipped*.

> Honest note: these companion projects run today as a single-maintainer (N=1)
> setup. They're built for technical early adopters, not yet for critical
> infrastructure.

## How priorities are set

Today this is shaped by two maintainers' real use (N=2) plus community 👍 on
the linked issues and Discussions. Items move between sections as they're
picked up; the changelog is the [Releases
page](https://github.com/bks-lab/open-bridge/releases).
