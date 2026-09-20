---
name: secrets
description: >-
  Resolves a secret reference to the program that needs it and never to the
  conversation. Owns the reference grammar of rules/secret-placement.md: `refs`
  lists every reference written down in the tree and the file and line it
  stands on, `check` resolves each one and reports bytes plus a sha256
  fingerprint instead of a value, `run` hands a value to a child process
  through its environment or standard input and scrubs what the child writes
  back. No command prints a secret. An empty entry is a miss, not a hit, and a
  read refused over ssh is a session problem, not a missing secret. Trigger:
  "/secrets", "secret", "token", "credential", "where do I put this token",
  "keychain", "vault", "keepass", "resolve a reference".
metadata:
  scope: core
allowed-tools:
  - Bash(python3:*)
  - Read
  - Grep
  - Glob
---

# Secrets

Owns every secret reference written down in this tree: what they are, whether
they still resolve here, and how a value reaches a program without reaching the
answer.
Read the referenced file ONLY when triggered.

The engine is `skills/secrets/engine/` behind the shim
`skills/secrets/secrets.sh`. The grammar it parses is the machine readable twin
of [`rules/secret-placement.md`](../../rules/secret-placement.md), which stays
the source of truth for which schemes exist and where a secret belongs.

## The principle

An agent reads this output. Whatever is printed here sits in the model's
context for the rest of the session, in the transcript, and in whatever log the
harness keeps. So this skill hands out three things about a secret and never a
fourth: its NAME (the reference), its LENGTH in bytes, and a FINGERPRINT (the
first eight hex characters of its sha256). That is enough to tell two live
tokens apart, to see that a rotation actually landed, and to prove that
something was read. It is not enough to use.

**There is deliberately no command that prints a value.** Not behind a flag,
not behind a confirmation, not in `--json`. `run` is the one path a value
takes, and it goes into a child process rather than into the answer: the
child's own output is scrubbed on the way back, and a stream that still holds
the value after scrubbing is dropped rather than printed.

The second thing the report carries is the one nobody had: CONTEXT. The same
reference is readable from a desktop session and refused over ssh. A report
that says `ok` on a laptop and `missing` on the same laptop over ssh is not
measuring the vault, it is measuring the session, and it has to say which.

## Arguments

Three verbs. `secrets.sh` resolves its own real path through the discovery
symlink, so it can be called from anywhere.

| Argument | Effect | Default |
|---|---|---|
| `refs [path...]` | Every reference in the tree, grouped, with file and line | whole tree from `--root` |
| `check [ref...]` | Resolve each reference: status, bytes, sha256, where | every reference in the tree |
| `check --all` | Measure the whole tree even when references are named | off |
| `check -v` | Also print every file and line a reference is written at | off |
| `run --env NAME=REF -- cmd` | Resolve REF into the child's environment as NAME | repeatable, none |
| `run --stdin REF -- cmd` | Resolve REF and write it to the child's standard input | none |
| `run --if-missing error\|warn\|ignore` | What an unresolvable reference does | `error` |
| `--root PATH` | Tree to read declarations from | `.` |
| `--keychain PATH` | Address this keychain file instead of the search list | the search list |
| `--db NAME=PATH` | Where a KeePass database lives on this machine | none declared |
| `--db-password-ref REF` | Reference holding the master password of those databases | none |
| `--key-file PATH` | Key file for the KeePass database | none |
| `--json` | Machine readable output, same fields, still no values | off |

## What is not here yet

Read a plan as a plan. Three verbs belong to this design and are NOT
implemented in this slice, so nothing resolves them today and typing one gets
an argparse usage error and exit `2`:

| Verb | Would do | State |
|---|---|---|
| `store` | write a value into a backend without it ever passing through argv | next slice |
| `where` | answer "where does this token belong" from the placement convention | next slice |
| `audit` | find raw values in the tree that should have been references | next slice |

The same applies one layer down. The grammar parses six schemes, and **two
backends answer**: `keychain://` and `keepass://`. A reference to
`azure-keyvault://`, `1password://` (`op://`), `vault://` or `file://` parses
cleanly and then reports `bad reference` with the line "this Bridge resolves:
keepass://, keychain://". That is a missing backend, not a broken URI, and it
is worth saying out loud before somebody edits a correct reference to fix it.

## Decision Tree

```
User wants to...
├── See every secret reference in the tree   → run `secrets refs`
├── "Is that token still there / still good" → run `secrets check`, then
│                                               references/resolve.md (§ Worked example: check)
├── Give a program a secret to run with      → Read references/resolve.md (§ Worked example: run)
├── Understand a status or an exit code      → Read references/resolve.md (§ What a row means)
├── Reach a KeePass database for the first
│   time, or wire its master password        → Read references/resolve.md (§ The bootstrap)
├── Know why a read works locally and fails
│   over ssh                                 → Read references/resolve.md (§ Context)
├── Know where a NEW token belongs           → Read rules/secret-placement.md, then
│                                               references/resolve.md (§ Addressing)
└── Ask what the schemes are                 → Answer from rules/secret-placement.md
```

## Reference map

| File | Owns |
|---|---|
| `references/resolve.md` | The mechanics: how each scheme is addressed, what each backend actually calls, the measured macOS and KeePass facts, the bootstrap, and a worked example per verb |
| [`rules/secret-placement.md`](../../rules/secret-placement.md) | Where a secret belongs: the scheme table and the group hierarchy |
| `engine/refs.py` | The grammar itself, and the only copy of it that runs |

## Hard Rules (non-negotiable)

- **Never print a value.** Not in an answer, not in a file, not in a commit, not
  in a test fixture. Names, byte counts and fingerprints are the whole
  vocabulary. If a value is needed, it is needed by a program, and `run` is how
  it gets there.
- **Never pass a value in argv.** Everything in argv is visible in `ps` to every
  process of the same user, which is how tokens ended up in the process list of
  two machines in this fleet. The tool that is called takes the value on stdin,
  and `engine.exec.run` has a `stdin_bytes` parameter for exactly that reason.
- **An empty entry is a miss, not a hit.** `security find-generic-password`
  exits 0 for an item holding zero bytes. A check that tested existence reported
  green while the caller got an empty string and failed a layer later, where it
  looked like a permission problem. A row is green only when bytes came back.
- **A failed read over ssh is a session problem, not a missing secret.** The
  login keychain has no unlocked session there. The entry may well be present,
  the password may well be right. A daemon that reads this as "gone" rotates a
  secret that was never lost.
- **Exit codes are the contract**, because a wrapper that resolves its secret at
  startup has to tell a machine problem from a rotation nobody finished:

  | Code | Means |
  |---|---|
  | `0` | everything asked for resolved |
  | `3` | missing: no entry, or an entry with no bytes in it |
  | `5` | refused: the operation was understood and not done, because doing it is unsafe |
  | `64` | the command line is wrong |
  | `69` | not reachable here: the backend tool is absent, or this session cannot use it |
  | `78` | bad reference: the URI does not parse, or no backend answers its scheme |

  `check` collapses its rows into one of these, and a row saying `not readable
  here` or `no backend here` does not make it fail. The table of which row
  produces which code is in `references/resolve.md` (§ What a row means).

- **A reference is a locator, never a value.** Parsing one is safe, printing one
  is safe, and committing one is the point of
  [`rules/secret-placement.md`](../../rules/secret-placement.md). Nothing in
  this skill writes a resolved value to disk.
- **Never resolve a secret on behalf of a unit file.** A declaration carries the
  reference unchanged and the program resolves it in its own process at run
  time. A resolved value written into a unit file is the one place it must not
  be.
