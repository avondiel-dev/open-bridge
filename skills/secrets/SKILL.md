---
name: secrets
description: >-
  Resolves a secret reference to the program that needs it and never to the
  conversation, and puts a new value into a declared store, never through
  argv. Owns the reference grammar of rules/secret-placement.md and the
  placement policy of infra/secret-stores/: `refs` lists every reference in the
  tree with its file and line, `check` reports bytes and a sha256 fingerprint
  instead of a value, `run` hands a value to a child process and scrubs what
  comes back, `where` answers where a new secret of a kind belongs, `store`
  writes it there and reads it back, `stores` lists the declarations. No
  command prints a secret. Trigger: "/secrets", "secret", "token",
  "credential", "where do I put this token", "keychain", "vault", "keepass",
  "store this token", "resolve a reference".
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

## Where a new secret goes

The other half of the question, and the half that had no answer. An agent handed
a token decided for itself where to keep it, and the result was small text files
with credentials in working folders on two machines. The answer is declared
once, in `infra/secret-stores/*.yaml`: one file per store, saying where that
store is, who reaches it from where, and which KIND of secret belongs in it.

The kinds are a closed list, because the question is a policy question and not a
guess about the value: `personal-token`, `org-credential`,
`customer-credential`, `service-runtime`, `ci-secret`, `household-shared`,
`break-glass`. `where` prints what each one means and which store holds it.

**PII is explicitly not a kind.** An IBAN, a tax id and a postal address
identify a person, they do not authenticate one. Moving them into a vault makes
them useless for what they are for and buys nothing, so `where iban` refuses
with that sentence rather than proposing a store. Personal data belongs where it
is used; `audit` will report it where it lies.

## Arguments

Six verbs. `secrets.sh` resolves its own real path through the discovery
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
| `where [kind]` | Which store a new secret of this kind belongs in, and what to call it | no kind: list the kinds |
| `where --owner NAME` | Narrow to the persona, org or customer it is for | every owner |
| `store REF` | Write a value into the store that answers REF, then read it back | value from stdin when piped |
| `store --from stdin\|clipboard\|prompt` | Where the value comes from. Never argv | `auto`: stdin when piped, else a hidden prompt |
| `store --kind KIND` | Refuse the write unless the target store declares this kind | inferred when the store holds exactly one |
| `store --replace` | Overwrite an entry that is already there | off |
| `store --tag KEY=VALUE` | Metadata written in the same call, where the backend carries it | repeatable, none |
| `stores` | Every declaration, what it holds, and what is wrong with it | whole tree from `--root` |
| `--root PATH` | Tree to read declarations from | `.` |
| `--keychain PATH` | Address this keychain file instead of the search list. Spell it absolutely: `security` reads a relative path as the login keychain on a write | the search list |
| `--db NAME=PATH` | Where a KeePass database lives on this machine | none declared |
| `--db-password-ref REF` | Reference holding the master password of those databases | none |
| `--key-file PATH` | Key file for the KeePass database | none |
| `--json` | Machine readable output, same fields, still no values | off |

## What is not here yet

Read a plan as a plan. One verb belongs to this design and is NOT implemented,
so nothing resolves it today and typing it gets an argparse usage error and
exit `2`:

| Verb | Would do | State |
|---|---|---|
| `audit` | find raw values in the tree that should have been references | next slice |

The same applies one layer down, and it is now the read and the write that
differ rather than the scheme list. The grammar parses six schemes and **five
backends read**: `keychain://`, `keepass://`, `azure-keyvault://`,
`1password://` (`op://`) and `file://`. `vault://` parses cleanly and then
reports that this Bridge cannot reach it yet, naming what it does reach. That
is a missing backend, not a broken URI, and it is worth saying out loud before
somebody edits a correct reference to fix it.

**Four of those five write, and the fifth refuses on purpose.** `1password://`
is read only here, because `op item create` and `op item edit` take the value
as a command line argument. Making the item in the app and pointing a reference
at it keeps the value out of the process list; doing it through `op` would not.

## Decision Tree

```
User wants to...
├── See every secret reference in the tree   → run `secrets refs`
├── "Is that token still there / still good" → run `secrets check`, then
│                                               references/resolve.md (§ Worked example: check)
├── Give a program a secret to run with      → Read references/resolve.md (§ Worked example: run)
├── Put a NEW value into a store             → Read references/store.md (§ The three sources),
│                                               then run `secrets where <kind>`
├── Know which store answers a reference,
│   or what a declaration has to say         → Read references/resolve.md (§ The declarations)
├── Understand a status or an exit code      → Read references/resolve.md (§ What a row means)
├── Reach a KeePass database for the first
│   time, or wire its master password        → Read references/resolve.md (§ The bootstrap)
├── Know why a read works locally and fails
│   over ssh                                 → Read references/resolve.md (§ Context)
├── Know where a NEW token belongs           → run `secrets where <kind>`, then
│                                               references/store.md (§ The placement policy)
├── Ask what the kinds are, or why PII is
│   not one of them                          → run `secrets where` with no kind
└── Ask what the schemes are                 → Answer from rules/secret-placement.md
```

## Reference map

| File | Owns |
|---|---|
| `references/resolve.md` | The READ side: how each scheme is addressed, what each backend calls, the store declarations a reference takes its options from, the measured macOS and KeePass facts, the bootstrap, and a worked example per verb |
| `references/store.md` | The WRITE side: the three value sources, the read-back, what each backend does on a write, and the placement policy worked through |
| [`rules/secret-placement.md`](../../rules/secret-placement.md) | Where a secret belongs: the scheme table and the group hierarchy |
| `infra/secret-stores/_template.yaml` | What a declaration says, field by field, and `_schema.yaml` next to it |
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
- **A write is proved by a read-back, never by an exit code.** Every tool
  involved exits 0 for an entry that holds nothing, and a value that lost two
  characters to a quoting rule is indistinguishable from a correct one until
  something tries to use it. So `store` writes, reads the entry again, and
  compares length and fingerprint before it reports anything.
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
