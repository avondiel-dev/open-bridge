---
summary: "ADR for storage outside git: which content belongs in an object store rather than a repository, how an entry points at it, how access is granted per instance, and what happens when a store cannot be reached"
type: reference
last_updated: 2026-09-22
related:
  - docs/data-model.md
  - rules/secret-placement.md
  - infra/secret-stores/_template.yaml
  - infra/backups/README.md
  - rules/deploy-reconciliation.md
---

# Storage beyond git

> ADR for the question: **where does content live that a repository must not
> hold, and how does an entry point at it without carrying it?**

**Status: decided, not built.** The implementation is
[#226](https://github.com/bks-lab/open-bridge/issues/226), and this file is the
contract it has to be true to.

## The answers

| Question | Answer |
|---|---|
| Is local storage a store behind the same interface? | Yes. Opt-in, never retroactive. |
| Which content moves? | What is read whole and moved as bytes. Configuration stays in git. |
| Reference format | `object://<store>/<key>`, naming the store and not the backend |
| Access per instance | The credential, by reference into a secret store. Not a list. |
| Offline | Fail with a named reason, optionally read from a cache, never queue a write |

## Context

A Bridge stores three ways today: tracked in a repository, ignored beside one,
or held in a secret store and reached by a reference URI. The third one solved
this problem once already. A credential must not sit in a repository, so the
value went somewhere else and the file kept a locator
([`rules/secret-placement.md`](../rules/secret-placement.md)). The reference is
tracked, the value is not.

Nothing else gets that treatment. Content that is neither configuration nor a
secret lands in the work tree, and the only thing keeping a sensitive file out of
a commit is an ignore entry somebody remembered to add next to it. Three cases
fall through: content that must not be pushed anywhere and therefore stays on one
machine, unreplicated; content too large to track; and corpora of terabytes where
a repository is not an option at all.

## Decision

**The line.** Git holds what is read as text, diffed and reviewed. A store holds
what is read whole and moved as bytes. Size is the usual symptom, not the rule: a
40 KB voiceprint belongs in a store, a 2 MB table somebody reviews belongs in git.
Git stays the primary source for the framework and for all configuration, and
this ADR moves no existing file.

### 1. Local storage is a store

A declared local directory is an object store with a local backend, a member of
the interface and not a special case beside it. Three things follow:

- A reference survives the move. One written while the object sat in a directory
  on one machine keeps resolving after the object moves to a shared store, so
  moving content between machines is a copy, not a migration.
- Offline gets an answer that is not a queue (decision 5).
- Nothing has to run to adopt it. A single machine gets the same references,
  resolver and placement policy as an instance with a server.

The boundary: declaring a local store is **opt-in and never retroactive**.
`imports/`, `.bridge/` and `work/` do not become stores. And a local store
declares what it is not (`replicated: false`, `recovery.backed_up: false`): a
store may have poor properties, it may not hide them.

### 2. One family, shaped like the secret stores

Stores are declared in `infra/object-stores/<id>.yaml`, and the family mirrors
`infra/secret-stores/` because it is the same question about a different payload:
`name`, `scope` (required, as the tripwire), `backend`, `addresses`, `location`,
`credentials`, `reachable_from`, `holds`, `recovery`. `holds` is the load-bearing
field: the declared answer to "where does this kind of content go", made once in
a file instead of per file by whoever is writing it.

### 3. The reference names the store

`object://<store>/<key>`. `<store>` is matched against `addresses` the way the
service of a `keychain://` reference is matched today; `<key>` is opaque to all
but the store. An entry tracks the URI plus size, content hash and class, never
the bytes and never a pre-signed URL, which is a credential with an expiry date.

A backend URI (`s3://bucket/key`) is rejected for the reason the KeePass reference
takes a logical name: where a store lives is a property of the machine, not of
the reference.

The object grammar is separate from the secret grammar and gets one source and a
drift guard from its first commit. The secret grammar lives in six copies that had
drifted apart before anything compared them; `scripts/check-secret-grammar.py`
exists because of that.

### 4. Access per instance is the credential

A declaration holds locators and policy. The credential is a reference into a
secret store, so a leaked declaration leaks a pointer, not access. Two instances
can share a declaration while one holds a read-write key and the other a
read-only key. A declared access list documents intent and enforces nothing;
where it disagrees with the store's own policy, the store is right. One key prefix
per instance or per customer keeps a per-customer instance inside its own
subtree.

### 5. Offline fails loud, may read from cache, never queues a write

- A read that cannot be served names its reason, and there are three: not
  reachable from here, not there, and a store this instance does not declare.
  None of them is an empty result, as the secrets engine already does it.
- A read may come from a content-addressed, size-capped cache under
  `.bridge/objects/`, and a cache hit says so.
- A write never queues. It fails, or it goes to a local store and is copied later
  by an operation somebody can see. A queue would report a write as landed while
  it is not, which [`rules/deploy-reconciliation.md`](../rules/deploy-reconciliation.md)
  refuses one layer down.

### 6. One resolver, and bytes never enter a context window

CORE ships the template, the schema, the grammar and one resolver every caller
goes through, but no server and no backend binary. The resolver returns a path, a
stream or a handle, never content: a multi-gigabyte object would end the session
that asked for it. A resolver in CORE is a choice, since `infra/backups/` ships
no executor. Objects follow `skills/secrets/` instead, because without one every
skill that touches a file carries its own copy-pasted sync call.

## Which content moves

| Moves to a store | Example |
|---|---|
| recordings | a meeting recording, raw audio |
| filed documents | a contract, an invoice, a scan |
| large exports and media | a video, a data export |
| generated deliverables carrying personal data | a rendered report with names in it |
| special-category data | a speaker voiceprint, a scan with health data |
| a large unstructured corpus | terabytes of infrastructure configuration |

| Stays in git | Why |
|---|---|
| every entry under the cluster wrappers | configuration, reviewed as a diff |
| the work system | small, textual, and its history is the point |
| skills, rules, docs, scripts | the framework itself |
| secrets | a secret store exists for them |
| anything read before a session's first answer | session start must not depend on a network |

The last row is a rule: a store may hold what a session opens later, never what a
session needs to start.

## Options considered

| Option | Verdict | Why |
|---|---|---|
| More ignored paths | rejected | bound to one machine, and placement stays a per-file decision |
| A second repository, or git-lfs | rejected | still replicates or hosts, no answer for content that may not be uploaded |
| A store referenced by backend URI | rejected | moving a store rewrites every reference |
| A store referenced by name, local is one of them | **selected** | the decisions above |

## What this is not

- **Not a backup.** `infra/backups/` declares what is replicated where; a store
  declares where content lives. A snapshot repository is not addressable per
  object, so a backup target is not a store.
- **Not a knowledge base.** A store holds bytes with keys. Answering questions over
  a corpus needs an index with complete rather than probable retrieval, designed
  elsewhere.
- **Not a secret store.** No per-field addressing, rotation or audit. A credential
  never goes into an object store.

## Not decided here

Encryption (leaning: client side for the class the store operator must not read,
with the key in a secret store), versioning and retention per class, garbage
collection of objects nothing references, the index over a corpus, and whether
an org overlay may ship objects or only references to them.
