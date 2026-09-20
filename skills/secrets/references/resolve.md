# resolve: from a reference to a value

The mechanics behind the three verbs. Read this when a row does not say what
you expected, when a database has to be reached for the first time, or when the
question is which tool actually runs underneath.

Nothing here prints a value. The examples below are real runs against a
throwaway keychain, and the one place a value would have appeared is the place
where the redaction shows instead.

## Addressing

A reference is a locator with four parts: the SCHEME says which store, the
first segment says WHICH store of that kind, the middle segments are the path
inside it, and the last one is the field.

| Scheme | Shape | Store is | Field |
|---|---|---|---|
| `keychain` | `keychain://<service>[/<account>]` | a keychain file, or the search list | none: a generic password item holds one value |
| `keepass` | `keepass://<db>/<group>/.../<entry>[/<field>]` | the logical database name | last segment, default `password` |
| `azure-keyvault` | `azure-keyvault://<vault>/<secret>` | the vault | none |
| `1password` | `1password://<vault>/<item>/<field>` | the vault | last segment, default `password` |
| `vault` | `vault://<mount>/<path>/.../<field>` | the KV mount | last segment, default `value` |
| `file` | `file://<absolute-path>` | the path itself, not split into segments | none |

Two spellings exist for the field, because the slash form goes ambiguous the
moment an entry is itself called `password`. The last segment is the field, and
a trailing `#field` overrides that and leaves every segment before it to the
path:

```
keepass://work/customers/acme/api-token            field: api-token? no: password
keepass://work/customers/acme/api-token#password   entry: api-token, field: password
```

`op://` is accepted on input, because that is the spelling the 1Password CLI
itself uses, and it is canonicalised to `1password://` on the way out. A report
therefore never shows both spellings for one secret.

**Two backends answer today: `keychain://` and `keepass://`.** The other four
parse and then report `bad reference`, naming what this Bridge resolves. That
is a missing backend rather than a broken URI, and the difference matters
before somebody edits a correct reference to make the message go away.

A reference with a placeholder in it (`<`, `>`, `{`, `}`, `$`, an ellipsis) is
read as an EXAMPLE in prose and never checked. Documentation is full of them:
measured on this repo, 21 of the 40 distinct references in the tree are
examples, and a scan that reported those as broken would bury the real ones.

## What each backend calls

### keychain

```
security find-generic-password -s <service> [-a <account>] -g [<keychain-path>]
```

The value comes back on **stderr**, on a line beginning `password:`. That is not
an error channel here, it is where `-g` prints.

Three measured shapes, on macOS 26 on 2026-09-19, against a throwaway keychain:

| Value stored | `-w` prints | `-g` prints |
|---|---|---|
| `abc` | `abc` | `password: "abc"` |
| `6c310a6c32` | `6c310a6c32` | `password: "6c310a6c32"` |
| `l1\nl2` | `6c310a6c32` | `password: 0x6C310A6C32  "l1\012l2"` |
| empty | nothing | `password:` |

**This is why the backend uses `-g` and not `-w`.** A value that contains a
newline, an umlaut or any other non-ASCII byte comes back hex encoded from
`-w`, and a token that happens to look like hex is spelled exactly the same
way. Ten characters of output, two different values, no way to tell them apart.
`-g` marks the hex form with `0x`, so the parser reads the encoding off the
output rather than guessing at it. Every caller in this fleet that used `-w`
and then asked "is this hex" was guessing, and the guess was invisible only
because the tokens involved happened to be ASCII.

Return codes are read, not lumped together:

| Signal | Verdict |
|---|---|
| rc `44` | no such item: a miss, `missing`, exit `3` |
| `User interaction is not allowed` on stderr | `not readable here`, exit `69`, never a miss |
| any other non-zero rc | a real error, reported with the first line of stderr |
| rc `0`, `password:` with nothing after it | the item exists and holds no bytes: `empty`, exit `3` |

The last row is the one that used to be green. `security` exits 0 for an item
with zero bytes in it, so a check that tested existence passed while the caller
got an empty string and failed one layer later, where it looked like a
permission problem.

**The write path, which lands in the next slice:** `security
add-generic-password -w` does NOT read from stdin. It takes the next argument,
so a piped value is silently discarded and the flag that follows it is stored
instead. The way to keep a value out of argv is `security -i`, which reads
whole command lines from stdin. That is measured, and it is the reason `store`
is a separate slice rather than a one line addition.

### keepass

```
keepassxc-cli show --quiet --show-protected --attributes <Attribute> \
    [--key-file <path>] [--pw-stdin | --no-password] <database.kdbx> <group/.../entry>
```

The master password goes in over **stdin**, with a trailing newline, never in
argv. `--pw-stdin` is added only when `keepassxc-cli show --help` on this
machine mentions it: newer builds name the stdin path explicitly, older ones
read the password from stdin anyway when stdin is not a terminal, so the flag
is added where it exists and omitted where it does not. The help text is
fetched once per backend and cached.

Field names are translated, and anything not in the table passes through
unchanged, because custom attributes are ordinary names:

| Reference field | KeePass attribute |
|---|---|
| `password` | `Password` |
| `username`, `user` | `UserName` |
| `url` | `URL` |
| `notes` | `Notes` |
| `title` | `Title` |

Errors are classified off the message rather than off the return code, which is
the same for all of them:

| stderr contains | Verdict |
|---|---|
| `could not find entry`, `no such entry` | `missing`, exit `3` |
| `wrong key`, `could not open`, `invalid credentials` | not reachable here, exit `69`: wrong master password, wrong key file, or a different database |
| anything else | a real error, with the first line of stderr |

**The database is addressed by its LOGICAL name, never by a path.**
`keepass://work/customers/acme/api-token` says which database; where that
database lives is a property of the machine, not of the reference. Until the
store declarations land, the mapping is passed in with `--db work=/path/to.kdbx`.
A reference naming a database this machine has no path for reports `no backend
here` with the databases it does know, which is a machine problem and not a
rotation.

Four facts about KDBX shape this backend, checked against the KeePassXC issue
tracker rather than assumed:

- **There is no journal.** A save rewrites the whole encrypted file. Two
  writers are a real conflict, not a transaction.
- **A `.lock` file next to the database marks that a client has it open.** A
  read taken under one carries that as a note on its row, and the write path
  that lands in the next slice refuses outright while one is present.
- **Reading under a lock is safe.** The file is opened read only and the GUI is
  not disturbed, so a `check` never has to wait for somebody to close KeePassXC.
- **Across a WSL mount (`/mnt/c/...`) the lock is not reliably visible to both
  sides.** So "no lock file" is weaker evidence there than it looks, and the
  refusal message says so rather than implying a guarantee it cannot give.

## Context

"Is this readable" is not a property of the entry. It is a property of the entry
AND the session asking. `Context` carries four facts about the session:
`platform`, `interactive`, `over_ssh`, `display`, detected from the environment
(`SSH_CONNECTION`, `SSH_TTY`, `SSH_CLIENT`, `DISPLAY`, `WAYLAND_DISPLAY`) and
from `sys.platform`.

What each backend does with them, before it runs anything:

| Backend | Says no when | Message |
|---|---|---|
| `keychain` | the platform is not `darwin` | the macOS keychain exists only on macOS |
| `keychain` | `over_ssh` and no `--keychain` was given | an ssh session has no unlocked login keychain |
| `keepass` | the database name has no path here | no path is known for this database on this machine |
| `keepass` | the `.kdbx` file is not at that path | the database file is not here |
| `keepass` | there is neither a master password source nor a key file | resolve one first, for example from the keychain |

A wrong "yes" is corrected by the read itself. A wrong "no" would hide a working
path, so the default is yes and a backend only says no about what it knows.

The ssh case is the one worth naming twice: run it from the logged-in desktop
session, or from a launchd agent in the `gui/$UID` domain, or hand the process
its own keychain file with `--keychain`. What must not happen is a wrapper
reading the refusal as "the secret is gone" and rotating it.

The two verbs learn it by different routes, which matters when debugging one of
them. `check` asks the backend's `readable_here` first and reports the session
verdict without running anything. `run` goes straight at the tool, so over ssh
its `69` comes from `security` itself saying `User interaction is not allowed`
on stderr. Same verdict, different evidence: a locale or a macOS release that
reworded that sentence would cost `run` the distinction while `check` kept it.

## The bootstrap

A KeePass database needs a master password, and the whole point of this skill
is that the agent never sees one. So **the master password is itself a
reference**, passed as `--db-password-ref`, and the resolver resolves that
first:

```
secrets check \
  --db work=~/vaults/work.kdbx \
  --db-password-ref keychain://keepass-work/master \
  keepass://work/customers/acme/api-token
```

The keychain holds the password of the database, the database holds the token,
and neither value is ever printed. Two rules keep that from turning into a
knot:

- **The master password may not live in a KeePass database.** A `keepass://`
  reference in `--db-password-ref` is refused outright, exit `5`, with the
  reason: put it in the OS keychain, which needs no second secret to open.
  A store whose credential lives in that same store cannot be opened.
- **The chain is one link deep on purpose.** The resolver tracks what it is
  currently resolving, and a reference needed to resolve itself is refused with
  that sentence rather than recursing until the stack gives out.

Every value is fetched once per command and cached in the resolver, so a run
that puts the same reference in three environment variables opens the vault
once.

## What a row means

`check` prints one row per reference and then collapses them into a single exit
code. `run` does not collapse anything: it resolves one reference at a time and
the failure's own code from `engine/errors.py` reaches the shell. The two
columns below are therefore not the same column, and reading them as one is how
a wrapper ends up treating a session problem as a rotation.

| Status | Fails `check` | `run` exits | Means |
|---|---|---|---|
| `ok` | no | `0` | bytes came back, and the row carries how many and their fingerprint |
| `empty` | yes | `3` | the entry exists and holds zero bytes: a hit for the store, a miss for the caller |
| `missing` | yes | `3` | no such entry |
| `not readable here` | **no** | `69` | the tool is installed, this session cannot use it. The entry may be perfectly fine |
| `no backend here` | **no** | `69` | nothing here answers that scheme, or no path is known for that database |
| `bad reference` | yes | `78` | the URI does not parse, or no backend answers its scheme |
| `error` | yes | the error's own code, for example `5` for a refusal | anything else, with the first line the tool said |

`check`'s own exit is `78` when any row is a `bad reference` and `3` when any
other row failed, so a run carrying both reports the configuration problem,
which is the one a person can fix.

**The two "no" rows are deliberate.** A laptop without KeePassXC installed is
not a broken tree, and a check that went red there would be switched off within
a week. Two consequences are worth knowing before trusting the summary line:

- `check` counts those rows as *resolved* in its closing sentence, so
  `1 references, 1 resolved, 0 to look at` can describe a reference nothing
  actually read. The row itself says `not readable here`; the tally does not.
- The same reference can be `ok` in a desktop session and `not readable here`
  in the ssh session five seconds later, on the same machine, with the same
  vault. That is the report measuring the session, which is what it is for.

## Worked example: refs

An inventory, derived from the tree, never a second list. A registry file naming
every secret would be wrong within a week, and wrong in the direction that
matters: a reference nobody registered is exactly the one nobody checks.

```
$ secrets refs workflow/workloads/_template.yaml
keychain://item
    workflow/workloads/_template.yaml:63

1 references in 1 files
```

Across the whole tree it groups by reference and lists every place it stands,
and it counts the examples separately rather than reporting them as broken:

```
$ secrets refs
...
keychain://token
    skills/workload/tests/test_backends.py:944
    skills/workload/tests/test_backends.py:946
    skills/workload/tests/test_model.py:316
    skills/workload/tests/test_model.py:326
vault://secret/path/value
    skills/workload/tests/test_model.py:995

19 references in 9 files
21 more carry a placeholder and are read as examples in prose
```

In a git tree the tracked files are what is searched, because that is what
ships. Outside one, or without git, the walk is the fallback. Symlinks are not
followed: the discovery symlinks (`.claude/skills` and friends) point back into
the tree, and following them counted every skill three times.

`--json` gives the same findings with `path`, `line`, `ref`, `raw` and `error`
per hit.

## Worked example: check

Two items in a throwaway keychain, one holding a token and one holding nothing:

```
$ secrets check --keychain ./demo.keychain-db \
    keychain://invoice-gateway/outbound keychain://invoice-gateway/rotated
reference                            status  bytes  sha256    where
-----------------------------------  ------  -----  --------  -------------------------------------------------------------
keychain://invoice-gateway/outbound  ok      40     49e7237e  ./demo.keychain-db: service invoice-gateway, account outbound
keychain://invoice-gateway/rotated   empty                    ./demo.keychain-db: service invoice-gateway, account rotated
    the item exists and holds no bytes

2 references, 1 resolved, 1 to look at
$ echo $?
3
```

The evidence that something was actually read is `40` and `49e7237e`: a length
and the first eight hex characters of the sha256. Two machines can compare that
fingerprint and agree they hold the same token without either of them learning
the other's copy. It is also how you see that a rotation landed: the length or
the fingerprint moves, and nothing else has to.

`rotated` is the row this column exists for. The item is there, `security`
exited 0, and there are no bytes in it.

With no references named, `check` measures the whole tree. `-v` adds the file
and line each reference is written at, so a red row points at the file to edit.
`--json` gives the same rows with `ref`, `scheme`, `status`, `where`, `bytes`,
`fingerprint`, `note` and `places`.

## Worked example: run

The one path a value takes, and it goes to a child process:

```
$ secrets run --keychain ./demo.keychain-db \
    --env GATEWAY_TOKEN=keychain://invoice-gateway/outbound \
    -- sh -c 'echo "posting with $GATEWAY_TOKEN"'
secrets: GATEWAY_TOKEN <- keychain://invoice-gateway/outbound (40 bytes, sha256 49e7237e)
posting with [redacted:GATEWAY_TOKEN]
```

Three things happened there, and each is deliberate:

1. The resolution is announced on **stderr**, with the name, the reference and
   the description. The child's own output stays clean on stdout.
2. The child printed the token. What came back says `[redacted:GATEWAY_TOKEN]`,
   naming the variable so the reader knows which secret was involved.
3. The exit code is the child's, unchanged. `secrets run` is a wrapper, not a
   verdict of its own.

The redaction covers the encodings a value plausibly wears on the way out:
base64 (including the forms with a trailing newline, because `printenv TOKEN |
base64` encodes the newline the shell added and that encoding shares only a
prefix with the encoding of the value alone), url-safe base64, hex in both
cases, percent escapes and JSON escapes. A token posted to an API and echoed
back inside a JSON error message is not spelled the way it was stored.

Two limits, both reported rather than silent:

- A value shorter than six bytes is **not** redacted, because the replacement
  would fire on ordinary words and hide the very output the caller needs to
  read. The run says which names it skipped.
- After scrubbing, the output is checked again. If a registered value survived,
  the stream is **dropped** and the caller is told which one it was. Printing it
  is the one thing that must not happen, so the belt has braces.

`--stdin REF` writes a value to the child's standard input instead, which is
how a tool that refuses an environment variable gets its credential without it
appearing in argv. `--if-missing warn` and `--if-missing ignore` turn an
unresolvable reference into a line on stderr rather than exit `3`, for the case
where a command legitimately runs with fewer credentials than it can use.
