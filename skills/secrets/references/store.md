# store: from a value to a store

The mechanics of the write side. Read this before putting a new secret
anywhere, when a write was refused, or when the question is which tool runs
underneath and what it does with the value on the way.

The read side is [`resolve.md`](resolve.md). The two share a resolver and a
reference grammar, and they differ in the one way that matters: a read that goes
wrong reports a miss, and a write that goes wrong leaves a value somewhere.

Nothing here prints a value. The runs below are real, against a throwaway
keychain and a throwaway tree, and the tokens in them were generated for the run
and thrown away with it.

## The three sources

A value reaches this program by one of three routes, and the fourth route is
not offered at all:

| `--from` | Where the value comes from | When it is right |
|---|---|---|
| `stdin` | a pipe: `printf %s "$VALUE" \| secrets store ...` | a script, a rotation job, anything already holding the value |
| `clipboard` | `pbpaste`, `wl-paste`, `xclip` or `Get-Clipboard` | a person copied it out of a provider's web page |
| `prompt` | `getpass`, not echoed | a person is reading it off a screen or a card |
| `auto` (default) | stdin when stdin is not a terminal, otherwise the prompt | almost always |

**argv is not one of them, and that is the whole point of the verb.** Everything
in a command line stands in `ps` for every process of the same user for as long
as the command runs, it stands in the shell history afterwards, and in an agent
session it stands in the transcript and in the model's context for the rest of
the session. `secrets store keychain://x/y --value <token>` is therefore not a
flag that exists and is discouraged. It does not exist.

Two consequences worth knowing before choosing a route:

- **The clipboard is not cleared afterwards.** It cannot be, safely: clearing a
  clipboard the person still needs is its own small disaster, and a clipboard
  manager has a copy either way. The run says so in its last line rather than
  implying the value is gone.
- **An empty value is a usage error, not an empty secret.** A pipe that produced
  nothing, a clipboard that held nothing and a prompt somebody hit return on all
  arrive the same way, and all three are far more likely to be a mistake than an
  intention:

```
$ printf '' | secrets store keychain://invoice-gateway/rotated
secrets: nothing arrived, so nothing was written
  an empty value is not a secret; check the pipe or the clipboard
$ echo $?
64
```

## The read-back

Every write is followed by a read of the same reference, and the length and the
fingerprint of what comes back have to match what went in. Only then does
anything report success.

**An exit code is not a proof, and in this fleet it has been wrong in all three
of the available directions:**

- The tool exited 0 and stored nothing. `security add-generic-password -w` does
  not read stdin; it takes the NEXT ARGUMENT, so a piped value is discarded in
  silence and the flag that follows it is stored instead. The item exists, every
  existence test is green, and the failure arrives wherever the secret is used.
- The tool exited 0 and stored something slightly different. A double quote or a
  backslash that lost its escaping shortens the value by exactly the characters
  that were escaped. A token that is two characters short looks like a wrong
  token at the far end, not like a quoting fault here.
- The tool exited 0 and wrote to a different store than the one the read
  addresses. Then the read-back reports an entry that is not there, which is the
  honest answer, and the value has still been written.

So `store` writes, reads, compares, and says what it compared:

```
$ printf %s "$VALUE" | secrets store keychain://invoice-gateway/outbound \
    --kind personal-token --keychain /home/opuser/demo.keychain-db
keychain://invoice-gateway/outbound
  stored in   /home/opuser/demo.keychain-db: service invoice-gateway, account outbound
  read back   41 bytes, sha256 96a317c1
  store       login-keychain (infra/secret-stores/login-keychain.yaml)
```

`41 bytes, sha256 96a317c1` is the evidence, and it is the same vocabulary
`check` uses. Two machines can compare that fingerprint and agree they hold the
same token without either of them learning the other's copy.

When the read-back disagrees, nothing is rolled back and the message says so.
A write that half succeeded is a state a person has to look at, and a tool that
quietly tried to tidy it would be deciding, on its own, to delete a credential.

## What each backend does on a write

### keychain

The value goes to `security -i` on **stdin**, as a whole command line:

```
add-generic-password -s "invoice-gateway" -a "outbound" -w "<value>" -A [-U] ["<keychain>"]
```

`security -i` reads command lines from standard input, which is the one way to
reach `add-generic-password` without the value standing in an argv. The
measured facts behind the rest of that line, taken on macOS 26 in a throwaway
keychain:

| Detail | Why it is that way |
|---|---|
| a double quote and a backslash each take exactly ONE backslash | two lengthen the value, none shortens it or fails the line with rc 2, and both failures look like a wrong password at the far end |
| a value with a newline or any unprintable byte goes as `-X <hex>` | the quoted form cannot carry it at all, and hex is equally out of argv |
| `-A`, never `-T` | the accessor of an unattended read is the `security` binary itself, so an app trust list does not cover it and the read hangs before falling back to nothing |

`-U` is what makes an add overwrite, and it is added only for `--replace`. An
item that is already there without it is a refusal rather than a silent
overwrite, because an overwrite of a credential somebody else put there cannot
be undone from here:

```
$ printf %s "$VALUE" | secrets store keychain://invoice-gateway/outbound
secrets: login-keychain holds one kind, so this is a personal-token
secrets: keychain://invoice-gateway/outbound: an item with this service and account is already there
  pass --replace to overwrite it. Overwriting through `-U` can raise a dialog on some releases; the skill then deletes and re-adds instead.
$ echo $?
5
```

**Name the keychain file with an ABSOLUTE path.** Measured on macOS 26 on
2026-09-20, with the same command line twice and only the spelling of the path
different: with an absolute path the item lands in the file that was named, and
with `./demo.keychain-db` it lands in the LOGIN keychain instead, rc 0 and no
message either way. The read of a relative path then finds nothing, so the
read-back reports an entry that is not there while the value sits in the login
keychain. `--keychain "$PWD/demo.keychain-db"` is the spelling to use.

### file

`file://<absolute-path>`, for a machine with no keychain and no agent, which is
usually a systemd service on a Linux box. It is the one backend where a careless
reader finds the value by following the locator, so it is the strictest:

- **The mode is set at creation, by the opener, never by a `chmod` afterwards.**
  A `chmod` that follows the write leaves a window in which the file stands
  there with the default umask and the secret already in it.
- **0600 or 0400, and nothing wider.** A file another account can read is
  refused on READ as well, not merely reported, because its content has to be
  treated as disclosed. The message says to rotate it and store the new value
  at 0600.
- **The path has to be inside a declared store.** Without that rule this backend
  is "write the token wherever", which is the habit the whole skill exists to
  end. A write outside every declaration is refused and names the fix: declare
  the directory in `infra/secret-stores/` first.
- A trailing newline is stripped on read, because a file a person edited
  usually ends with one that was never part of the value.

### azure-keyvault

```
az keyvault secret set --vault-name <vault> --name <secret> --file <path> \
    [--subscription <id>] --content-type text/plain [--tags k=v ...] -o none
```

Three things this does that a hand written `az` line in a script usually does
not, each of them a scar:

- **The value goes in through `--file`, never `--value`.** A value on a command
  line stands in the process list, and this was the most common way a token left
  a shell in this fleet. The file is created at 0600 in a private directory and
  removed in a `finally`, whatever the call did.
- **The metadata goes in the SAME call.** `az keyvault secret set --value` alone
  creates a new version with `contentType: null` and no tags, so the portal
  shows a secret nobody can place any more. The second call that fixes it is the
  one people forget. `--tag KEY=VALUE` on `store` is what fills it.
- **`--subscription` is passed whenever the store declares one.** The default
  subscription of a machine is not always the tenant of the vault, and `az`
  answers for the wrong one without a word, which reads as "the secret is gone".

### keepass

```
keepassxc-cli add|edit --quiet --password-prompt [--key-file <path>] \
    <database.kdbx> <group/.../entry>
```

`add` for a new entry, `edit` with `--replace`. Two values arrive on **stdin**
and neither in argv, and **the order is the contract**: first the master
password that opens the database, then the value for the entry, because
`--password-prompt` asks for the entry's password after the database is open.
Swap the two lines and the database is asked to open with the secret as its
master password, which fails in a way that looks exactly like a wrong master
password and is not.

Two refusals, both deliberate:

- **While a `.lock` file stands next to the database.** KDBX has no journal: a
  save rewrites the whole encrypted file, and the merge KeePassXC offers happens
  in the GUI, on reload, with a person present. Writing under a lock is how one
  of the two versions quietly wins. The message names the lock file and adds the
  part that cannot be promised: across a WSL mount (`/mnt/c/...`) the lock of
  the Windows side may not be visible here at all, so a write can still collide.
- **Any field other than the password.** The reference grammar can address
  `username`, `url`, `notes` and custom attributes, and reading them works.
  Writing them through the CLI is a different set of flags per field, so the
  skill writes the one field it can write correctly and says to do the rest in
  KeePassXC itself.

### 1password

**Refused, and the refusal is the feature.** `op item create` and `op item edit`
take the value as a command line argument (`field=value`), so storing a secret
through them would put it in the process list of every process of this user. The
template form reads a file, and a file with the value in it is the thing this
skill exists to stop creating.

So the skill says what to do instead: make the item in the app or with `op`
yourself, point the reference at it, and run `secrets check` to prove it
resolves. Reading through `op read` is fully supported, which is the half that
can be done without the value passing a command line.

## The placement policy

`where` and `store` read the same declarations, from `infra/secret-stores/`.
`where` answers before anything is written; `store` enforces the same answer at
the moment of the write, because a policy nothing reads at that moment is
documentation, and the loose token file gets written anyway next to a file
saying it should not be.

### Asking first

```
$ secrets where personal-token
personal-token: created under one person's identity; the provider's audit log shows that person

login-keychain  (keychain)
    The login keychain of this laptop
    reference   keychain://<provider>-<tenant>-<role>/<account>
    naming      <provider>-<tenant>-<role>
    note        Personal tokens stay personal: the provider's audit log shows the person.
    declared in infra/secret-stores/login-keychain.yaml
```

The row carries the shape of the reference, so the next step is filling in the
angle brackets rather than inventing a name. With `--owner` the answer narrows
to the persona, org or customer the secret is for, and a declaration that names
that owner sorts above a general one. A store that this session cannot reach
says so on its own row rather than being hidden, because the store is still the
right place and the session is the thing that is wrong:

```
$ secrets where customer-credential --owner acme
customer-credential: belongs to one customer's systems and stays in that customer's subtree

work-kdbx for acme  (keepass)
    reference   keepass://work/<system>-<role>/<field>
    naming      <system>-<role>
    reachable   no, from this session: work-kdbx declares itself reachable from interactive, and this session is launchd-gui
    declared in infra/secret-stores/work-vault.yaml
```

With no kind at all, `where` prints the closed list and, under it, the things
that are deliberately NOT kinds:

```
not kinds, and deliberately so:
  iban                 an IBAN is on every invoice the user writes. It is identifying, not authenticating.
  tax-id               a tax id identifies a person and unlocks nothing.
  address              an address is contact data.
  pii                  personal data belongs where it is used, not in a vault.
```

Asking for one of those is refused with its own sentence and exit `5`. The
reason is worth keeping: moving an IBAN into a vault makes it useless for the
thing it is for, since it goes on every invoice anyway, and buys no security at
all. Personal data is an `audit` finding where it lies, not a placement problem.

### Enforcing at the write

`--kind` is checked against the target store before the value is read from
anywhere:

```
$ printf %s "$VALUE" | secrets store keychain://invoice-gateway/outbound \
    --kind customer-credential --replace
secrets: keychain://invoice-gateway/outbound: login-keychain does not hold customer-credential secrets
  it declares: personal-token. This kind belongs in: work-kdbx. `secrets where customer-credential` prints the shape.
$ echo $?
5
```

**Leaving `--kind` out does not turn the check off.** A store that declares
exactly one kind answers the question by itself, and says on stderr that it did:

```
secrets: login-keychain holds one kind, so this is a personal-token
```

A store that declares several cannot answer it, and the write stops rather than
guessing which line of the policy it belongs under. A gate that only fires when
the caller asks for it is a gate nobody trips.

### Reading the declarations back

`stores` lists what is declared and what is wrong with it, which is the quickest
way to see why a reference found no store:

```
$ secrets stores
login-keychain         keychain         *
                       holds: personal-token
work-kdbx              keepass          work
                       holds: org-credential

1 problem(s):
  - infra/secret-stores/work-vault.yaml: its own password is stored in itself, so nothing can open it
```

That first problem is the loop the checker exists for: a database whose master
password is an entry inside that same database cannot be opened by anything, and
without this line the failure arrives much later, as a resolver refusing a
reference for a reason that sounds like a bug in the resolver. The other
problems it reports are a store with an empty `addresses:` list (it answers
nothing), an unknown backend, an unknown kind in a `holds:` line, and a keepass
store with no `location.path`. Exit is `78` when there is any problem, so a
scheduled run can gate on it.
