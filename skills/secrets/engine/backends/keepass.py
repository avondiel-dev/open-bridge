"""`keepass://<db>/<group>/.../<entry>[/<field>]` against a KeePass database.

The database is addressed by its LOGICAL name, never by a path: `keepass://work/
customers/acme/api-token` says which database, and where that database lives is
a property of the machine, not of the reference. Until the store declarations
land, the mapping is passed in (`--db name=/path/to.kdbx`).

Two things about KDBX that shape this backend, checked against the KeePassXC
issue tracker rather than assumed:

* There is no journal. A save rewrites the whole encrypted file. A `.lock` file
  next to the database marks that a client has it open, and KeePassXC merges a
  file that changed underneath it when it notices, on reload. So two writers are
  a real conflict, not a transaction, and this backend refuses to write while a
  lock file is present.
* Across a WSL mount (`/mnt/c/...`) the lock is not reliably visible to both
  sides, so "no lock file" is weaker evidence there than it looks. The refusal
  message says so rather than implying a guarantee.

Reading is safe under a lock: it opens the file read only and the GUI is not
disturbed.
"""

from __future__ import annotations

import os

from ..errors import BackendUnavailable, ReferenceError_, Refused, SecretsError
from ..refs import Ref
from ..values import Reading, Secret
from .base import Backend

#: Our field names, and what KeePass calls the same thing. Anything not listed
#: is passed through unchanged, because custom attributes are ordinary names.
ATTRIBUTES = {
    "password": "Password",
    "username": "UserName",
    "user": "UserName",
    "url": "URL",
    "notes": "Notes",
    "title": "Title",
}


class KeePassBackend(Backend):
    scheme = "keepass"
    binary = "keepassxc-cli"

    def __init__(self, *, databases: dict | None = None, password: Secret | None = None,
                 key_file: str | None = None, **kwargs):
        super().__init__(**kwargs)
        #: logical name -> path of the .kdbx
        self.databases = dict(databases or {})
        #: The master password, already resolved from another reference. The
        #: bootstrap this enables is the point: the keychain holds the password
        #: of the database, so the agent never sees either.
        self.password = password
        self.key_file = key_file
        self._help: str | None = None

    def install_hint(self) -> str:
        return "install KeePassXC; keepassxc-cli ships with it"

    # -- addressing ---------------------------------------------------------

    def database_path(self, ref: Ref) -> str:
        try:
            path = self.databases[ref.store]
        except KeyError:
            raise ReferenceError_(
                f"no database named {ref.store!r} on this machine",
                ref=ref.canonical,
                hint=("name it with --db {}=/path/to.kdbx, or declare the store; known here: {}"
                      .format(ref.store, ", ".join(sorted(self.databases)) or "none")),
            ) from None
        return os.path.expanduser(str(path))

    def entry_path(self, ref: Ref) -> str:
        if not ref.path:
            raise ReferenceError_(
                "the reference names a database but no entry",
                ref=ref.canonical,
                hint="keepass://<db>/<group>/…/<entry>/<field>",
            )
        return "/".join(ref.path)

    def attribute(self, ref: Ref) -> str:
        field = ref.field or "password"
        return ATTRIBUTES.get(field.lower(), field)

    def lock_file(self, ref: Ref) -> str:
        return self.database_path(ref) + ".lock"

    def locked(self, ref: Ref) -> bool:
        return os.path.exists(self.lock_file(ref))

    # -- capability ---------------------------------------------------------

    def readable_here(self, ref: Ref) -> tuple[bool, str]:
        if ref.store not in self.databases:
            return False, "no path is known for this database on this machine"
        path = self.database_path(ref)
        if not os.path.exists(path):
            return False, f"the database file is not here: {path}"
        if self.password is None and self.key_file is None:
            return False, "no master password source; resolve one first, for example from the keychain"
        return True, ""

    def help_text(self) -> str:
        """`keepassxc-cli show --help`, cached. Used to adapt to the version here."""
        if self._help is None:
            from .. import exec as exec_mod

            done = exec_mod.run([self.binary, "show", "--help"], runner=self.runner)
            self._help = (done.stdout or "") + (done.stderr or "")
        return self._help

    # -- read ---------------------------------------------------------------

    def argv_read(self, ref: Ref) -> list[str]:
        argv = [str(self.binary), "show", "--quiet", "--show-protected",
                "--attributes", self.attribute(ref)]
        if self.key_file:
            argv += ["--key-file", self.key_file]
        if self.password is None:
            argv.append("--no-password")
        elif "--pw-stdin" in self.help_text():
            # Newer builds name the stdin path explicitly. Older ones read the
            # password from stdin anyway when stdin is not a terminal, so the
            # flag is added when it exists and omitted when it does not.
            argv.append("--pw-stdin")
        argv += [self.database_path(ref), self.entry_path(ref)]
        return argv

    def read(self, ref: Ref) -> Reading:
        self.require_available(ref)
        ok, why = self.readable_here(ref)
        if not ok:
            raise BackendUnavailable(why, ref=ref.canonical)
        from .. import exec as exec_mod

        stdin_bytes = None if self.password is None else self.password.expose() + b"\n"
        done = exec_mod.run(self.argv_read(ref), stdin_bytes=stdin_bytes, runner=self.runner)
        note = "the database is open elsewhere (.lock present)" if self.locked(ref) else ""

        if done.rc != 0:
            lowered = (done.stderr or "").lower()
            if "could not find entry" in lowered or "no such entry" in lowered:
                # The lock matters most on the miss path: somebody is editing in
                # the GUI and may not have saved, so this miss is the least
                # trustworthy kind there is. Dropping the note here lost exactly
                # the half a reader needs.
                missed = "no such entry in this database"
                return Reading(ref=ref.canonical, present=False, store=ref.store,
                               note=f"{note}; {missed}" if note else missed)
            if "wrong key" in lowered or "could not open" in lowered or "invalid credentials" in lowered:
                raise BackendUnavailable(
                    "the database did not open with the credentials given",
                    ref=ref.canonical,
                    hint="wrong master password, wrong key file, or a database that is not this one",
                )
            raise SecretsError(
                f"keepassxc-cli exited {done.rc}",
                ref=ref.canonical,
                hint=_first_line(done.stderr) or "no message on stderr",
            )

        # `--attributes` prints the value and nothing else, one trailing newline.
        raw = _strip_one_newline(done.stdout or "")
        secret = Secret(raw, origin=ref.canonical)
        if secret.is_empty():
            return Reading(ref=ref.canonical, present=False, secret=secret, store=ref.store,
                           note=(note + "; " if note else "") + "the attribute exists and is empty")
        return Reading(ref=ref.canonical, present=True, secret=secret, store=ref.store, note=note)

    # -- write --------------------------------------------------------------

    def argv_write(self, ref: Ref, *, replace: bool) -> list:
        verb = "edit" if replace else "add"
        argv = [str(self.binary), verb, "--quiet", "--password-prompt"]
        if self.key_file:
            argv += ["--key-file", self.key_file]
        argv += [self.database_path(ref), self.entry_path(ref)]
        return argv

    def stdin_for_write(self, secret: Secret) -> bytes:
        """The two lines the tool reads, in the order it asks for them.

        First the master password to open the database, then the value for the
        entry, because `--password-prompt` asks for the entry's password after
        the database is open. Both arrive on stdin and neither in argv. The
        order IS the contract: swap the lines and the database refuses to open
        with the secret as its master password, which is a failure that looks
        like a wrong master password and is not.
        """
        master = b"" if self.password is None else self.password.expose()
        return master + b"\n" + secret.expose() + b"\n"

    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:
        self.require_available(ref)
        ok, why = self.readable_here(ref)
        if not ok:
            raise BackendUnavailable(why, ref=ref.canonical)
        if self.locked(ref):
            # A save rewrites the whole file: KDBX has no journal, and the merge
            # KeePassXC offers happens in the GUI, on reload, with a person
            # present. Writing under a lock is how one of the two versions
            # quietly wins. Across a WSL mount the lock is not even reliably
            # visible, so the absence of one is weaker evidence than it looks.
            raise Refused(
                "the database is open in another client",
                ref=ref.canonical,
                hint=(f"close it, or write it there. The lock is {self.lock_file(ref)}. "
                      f"On a WSL mount the lock of the Windows side may not be visible here at "
                      f"all, so a write can still collide."),
            )
        if ref.field and ref.field.lower() not in ("password", "") :
            raise Refused(
                "this Bridge writes the password field only",
                ref=ref.canonical,
                hint=f"the reference names the field {ref.field!r}; write it in KeePassXC itself",
            )
        from .. import exec as exec_mod

        done = exec_mod.run(self.argv_write(ref, replace=replace),
                            stdin_bytes=self.stdin_for_write(secret), runner=self.runner,
                            timeout_sec=120)
        if done.rc != 0:
            lowered = (done.stderr or "").lower()
            if "already exists" in lowered:
                raise Refused("an entry of that name is already there", ref=ref.canonical,
                              hint="pass --replace to edit it instead")
            raise SecretsError(f"keepassxc-cli exited {done.rc}", ref=ref.canonical,
                               hint=_first_line(done.stderr) or "no message on stderr")
        return self.read(ref)

    # -- description --------------------------------------------------------

    def locate(self, ref: Ref) -> str:
        where = self.databases.get(ref.store, f"<database {ref.store} not declared here>")
        return f"{where}: {self.entry_path(ref)} / {self.attribute(ref)}"


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _strip_one_newline(text: str) -> str:
    """Exactly one, never every trailing newline: a PEM key ends with one."""
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n") or text.endswith("\r"):
        return text[:-1]
    return text
