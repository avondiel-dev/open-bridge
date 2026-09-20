"""`keychain://<service>[/<account>]` against the macOS Keychain.

Reading uses `security find-generic-password -g`, and the `-g` is the whole
point. Measured on macOS 26 on 2026-09-19 against a throwaway keychain:

    value stored          `-w` prints        `-g` prints
    "abc"                 abc                password: "abc"
    "6c310a6c32"          6c310a6c32         password: "6c310a6c32"
    "l1\nl2"              6c310a6c32         password: 0x6C310A6C32  "l1\012l2"   # pragma: allowlist secret
    ""                    (nothing)          password:

So `-w` is ambiguous: a value that contains a newline, an umlaut or any other
non-ASCII byte comes back hex encoded, and a token that happens to look like hex
is spelled exactly the same way. Ten characters of output, two different values,
no way to tell. `-g` marks the hex form with `0x`, so that is what this backend
parses. Every caller in this fleet that used `-w` and then asked "is it hex"
guessed, and the guess is only invisible because the tokens involved were ASCII.

The other measured fact, for the write path that lands with `secrets store`:
`security add-generic-password -w` does NOT read from stdin. It takes the next
argument, so a piped value is silently discarded and the flag that follows is
stored instead. The way to keep a value out of argv is `security -i`, which
reads whole command lines from stdin.
"""

from __future__ import annotations

import os
import re

from ..errors import NotReadableHere, Refused, SecretsError
from ..refs import Ref
from ..values import Reading, Secret
from .base import Backend

#: `security` exit codes worth telling apart. 44 is the one that means "no such
#: item"; everything else is a real failure and must not be reported as a miss.
RC_ITEM_NOT_FOUND = 44

#: What the tool says when the session has no unlocked keychain. This is the ssh
#: case, and it must never be read as "the entry is gone".
INTERACTION_REFUSED = "User interaction is not allowed"

_PASSWORD_LINE = re.compile(r'^password:\s*(?P<rest>.*)$', re.MULTILINE)
_HEX = re.compile(r'^0x([0-9A-Fa-f]+)')
_OCTAL_ESCAPE = re.compile(r'\\([0-7]{1,3})')


class KeychainBackend(Backend):
    scheme = "keychain"
    binary = "security"

    def __init__(self, *, keychain_path: str | None = None, **kwargs):
        super().__init__(**kwargs)
        #: A keychain file to address instead of the search list. The suite uses
        #: it to work in a throwaway keychain; a store declaration uses it when a
        #: machine keeps a separate keychain for service credentials.
        #:
        #: Absolute, always. `security` resolves a relative path against its own
        #: working directory, so a read and a write issued from two different
        #: directories addressed two different files, and the second one looked
        #: like a missing item rather than like a path problem.
        self.keychain_path = (os.path.abspath(os.path.expanduser(str(keychain_path)))
                              if keychain_path else None)

    def install_hint(self) -> str:
        return "keychain:// needs macOS; on Linux use secret-service, on Windows the credential manager"

    def readable_here(self, ref: Ref) -> tuple[bool, str]:
        if self.context.platform != "darwin":
            return False, "the macOS keychain exists only on macOS"
        if self.context.over_ssh and self.keychain_path is None:
            return False, ("an ssh session has no unlocked login keychain; run this from a "
                           "desktop session, or from a launchd agent in the gui domain")
        return True, ""

    # -- read ---------------------------------------------------------------

    def argv_read(self, ref: Ref) -> list[str]:
        argv = ["security", "find-generic-password", "-s", ref.store]
        account = ref.path[0] if ref.path else None
        if account:
            argv += ["-a", account]
        argv.append("-g")
        if self.keychain_path:
            argv.append(self.keychain_path)
        return argv

    def read(self, ref: Ref) -> Reading:
        self.require_available(ref)
        from .. import exec as exec_mod

        done = exec_mod.run(self.argv_read(ref), runner=self.runner)
        if done.rc == RC_ITEM_NOT_FOUND:
            return Reading(ref=ref.canonical, present=False, store=self._store_label(),
                           note="no such item in this keychain")
        if INTERACTION_REFUSED in done.stderr:
            raise NotReadableHere(
                "the keychain refused to answer without a user at the screen",
                ref=ref.canonical,
                hint=("this is the ssh case: the entry may well be there. Run it in the "
                      "logged-in session, or through a launchd agent in gui/$UID."),
            )
        if done.rc != 0:
            raise SecretsError(
                f"security exited {done.rc}",
                ref=ref.canonical,
                hint=_first_line(done.stderr) or "no message on stderr",
            )

        raw = parse_password(done.stderr)
        if raw is None:
            raise SecretsError(
                "security reported success without a password line",
                ref=ref.canonical,
                hint="this is a parser problem, not a vault problem; the entry exists",
            )
        secret = Secret(raw, origin=ref.canonical)
        if secret.is_empty():
            # An entry with zero bytes. `security` exits 0 for it, which is how
            # an empty value once travelled three layers before failing.
            return Reading(ref=ref.canonical, present=False, secret=secret,
                           store=self._store_label(), note="the item exists and holds no bytes")
        return Reading(ref=ref.canonical, present=True, secret=secret, store=self._store_label())

    # -- write --------------------------------------------------------------

    def write_line(self, ref: Ref, secret: Secret, *, replace: bool = False) -> str:
        """The command line `security -i` is fed on stdin, value included.

        Never argv. Measured on 2026-09-04: `add-generic-password -w` does not
        read stdin, it takes the NEXT ARGUMENT, so a piped value is discarded in
        silence and the following flag is stored instead. The entry then exists,
        every existence test is green, and the failure arrives wherever the
        secret is used. `security -i` reads whole command lines from stdin, so
        the value reaches the process without passing the process list.

        Escaping, measured the same day: a double quote and a backslash must be
        escaped or the value arrives short by two characters, or the command
        fails with rc 2. A value with a newline cannot be written this way at
        all and goes as hex through `-X`, which is equally out of argv.
        """
        account = ref.path[0] if ref.path else "default"
        parts = ["add-generic-password", "-s", _quote(ref.store), "-a", _quote(account)]
        raw = secret.expose()
        if _needs_hex(raw):
            parts += ["-X", raw.hex()]
        else:
            parts += ["-w", '"' + _escape(raw.decode("utf-8")) + '"']
        # -A, not -T: the accessor of an unattended read is the `security` binary
        # itself, so an app trust list does not cover it and the read hangs for
        # ten seconds in a launchd context before falling back to nothing.
        parts.append("-A")
        if replace:
            parts.append("-U")
        if self.keychain_path:
            parts.append(_quote(self.keychain_path))
        return " ".join(parts)

    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:
        self.require_available(ref)
        from .. import exec as exec_mod

        line = self.write_line(ref, secret, replace=replace) + "\n"
        done = exec_mod.run(["security", "-i"], stdin_bytes=line.encode("utf-8"),
                            runner=self.runner)
        if done.rc != 0:
            if "already exists" in (done.stderr or "").lower():
                raise Refused(
                    "an item with this service and account is already there",
                    ref=ref.canonical,
                    hint=("pass --replace to overwrite it. Overwriting through `-U` can raise a "
                          "dialog on some releases; the skill then deletes and re-adds instead."),
                )
            raise SecretsError(
                f"security exited {done.rc}",
                ref=ref.canonical,
                hint=_first_line(done.stderr) or "no message on stderr",
            )
        return self.read(ref)

    def delete(self, ref: Ref) -> bool:
        """Remove an item. Used by the replace path, never on its own."""
        from .. import exec as exec_mod

        argv = ["security", "delete-generic-password", "-s", ref.store]
        if ref.path:
            argv += ["-a", ref.path[0]]
        if self.keychain_path:
            argv.append(self.keychain_path)
        return exec_mod.run(argv, runner=self.runner).rc == 0

    # -- description --------------------------------------------------------

    def locate(self, ref: Ref) -> str:
        where = self.keychain_path or "login keychain"
        account = f", account {ref.path[0]}" if ref.path else ""
        return f"{where}: service {ref.store}{account}"

    def _store_label(self) -> str:
        return self.keychain_path or "login.keychain-db"


def parse_password(stderr: str) -> bytes | None:
    """The value out of a `security -g` report, or None when there is no line.

    Three shapes, all of them measured rather than assumed:

        password: "plain text"
        password: 0x6C310A6C32  "l1\\012l2"   # pragma: allowlist secret
        password:
    """
    match = _PASSWORD_LINE.search(stderr or "")
    if match is None:
        return None
    rest = match.group("rest").strip()
    if rest == "":
        return b""
    hex_match = _HEX.match(rest)
    if hex_match:
        return bytes.fromhex(hex_match.group(1))
    if rest.startswith('"'):
        return _unquote(rest)
    # Unquoted and not hex: the tool prints this for nothing known, but a parser
    # that returns None here would report a present entry as a parse failure.
    return rest.encode("utf-8")


def _unquote(rest: str) -> bytes:
    """Undo the quoting `security` applies to a printable value.

    Measured on macOS 26 on 2026-09-20 against a throwaway keychain, eleven
    values: the tool prints the quoted form when every byte is printable ASCII
    and none is a backslash, and the hex form otherwise. It does NOT escape a
    double quote inside the value, so `a"b` is printed as:

        password: "a"b"

    A parser that stops at the first inner quote returns one byte for a three
    byte secret, with present=True and no note. That is worse than a miss: the
    caller uses the truncated value and the far end rejects it, which reads like
    a wrong password rather than a parser fault. The value therefore runs to the
    LAST quote on the line, which is unambiguous because the tool prints nothing
    after it, and the hex form is already taken by the `0x` branch above.
    """
    end = rest.rfind('"')
    body = rest[1:end] if end > 0 else rest[1:]
    # Older releases print an octal escape for a control character. Current ones
    # use the hex form for anything unprintable, so this is a compatibility
    # path, not the common one.
    body = _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), body)
    # An escaped quote or backslash cannot come off the measured tool, which
    # switches to the hex form for a value holding a backslash. Older releases
    # do print them, and undoing them costs nothing here: a value that really
    # held a backslash never reaches this branch.
    body = body.replace('\\"', '"').replace("\\\\", "\\")
    return body.encode("utf-8", errors="surrogateescape")


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _escape(text: str) -> str:
    """Backslash and double quote, in that order, or the value arrives short."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _quote(text: str) -> str:
    return '"' + _escape(text) + '"'


def _needs_hex(raw: bytes) -> bool:
    """A value the quoted form cannot carry: a newline, or anything unprintable."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)
