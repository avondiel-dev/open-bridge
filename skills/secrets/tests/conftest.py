"""Shared test scaffolding for the secrets skill.

Two jobs, and both of them are load bearing.

1. NOTHING HERE TOUCHES A REAL SECRET STORE. `MachineGuard` patches
   `subprocess.Popen`, `subprocess.run`, `os.system` and `os.popen` for the
   duration of every test and raises on any attempt to exec `security`,
   `keepassxc-cli`, `az`, `op`, `ssh`, `scp`, `sudo` or `secret-tool`,
   including one hidden inside `sh -c`. It is stricter than it looks, and it
   has to be: whoever runs this suite has a real login keychain and a real
   vault sitting right there, so a backend that reached around the `runner=`
   seam would read a LIVE token and the case would go green on the strength of
   it. The guard turns that into a loud failure instead of a quiet pass.

   The one deliberate exception is `temporary_keychain()`, the macOS tier. It
   builds a throwaway keychain file of its own, yields it, and deletes it
   afterwards. It reaches past the guard through `unguarded_security()`, the
   single door, which in turn uses `_UNGUARDED_POPEN`. Both are spelled that way
   so the bypass shows up in a grep rather than hiding inside a helper with an
   innocent name.

2. ENGINE MODULES ARE IMPORTED LAZILY. `mod("engine.values")` returns a proxy
   that imports on first attribute access, inside the test body. Without it a
   missing or broken module collapses a whole file into one collection error,
   and the suite reports a single failure where it should report a hundred. The
   count of red cases is the evidence that the suite examines something, so the
   count has to survive the absence of the implementation.

`FakeRunner.argv_carried()` is the assertion this whole skill exists for.
Anything in argv is visible in `ps` to every process of the same user, which is
how tokens ended up in the process list of two machines in this fleet before
anyone looked. A value belongs on stdin; every case that hands one to a backend
asserts that it did not travel the other way.

The attribute names used by `FakeRunner` and `completed()` ARE the contract with
`engine.exec`. If the engine names them differently, the engine is what changes.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SKILL_DIR = TESTS_DIR.parent
FIXTURES = TESTS_DIR / "fixtures"

# `import engine.x` has to work from inside the tests directory. The runner
# starts unittest with the skill directory as the top level, but the standalone
# import check does not, and a suite that only collects under one of the two is
# a suite somebody will eventually run the other way.
if str(SKILL_DIR) not in sys.path:
    sys.path.insert(0, str(SKILL_DIR))

#: `subprocess.Popen` as it stands BEFORE any guard has patched it, captured at
#: import time. `MachineGuard` installs its patch in `setUp` and removes it in
#: `addCleanup`, so import time is reliably outside that window.
#:
#: POPEN AND NOT RUN, which cost a round to learn: `subprocess.run` looks `Popen`
#: up in its own module namespace every call, so a saved `run` walks straight
#: back into the patched `Popen` and is refused. A bypass through `run` is not a
#: bypass. The only caller is `unguarded_security()` below, and the name is
#: deliberately ugly: a second caller appearing here is a hole in the guard and
#: should read like one.
_UNGUARDED_POPEN = subprocess.Popen


# ---------------------------------------------------------------------------
# Lazy engine import
# ---------------------------------------------------------------------------

class _LazyModule:
    """Imports on first attribute access, so the failure lands inside a test."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._loaded = None

    def __getattr__(self, attr):
        if self._loaded is None:
            self._loaded = importlib.import_module(self._name)
        return getattr(self._loaded, attr)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<lazy module {self._name}>"


def mod(name: str) -> _LazyModule:
    """Return a lazy proxy for an engine module."""
    return _LazyModule(name)


#: The seam every fake in this file builds results for.
_exec = mod("engine.exec")


# ---------------------------------------------------------------------------
# The machine guard
# ---------------------------------------------------------------------------

#: Every binary that can reach a live secret store from here. `az` and `op` are
#: on the list although no backend implements those schemes yet: the grammar
#: already accepts `azure-keyvault://` and `1password://`, so the day a backend
#: lands is the day an unguarded suite would start talking to a real tenant.
#: `ssh`, `scp` and `sudo` are here because a store on another machine is still
#: a store, and `secret-tool` is the Linux keyring, which CI has.
_DENY = {"security", "keepassxc-cli", "az", "op", "ssh", "scp", "sudo", "secret-tool"}
_SHELLS = {"sh", "bash", "zsh", "dash"}


def _first_denied(argv):
    """The first denied binary in `argv`, or None. Looks inside `sh -c` too.

    A denylist that only reads argv[0] is walked past by one layer of shell,
    and the engine's own guard script is a shell script, so that layer is not
    hypothetical here.
    """
    if argv is None:
        return None
    if isinstance(argv, (str, bytes)):
        text = argv.decode() if isinstance(argv, bytes) else argv
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()
    else:
        parts = [str(a) for a in argv]
    if not parts:
        return None
    head = os.path.basename(parts[0])
    if head in _DENY:
        return head
    if head in _SHELLS and "-c" in parts:
        index = parts.index("-c")
        payload = parts[index + 1] if len(parts) > index + 1 else ""
        try:
            inner = shlex.split(payload)
        except ValueError:
            inner = payload.split()
        if inner and os.path.basename(inner[0]) in _DENY:
            return os.path.basename(inner[0])
    return None


class MachineGuard(unittest.TestCase):
    """Base class that refuses to let a test reach a real secret store.

    Every test class in this suite inherits it, directly or through another
    class that does, and a meta case enforces that. In a green run the guard
    never fires, so nothing else here would ever notice that it had stopped
    refusing.
    """

    def setUp(self):
        super().setUp()
        self._real_popen = subprocess.Popen
        self._real_run = subprocess.run
        guard = self

        class GuardedPopen(self._real_popen):  # type: ignore[misc,valid-type]
            def __init__(self, args, *a, **kw):
                denied = _first_denied(args)
                if denied:
                    raise AssertionError(
                        f"the suite tried to exec {denied!r}. That reaches a real vault on "
                        f"this machine; pass FakeRunner as runner= instead. argv={args!r}"
                    )
                super().__init__(args, *a, **kw)

        def guarded_run(args, *a, **kw):
            denied = _first_denied(args)
            if denied:
                raise AssertionError(
                    f"the suite tried to exec {denied!r} via subprocess.run. argv={args!r}"
                )
            return guard._real_run(args, *a, **kw)

        # os.system and os.popen do not go through subprocess at all, so
        # patching subprocess alone leaves a second, quieter door open.
        self._real_system = os.system
        self._real_os_popen = os.popen

        def guarded_system(command):
            denied = _first_denied(command)
            if denied:
                raise AssertionError(
                    f"the suite tried to exec {denied!r} via os.system. command={command!r}"
                )
            return guard._real_system(command)

        def guarded_os_popen(command, *a, **kw):
            denied = _first_denied(command)
            if denied:
                raise AssertionError(
                    f"the suite tried to exec {denied!r} via os.popen. command={command!r}"
                )
            return guard._real_os_popen(command, *a, **kw)

        subprocess.Popen = GuardedPopen
        subprocess.run = guarded_run
        os.system = guarded_system
        os.popen = guarded_os_popen
        self.addCleanup(self._restore_subprocess)

    def _restore_subprocess(self):
        subprocess.Popen = self._real_popen
        subprocess.run = self._real_run
        os.system = self._real_system
        os.popen = self._real_os_popen

    # helpers ---------------------------------------------------------------

    def tmpdir(self) -> Path:
        """A throwaway directory, removed when the case ends.

        On the base class rather than in each suite because `file://` entries,
        KDBX paths and the tree scan all need one, and a directory that outlives
        a failed case is a file with a secret shaped name left on a real disk.
        """
        folder = Path(tempfile.mkdtemp(prefix="secrets-test-"))
        self.addCleanup(shutil.rmtree, folder, ignore_errors=True)
        return folder


# ---------------------------------------------------------------------------
# The seam double
# ---------------------------------------------------------------------------

def completed(rc: int = 0, stdout: str = "", stderr: str = ""):
    """An `engine.exec.Completed`, for a route or for a direct return value."""
    return _exec.Completed(rc=rc, stdout=stdout, stderr=stderr)


class FakeRunner:
    """Stands in for the process, records what was asked, answers from routes.

    Called exactly the way `engine.exec.run` calls a runner, `runner(argv,
    invocation=Invocation(...))`, so a backend driven through here is driven
    through its real code path and not through a shortcut the test invented.

    Routing is by substring against the joined argv, first match wins, so a case
    says what a call answers without pinning how the backend phrases it.
    """

    def __init__(self, routes=None, default=None):
        self.routes = list(routes or [])
        self.default = default
        self.calls: list = []

    def add(self, needle: str, completed=None, raises=None) -> "FakeRunner":
        """Answer any call whose joined argv contains `needle`."""
        self.routes.append((needle, completed, raises))
        return self

    def __call__(self, argv, *, invocation=None):
        argv = tuple(str(a) for a in (argv or ()))
        self.calls.append({
            "argv": argv,
            "joined": " ".join(argv),
            # The two fields the argv rule is measured against. `stdin_bytes` is
            # where a value is SUPPOSED to travel, and `env` is the third place
            # a value can leak into a child, so both are kept rather than the
            # whole Invocation: a test that asserts on a field has to have it.
            "stdin_bytes": getattr(invocation, "stdin_bytes", None),
            "env": getattr(invocation, "env", None),
        })
        joined = self.calls[-1]["joined"]
        for needle, answer, raises in self.routes:
            if needle in joined:
                if raises is not None:
                    raise raises
                answer = completed() if answer is None else answer
                return self._with_argv(answer, argv)
        if self.default is not None:
            return self._with_argv(self.default, argv)
        return self._with_argv(completed(), argv)

    @staticmethod
    def _with_argv(answer, argv):
        """Fill in the argv a route could not know when it was written.

        `Completed` is frozen, so this replaces rather than assigns, and it only
        fills an EMPTY argv: a route that pinned one meant it.
        """
        if getattr(answer, "argv", ()):
            return answer
        return dataclasses.replace(answer, argv=argv)

    # convenience -----------------------------------------------------------

    @property
    def joined_calls(self) -> str:
        return "\n".join(call["joined"] for call in self.calls)

    def called_with(self, needle: str) -> bool:
        return any(needle in call["joined"] for call in self.calls)

    def index_of(self, needle: str) -> int:
        for position, call in enumerate(self.calls):
            if needle in call["joined"]:
                return position
        raise AssertionError(
            f"no recorded call contains {needle!r}; calls were:\n{self.joined_calls}")

    def argv_carried(self, value) -> bool:
        """True when `value` appears anywhere in the argv of any recorded call.

        The one assertion this skill exists for, and it is phrased as a positive
        so the failure message can say what was found. argv is world readable
        through `ps` for every process of the same user, so a value there is
        disclosed to the whole machine the moment the call runs, whether or not
        the call succeeds. Only argv is inspected: `stdin_bytes` is the correct
        channel and `env` is checked by its own cases, which have a different
        threat model.
        """
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="surrogateescape")
        value = str(value)
        return any(value in token for call in self.calls for token in call["argv"])


# ---------------------------------------------------------------------------
# What `security find-generic-password -g` actually prints
#
# RE-MEASURED on macOS 26 on 2026-09-20 against a throwaway keychain, which is
# what `temporary_keychain()` below exists for. The password goes to STDERR and
# the attribute dump to STDOUT, which is the detail every script that pipes only
# one of the two streams gets wrong.
#
#     value stored           stderr
#     "abc"                  password: "abc"
#     "a b"    "a~b"  "a$b"  password: "a b"          printable ASCII stays quoted
#     'a"b'                  password: "a"b"          the quote is NOT escaped
#     "a\\b"                 password: 0x615C62  "a\134b"
#     "a" umlaut "b"         password: 0x61C3A462  "a\303\244b"
#     "l1\nl2"               password: 0x6C310A6C32  "l1\012l2"   # pragma: allowlist secret
#     ""                     password:                with a TRAILING SPACE
#
# So the rule the tool actually follows: the quoted form when every byte is
# printable ASCII AND none is a backslash, the hex form otherwise. Two places
# where the engine's own docstring is a shade off the measurement, and both are
# recorded here rather than smoothed over, because a fixture that is prettier
# than the tool teaches the parser a shape it will never meet:
#
#   * the empty line carries a trailing space, since the tool prints
#     "password: " and then whatever the value renders as, which here is nothing.
#   * a double quote inside a value is passed through RAW, so `a"b` comes back
#     as `password: "a"b"`. That line has three quotes in it and no way to tell
#     which one closes the value. It is the tool's ambiguity, not ours, and the
#     fixture reproduces it so that a case can be written against it.
# ---------------------------------------------------------------------------

def keychain_report(value=None, hex_value=None, empty: bool = False) -> str:
    """The stderr a `security find-generic-password -g` leaves behind.

    Exactly one of the three has to be given. `value` produces the quoted form,
    `hex_value` the hex form (bytes, or the hex digits as a string) together
    with the quoted rendering the tool prints beside it, and `empty` the bare
    line an item with zero bytes in it produces.

    `value` REFUSES anything the real tool would have printed as hex. That
    refusal is the point of the helper: hand-writing `password: "a\\b"` as a
    fixture would put a shape into the suite that the tool never emits, and a
    parser tested against it is tested against nothing.
    """
    chosen = [name for name, given in
              (("value", value is not None), ("hex_value", hex_value is not None),
               ("empty", bool(empty))) if given]
    if len(chosen) != 1:
        raise AssertionError(
            "say which measured shape you want, one of value=, hex_value= or "
            f"empty=True; got {chosen or ['none']}")

    if empty:
        # The space before the newline is measured and load bearing. An editor
        # that strips trailing whitespace cannot reach it here, because it sits
        # inside a literal in the middle of the line.
        return "password: " + "\n"
    if hex_value is not None:
        raw = bytes.fromhex(hex_value) if isinstance(hex_value, str) else bytes(hex_value)
        return f'password: 0x{raw.hex().upper()}  "{_tool_quoted(raw)}"\n'

    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if not _renders_quoted(raw):
        raise AssertionError(
            "security prints this value in the hex form, not the quoted form: it "
            "holds a backslash or a byte outside printable ASCII. Pass it as "
            "hex_value= so the fixture says what the tool says.")
    return f'password: "{raw.decode("ascii")}"\n'


def _renders_quoted(raw: bytes) -> bool:
    """True when the tool would print this value quoted rather than as hex."""
    return all(0x20 <= byte < 0x7F for byte in raw) and 0x5C not in raw


def _tool_quoted(raw: bytes) -> str:
    """The body of the quoted half of the HEX form, as the tool renders it.

    A backslash and every byte outside printable ASCII become a three digit
    octal escape, which is what `\\134` and `\\012` are in the table above. A
    double quote is left alone, because the tool leaves it alone, and a helper
    that escaped it here would hide exactly the ambiguity worth testing.
    """
    out = []
    for byte in raw:
        if 0x20 <= byte < 0x7F and byte != 0x5C:
            out.append(chr(byte))
        else:
            out.append("\\%03o" % byte)
    return "".join(out)


def keychain_attributes(service: str, account=None,
                        keychain_path: str = "login.keychain-db",
                        version: int = 512) -> str:
    """The attribute dump the same call prints on STDOUT.

    Separate because the backend parses stderr and ignores this, and a case that
    proves it ignores it needs the bytes to hand it. The timestamps are fixed
    rather than generated: a fixture that reads the clock makes a failure at
    23:59 a different failure from the same one at 00:01.

    `version` is 512 for a login keychain and 256 for one that
    `temporary_keychain()` just made, measured. It is a parameter rather than a
    constant because those are two different files and the tier tests meet both.
    """
    # Built outside the list because a backslash inside an f-string expression
    # is a syntax error before Python 3.12, and this file has to parse on the
    # oldest interpreter anyone runs the suite with.
    acct = '"%s"' % account if account else "<NULL>"
    lines = [
        f'keychain: "{keychain_path}"',
        f"version: {version}",
        'class: "genp"',
        "attributes:",
        f'    0x00000007 <blob>="{service}"',
        "    0x00000008 <blob>=<NULL>",
        f'    "acct"<blob>={acct}',
        '    "cdat"<timedate>=0x32303236303931393038333330305A00  "20260919083300Z\\000"',
        '    "crtr"<uint32>=<NULL>',
        '    "cusi"<sint32>=<NULL>',
        '    "desc"<blob>=<NULL>',
        '    "gena"<blob>=<NULL>',
        '    "icmt"<blob>=<NULL>',
        '    "invi"<sint32>=<NULL>',
        '    "mdat"<timedate>=0x32303236303931393038333330305A00  "20260919083300Z\\000"',
        '    "nega"<sint32>=<NULL>',
        '    "prot"<blob>=<NULL>',
        '    "scrp"<sint32>=<NULL>',
        f'    "svce"<blob>="{service}"',
        '    "type"<uint32>=<NULL>',
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# The macOS tier
# ---------------------------------------------------------------------------

#: The one tier that runs against the real tool, and only where the real tool
#: is. Everywhere else these cases skip by name, which is honest: the parser
#: shapes above are a RECORDING of this tool, and a recording nobody re-measures
#: is a guess that has been written down.
requires_real_keychain = unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("security") is not None,
    "the real keychain tier needs macOS and the security binary",
)


def unguarded_security(*args, check: bool = True, timeout: float = 30):
    """Run `security` with `MachineGuard` stepped around. One door, named as one.

    The macOS tier has to reach the real tool, and it also has to POPULATE the
    throwaway keychain it made, so the door cannot be private to
    `temporary_keychain()`. It is a function rather than a patch so that every
    use of it is a grep away, and it refuses everywhere the tier does not run.

    Returns an `engine.exec.Completed`, the same shape `FakeRunner` returns, so
    a tier case compares the real stderr against `keychain_report()` through the
    same attribute names the mocked cases use.
    """
    if sys.platform != "darwin" or shutil.which("security") is None:
        raise RuntimeError(
            "unguarded_security() needs macOS and the security binary. Decorate the "
            "case with @requires_real_keychain so it skips instead of failing.")

    argv = ("security", *(str(a) for a in args))
    process = _UNGUARDED_POPEN(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = process.communicate(timeout=timeout)
    except BaseException:
        process.kill()
        process.communicate()
        raise
    done = _exec.Completed(
        rc=process.returncode,
        stdout=out.decode("utf-8", errors="replace"),
        stderr=err.decode("utf-8", errors="replace"),
        argv=argv,
    )
    if check and done.rc != 0:
        raise AssertionError(
            f"security {args[0] if args else ''} exited {done.rc}: {done.stderr.strip()}")
    return done


@contextlib.contextmanager
def temporary_keychain(prefix: str = "secrets-suite"):
    """Create a throwaway keychain, yield its path, delete it afterwards.

    THIS IS THE ONE PLACE THAT REACHES A REAL STORE, and it reaches its own: a
    keychain file in a temporary directory, never the login keychain. It is
    created and never added to the search list, so an unqualified lookup
    elsewhere on this account cannot find its way into it.

    The delete runs in a `finally` and the directory goes with it. A keychain
    left behind is not only clutter: it is a file with a password in it, sitting
    under a temporary directory that nothing will clean up on a Mac that does
    not reboot.

    Misuse is refused rather than diagnosed later, in `unguarded_security()`:
    without `@requires_real_keychain` on the case a Linux runner would report a
    missing binary, which reads like an environment problem rather than like a
    decorator somebody forgot.
    """
    folder = Path(tempfile.mkdtemp(prefix="secrets-keychain-"))
    path = folder / f"{prefix}.keychain-db"
    # The keychain's own password, in argv, which is exactly what this skill
    # tells everyone else not to do. It is deliberate and it is sound: the value
    # guards nothing that outlives the case, and `security create-keychain`
    # blocks on an interactive prompt without `-p`, which in a suite is a hang
    # rather than a failure.
    password = synthetic_token("kcpw")
    unguarded_security("create-keychain", "-p", password, str(path))
    try:
        yield str(path)
    finally:
        unguarded_security("delete-keychain", str(path), check=False)
        shutil.rmtree(folder, ignore_errors=True)


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

#: Deliberately missing the characters that are easy to confuse when a failure
#: is read off a terminal, since that is the only place these ever show up.
_TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"  # pragma: allowlist secret


def synthetic_token(prefix: str = "tok", length: int = 32) -> str:
    """A token shaped string, assembled here rather than pasted anywhere.

    No fixture in this tree holds a credential, not even a revoked one, and the
    way to keep that true is to have no literal to copy in the first place. The
    result is deterministic per `prefix`, so a failing assertion reproduces, and
    it is comfortably longer than `values.MIN_REDACTABLE`, so the redactor takes
    it rather than skipping it as too short to be safe.
    """
    offset = sum(ord(c) for c in prefix)
    body = "".join(_TOKEN_ALPHABET[(offset + step * 7) % len(_TOKEN_ALPHABET)]
                   for step in range(length))
    return f"{prefix}_{body}"  # pragma: allowlist secret
