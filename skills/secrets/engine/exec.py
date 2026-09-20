"""The one place this skill starts a process, and the seam the tests drive.

Every backend takes a `runner` keyword and calls it instead of touching
`subprocess` itself. That is what lets the suite assert on the argv of a real
Keychain call on a machine that has no Keychain, and it is why the guard in
`tests/conftest.py` can refuse `security`, `keepassxc-cli`, `az` and `op`
outright: a backend that reached around the seam would fail loudly rather than
quietly talk to the developer's own vault.

Two rules hold here and nowhere else:

1. A VALUE NEVER TRAVELS IN ARGV. `run` takes `stdin_bytes` for exactly that
   reason. Everything in argv is visible in `ps` to every process of the same
   user, which is how tokens ended up in the process list of two machines in
   this fleet before anyone looked.
2. `Completed` carries what the process said, and this module does not decide
   whether that is safe to print. Redaction belongs to the caller that knows
   which values were in play (`values.Redactor`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field

DEFAULT_TIMEOUT_SEC = 30

#: A day. `secrets run -- cmd` wraps the caller's own command, and that command
#: may legitimately run for hours, so it gets a deadline that exists only to
#: stop a hung child from living past the session that started it.
NO_DEADLINE = 86400

#: Output larger than this is cut. A child that dumps a megabyte of log into a
#: redactor costs time and buys nothing; the cut is reported, never silent.
MAX_CAPTURE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Completed:
    """The result of one process. The attribute names are the test contract."""

    rc: int = 0
    #: Not in the repr. For several backends the value IS `stdout`, and for the
    #: keychain it is `stderr`. A dataclass repr reaches a log line, a debugger
    #: frame dump and a test-runner assertion introspection, which is the same
    #: reason `Invocation.stdin_bytes` is hidden.
    stdout: str = field(default="", repr=False)
    stderr: str = field(default="", repr=False)
    argv: tuple = ()
    duration_sec: float = 0.0
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


@dataclass
class Invocation:
    """What a runner is asked to do. Kept as data so a test can inspect it.

    `stdin_bytes` is deliberately NOT part of the repr: it is the one field that
    can hold a secret, and a dataclass repr is exactly the kind of thing that
    ends up in a log line.
    """

    argv: tuple
    stdin_bytes: bytes | None = field(default=None, repr=False)
    env: dict | None = None
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    cwd: str | None = None


def which(binary: str) -> str | None:
    """`shutil.which`, wrapped so tests can see one name for the probe."""
    return shutil.which(binary)


def run(argv, *, stdin_bytes: bytes | None = None, env: dict | None = None,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC, cwd: str | None = None,
        runner=None) -> Completed:
    """Run `argv`, capture both streams, return `Completed`.

    `runner`, when given, replaces the real execution. It receives the argv
    tuple and the `Invocation`, and returns a `Completed`. That is the seam.
    """
    argv = tuple(str(a) for a in argv)
    invocation = Invocation(argv=argv, stdin_bytes=stdin_bytes, env=env,
                            timeout_sec=timeout_sec, cwd=cwd)
    if runner is not None:
        return runner(argv, invocation=invocation)

    started = time.monotonic()
    try:
        done = subprocess.run(
            argv,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout_sec,
            cwd=cwd,
            env=_merged_env(env),
        )
    except FileNotFoundError:
        return Completed(rc=127, stderr=f"{argv[0]}: not found", argv=argv,
                         duration_sec=time.monotonic() - started)
    except subprocess.TimeoutExpired:
        return Completed(rc=124, stderr=f"{argv[0]}: timed out after {timeout_sec}s",
                         argv=argv, duration_sec=time.monotonic() - started,
                         timed_out=True)

    out, out_cut = _text(done.stdout)
    err, err_cut = _text(done.stderr)
    return Completed(rc=done.returncode, stdout=out, stderr=err, argv=argv,
                     duration_sec=time.monotonic() - started,
                     truncated=out_cut or err_cut)


def spawn(argv, *, env: dict | None = None, stdin_bytes: bytes | None = None,
          timeout_sec: float | None = None, cwd: str | None = None,
          runner=None) -> Completed:
    """Run a child of the CALLER, not of a backend: `secrets run -- cmd`.

    Separate from `run` because the intent differs and the defaults follow it:
    no timeout by default (the caller's command may legitimately take an hour),
    and the environment is the one the caller assembled, additions included.
    """
    return run(argv, stdin_bytes=stdin_bytes, env=env, cwd=cwd,
               timeout_sec=NO_DEADLINE if timeout_sec is None else timeout_sec,
               runner=runner)


def _merged_env(extra: dict | None) -> dict | None:
    if extra is None:
        return None
    merged = dict(os.environ)
    merged.update({str(k): str(v) for k, v in extra.items()})
    return merged


def _text(raw: bytes | None) -> tuple[str, bool]:
    if not raw:
        return "", False
    cut = len(raw) > MAX_CAPTURE_BYTES
    if cut:
        raw = raw[:MAX_CAPTURE_BYTES]
    return raw.decode("utf-8", errors="replace"), cut
