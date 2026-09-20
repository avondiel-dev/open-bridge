"""Failures of the secrets broker, and the exit code each one leaves behind.

The codes are the contract. A wrapper script that resolves a reference at start
has to be able to tell "the vault is not reachable from here" from "the entry is
gone", because the first is a machine problem and the second is a rotation that
nobody finished. Both were one silent empty string before this skill existed.

Nothing in this module may carry a secret value. The message of an error is
printed, logged and sometimes mailed; the value never is. Every constructor
therefore takes a reference, a reason and at most a length, and there is no
parameter that could hold the value itself.
"""

from __future__ import annotations

# sysexits.h names, because a caller reading `rc == 69` in a log finds the
# meaning in a manual page rather than in this file.
EX_OK = 0
EX_MISSING = 3        # the entry is not there, or its value is empty
EX_REFUSED = 5        # the operation would be unsafe, so it was not done
EX_USAGE = 64         # EX_USAGE: the command line is wrong
EX_UNAVAILABLE = 69   # EX_UNAVAILABLE: the backend tool is absent or unusable
EX_CONFIG = 78        # EX_CONFIG: the reference or the declaration is wrong


class SecretsError(Exception):
    """Base class. Carries an exit code and never a value."""

    exit_code = EX_CONFIG

    def __init__(self, message: str, *, ref: str | None = None, hint: str | None = None):
        self.ref = ref
        self.hint = hint
        super().__init__(message)

    def report(self) -> str:
        """One or two lines for a human, with the reference but not the value."""
        lines = [str(self)]
        if self.ref:
            lines[0] = f"{self.ref}: {lines[0]}"
        if self.hint:
            lines.append(f"  {self.hint}")
        return "\n".join(lines)


class ReferenceError_(SecretsError):
    """The URI does not parse, or names a scheme nobody implements.

    Named with a trailing underscore because `ReferenceError` is a builtin and
    shadowing it inside a package that other code imports from is the kind of
    joke that costs an afternoon.
    """

    exit_code = EX_CONFIG


class UsageError(SecretsError):
    exit_code = EX_USAGE


class BackendUnavailable(SecretsError):
    """The tool that owns this backend is not installed, or cannot run here."""

    exit_code = EX_UNAVAILABLE


class NotReadableHere(BackendUnavailable):
    """The store exists, but not for this process.

    The login keychain over ssh is the case this class exists for: the entry is
    present, the password is right, and the read still fails because the session
    has no unlocked keychain. A daemon that treats this as "missing" rotates a
    secret that was never gone.
    """

    exit_code = EX_UNAVAILABLE


class SecretMissing(SecretsError):
    """No entry, or an entry whose value is empty.

    An empty value is a miss, not a hit. `security find-generic-password` exits
    0 for an entry with zero bytes in it, and every caller that tested existence
    instead of length carried that emptiness one layer further before failing.
    """

    exit_code = EX_MISSING


class Refused(SecretsError):
    """The operation was understood and not done, because doing it is unsafe."""

    exit_code = EX_REFUSED
