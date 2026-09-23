"""Failures of the resolver, each with an exit code and a named outcome.

The ADR (docs/object-store.md, decision 5) asks for a read that cannot be served
to name its reason, and names three: not reachable from here, not there, and a
store this instance does not declare. A caller has to be able to tell them
apart, because the first is a machine problem, the second is content that went
missing, and the third is a reference written for another instance. None of
them may arrive as an empty result, which is what "not there" and "not
reachable" both used to look like to a script that only checked for output.

The outcome word is printed with every failure, so a log can be grepped for it
without knowing the exit codes.
"""

from __future__ import annotations

# sysexits.h names where one fits, the secrets skill's codes where one exists.
EX_OK = 0
EX_NOT_FOUND = 3      # the store answered: there is no such object
EX_UNDECLARED = 4     # the reference is well formed; no declaration here answers its store
EX_REFUSED = 5        # the operation would be unsafe, or the store refused it
EX_USAGE = 64         # EX_USAGE: the command line is wrong
EX_SOFTWARE = 70      # EX_SOFTWARE: something the resolver did not expect
EX_UNAVAILABLE = 69   # EX_UNAVAILABLE: the store is not reachable from here
EX_CONFIG = 78        # EX_CONFIG: the reference or a declaration is wrong


class ObjectStoreError(Exception):
    """Base class. Carries an exit code and an outcome word, never content."""

    exit_code = EX_CONFIG
    outcome = "error"

    def __init__(self, message: str, *, ref: str | None = None, hint: str | None = None):
        self.ref = ref
        self.hint = hint
        super().__init__(message)

    def report(self) -> str:
        head = f"{self.outcome}: {self}"
        if self.ref:
            head = f"{self.ref}: {head}"
        return head + (f"\n  {self.hint}" if self.hint else "")


class MalformedReference(ObjectStoreError):
    exit_code = EX_CONFIG
    outcome = "malformed-reference"


class UndeclaredStore(ObjectStoreError):
    exit_code = EX_UNDECLARED
    outcome = "store-not-declared"


class NotReachable(ObjectStoreError):
    exit_code = EX_UNAVAILABLE
    outcome = "not-reachable"


class NotFound(ObjectStoreError):
    exit_code = EX_NOT_FOUND
    outcome = "not-found"


class Denied(ObjectStoreError):
    """The store is there and said no. Not the same as "not there"."""

    exit_code = EX_REFUSED
    outcome = "denied"


class Refused(ObjectStoreError):
    """The resolver itself will not do this: a key outside the root, a hash
    that does not match, an object too large for the path it was asked for."""

    exit_code = EX_REFUSED
    outcome = "refused"


class DeclarationError(ObjectStoreError):
    exit_code = EX_CONFIG
    outcome = "bad-declaration"


class CredentialsUnavailable(ObjectStoreError):
    exit_code = EX_CONFIG
    outcome = "credentials-unavailable"


class UsageError(ObjectStoreError):
    exit_code = EX_USAGE
    outcome = "usage"


class Unexpected(ObjectStoreError):
    """Anything the resolver did not anticipate. Only the exception's TYPE is
    reported: its message is not ours, and one such message (a ValueError from
    http.client) carried a whole signed Authorization header."""

    exit_code = EX_SOFTWARE
    outcome = "unexpected"
