"""`1password://<vault>/<item>/<field>`, and `op://…`, through the 1Password CLI.

Reading is what this backend does. `op read` takes the reference the CLI itself
understands and prints the value, which the wrapper consumes; the agent never
sees it.

Writing is REFUSED, and the reason is the rule rather than an oversight:
`op item create` and `op item edit` take the value as a command line argument
(`field=value`), so storing a secret through them would put it in the process
list of every process of the same user. The template form reads a file, and a
file with the value in it is the thing this skill exists to stop creating. So
the skill says what to do instead rather than doing it badly.
"""

from __future__ import annotations

from ..errors import BackendUnavailable, NotReadableHere, Refused, SecretsError
from ..refs import Ref
from ..values import Reading, Secret
from .base import Backend


class OnePasswordBackend(Backend):
    scheme = "1password"
    binary = "op"

    def __init__(self, *, account: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.account = account

    def install_hint(self) -> str:
        return "install the 1Password CLI (op) and sign in, or enable the desktop app integration"

    # -- addressing ---------------------------------------------------------

    def op_reference(self, ref: Ref) -> str:
        """The same address in the CLI's own spelling."""
        if not ref.path:
            raise Refused("the reference names a vault but no item",
                          ref=ref.canonical, hint="1password://<vault>/<item>/<field>")
        field = ref.field or "password"
        return "op://" + "/".join([ref.store, *ref.path, field])

    def argv_read(self, ref: Ref) -> list:
        argv = ["op", "read", self.op_reference(ref), "--no-newline"]
        if self.account:
            argv += ["--account", self.account]
        return argv

    def read(self, ref: Ref) -> Reading:
        self.require_available(ref)
        from .. import exec as exec_mod

        done = exec_mod.run(self.argv_read(ref), runner=self.runner, timeout_sec=60)
        if done.rc != 0:
            lowered = (done.stderr or "").lower()
            if "isn't an item" in lowered or "not found" in lowered or "no item matches" in lowered:
                return Reading(ref=ref.canonical, present=False, store=ref.store,
                               note="no such item or field in this vault")
            # "signed in", not "not signed in": the CLI writes "you are not
            # currently signed in", and the word in between made the narrower
            # match miss it, so a signed-out CLI was reported as a fault of the
            # item rather than of the session.
            if ("signed in" in lowered or "session expired" in lowered
                    or "authorization" in lowered or "no account found" in lowered):
                raise NotReadableHere(
                    "the 1Password CLI has no session here",
                    ref=ref.canonical,
                    hint="`op signin`, or turn on the desktop app integration. The item is "
                         "probably fine; this session simply cannot ask.")
            raise SecretsError(f"op exited {done.rc}", ref=ref.canonical,
                               hint=_first_line(done.stderr) or "no message on stderr")

        secret = Secret(done.stdout, origin=ref.canonical)
        if secret.is_empty():
            return Reading(ref=ref.canonical, present=False, secret=secret, store=ref.store,
                           note="the field exists and is empty")
        return Reading(ref=ref.canonical, present=True, secret=secret, store=ref.store)

    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:
        raise Refused(
            "this Bridge does not write to 1Password",
            ref=ref.canonical,
            hint=("`op item create` and `op item edit` take the value as a command line "
                  "argument, which puts it in the process list. Create the item in the app or "
                  "with `op` yourself, then point the reference at it and run `secrets check`."),
        )

    def locate(self, ref: Ref) -> str:
        account = f" ({self.account})" if self.account else ""
        return f"1Password vault {ref.store}{account}: {'/'.join(ref.path)} / {ref.field or 'password'}"


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""
