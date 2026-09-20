"""`azure-keyvault://<vault>/<secret>` through the Azure CLI.

Three things this backend does that a hand-written `az` call in a script
usually does not, each of them a scar from this fleet:

* `--subscription` is always passed when the store declares one. The default
  subscription of a machine is not always the tenant of the vault, and `az`
  answers for the wrong one without a word, which reads as "the secret is gone".
* A write carries the metadata IN THE SAME CALL. `az keyvault secret set
  --value` alone creates a new version with `contentType: null` and no tags, so
  the portal shows a secret nobody can place any more. The fix afterwards is a
  second call that people forget; doing it in one is free.
* The value goes in through `--file`, never `--value`. A value on the command
  line stands in the process list, and this was the most common way a token
  left a shell in this fleet. The file is created at 0600 in a private
  directory and removed in a `finally`.
"""

from __future__ import annotations

import os
import tempfile

from ..errors import Refused, SecretsError
from ..refs import Ref
from ..values import Reading, Secret
from .base import Backend


class AzureKeyVaultBackend(Backend):
    scheme = "azure-keyvault"
    binary = "az"

    def __init__(self, *, subscription: str | None = None, vault_url: str | None = None,
                 content_type: str = "text/plain", tags: dict | None = None, **kwargs):
        super().__init__(**kwargs)
        self.subscription = subscription
        self.vault_url = vault_url
        self.content_type = content_type
        self.tags = dict(tags or {})

    def install_hint(self) -> str:
        return "install the Azure CLI (az) and sign in with `az login`"

    # -- addressing ---------------------------------------------------------

    def secret_name(self, ref: Ref) -> str:
        if not ref.path:
            raise Refused("the reference names a vault but no secret",
                          ref=ref.canonical, hint="azure-keyvault://<vault>/<secret>")
        return ref.path[0]

    def _common(self, ref: Ref) -> list:
        argv = ["--vault-name", ref.store, "--name", self.secret_name(ref)]
        if self.subscription:
            argv += ["--subscription", self.subscription]
        return argv

    def readable_here(self, ref: Ref) -> tuple[bool, str]:
        # `az` keeps its own session. Asking it here would cost a process per
        # reference, so the honest answer is "the CLI decides", and a signed-out
        # CLI surfaces as its own error with its own message.
        return True, ""

    # -- read ---------------------------------------------------------------

    def argv_read(self, ref: Ref) -> list:
        return ["az", "keyvault", "secret", "show", *self._common(ref),
                "--query", "value", "-o", "tsv"]

    def read(self, ref: Ref) -> Reading:
        self.require_available(ref)
        from .. import exec as exec_mod

        done = exec_mod.run(self.argv_read(ref), runner=self.runner, timeout_sec=60)
        if done.rc != 0:
            lowered = (done.stderr or "").lower()
            if "secretnotfound" in lowered or "was not found" in lowered:
                return Reading(ref=ref.canonical, present=False, store=ref.store,
                               note="no secret of that name in this vault")
            if "forbidden" in lowered or "does not have secrets get permission" in lowered:
                from ..errors import NotReadableHere

                raise NotReadableHere(
                    "the signed-in identity may not read this vault",
                    ref=ref.canonical,
                    hint="the secret may be there. Check the access policy or the RBAC role, "
                         "and which subscription the CLI is pointed at.")
            raise SecretsError(f"az exited {done.rc}", ref=ref.canonical,
                               hint=_first_line(done.stderr) or "no message on stderr")

        raw = _strip_one_newline(done.stdout)
        secret = Secret(raw, origin=ref.canonical)
        if secret.is_empty():
            return Reading(ref=ref.canonical, present=False, secret=secret, store=ref.store,
                           note="the secret exists and its value is empty")
        return Reading(ref=ref.canonical, present=True, secret=secret, store=ref.store)

    # -- write --------------------------------------------------------------

    def argv_write(self, ref: Ref, path: str, tags: dict) -> list:
        argv = ["az", "keyvault", "secret", "set", *self._common(ref), "--file", path]
        if self.content_type:
            argv += ["--content-type", self.content_type]
        if tags:
            argv.append("--tags")
            argv += [f"{key}={value}" for key, value in sorted(tags.items())]
        argv += ["-o", "none"]
        return argv

    def write(self, ref: Ref, secret: Secret, *, replace: bool = False, tags=None) -> Reading:
        self.require_available(ref)
        from .. import exec as exec_mod

        merged = dict(self.tags)
        merged.update(tags or {})
        folder = tempfile.mkdtemp(prefix="bridge-secret-")
        path = os.path.join(folder, "value")
        try:
            def opener(name, flags):
                return os.open(name, flags | os.O_CREAT | os.O_TRUNC, 0o600)

            with open(path, "wb", opener=opener) as handle:
                handle.write(secret.expose())
            done = exec_mod.run(self.argv_write(ref, path, merged), runner=self.runner,
                                timeout_sec=120)
        finally:
            try:
                os.remove(path)
            except OSError:  # pragma: no cover - the file was never created
                pass
            try:
                os.rmdir(folder)
            except OSError:  # pragma: no cover - something else is in there
                pass

        if done.rc != 0:
            raise SecretsError(f"az exited {done.rc}", ref=ref.canonical,
                               hint=_first_line(done.stderr) or "no message on stderr")
        return self.read(ref)

    def locate(self, ref: Ref) -> str:
        where = self.vault_url or f"vault {ref.store}"
        subscription = f", subscription {self.subscription}" if self.subscription else ""
        return f"{where}: {self.secret_name(ref)}{subscription}"


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
