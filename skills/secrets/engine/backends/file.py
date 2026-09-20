"""`file://<absolute-path>`: a value in a file, at mode 0600, inside a store.

This is the fallback for a machine with no keychain and no agent, a systemd
service on a Linux box being the usual case, and it is the one backend where a
careless reader finds the value by following the locator. So it is the strictest
about the things that can go wrong with a file:

* The mode is set AT CREATION, with an opener, never with a `chmod` afterwards.
  A `chmod` that follows the write leaves a window in which the file stands
  there with the default umask and the secret already in it.
* A file that is group or world readable is refused on READ as well, not only
  reported, because the value in it must be treated as disclosed.
* The path must be inside a declared store. Without that rule this backend is
  just "write the token wherever", which is the habit the whole skill exists to
  end: tokens in small text files across working folders and temp directories.
"""

from __future__ import annotations

import os
import stat

from ..errors import Refused, SecretsError
from ..refs import Ref
from ..values import Reading, Secret
from .base import Backend

#: The only modes a secret file may carry: owner read, or owner read and write.
ALLOWED_MODES = (0o600, 0o400)


class FileBackend(Backend):
    scheme = "file"
    binary = None

    def __init__(self, *, allowed_roots=None, **kwargs):
        super().__init__(**kwargs)
        #: Directories a store declares. Empty means nothing is allowed to be
        #: written, and a read warns that the file sits outside any declaration.
        self.allowed_roots = [os.path.realpath(os.path.expanduser(str(root)))
                              for root in (allowed_roots or [])]

    # -- placement ----------------------------------------------------------

    def path_of(self, ref: Ref) -> str:
        # realpath, not abspath: a symlink inside a declared store pointing out
        # of it passed a lexical check, took the value, and left it in a file
        # the store model never sanctioned. Measured in review.
        return os.path.realpath(os.path.expanduser(ref.store))

    def inside_a_store(self, ref: Ref) -> bool:
        path = self.path_of(ref)
        return any(path == root or path.startswith(root.rstrip("/") + "/")
                   for root in self.allowed_roots)

    def readable_here(self, ref: Ref) -> tuple[bool, str]:
        path = self.path_of(ref)
        if not os.path.exists(path):
            return False, f"no file at {path}"
        return True, ""

    # -- read ---------------------------------------------------------------

    def read(self, ref: Ref) -> Reading:
        path = self.path_of(ref)
        if not os.path.exists(path):
            return Reading(ref=ref.canonical, present=False, store=_folder(path),
                           note="no file at this path")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode not in ALLOWED_MODES:
            raise Refused(
                f"this file is mode {oct(mode)}, so its content is not a secret any more",
                ref=ref.canonical,
                hint=("anything another account can read has to be treated as disclosed. "
                      "Rotate it, then store the new value at 0600."),
            )
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as problem:
            raise SecretsError("the file is there and cannot be read",
                               ref=ref.canonical, hint=str(problem)) from None
        # A file written by a person usually ends with a newline that was never
        # part of the value, and a token with a trailing newline fails at the
        # far end in a way that looks like a wrong token.
        raw = _strip_one_newline(raw)
        secret = Secret(raw, origin=ref.canonical)
        note = "" if self.inside_a_store(ref) else "this file is outside every declared store"
        if secret.is_empty():
            return Reading(ref=ref.canonical, present=False, secret=secret,
                           store=_folder(path), note=(note + "; " if note else "") + "the file is empty")
        return Reading(ref=ref.canonical, present=True, secret=secret,
                       store=_folder(path), note=note)

    # -- write --------------------------------------------------------------

    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:
        path = self.path_of(ref)
        if not self.inside_a_store(ref):
            # No `self.allowed_roots and` here. An empty list means NOTHING is
            # declared, and the first version read that as "everything is
            # allowed": on a fresh instance, which declares nothing, the write
            # went through and left exactly the loose token file this backend
            # exists to stop. An empty policy refuses.
            raise Refused(
                "this path is not inside any declared store",
                ref=ref.canonical,
                hint=("declare the directory in infra/secret-stores/ first "
                      + ("(nothing is declared here yet). " if not self.allowed_roots else "")
                      + "A value written somewhere nobody declared is the loose token file "
                        "this skill exists to stop being created."),
            )
        if os.path.exists(path) and not replace:
            raise Refused("a file is already there", ref=ref.canonical,
                          hint="pass --replace to overwrite it")
        folder = os.path.dirname(path)
        if folder and not os.path.isdir(folder):
            # NOT `os.makedirs(folder, mode=0o700)`: that mode reaches the LAST
            # component only, and every directory created on the way there gets
            # the default 0777 masked by the umask, which is 0755 on an ordinary
            # machine. A secret at 0600 inside a directory another account can
            # list is a smaller leak than the value and a leak all the same.
            _make_private_dirs(folder)
        # The mode belongs to the open, not to a chmod afterwards.
        def opener(name, flags):
            # O_NOFOLLOW: the last component may not be a symlink, so a link
            # planted in the store cannot redirect the value out of it. The
            # mode belongs to the open and not to a later chmod.
            return os.open(name, flags | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)

        with open(path, "wb", opener=opener) as handle:
            handle.write(secret.expose())
        os.chmod(path, 0o600)   # for the replace case, where the file existed already
        return self.read(ref)

    def locate(self, ref: Ref) -> str:
        return self.path_of(ref)


def _make_private_dirs(folder: str) -> None:
    """Create every missing component at 0700, one at a time."""
    missing = []
    current = folder
    while current and not os.path.isdir(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for path in reversed(missing):
        # No chmod afterwards: a umask can only CLEAR permission bits, never
        # add them, so 0o700 through mkdir is already the narrowest outcome.
        # The chmod that stood here made the mode look guarded twice and hid
        # the mkdir mode from the mutation battery, which is how a guard stops
        # being measured.
        os.mkdir(path, 0o700)


def _folder(path: str) -> str:
    return os.path.dirname(path) or "/"


def _strip_one_newline(raw: bytes) -> bytes:
    """Exactly one trailing newline, never more.

    `rstrip(b"\r\n")` eats every trailing newline, which quietly truncates a
    PEM key: its `-----END …-----` line ends with one, and a file that held two
    comes back different from the file that was written. The read-back check
    cannot catch that, because it compares against the value the same stripping
    already changed.
    """
    if raw.endswith(b"\r\n"):
        return raw[:-2]
    if raw.endswith(b"\n") or raw.endswith(b"\r"):
        return raw[:-1]
    return raw
