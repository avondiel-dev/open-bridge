"""Backend registry: scheme name to the class that answers it."""

from __future__ import annotations

from .. import refs as refs_mod
from ..errors import BackendUnavailable, ReferenceError_
from .base import Backend, Context
from .keychain import KeychainBackend
from .keepass import KeePassBackend

#: Only the schemes this Bridge can actually reach are listed. A scheme that the
#: grammar knows and no backend answers is a clear error at resolve time, not a
#: silent miss: `refs.SCHEMES` documents what may be written down, this registry
#: says what can be read today.
REGISTRY = {
    KeychainBackend.scheme: KeychainBackend,
    KeePassBackend.scheme: KeePassBackend,
}

IMPLEMENTED = tuple(sorted(REGISTRY))


def backend_for(scheme: str, **kwargs) -> Backend:
    """The backend for `scheme`, constructed with the given seams."""
    try:
        cls = REGISTRY[scheme]
    except KeyError:
        known = ", ".join(f"{name}://" for name in IMPLEMENTED)
        if scheme in refs_mod.BY_NAME:
            # The declaration is right and the capability is missing. Reporting
            # it as a bad reference would send a reader to fix a file that
            # rules/secret-placement.md told them to write exactly like that.
            raise BackendUnavailable(
                f"{scheme}:// is a declared scheme that this Bridge cannot read yet",
                hint="resolved today: " + known,
            ) from None
        raise ReferenceError_(
            f"no backend for {scheme}://",
            hint="this Bridge resolves: " + known,
        ) from None
    return cls(**kwargs)


__all__ = ["Backend", "Context", "KeychainBackend", "KeePassBackend",
           "REGISTRY", "IMPLEMENTED", "backend_for"]
