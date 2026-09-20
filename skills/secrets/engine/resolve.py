"""From a reference to a value, through exactly one backend.

The resolver owns three things a backend must not own: which options apply on
this machine, how a backend gets the credential it needs to open its own store,
and the promise that a value is fetched once per run rather than once per use.

The bootstrap is worth naming. A KeePass database needs a master password, and
the whole point of this skill is that the agent never sees one. So the master
password is itself a reference, usually into the OS keychain, and the resolver
resolves that first. The chain is one link deep on purpose: a database whose
password lives in another database is a loop waiting to happen, and the error
says so instead of recursing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import refs as refs_mod
from .backends import backend_for
from .backends.base import Context
from .errors import Refused, SecretMissing
from .values import Reading, Secret


@dataclass
class Options:
    """What this machine adds to a reference. Never a value, except the one
    deliberate exception: `db_password_ref` is a REFERENCE to a value."""

    #: A keychain file instead of the search list.
    keychain_path: str | None = None
    #: Logical KeePass database name -> path of the .kdbx here.
    databases: dict = field(default_factory=dict)
    #: Where the master password of those databases comes from.
    db_password_ref: str | None = None
    #: A key file, when the database uses one.
    key_file: str | None = None

    def with_database(self, spec: str) -> "Options":
        """Accept `name=/path/to.kdbx` from the command line."""
        name, sep, path = spec.partition("=")
        if not sep or not name.strip() or not path.strip():
            raise ValueError(f"expected name=/path/to.kdbx, got {spec!r}")
        self.databases[name.strip()] = path.strip()
        return self


class Resolver:
    """Reads references. One instance per command, so the cache is bounded."""

    def __init__(self, options: Options | None = None, *, runner=None,
                 context: Context | None = None):
        self.options = options or Options()
        self.runner = runner
        self.context = context or Context.detect()
        self._backends: dict = {}
        self._readings: dict = {}
        self._resolving: set = set()

    # -- backends -----------------------------------------------------------

    def backend(self, scheme: str):
        if scheme not in self._backends:
            self._backends[scheme] = self._build(scheme)
        return self._backends[scheme]

    def _build(self, scheme: str):
        kwargs = {"runner": self.runner, "context": self.context}
        if scheme == "keychain":
            kwargs["keychain_path"] = self.options.keychain_path
        if scheme == "keepass":
            kwargs["databases"] = self.options.databases
            kwargs["key_file"] = self.options.key_file
            kwargs["password"] = self._database_password()
        return backend_for(scheme, **kwargs)

    def _database_password(self) -> Secret | None:
        ref_text = self.options.db_password_ref
        if not ref_text:
            return None
        ref = refs_mod.parse(ref_text)
        if ref.scheme == "keepass":
            raise Refused(
                "the master password of a KeePass database may not live in a KeePass database",
                ref=ref.canonical,
                hint="put it in the OS keychain, which needs no second secret to open",
            )
        reading = self.read(ref)
        if not reading.present or reading.secret is None:
            raise SecretMissing(
                "the master password reference resolves to nothing",
                ref=ref.canonical,
                hint=reading.note or "no entry, or an entry with no bytes in it",
            )
        return reading.secret

    # -- reading ------------------------------------------------------------

    def read(self, ref) -> Reading:
        """Resolve one reference. Cached per resolver, so a value is fetched once."""
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        key = parsed.canonical
        if key in self._readings:
            return self._readings[key]
        if key in self._resolving:
            raise Refused(
                "this reference is needed to resolve itself",
                ref=key,
                hint="a store whose credential lives in that same store cannot be opened",
            )
        self._resolving.add(key)
        try:
            reading = self.backend(parsed.scheme).read(parsed)
        finally:
            self._resolving.discard(key)
        self._readings[key] = reading
        return reading

    def require(self, ref) -> Secret:
        """The value, or a `SecretMissing` that names what was missing."""
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        reading = self.read(parsed)
        if not reading.present or reading.secret is None:
            raise SecretMissing(
                "no value behind this reference",
                ref=parsed.canonical,
                hint=reading.note or "no entry, or an entry with no bytes in it",
            )
        return reading.secret

    # -- description --------------------------------------------------------

    def readable_here(self, ref) -> tuple[bool, str]:
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        backend = self.backend(parsed.scheme)
        if not backend.available():
            return False, f"{backend.binary} is not installed here"
        return backend.readable_here(parsed)

    def locate(self, ref) -> str:
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        return self.backend(parsed.scheme).locate(parsed)
