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
from . import stores as stores_mod
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
    #: The tree whose `infra/secret-stores/` declarations apply. A declaration
    #: says the same things these flags say, and says them once per machine
    #: instead of once per invocation.
    root: str = "."

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
                 context: Context | None = None, stores=None):
        self.options = options or Options()
        self.runner = runner
        self.context = context or Context.detect()
        #: Declarations, already loaded. None means "load them on first need",
        #: and a list means "these and no others", which is what a test hands in.
        self._stores = stores
        self._backends: dict = {}
        self._readings: dict = {}
        self._resolving: set = set()

    # -- declarations -------------------------------------------------------

    @property
    def stores(self) -> list:
        if self._stores is None:
            try:
                self._stores = stores_mod.load(self.options.root)
            except stores_mod.MissingParser:
                # A machine without PyYAML can still resolve everything the
                # command line names. Saying so here beats failing a `check`
                # that would otherwise have worked.
                self._stores = []
        return self._stores

    def store_for(self, ref) -> object | None:
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        return stores_mod.for_reference(self.stores, parsed)

    # -- backends -----------------------------------------------------------

    def backend(self, scheme: str, store=None):
        # Keyed on the declaration FILE, not on `name:`. Nothing makes `name:`
        # unique, and two stores that shared one gave the second reference the
        # first one's backend object: a Key Vault write aimed at the wrong
        # subscription, reported as success.
        key = (scheme, store.source if store is not None else "")
        if key not in self._backends:
            self._backends[key] = self._build(scheme, store)
        return self._backends[key]

    def backend_for_ref(self, ref):
        """The backend a reference goes through, with its store's options."""
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        return self.backend(parsed.scheme, self.store_for(parsed))

    def _build(self, scheme: str, store=None):
        kwargs = {"runner": self.runner, "context": self.context}
        # The command line wins over a declaration, because it is what somebody
        # typed just now, usually to work around the very thing a declaration
        # got wrong.
        declared = store.backend_options() if store is not None else {}
        if scheme == "keychain":
            kwargs["keychain_path"] = self.options.keychain_path or declared.get("keychain_path")
        if scheme == "keepass":
            databases = dict(declared.get("databases") or {})
            databases.update(self.options.databases)
            kwargs["databases"] = databases
            kwargs["key_file"] = self.options.key_file or declared.get("key_file")
            kwargs["password"] = self._database_password(store)
        if scheme == "azure-keyvault" and store is not None:
            kwargs["subscription"] = store.location.get("subscription")
            kwargs["vault_url"] = store.location.get("vault_url")
        if scheme == "1password" and store is not None:
            kwargs["account"] = store.location.get("account")
        if scheme == "file":
            kwargs["allowed_roots"] = [
                s.location.get("path") for s in self.stores
                if s.backend == "file" and s.location.get("path")
            ]
        return backend_for(scheme, **kwargs)

    def _database_password(self, store=None) -> Secret | None:
        ref_text = self.options.db_password_ref or (store.password_ref() if store is not None else "")
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
            reading = self.backend_for_ref(parsed).read(parsed)
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
        store = self.store_for(parsed)
        if store is not None:
            reaches, why = store.reaches(self.context)
            if not reaches:
                return False, why
        backend = self.backend(parsed.scheme, store)
        if not backend.available():
            return False, f"{backend.binary} is not installed here"
        return backend.readable_here(parsed)

    def locate(self, ref) -> str:
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        return self.backend_for_ref(parsed).locate(parsed)

    # -- writing ------------------------------------------------------------

    def store(self, ref, secret: Secret, *, replace: bool = False, tags=None) -> Reading:
        """Write a value, then read it back and compare. An exit code is not a proof.

        The read-back is not ceremony. An entry that exists and holds nothing
        exits 0 from every tool involved, and a value that lost two characters
        to a quoting rule is indistinguishable from a correct one until it is
        used. So the write is followed by a read, and the fingerprints have to
        match before anything reports success.
        """
        parsed = ref if isinstance(ref, refs_mod.Ref) else refs_mod.parse(str(ref))
        backend = self.backend_for_ref(parsed)
        # Metadata is backend business: Key Vault takes it and loses it when it
        # is set in a second call, the others have nowhere to put it. Passing it
        # only where it is accepted keeps the signature of `write` honest.
        extra = {"tags": tags} if tags and hasattr(backend, "argv_write") and \
            backend.scheme == "azure-keyvault" else {}
        reading = backend.write(parsed, secret, replace=replace, **extra)
        self._readings.pop(parsed.canonical, None)
        if not reading.present or reading.secret is None:
            raise SecretMissing(
                "the write reported success and the entry reads back empty",
                ref=parsed.canonical,
                hint=reading.note or "nothing came back from the store",
            )
        if reading.secret != secret:
            raise Refused(
                "the value read back is not the value written",
                ref=parsed.canonical,
                hint=(f"wrote {secret.describe()}, read {reading.secret.describe()}. "
                      f"Nothing was rolled back; look at the entry before writing again."),
            )
        self._readings[parsed.canonical] = reading
        return reading
