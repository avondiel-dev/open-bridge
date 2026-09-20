"""The store declarations, and the placement policy they carry.

`infra/secret-stores/<slug>.yaml` says where a store is, who can read it from
where, and which KIND of secret belongs in it. This module reads those files and
answers two questions:

* resolve: given a reference, which store answers it, and what does the backend
  need to know (a keychain file, a .kdbx path, a vault url, how to unlock it).
* place: given a kind of secret, where does a NEW one go and what is it called.

The second question is the one that had no answer. An agent handed a token
decided for itself where to keep it, and the result was small text files with
credentials in working folders on two machines. A policy that lives in a file is
not smarter than the agent, it is merely the same decision every time, made once
and reviewable.

Reading YAML without a YAML library would be its own small disaster, so this
module imports `yaml` and says clearly what is missing when it is absent. The
rest of the skill works without it: `check` and `run` take their paths from the
command line, and only the store declarations need a parser.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .errors import Refused, SecretsError
from .refs import Ref

#: Where declarations live, relative to the tree root.
FAMILY = "infra/secret-stores"

#: The closed list, as in `_schema.yaml`. A kind is a policy question ("where
#: does this belong"), never a guess about the value.
KINDS = (
    "personal-token",
    "org-credential",
    "customer-credential",
    "service-runtime",
    "ci-secret",
    "household-shared",
    "break-glass",
)

#: What each kind means, one line, for `where` and for an error message.
KIND_SUMMARY = {
    "personal-token": "created under one person's identity; the provider's audit log shows that person",
    "org-credential": "the organisation holds it: a service principal, a shared API account",
    "customer-credential": "belongs to one customer's systems and stays in that customer's subtree",
    "service-runtime": "a daemon needs it at start, without a person present",
    "ci-secret": "belongs in the CI provider's own store; the Bridge holds a pointer, not a copy",
    "household-shared": "a shared everyday login; locking it into one person's vault breaks the household",
    "break-glass": "a dated copy for recovery, never the source and never what a script reads",
}

#: What is NOT a kind, and why. An IBAN or a tax id identifies a person, it does
#: not authenticate one, and moving it into a vault makes it useless for the
#: thing it is for while buying no security at all.
NOT_A_KIND = {
    "iban": "an IBAN is on every invoice the user writes. It is identifying, not authenticating.",
    "tax-id": "a tax id identifies a person and unlocks nothing.",
    "address": "an address is contact data.",
    "pii": "personal data belongs where it is used, not in a vault.",
}


class MissingParser(SecretsError):
    """PyYAML is not installed, and store declarations are YAML."""


@dataclass
class Placement:
    """One line of a store's `holds:` list, with its store."""

    store: "Store"
    kind: str
    owner: str = ""
    naming: str = ""
    note: str = ""

    def reference_shape(self) -> str:
        """The reference `where` proposes, with the naming shape left in it."""
        name = self.naming or "<name>"
        scheme = self.store.backend
        first = self.store.addresses[0] if self.store.addresses else "<store>"
        if first == "*" or first.endswith("*"):
            first = first.rstrip("*") or "<store>"
        if scheme == "keychain":
            return f"keychain://{name}/<account>"
        if scheme == "file":
            return f"file://{self.store.location.get('path', '<directory>')}/{name}"
        if scheme in ("keepass", "vault", "1password"):
            # 1Password addresses ONE FIELD of one item, the same as the other
            # two. Leaving it out of this branch printed a line without a field,
            # which parses because the grammar fills in `password`, so an item
            # whose value sits in `credential` was addressed wrongly by a line
            # this skill printed for a person to paste.
            return f"{scheme}://{first}/{name}/<field>"
        return f"{scheme}://{first}/{name}"


@dataclass
class Store:
    """One declaration."""

    name: str
    backend: str
    addresses: tuple = ()
    summary: str = ""
    location: dict = field(default_factory=dict)
    unlock: dict = field(default_factory=dict)
    reachable_from: dict = field(default_factory=dict)
    holds: tuple = ()
    recovery: dict = field(default_factory=dict)
    source: str = ""
    #: True when `addresses:` was written as a plain string rather than a list.
    addresses_malformed: bool = False

    # -- matching -----------------------------------------------------------

    def answers(self, ref: Ref) -> bool:
        """True when this store is the one a reference addresses."""
        if ref.scheme != self.backend:
            return False
        return any(_matches(pattern, ref.store) for pattern in self.addresses)

    def placements(self) -> list:
        out = []
        for raw in self.holds:
            if not isinstance(raw, dict):
                continue
            out.append(Placement(store=self, kind=str(raw.get("kind", "")),
                                 owner=str(raw.get("owner", "")),
                                 naming=str(raw.get("naming", "")),
                                 note=str(raw.get("note", ""))))
        return out

    # -- what a backend needs ----------------------------------------------

    def backend_options(self) -> dict:
        """The keywords this store contributes to its backend."""
        options: dict = {}
        if self.backend == "keychain":
            path = self.location.get("keychain_path") or None
            if path:
                options["keychain_path"] = expand(path)
        elif self.backend == "keepass":
            path = self.location.get("path")
            if path:
                options["databases"] = {address: expand(path) for address in self.addresses}
            key_file = self.unlock.get("key_file")
            if key_file:
                options["key_file"] = expand(key_file)
        return options

    def password_ref(self) -> str:
        return str(self.unlock.get("password_ref") or "")

    def reaches(self, context, environ=None) -> tuple[bool, str]:
        """Whether this store is addressable from the session described by `context`."""
        contexts = list(self.reachable_from.get("contexts") or [])
        if not contexts or "any" in contexts:
            return True, ""
        here = session_kind(context, environ)
        if here in contexts:
            return True, ""
        return False, (f"{self.name} declares itself reachable from {', '.join(contexts)}, "
                       f"and this session is {here}")


#: Environment variables every common runner sets. A pipeline is its own kind
#: of session: it has no person, no desktop and no keychain, and a store that
#: declares `ci` was unreachable from everywhere before this existed.
CI_MARKERS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "TF_BUILD", "JENKINS_URL")


def session_kind(context, environ=None) -> str:
    """Which of the declared contexts this session IS.

    Derived from the platform as well as from the two booleans. The first
    version read `not interactive` as `launchd-gui`, which is a macOS thing, so
    a daemon on a Linux box was told it was a launchd session. That message is
    the entire output of the call, so it has to be true.
    """
    import os as os_mod

    env = os_mod.environ if environ is None else environ
    if any(env.get(name) for name in CI_MARKERS):
        return "ci"
    if context.over_ssh:
        return "ssh"
    if context.interactive:
        return "interactive"
    return "launchd-gui" if context.platform == "darwin" else "service"


def _matches(pattern: str, value: str) -> bool:
    pattern = str(pattern)
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def expand(path: str) -> str:
    """`~` and `${VAR}` in a declared path, without inventing a value."""
    return os.path.expandvars(os.path.expanduser(str(path)))


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def load(root: str = ".") -> list:
    """Every declaration under `infra/secret-stores/`, `_`-files excluded."""
    folder = Path(root) / FAMILY
    if not folder.is_dir():
        return []
    try:
        import yaml  # noqa: PLC0415 - optional, and only this module needs it
    except ImportError as problem:  # pragma: no cover - depends on the machine
        raise MissingParser(
            "store declarations are YAML and PyYAML is not installed here",
            hint="pip install pyyaml, or name the store on the command line with --db and --keychain",
        ) from problem

    stores = []
    for path in sorted(folder.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            continue
        declared = raw.get("addresses")
        if isinstance(declared, str):
            # `addresses: "cf-*"` instead of a list turned into the characters
            # of that string, one of which was `*`, and the store then answered
            # every reference of its backend. Refusing beats coercing: a store
            # that answers everything is the one mistake nobody notices.
            addresses: tuple = ()
            malformed = True
        else:
            addresses = tuple(declared or ())
            malformed = False
        stores.append(Store(
            name=str(raw.get("name") or path.stem),
            backend=str(raw.get("backend") or ""),
            addresses=addresses,
            addresses_malformed=malformed,
            summary=str(raw.get("summary") or ""),
            location=dict(raw.get("location") or {}),
            unlock=dict(raw.get("unlock") or {}),
            reachable_from=dict(raw.get("reachable_from") or {}),
            holds=tuple(raw.get("holds") or ()),
            recovery=dict(raw.get("recovery") or {}),
            source=str(path),
        ))
    return stores


def for_reference(stores, ref: Ref):
    """The first store that answers this reference, or None."""
    for store in stores:
        if store.answers(ref):
            return store
    return None


def placements_for(stores, kind: str, owner: str = "") -> list:
    """Every declared place a secret of this kind may go, best match first."""
    if kind in NOT_A_KIND:
        raise Refused(
            f"{kind} is not a kind of secret",
            hint=NOT_A_KIND[kind] + " Audit reports it where it lies; it is not moved into a store.",
        )
    if kind not in KINDS:
        raise Refused(
            f"unknown kind {kind!r}",
            hint="declared kinds: " + ", ".join(KINDS),
        )
    matches = []
    for store in stores:
        for placement in store.placements():
            if placement.kind != kind:
                continue
            if owner and placement.owner and placement.owner != owner:
                continue
            matches.append(placement)
    # A line that names the owner is the specific answer and sorts first.
    matches.sort(key=lambda placement: (0 if placement.owner else 1, placement.store.name))
    return matches


def check_declarations(stores) -> list:
    """Problems a reader should know about, one line each.

    The loop this catches first: a store whose own password lives inside itself.
    It cannot be opened, and the message says that rather than recursing until
    something else gives way.
    """
    problems = []
    seen_names: dict = {}
    for store in stores:
        if store.name in seen_names:
            # Two declarations with one name shared a backend object, so the
            # second reference ran with the first one's subscription: a write
            # aimed at the wrong tenant, reported as success.
            problems.append(
                f"{store.source}: the name {store.name!r} is already used by {seen_names[store.name]}")
        seen_names[store.name] = store.source
        if store.addresses_malformed:
            problems.append(
                f"{store.source}: `addresses` is a string; it must be a list, "
                f"otherwise it is read as one pattern per character and one of them is `*`")
        if store.backend and store.backend not in {"keychain", "keepass", "azure-keyvault",
                                                   "1password", "vault", "file"}:
            problems.append(f"{store.source}: unknown backend {store.backend!r}")
        if not store.addresses:
            problems.append(f"{store.source}: answers no reference, because `addresses` is empty")
        password_ref = store.password_ref()
        if password_ref:
            from . import refs as refs_mod

            try:
                parsed = refs_mod.parse(password_ref)
            except SecretsError as problem:
                # No `continue` here. It skipped to the next STORE, so the
                # `holds:` lines of this file were never read and a second
                # problem in the same file appeared only after the first was
                # fixed: one edit and one full run too many, in the function
                # whose whole job is to list what a reader has to fix.
                problems.append(f"{store.source}: unlock.password_ref does not parse: {problem}")
                parsed = None
            if parsed is not None and parsed.scheme == store.backend and store.answers(parsed):
                problems.append(
                    f"{store.source}: its own password is stored in itself, so nothing can open it")
        for placement in store.placements():
            if placement.kind not in KINDS:
                problems.append(
                    f"{store.source}: holds an unknown kind {placement.kind!r}")
    for store in stores:
        # Over `stores`, not over a dict keyed by name: the dict collapsed two
        # declarations that shared a name, and the second one was never checked.
        if store.backend == "keepass" and not store.location.get("path"):
            problems.append(f"{store.source}: a keepass store needs location.path")
    return problems
