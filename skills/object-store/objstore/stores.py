"""Declarations under infra/object-stores/, and which one answers a reference.

Validation of a declaration's full shape is the schema's job
(scripts/validate-bridge.py runs it). This module refuses only what would make
it resolve the wrong thing: a declaration it cannot read, a backend it does not
implement, a store without a name or without addresses. Everything else is read
as declared, because a second, partial copy of the schema here would drift from
the first.

PyYAML is imported on first use and only here, the way the secrets skill does
it: the rest of the resolver runs on the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .errors import DeclarationError
from .refs import BACKENDS, ObjectRef

FOLDER = ("infra", "object-stores")


@dataclass(frozen=True)
class Store:
    name: str
    backend: str
    addresses: tuple
    source: str
    location: dict = field(default_factory=dict)
    credentials: dict = field(default_factory=dict)
    reachable_from: dict = field(default_factory=dict)
    holds: tuple = ()
    replicated: bool | None = None
    recovery: dict = field(default_factory=dict)

    @property
    def classes(self) -> tuple:
        return tuple(str(item.get("class", "?")) for item in self.holds if isinstance(item, dict))


def load(root) -> list:
    folder = Path(root).joinpath(*FOLDER)
    if not folder.is_dir():
        return []
    paths = [p for p in sorted(folder.glob("*.yaml")) if not p.name.startswith("_")]
    if not paths:
        return []
    try:
        import yaml  # noqa: PLC0415 - optional, and only this module needs it
    except ImportError as exc:
        raise DeclarationError(
            "store declarations are YAML and PyYAML is not installed",
            hint="pip install pyyaml") from exc

    stores = []
    for path in paths:
        where = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise DeclarationError(f"cannot be read as YAML: {exc}", ref=where) from exc
        if not isinstance(data, dict):
            raise DeclarationError("is not a mapping", ref=where)
        name, backend = data.get("name"), data.get("backend")
        addresses = data.get("addresses") or []
        if not name:
            raise DeclarationError("has no name", ref=where)
        if backend not in BACKENDS:
            raise DeclarationError(
                f"backend {backend!r} is not one this resolver implements ({', '.join(BACKENDS)})",
                ref=where, hint="a backend nothing implements is written down and resolved by nothing")
        if not isinstance(addresses, list) or not addresses:
            raise DeclarationError("has no addresses, so no reference can reach it", ref=where)
        stores.append(Store(
            name=str(name), backend=backend, addresses=tuple(str(a) for a in addresses),
            source=where,
            location=dict(data.get("location") or {}),
            credentials=dict(data.get("credentials") or {}),
            reachable_from=dict(data.get("reachable_from") or {}),
            holds=tuple(data.get("holds") or ()),
            replicated=data.get("replicated"),
            recovery=dict(data.get("recovery") or {}),
        ))
    return stores


def specificity(address: str, store: str):
    """How specifically an address answers a store name, or None when it does not.

    An exact name beats any prefix, a longer prefix beats a shorter one, and
    `*` answers only what nothing else claims.
    """
    if address == store:
        return (3, len(address))
    if address.endswith("*") and len(address) > 1 and store.startswith(address[:-1]):
        return (2, len(address) - 1)
    if address == "*":
        return (1, 0)
    return None


def for_reference(stores: list, ref: ObjectRef):
    """The declaration whose addresses answer the reference's store most specifically.

    NOT the first one in file order, and this differs from the secret stores on
    purpose. First match let `archive.yaml` with addresses ["*"] take a
    reference meant for a named local store, because "archive" sorts first, and
    content declared as staying on this machine went to a bucket. A tie between
    two stores at the same specificity is refused rather than settled by a
    filename.
    """
    best, claimants = None, []
    for store in stores:
        ranks = [r for r in (specificity(a, ref.store) for a in store.addresses) if r is not None]
        if not ranks:
            continue
        rank = max(ranks)
        if best is None or rank > best:
            best, claimants = rank, [store]
        elif rank == best:
            claimants.append(store)
    if not claimants:
        return None
    if len(claimants) > 1:
        raise DeclarationError(
            f"{len(claimants)} declarations claim the store {ref.store!r} equally: "
            f"{', '.join(s.source for s in claimants)}",
            ref=ref.canonical, hint="make one address more specific; a filename must not decide")
    return claimants[0]
