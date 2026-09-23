"""Credentials for a store: references in the declaration, values only in memory.

Three ways in, in this order:

1. The environment, PER STORE: OBJECT_STORE_<NAME>_ACCESS_KEY_ID and
   OBJECT_STORE_<NAME>_SECRET_ACCESS_KEY, where <NAME> is the store's name in
   upper case with `-` as `_`. That is what `secrets run --env NAME=<ref> -- ...`
   hands a child process. Per store and not one pair for all: a single pair
   went to every S3 store, so store B's endpoint received store A's access key
   and a request signed with it, and the refusal read as a policy problem.
2. A provider the caller passes in (the tests do).
3. The secrets skill next to this one, imported in-process, resolving the
   declaration's `credentials.access_key_ref` and `secret_key_ref`.

Values are stripped and then checked for anything a request header cannot
carry. A stored key with a trailing newline is common, and one in the middle
made http.client raise an error whose message held the signed header.

When none of the three can answer, the failure is named
`credentials-unavailable`. A store that cannot be opened must not read like a
store that is not there.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .errors import CredentialsUnavailable

#: The secrets skill, where the repo layout puts it: next to this skill.
SECRETS_SKILL = Path(__file__).resolve().parents[2] / "secrets"


def env_names(store_name: str) -> tuple:
    stem = "OBJECT_STORE_" + store_name.upper().replace("-", "_")
    return f"{stem}_ACCESS_KEY_ID", f"{stem}_SECRET_ACCESS_KEY"


def _clean(value, store) -> str:
    value = str(value).strip()
    if not value or any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):
        raise CredentialsUnavailable(
            "a credential value is empty or contains a character a request header cannot carry",
            ref=store.source, hint="the value itself is not shown; check the stored entry")
    return value


def keys_for(store, provider, root) -> tuple:
    access_name, secret_name = env_names(store.name)
    access, secret = os.environ.get(access_name), os.environ.get(secret_name)
    if access and secret:
        return _clean(access, store), _clean(secret, store)
    access_ref = store.credentials.get("access_key_ref")
    secret_ref = store.credentials.get("secret_key_ref")
    if not access_ref or not secret_ref:
        raise CredentialsUnavailable(
            "the store declares no credentials and none were handed over",
            ref=store.source,
            hint=f"declare credentials.access_key_ref and secret_key_ref, or set {access_name} "
                 f"and {secret_name} through `secrets run --env`")
    if provider is None:
        provider = _secrets_provider(root, store)
    try:
        return _clean(provider(access_ref), store), _clean(provider(secret_ref), store)
    except CredentialsUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - the secrets skill's errors carry no value
        raise CredentialsUnavailable(
            f"the secrets skill could not resolve the store's credentials ({type(exc).__name__})",
            ref=store.source) from None


def _secrets_provider(root, store):
    if not (SECRETS_SKILL / "engine" / "resolve.py").is_file():
        access_name, secret_name = env_names(store.name)
        raise CredentialsUnavailable(
            f"no secrets skill at {SECRETS_SKILL}, so the credential references cannot be resolved here",
            ref=store.source,
            hint=f"run under `secrets run --env {access_name}=<ref> --env {secret_name}=<ref> -- ...`")
    # The secrets skill's package is called `engine`, which is why this one is
    # not. It goes onto sys.path only here, and only when a reference has to be
    # resolved in-process.
    if str(SECRETS_SKILL) not in sys.path:
        sys.path.insert(0, str(SECRETS_SKILL))
    from engine.resolve import Options, Resolver  # noqa: PLC0415 - the sibling skill, on demand

    resolver = Resolver(Options(root=str(root)))

    def provide(ref: str) -> str:
        return resolver.require(ref).expose_text()
    return provide
