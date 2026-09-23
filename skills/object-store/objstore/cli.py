"""object-store: resolve object://<store>/<key> to a path, never to content.

    object-store.sh stores                              the declarations here
    object-store.sh stat   <ref>                        size and sha256
    object-store.sh path   <ref> [--sha256 H]           a local path to the bytes
    object-store.sh fetch  <ref> --to FILE [--sha256 H] the bytes, into FILE
    object-store.sh put    <ref> --from FILE            write, or fail; never queued
    object-store.sh init   <store>                      mark an existing local store root
    object-store.sh forget --sha256 H                   drop a cached copy

No command prints an object's content. Where the bytes came from (store or
cache) goes to stderr as `served from: ...`, so stdout stays a path or a line.

A failure prints `<ref>: <outcome>: <message>` on stderr, nothing on stdout, and
exits with the outcome's code: 3 not-found, 4 store-not-declared,
5 denied or refused, 64 usage, 69 not-reachable, 70 unexpected,
78 malformed-reference or credentials-unavailable or bad-declaration.
Nothing escapes as a traceback: an unexpected exception is reported by its type
only, because its message is not the resolver's and one such message carried a
signed Authorization header.
"""

from __future__ import annotations

import argparse
import sys

from .errors import ObjectStoreError, Unexpected
from .resolver import Resolver


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="object-store", description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", default=".", help="the Bridge whose infra/object-stores/ applies")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("stores", help="list the declarations")
    stat = sub.add_parser("stat", help="size and sha256 of an object")
    stat.add_argument("ref")
    path = sub.add_parser("path", help="a local path to the object's bytes")
    path.add_argument("ref")
    path.add_argument("--sha256", help="the hash the entry tracks; enables the cache")
    fetch = sub.add_parser("fetch", help="write the object to a file")
    fetch.add_argument("ref")
    fetch.add_argument("--to", required=True)
    fetch.add_argument("--sha256")
    put = sub.add_parser("put", help="write a file to the store")
    put.add_argument("ref")
    put.add_argument("--from", dest="source", required=True)
    init = sub.add_parser("init", help="mark an existing directory as a declared local store")
    init.add_argument("store")
    forget = sub.add_parser("forget", help="drop a cached copy, for an object that was erased")
    forget.add_argument("--sha256", required=True)
    return parser


def _line(result) -> str:
    size = "unknown" if result.size is None else result.size
    return f"size={size}  sha256={result.sha256 or 'unknown'}"


def _run(args, credentials) -> None:
    resolver = Resolver(args.root, credentials=credentials)
    if args.command == "stores":
        if not resolver.stores:
            print("no store is declared in infra/object-stores/")
        for store in resolver.stores:
            print(f"{store.name}  backend={store.backend}  addresses={','.join(store.addresses)}"
                  f"  holds={','.join(store.classes) or '-'}  replicated={store.replicated}"
                  f"  backed_up={store.recovery.get('backed_up')}  ({store.source})")
    elif args.command == "stat":
        result = resolver.stat(args.ref)
        print(f"{result.uri}  {_line(result)}")
    elif args.command == "path":
        result = resolver.path(args.ref, expect_sha256=args.sha256)
        print(result.path)
        print(f"served from: {result.source}", file=sys.stderr)
    elif args.command == "fetch":
        result = resolver.fetch(args.ref, args.to, expect_sha256=args.sha256)
        print(f"wrote {result.path}  {_line(result)}")
        print(f"served from: {result.source}", file=sys.stderr)
    elif args.command == "put":
        result = resolver.put(args.ref, args.source)
        print(f"stored {result.uri}  {_line(result)}")
    elif args.command == "init":
        print(f"marked {resolver.init(args.store)}")
    elif args.command == "forget":
        dropped = resolver.forget(args.sha256)
        print("dropped the cached copy" if dropped else "no cached copy under that hash")


def main(argv=None, *, credentials=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _run(args, credentials)
    except ObjectStoreError as exc:
        print(exc.report(), file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 - the one place nothing may escape raw
        failure = Unexpected(f"{type(exc).__name__} (its message is not shown; it is not ours)")
        print(failure.report(), file=sys.stderr)
        return failure.exit_code
    return 0


if __name__ == "__main__":
    sys.exit(main())
