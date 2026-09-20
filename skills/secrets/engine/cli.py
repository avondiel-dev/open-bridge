"""The command line. Three verbs in this slice: `refs`, `check`, `run`.

There is deliberately no verb that prints a secret. That is the constraint the
whole skill is built on: an agent reads this output, and anything printed here
is in the model's context for the rest of the session, in the transcript, and in
whatever log the harness keeps. `run` is the way a value reaches a program, and
even there the child's own output is scrubbed before it comes back.

Exit codes are the ones in `errors.py`, because a wrapper script that resolves
its secret at start has to tell "not reachable from this session" (69) from "the
entry is gone" (3). Every caller in this fleet that could not tell them apart
treated both as "no secret" and started without one.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import check as check_mod
from . import discover
from .errors import EX_OK, EX_USAGE, SecretsError, UsageError
from .resolve import Options, Resolver
from .values import Redactor

PROGRAM = "secrets"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Resolve secret references without printing their values.",
        epilog="No command prints a secret. `run` hands one to a child process and scrubs what comes back.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("refs", help="every secret reference written down in the tree")
    _add_common(listing)
    listing.add_argument("paths", nargs="*", help="limit to these files or directories")

    checking = sub.add_parser("check", help="resolve references and measure what comes back")
    _add_common(checking)
    checking.add_argument("refs", nargs="*", help="references to check; default is the whole tree")
    checking.add_argument("--all", action="store_true",
                          help="check every reference in the tree (the default when none is named)")
    checking.add_argument("-v", "--verbose", action="store_true",
                          help="also print where each reference is written down")

    running = sub.add_parser("run", help="run a command with secrets in its environment")
    _add_common(running)
    running.add_argument("--env", action="append", default=[], metavar="NAME=REF",
                         help="resolve REF and put it in the child's environment as NAME")
    running.add_argument("--stdin", metavar="REF",
                         help="resolve REF and write it to the child's standard input")
    running.add_argument("--if-missing", choices=("error", "warn", "ignore"), default="error",
                         help="what to do when a reference resolves to nothing (default: error)")
    running.add_argument("argv", nargs=argparse.REMAINDER,
                         help="-- followed by the command to run")

    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", default=".", help="tree to read declarations from (default: .)")
    parser.add_argument("--keychain", metavar="PATH",
                        help="address this keychain file instead of the search list")
    parser.add_argument("--db", action="append", default=[], metavar="NAME=PATH",
                        help="where a KeePass database lives on this machine")
    parser.add_argument("--db-password-ref", metavar="REF",
                        help="reference holding the master password of those databases")
    parser.add_argument("--key-file", metavar="PATH", help="key file for the KeePass database")
    parser.add_argument("--json", action="store_true", help="machine readable output")


def options_from(args) -> Options:
    options = Options(keychain_path=getattr(args, "keychain", None),
                      db_password_ref=getattr(args, "db_password_ref", None),
                      key_file=getattr(args, "key_file", None))
    for spec in getattr(args, "db", []) or []:
        try:
            options.with_database(spec)
        except ValueError as problem:
            raise UsageError(str(problem)) from None
    return options


# ---------------------------------------------------------------------------
# refs
# ---------------------------------------------------------------------------

def command_refs(args, out, err) -> int:
    findings = discover.find(args.root, args.paths or None)
    if args.json:
        payload = [
            {"path": f.path, "line": f.line, "ref": f.ref.canonical if f.ref else f.raw,
             "raw": f.raw, "error": f.error}
            for f in findings
        ]
        print(json.dumps(payload, indent=2), file=out)
        return EX_OK

    if not findings:
        print("no secret references in this tree", file=out)
        return EX_OK

    grouped = discover.group_by_ref(findings, examples=False)
    broken = 0
    for key in sorted(grouped):
        group = grouped[key]
        first = group[0]
        mark = "" if first.ok else "   <- does not parse: " + first.error
        print(f"{key}{mark}", file=out)
        for finding in group:
            print(f"    {finding.path}:{finding.line}", file=out)
        broken += 0 if first.ok else 1
    examples = {f.raw for f in findings if f.example}
    print("", file=out)
    print(f"{len(grouped)} references in {len({f.path for f in findings if not f.example})} files"
          + (f", {broken} do not parse" if broken else ""), file=out)
    if examples:
        print(f"{len(examples)} more carry a placeholder and are read as examples in prose", file=out)
    return EX_OK


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def command_check(args, out, err) -> int:
    resolver = Resolver(options_from(args))
    if args.refs and not args.all:
        rows = check_mod.check_refs(resolver, args.refs)
    else:
        rows, _ = check_mod.check_tree(resolver, args.root)

    if args.json:
        print(json.dumps([row.as_dict() for row in rows], indent=2), file=out)
    else:
        print(check_mod.render(rows, verbose=args.verbose), file=out)
    return EX_OK if not any(row.failed for row in rows) else check_mod_exit(rows)


def check_mod_exit(rows) -> int:
    """78 when something is written wrong, 3 when something is gone.

    The two are different jobs: a bad reference is fixed in a file, a missing
    secret is fixed in a vault. An error that is neither is reported as 78 as
    well, because the thing to do with it is read the note, not rotate a key.
    """
    from .errors import EX_CONFIG, EX_MISSING

    if any(row.status in (check_mod.BAD_REFERENCE, check_mod.ERROR) for row in rows):
        return EX_CONFIG
    return EX_MISSING


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def command_run(args, out, err) -> int:
    from . import exec as exec_mod

    argv = list(args.argv or [])
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise UsageError("nothing to run", hint="secrets run --env NAME=ref -- your-command")

    resolver = Resolver(options_from(args))
    redactor = Redactor()
    environment: dict = {}
    missing: list[str] = []

    for spec in args.env:
        name, sep, reference = spec.partition("=")
        if not sep or not name.strip():
            raise UsageError(f"expected NAME=reference, got {spec!r}")
        name = name.strip()
        secret = _resolve_or_note(resolver, reference.strip(), args.if_missing, missing, err)
        if secret is None:
            continue
        try:
            environment[name] = secret.expose_text()
        except UnicodeDecodeError:  # pragma: no cover - surrogateescape does not raise
            raise SecretsError("this value is not text and cannot go into the environment",
                               ref=reference) from None
        redactor.register(name, secret)
        print(f"{PROGRAM}: {name} <- {reference.strip()} ({secret.describe()})", file=err)

    stdin_bytes = None
    if args.stdin:
        secret = _resolve_or_note(resolver, args.stdin, args.if_missing, missing, err)
        if secret is not None:
            stdin_bytes = secret.expose()
            redactor.register("stdin", secret)
            print(f"{PROGRAM}: standard input <- {args.stdin} ({secret.describe()})", file=err)

    if missing and args.if_missing == "error":
        for line in missing:
            print(f"{PROGRAM}: {line}", file=err)
        from .errors import EX_MISSING

        return EX_MISSING
    if redactor.skipped:
        print(f"{PROGRAM}: too short to redact safely, so the child's output is printed as it came: "
              + ", ".join(redactor.skipped), file=err)

    done = exec_mod.spawn(argv, env=environment, stdin_bytes=stdin_bytes)
    _emit(done.stdout, redactor, out, "standard output", err)
    _emit(done.stderr, redactor, err, "standard error", err)
    if done.truncated:
        print(f"{PROGRAM}: the child wrote more than {exec_mod.MAX_CAPTURE_BYTES} bytes; the rest was cut",
              file=err)
    return done.rc


def _resolve_or_note(resolver, reference, if_missing, missing, err):
    from .errors import SecretMissing

    try:
        return resolver.require(reference)
    except SecretMissing as problem:
        if if_missing == "error":
            missing.append(problem.report())
            return None
        if if_missing == "warn":
            print(f"{PROGRAM}: {problem.report()}", file=err)
        return None


def _emit(text: str, redactor: Redactor, stream, label: str, err) -> None:
    if not text:
        return
    cleaned = redactor.scrub(text)
    if redactor.holds(cleaned):
        # The belt to the braces. If a value survived scrubbing, printing the
        # stream is the one thing that must not happen, so the stream is dropped
        # and the caller is told which one.
        print(f"{PROGRAM}: refused to print the child's {label}: it still contained a secret "
              f"after redaction", file=err)
        return
    stream.write(cleaned)
    if not cleaned.endswith("\n"):
        stream.write("\n")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

COMMANDS = {
    "refs": command_refs,
    "check": command_check,
    "run": command_run,
}


def main(argv=None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as stop:  # argparse already printed the message
        # `--help` raises SystemExit(0), and `0 or EX_USAGE` is EX_USAGE. A
        # wrapper probing whether the tool is installed then reads a usage error
        # out of a successful help.
        code = stop.code
        if code is None or code == 0:
            return EX_OK
        return int(code) if isinstance(code, int) else EX_USAGE

    handler = COMMANDS[args.command]
    try:
        return handler(args, out, err)
    except SecretsError as problem:
        print(f"{PROGRAM}: {problem.report()}", file=err)
        return problem.exit_code
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print(f"{PROGRAM}: interrupted", file=err)
        return 130


if __name__ == "__main__":  # pragma: no cover - module entry
    raise SystemExit(main())
