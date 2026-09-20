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

from . import audit as audit_mod
from . import check as check_mod
from . import discover
from . import stores as stores_mod
from .errors import EX_CONFIG, EX_MISSING, EX_OK, EX_USAGE, Refused, SecretsError, UsageError
from .resolve import Options, Resolver
from .values import Redactor, Secret

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

    placing = sub.add_parser("where", help="where a new secret of this kind belongs")
    _add_common(placing)
    placing.add_argument("kind", help="one of the declared kinds; omit to list them",
                         nargs="?", default="")
    placing.add_argument("--owner", default="",
                         help="the persona, org or customer this secret is for")

    storing = sub.add_parser("store", help="put a value into a store, without it passing through argv")
    _add_common(storing)
    storing.add_argument("ref", help="the reference to write")
    storing.add_argument("--from", dest="source", default="auto",
                         choices=("auto", "stdin", "clipboard", "prompt"),
                         help="where the value comes from (default: stdin when piped, else a hidden prompt)")
    storing.add_argument("--kind", default="",
                         help="the kind this secret is, checked against the store's policy")
    storing.add_argument("--replace", action="store_true",
                         help="overwrite an entry that is already there")
    storing.add_argument("--tag", action="append", default=[], metavar="KEY=VALUE",
                         help="metadata for backends that carry it (Key Vault)")

    listing_stores = sub.add_parser("stores", help="the declared stores, and what is wrong with them")
    _add_common(listing_stores)

    auditing = sub.add_parser("audit", help="plaintext that should have been a reference")
    _add_common(auditing)
    auditing.add_argument("--also", action="append", default=[], metavar="PATH",
                          help="a place outside the tree to scan as well, repeatable")
    auditing.add_argument("--no-pii", action="store_true",
                          help="credentials only; personal data is reported by default and never moved")
    auditing.add_argument("--with-gitleaks", action="store_true",
                          help="ask gitleaks for a second opinion when it is installed")
    auditing.add_argument("-v", "--verbose", action="store_true",
                          help="also show hits inside declared stores and the reason for each pattern")

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
                      key_file=getattr(args, "key_file", None),
                      root=getattr(args, "root", "."))
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
# audit
# ---------------------------------------------------------------------------

def command_audit(args, out, err) -> int:
    """Find the values that never became a reference, and say where they belong.

    Exit code: 0 when no credential is loose, `EX_MISSING` when at least one is.
    Personal data does not change the code. It is worth reporting and it is not
    a secret, so a tree that holds an invoice with an IBAN in it is not broken.
    """
    resolver = Resolver(options_from(args))
    report = audit_mod.run(args.root, also=args.also, stores=resolver.stores,
                           include_pii=not args.no_pii)
    if args.with_gitleaks:
        _, message = audit_mod.gitleaks(args.root)
        report.gitleaks = message

    if args.json:
        print(json.dumps({
            "findings": [finding.as_dict() for finding in report.findings],
            "files_read": report.files_read,
            "credentials": len(report.credentials),
            "pii": len(report.pii),
            "gitleaks": report.gitleaks,
        }, indent=2), file=out)
    else:
        print(audit_mod.render(report, verbose=args.verbose), file=out)
    return EX_MISSING if report.credentials else EX_OK


# ---------------------------------------------------------------------------
# where
# ---------------------------------------------------------------------------

def command_where(args, out, err) -> int:
    """Answers "where does this kind of secret go", from the declarations.

    The question this verb exists for is the one that had no answer at all: an
    agent handed a token decided for itself where to put it, and small text
    files with credentials appeared in working folders. A file answering it is
    not cleverer than the agent, it is merely the same answer every time.
    """
    declared = stores_mod.load(args.root)
    if not args.kind:
        if args.json:
            print(json.dumps({"kinds": {kind: stores_mod.KIND_SUMMARY[kind]
                                        for kind in stores_mod.KINDS},
                              "not_a_kind": stores_mod.NOT_A_KIND}, indent=2), file=out)
            return EX_OK
        print("kinds a store can declare:", file=out)
        for kind in stores_mod.KINDS:
            print(f"  {kind:20} {stores_mod.KIND_SUMMARY[kind]}", file=out)
        print("", file=out)
        print("not kinds, and deliberately so:", file=out)
        for kind, why in stores_mod.NOT_A_KIND.items():
            print(f"  {kind:20} {why}", file=out)
        return EX_OK

    placements = stores_mod.placements_for(declared, args.kind, args.owner)
    if args.json:
        print(json.dumps([{
            "store": placement.store.name,
            "backend": placement.store.backend,
            "owner": placement.owner,
            "naming": placement.naming,
            "reference": placement.reference_shape(),
            "note": placement.note,
            "source": placement.store.source,
        } for placement in placements], indent=2), file=out)
        return EX_OK if placements else EX_CONFIG

    print(f"{args.kind}: {stores_mod.KIND_SUMMARY[args.kind]}", file=out)
    print("", file=out)
    if not placements:
        print("no store declares this kind.", file=out)
        if not declared:
            print(f"  There are no declarations at all under {stores_mod.FAMILY}/.", file=out)
            print(f"  Copy {stores_mod.FAMILY}/_template.yaml and fill it in.", file=out)
        else:
            print(f"  {len(declared)} store(s) are declared, none of them for this kind.", file=out)
            print(f"  Add a `holds:` line to the right one, in {stores_mod.FAMILY}/.", file=out)
        return EX_CONFIG

    for placement in placements:
        store = placement.store
        owner = f" for {placement.owner}" if placement.owner else ""
        print(f"{store.name}{owner}  ({store.backend})", file=out)
        if store.summary:
            print(f"    {store.summary}", file=out)
        print(f"    reference   {placement.reference_shape()}", file=out)
        if placement.naming:
            print(f"    naming      {placement.naming}", file=out)
        if placement.note:
            print(f"    note        {placement.note}", file=out)
        reaches, why = store.reaches(Resolver(options_from(args)).context)
        if not reaches:
            print(f"    reachable   no, from this session: {why}", file=out)
        print(f"    declared in {store.source}", file=out)
    return EX_OK


# ---------------------------------------------------------------------------
# stores
# ---------------------------------------------------------------------------

def command_stores(args, out, err) -> int:
    declared = stores_mod.load(args.root)
    problems = stores_mod.check_declarations(declared)
    if args.json:
        print(json.dumps({"stores": [{
            "name": store.name, "backend": store.backend,
            "addresses": list(store.addresses), "summary": store.summary,
            "holds": [placement.kind for placement in store.placements()],
            "source": store.source,
        } for store in declared], "problems": problems}, indent=2), file=out)
        return EX_OK if not problems else EX_CONFIG

    if not declared:
        print(f"no stores declared under {stores_mod.FAMILY}/", file=out)
        print(f"  the template is {stores_mod.FAMILY}/_template.yaml", file=out)
        return EX_OK
    for store in declared:
        kinds = ", ".join(placement.kind for placement in store.placements()) or "nothing declared"
        print(f"{store.name:22} {store.backend:16} {', '.join(store.addresses)}", file=out)
        print(f"{'':22} holds: {kinds}", file=out)
    print("", file=out)
    if problems:
        print(f"{len(problems)} problem(s):", file=out)
        for problem in problems:
            print(f"  - {problem}", file=out)
        return EX_CONFIG
    print(f"{len(declared)} store(s), no problems", file=out)
    return EX_OK


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

def command_store(args, out, err) -> int:
    """Write a value that never passes through a command line.

    Three sources, and all of them keep the value out of argv and out of this
    program's own output: a pipe, the clipboard, or a hidden prompt. The fourth
    way, typing it as an argument, is not offered at all. That is the way it
    reached the process list on two machines in this fleet.
    """
    resolver = Resolver(options_from(args))
    ref = resolver_parse(args.ref)

    store = resolver.store_for(ref)
    kind = args.kind or _infer_kind(store, err)
    if kind:
        _check_kind_against_policy(resolver, store, ref, kind, err)

    secret = read_value(args.source, err)
    if secret.is_empty():
        raise UsageError("nothing arrived, so nothing was written",
                         hint="an empty value is not a secret; check the pipe or the clipboard")

    reading = resolver.store(ref, secret, replace=args.replace, tags=_tags_from(args))
    where = resolver.locate(ref)
    if args.json:
        print(json.dumps({"ref": ref.canonical, "bytes": reading.length,
                          "fingerprint": reading.fingerprint, "where": where,
                          "store": store.name if store is not None else ""}, indent=2), file=out)
    else:
        print(f"{ref.canonical}", file=out)
        print(f"  stored in   {where}", file=out)
        print(f"  read back   {reading.length} bytes, sha256 {reading.fingerprint}", file=out)
        if store is not None:
            print(f"  store       {store.name} ({store.source})", file=out)
        if args.source == "clipboard":
            print("  the clipboard still holds the value; clear it when you are done", file=out)
    return EX_OK


def _tags_from(args) -> dict:
    """`--tag key=value`, for the backends that carry metadata."""
    tags = {}
    for spec in getattr(args, "tag", []) or []:
        key, sep, value = spec.partition("=")
        if not sep or not key.strip():
            raise UsageError(f"expected KEY=VALUE, got {spec!r}")
        tags[key.strip()] = value.strip()
    return tags


def resolver_parse(text: str):
    from . import refs as refs_mod

    return refs_mod.parse(text)


def _check_kind_against_policy(resolver, store, ref, kind, err) -> None:
    """Refuse a write into a store that does not declare this kind.

    The policy is only worth having if something reads it at the moment of the
    write. Otherwise it is documentation, and the loose token file gets written
    anyway, next to a file that says it should not be.
    """
    if kind in stores_mod.NOT_A_KIND:
        raise Refused(f"{kind} is not a kind of secret",
                      hint=stores_mod.NOT_A_KIND[kind])
    if kind not in stores_mod.KINDS:
        raise Refused(f"unknown kind {kind!r}", hint="declared kinds: " + ", ".join(stores_mod.KINDS))
    if store is None:
        print(f"{PROGRAM}: no store declares this reference, so the policy cannot be checked",
              file=err)
        return
    declared = {placement.kind for placement in store.placements()}
    if kind not in declared:
        elsewhere = stores_mod.placements_for(resolver.stores, kind)
        names = ", ".join(sorted({placement.store.name for placement in elsewhere})) or "nowhere yet"
        raise Refused(
            f"{store.name} does not hold {kind} secrets",
            ref=ref.canonical,
            hint=f"it declares: {', '.join(sorted(declared)) or 'nothing'}. "
                 f"This kind belongs in: {names}. `secrets where {kind}` prints the shape.",
        )


def _infer_kind(store, err) -> str:
    """What kind this is, when nobody said, so the policy is not opt-in.

    A gate that only fires when the caller asks for it is documentation. The
    rule here: a store that holds exactly one kind answers the question by
    itself; a store that holds several cannot, and the write stops rather than
    guessing which line of the policy it belongs under.
    """
    if store is None:
        return ""
    kinds = sorted({placement.kind for placement in store.placements()})
    if len(kinds) == 1:
        print(f"{PROGRAM}: {store.name} holds one kind, so this is a {kinds[0]}", file=err)
        return kinds[0]
    if not kinds:
        return ""
    raise Refused(
        f"{store.name} holds several kinds, so this write needs to say which one",
        hint=f"pass --kind, one of: {', '.join(kinds)}. `secrets where <kind>` prints the shape.",
    )


def read_value(source: str, err) -> Secret:
    """The value, from a pipe, the clipboard or a hidden prompt. Never from argv."""
    import sys as sys_mod

    if source == "auto":
        source = "stdin" if not sys_mod.stdin.isatty() else "prompt"
    if source == "stdin":
        raw = sys_mod.stdin.buffer.read()
        # One trailing newline, the one `printf '%s\n'` or an editor adds.
        # Stripping every trailing newline truncates a PEM key, and the
        # read-back check cannot catch it: it compares against the value this
        # line already changed.
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n") or raw.endswith(b"\r"):
            raw = raw[:-1]
        return Secret(raw)
    if source == "clipboard":
        return Secret(read_clipboard())
    import getpass

    typed = getpass.getpass("value (not echoed): ")
    return Secret(typed)


def read_clipboard() -> bytes:
    """The clipboard, through the platform's own tool.

    The clipboard is the one channel that persists nothing: not the shell
    history, not the transcript, not a file. It is how a value gets from a
    person to this process without either of them writing it down.
    """
    from . import exec as exec_mod

    candidates = (["pbpaste"], ["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"],
                  ["powershell.exe", "-NoProfile", "-Command", "Get-Clipboard"])
    for argv in candidates:
        if exec_mod.which(argv[0]) is None:
            continue
        done = exec_mod.run(argv, timeout_sec=15)
        if done.rc == 0:
            return done.stdout.rstrip("\r\n").encode("utf-8")
        raise SecretsError(f"{argv[0]} exited {done.rc}",
                           hint=done.stderr.strip() or "no message on stderr")
    raise SecretsError(
        "no clipboard tool here",
        hint="pbpaste on macOS, wl-paste or xclip on Linux, Get-Clipboard on Windows",
    )


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
    "where": command_where,
    "stores": command_stores,
    "store": command_store,
    "audit": command_audit,
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
