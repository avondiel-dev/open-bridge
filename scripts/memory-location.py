#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve where Claude Code's auto memory lives for this repo, and manage
the move from the legacy hash path into a directory inside the repo.

THE SETTING. Claude Code reads `autoMemoryDirectory` from any settings scope
(project `.claude/settings.json`, local `.claude/settings.local.json`, or the
user's `~/.claude/settings.json`). The value must be an absolute path, or
start with `~/`; a relative value is silently ignored and the harness falls
back to its own default, `~/.claude/projects/<encoded-root>/memory` (the
absolute project path with every `/` replaced by `-`). The setting is keyed
to the git PROJECT: a value set in the main checkout also governs every
linked worktree and every subdirectory (session transcripts stay per cwd;
memory does not). See https://code.claude.com/docs/en/memory and
`docs/memory.md`.

THIS SCRIPT is the one resolver every CORE reader should call instead of
reconstructing that hash path by hand (the derivation used to be duplicated
in `scripts/okf-export.py`'s `default_memory_dir()`, and drifts silently the
moment an instance opts into an in-repo directory).

    python3 scripts/memory-location.py status [--json]
    python3 scripts/memory-location.py enable [--path work/memory] [--dry-run]
    python3 scripts/memory-location.py migrate [--dry-run] [--prefer-newer]
    python3 scripts/memory-location.py stub-legacy --yes
    python3 scripts/memory-location.py check

`resolve_memory_dir(start, home=None)` is the library entry point: it never
raises on a missing git binary, a missing settings file, or invalid JSON, and
returns `(Path, source, warnings)` where `source` is one of `setting:local`,
`setting:project`, `setting:user` or `legacy`.

Contract: `scripts/tests/test_memory_location.py`.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

LOAD_LIMIT_LINES = 200
LOAD_LIMIT_BYTES = 25 * 1024  # "25 KB" per the harness's own load cap
HOOK_CHAR_LIMIT = 120
STUB_MARKER = "<!-- memory-location: pointer stub, see scripts/memory-location.py -->"
PRE_MOVE_SUFFIX = ".pre-move"

INDEX_LINE_RE = re.compile(
    r"^-\s*\[(?P<title>[^\]]*)\]\((?P<link>[^)]+)\)\s*(?:\u2014|\u2013|-|:)\s*(?P<hook>.*)$"
)
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+\.md)\)")


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _git_common_dir(start: Path) -> Path | None:
    """Absolute `--git-common-dir` for `start`, or None if git could not answer.

    A linked worktree's common dir lives inside the MAIN checkout, so this is
    what makes a worktree resolve to the same settings as the checkout it was
    made from, per the harness's own project-keyed scoping.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    return Path(out) if out else None


def repo_root_for(start) -> Path:
    """The repo root that owns memory for `start`: the main checkout's parent
    directory when `start` is inside a git project (worktree or not), or
    `start` itself, resolved, when it is not a git project at all."""
    common_dir = _git_common_dir(Path(start))
    if common_dir is not None:
        return common_dir.parent
    return Path(start).resolve()


def legacy_memory_dir(repo_root: Path, home: Path) -> Path:
    """The harness's own default: the leading `/` becomes a leading `-` too."""
    encoded = str(repo_root).replace("/", "-")
    return home / ".claude" / "projects" / encoded / "memory"


def _read_json_object(path: Path) -> tuple[dict | None, str | None]:
    """(parsed dict, None) on success; (None, warning) on a file that exists
    but is not a JSON object. Missing files are the caller's business."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON, skipped: {exc}"
    if not isinstance(data, dict):
        return None, f"{path} does not hold a JSON object, skipped"
    return data, None


def resolve_memory_dir(start, home=None) -> tuple[Path, str, list[str]]:
    """(memory_dir, source, warnings). Never raises.

    Precedence: repo_root/.claude/settings.local.json, then
    repo_root/.claude/settings.json, then home/.claude/settings.json. The
    FIRST of those that contains the `autoMemoryDirectory` key decides,
    whether or not its value turns out to be usable; an unusable value falls
    through to the legacy hash path rather than trying the next file.
    """
    home = Path(home) if home is not None else Path.home()
    repo_root = repo_root_for(start)
    warnings: list[str] = []

    candidates = [
        (repo_root / ".claude" / "settings.local.json", "setting:local"),
        (repo_root / ".claude" / "settings.json", "setting:project"),
        (home / ".claude" / "settings.json", "setting:user"),
    ]

    for path, source in candidates:
        if not path.is_file():
            continue
        data, warning = _read_json_object(path)
        if data is None:
            if warning:
                warnings.append(warning)
            continue
        if "autoMemoryDirectory" not in data:
            continue
        value = data["autoMemoryDirectory"]
        if isinstance(value, str) and value:
            if value.startswith("~/"):
                return (home / value[2:]), source, warnings
            if Path(value).is_absolute():
                return Path(value), source, warnings
        warnings.append(
            f"autoMemoryDirectory={value} in {path} is not absolute; "
            "Claude Code ignores it silently"
        )
        break  # the first file WITH the key decides, valid or not

    return legacy_memory_dir(repo_root, home), "legacy", warnings


# ---------------------------------------------------------------------------
# Shared file-listing (migrate and status's drift preview use the same set)
# ---------------------------------------------------------------------------


def _top_level_files(directory: Path) -> dict[str, Path]:
    """{name: path} for top-level regular files. Directories, any name
    containing `.bak`, and the `MEMORY.md.pre-move` copy that stub-legacy
    keeps are excluded. Empty dict when `directory` is not a dir."""
    if not directory.is_dir():
        return {}
    out: dict[str, Path] = {}
    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        if ".bak" in entry.name or entry.name.endswith(PRE_MOVE_SUFFIX):
            continue
        out[entry.name] = entry
    return out


def _count_md(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.glob("*.md") if p.is_file())


def _is_stub(path: Path) -> bool:
    """True when `path` is a legacy MEMORY.md already replaced by stub-legacy."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(len(STUB_MARKER)) == STUB_MARKER
    except OSError:
        return False


def _migrate_plan(
    source_dir: Path, target_dir: Path, prefer_newer: bool
) -> tuple[list[str], list[str], list[str]]:
    """(to_copy, skipped, conflicts) file names, computed with zero writes.

    A source `MEMORY.md` that is itself a pointer stub (written by
    `stub-legacy`) is excluded from all three lists rather than treated as
    ordinary content: it is not the real index, and letting `--prefer-newer`
    copy it over the target (its mtime is always the newest thing around
    right after `stub-legacy` runs) would overwrite the real, already-migrated
    index with the pointer text.
    """
    source_files = _top_level_files(source_dir)
    target_files = _top_level_files(target_dir)

    stub_path = source_files.get("MEMORY.md")
    if stub_path is not None and _is_stub(stub_path):
        del source_files["MEMORY.md"]

    to_copy: list[str] = []
    skipped: list[str] = []
    conflicts: list[str] = []

    for name, src in sorted(source_files.items()):
        dst = target_files.get(name)
        if dst is None:
            to_copy.append(name)
            continue
        if filecmp.cmp(src, dst, shallow=False):
            skipped.append(name)
            continue
        if prefer_newer and src.stat().st_mtime > dst.stat().st_mtime:
            to_copy.append(name)
            continue
        conflicts.append(name)

    return to_copy, skipped, conflicts


# ---------------------------------------------------------------------------
# check: lint a resolved MEMORY.md
# ---------------------------------------------------------------------------


def lint_memory_index(memory_dir: Path) -> list[str]:
    """Violation strings for `memory_dir/MEMORY.md`. Empty list when the
    directory or the file itself is missing (nothing to lint yet)."""
    index_path = memory_dir / "MEMORY.md"
    if not memory_dir.is_dir() or not index_path.is_file():
        return []

    text = index_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    violations: list[str] = []

    if len(lines) > LOAD_LIMIT_LINES:
        violations.append(
            f"MEMORY.md has {len(lines)} lines, over the {LOAD_LIMIT_LINES}-line load limit"
        )
    byte_size = len(text.encode("utf-8"))
    if byte_size > LOAD_LIMIT_BYTES:
        violations.append(
            f"MEMORY.md is {byte_size} bytes, over the {LOAD_LIMIT_BYTES}-byte (25 KB) load limit"
        )

    for lineno, line in enumerate(lines, start=1):
        match = INDEX_LINE_RE.match(line)
        if not match or not match.group("link").endswith(".md"):
            continue
        hook = match.group("hook")
        if len(hook) > HOOK_CHAR_LIMIT:
            violations.append(
                f"MEMORY.md:{lineno} hook is {len(hook)} chars, over the "
                f"{HOOK_CHAR_LIMIT}-char cap: {match.group('title')!r}"
            )

    for lineno, line in enumerate(lines, start=1):
        for link in LINK_RE.findall(line):
            if "://" in link or link.startswith("/") or link.startswith("~"):
                continue
            if not (memory_dir / link).is_file():
                violations.append(f"MEMORY.md:{lineno} links to missing file: {link}")

    return violations


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def build_status(repo_arg, home=None) -> dict:
    home = Path(home) if home is not None else Path.home()
    repo_root = repo_root_for(repo_arg)
    memory_dir, source, warnings = resolve_memory_dir(repo_arg, home)
    legacy_dir = legacy_memory_dir(repo_root, home)

    memory_files_set = _top_level_files(memory_dir)
    legacy_files_set = _top_level_files(legacy_dir)
    legacy_index = legacy_files_set.get("MEMORY.md")
    if legacy_index is not None and _is_stub(legacy_index):
        # a pointer stub is not drift: stub-legacy wrote it on purpose
        del legacy_files_set["MEMORY.md"]

    only_in_legacy = sorted(set(legacy_files_set) - set(memory_files_set))
    newer_in_legacy: list[str] = []
    for name in sorted(set(legacy_files_set) & set(memory_files_set)):
        legacy_path = legacy_files_set[name]
        memory_path = memory_files_set[name]
        if filecmp.cmp(legacy_path, memory_path, shallow=False):
            continue
        if legacy_path.stat().st_mtime > memory_path.stat().st_mtime:
            newer_in_legacy.append(name)

    index_path = memory_dir / "MEMORY.md"
    if index_path.is_file():
        index_text = index_path.read_text(encoding="utf-8", errors="replace")
        index_lines = len(index_text.splitlines())
        index_bytes = len(index_text.encode("utf-8"))
    else:
        index_lines = 0
        index_bytes = 0

    return {
        "memory_dir": str(memory_dir),
        "source": source,
        "legacy_dir": str(legacy_dir),
        "memory_dir_exists": memory_dir.is_dir(),
        "legacy_exists": legacy_dir.is_dir(),
        "memory_files": _count_md(memory_dir),
        "legacy_files": _count_md(legacy_dir),
        "only_in_legacy": only_in_legacy,
        "newer_in_legacy": newer_in_legacy,
        "index_lines": index_lines,
        "index_bytes": index_bytes,
        "index_within_load_limit": index_lines <= LOAD_LIMIT_LINES
        and index_bytes <= LOAD_LIMIT_BYTES,
        "warnings": warnings,
    }


def cmd_status(args) -> int:
    status = build_status(args.repo)
    if args.json:
        print(json.dumps(status, indent=2))
        return 0

    print(f"memory_dir:   {status['memory_dir']}  ({status['source']})")
    print(f"exists:       {status['memory_dir_exists']}, {status['memory_files']} fact file(s)")
    if status["source"] != "legacy":
        print(f"legacy_dir:   {status['legacy_dir']}")
        print(
            f"legacy:       exists={status['legacy_exists']}, "
            f"{status['legacy_files']} fact file(s)"
        )
        if status["only_in_legacy"]:
            print(f"only in legacy (never migrated): {', '.join(status['only_in_legacy'])}")
        if status["newer_in_legacy"]:
            print(f"newer in legacy (a running session wrote after migrate): "
                  f"{', '.join(status['newer_in_legacy'])}")
    print(
        f"MEMORY.md:    {status['index_lines']} lines, {status['index_bytes']} bytes, "
        f"within load limit: {status['index_within_load_limit']}"
    )
    for warning in status["warnings"]:
        print(f"warning: {warning}")
    return 0


# ---------------------------------------------------------------------------
# enable
# ---------------------------------------------------------------------------


def cmd_enable(args) -> int:
    repo_root = repo_root_for(args.repo)
    if args.path:
        if args.path.startswith("~/"):
            target = Path.home() / args.path[2:]
        else:
            target = Path(args.path)
            if not target.is_absolute():
                target = repo_root / target
    else:
        target = repo_root / "work" / "memory"

    settings_path = repo_root / ".claude" / "settings.local.json"
    existing, warning = (
        _read_json_object(settings_path) if settings_path.is_file() else ({}, None)
    )
    if settings_path.is_file() and existing is None:
        print(f"error: {warning or f'{settings_path} is not a JSON object'}", file=sys.stderr)
        return 2

    if _is_git_repo(repo_root):
        rel = str(settings_path.relative_to(repo_root))
        ignored = _check_ignore(repo_root, rel)
        if ignored is False:
            print(
                f"error: {rel} is NOT git-ignored in this repo. Refusing to write an "
                "absolute path into a file that could be committed. Add it to "
                ".gitignore first (see rules/secret-placement.md).",
                file=sys.stderr,
            )
            return 2

    updated = dict(existing)
    already = updated.get("autoMemoryDirectory") == str(target)
    updated["autoMemoryDirectory"] = str(target)

    if already:
        print(f"unchanged: autoMemoryDirectory already {target} in {settings_path}")
        return 0

    if args.dry_run:
        print(f"would write autoMemoryDirectory={target} to {settings_path}")
        return 0

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
    print(f"wrote autoMemoryDirectory={target} to {settings_path}")
    print(
        "note: a session that was already running can keep writing to its old "
        "memory directory. Run 'migrate' now, restart sessions, then run it again."
    )
    return 0


def _is_git_repo(root: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def _check_ignore(root: Path, rel_path: str) -> bool | None:
    """True/False when git can answer; None on any git-level ambiguity, in
    which case the caller does not refuse on it (fail open on the tool, not
    on the safety property itself)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-q", rel_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


# ---------------------------------------------------------------------------
# migrate
# ---------------------------------------------------------------------------


def cmd_migrate(args) -> int:
    repo_root = repo_root_for(args.repo)
    home = Path.home()
    memory_dir, source, _warnings = resolve_memory_dir(args.repo, home)
    legacy_dir = legacy_memory_dir(repo_root, home)

    if source == "legacy":
        print(
            "error: no autoMemoryDirectory is configured, so there is nothing to "
            "migrate INTO. Run 'enable' first.",
            file=sys.stderr,
        )
        return 2
    if not legacy_dir.is_dir():
        print(f"error: legacy directory does not exist: {legacy_dir}", file=sys.stderr)
        return 2

    to_copy, skipped, conflicts = _migrate_plan(legacy_dir, memory_dir, args.prefer_newer)

    if args.dry_run:
        print(f"would copy {len(to_copy)}, skip {len(skipped)}, conflict {len(conflicts)}")
        if conflicts:
            print(f"conflicts: {', '.join(sorted(conflicts))}")
        return 1 if conflicts else 0

    memory_dir.mkdir(parents=True, exist_ok=True)
    for name in to_copy:
        shutil.copy2(legacy_dir / name, memory_dir / name)

    print(f"copied {len(to_copy)}, skipped {len(skipped)} (identical), "
          f"{len(conflicts)} conflict(s)")
    if conflicts:
        print(f"conflicts (neither copied nor touched, resolve by hand): "
              f"{', '.join(sorted(conflicts))}")
        print("legacy directory left untouched; safe to re-run 'migrate' later.")
    return 1 if conflicts else 0


# ---------------------------------------------------------------------------
# stub-legacy
# ---------------------------------------------------------------------------


def cmd_stub_legacy(args) -> int:
    if not args.yes:
        print("error: refusing without --yes (this rewrites the legacy MEMORY.md)",
              file=sys.stderr)
        return 2

    repo_root = repo_root_for(args.repo)
    home = Path.home()
    memory_dir, source, _warnings = resolve_memory_dir(args.repo, home)
    legacy_dir = legacy_memory_dir(repo_root, home)

    if source == "legacy":
        print("error: autoMemoryDirectory is not configured, memory IS still the "
              "legacy directory. Nothing to point away from.", file=sys.stderr)
        return 2

    legacy_index = legacy_dir / "MEMORY.md"
    if legacy_index.is_file():
        existing = legacy_index.read_text(encoding="utf-8", errors="replace")
        if existing.startswith(STUB_MARKER):
            print(f"error: {legacy_index} is already a pointer stub.", file=sys.stderr)
            return 2

    to_copy, _skipped, conflicts = _migrate_plan(legacy_dir, memory_dir, prefer_newer=False)
    if to_copy or conflicts:
        print(
            "error: a dry-run migrate would still copy or conflict on "
            f"{len(to_copy) + len(conflicts)} file(s); run 'migrate' (and resolve any "
            "conflicts) before stubbing the legacy index.",
            file=sys.stderr,
        )
        if to_copy:
            print(f"  would copy: {', '.join(sorted(to_copy))}", file=sys.stderr)
        if conflicts:
            print(f"  conflicts:  {', '.join(sorted(conflicts))}", file=sys.stderr)
        return 2

    if not legacy_dir.is_dir():
        print(f"error: legacy directory does not exist: {legacy_dir}", file=sys.stderr)
        return 2

    pre_move = legacy_dir / f"MEMORY.md{PRE_MOVE_SUFFIX}"
    if legacy_index.is_file():
        legacy_index.replace(pre_move)

    stub = (
        f"{STUB_MARKER}\n"
        "# Memory has moved\n\n"
        "Auto memory for this repo now lives at:\n\n"
        f"    {memory_dir}\n\n"
        "This file is a pointer, not the index; nothing reads it. The previous "
        f"index is kept next to it as `MEMORY.md{PRE_MOVE_SUFFIX}` for reference.\n"
    )
    legacy_index.write_text(stub, encoding="utf-8")
    print(f"wrote pointer stub to {legacy_index} (previous index kept as {pre_move.name})")
    return 0


STUB_LEGACY_HELP = (
    "Run this only after every session that was started BEFORE 'enable' has "
    "ended: such a session is still writing to the legacy directory and would "
    "rewrite MEMORY.md there on its next save, undoing the stub."
)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def cmd_check(args) -> int:
    memory_dir, _source, _warnings = resolve_memory_dir(args.repo)
    violations = lint_memory_index(memory_dir)
    if not violations:
        return 0
    for violation in violations:
        print(violation, file=sys.stderr)
    print(f"memory-location check: {len(violations)} finding(s)", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memory-location",
        description="Resolve and manage Claude Code's autoMemoryDirectory for this repo.",
    )
    parser.add_argument("--repo", default=".", help="repo path (default: cwd)")
    sub = parser.add_subparsers(dest="command", required=True)

    st = sub.add_parser("status", help="where memory resolves to today, and drift vs legacy")
    st.add_argument("--json", action="store_true", help="machine-readable output")
    st.set_defaults(func=cmd_status)

    en = sub.add_parser("enable", help="write autoMemoryDirectory into settings.local.json")
    en.add_argument(
        "--path",
        help="target dir: relative to --repo, absolute, or ~/-prefixed (default: work/memory)",
    )
    en.add_argument("--dry-run", action="store_true", help="report only, no write")
    en.set_defaults(func=cmd_enable)

    mi = sub.add_parser("migrate", help="copy legacy fact files into the resolved directory")
    mi.add_argument("--dry-run", action="store_true", help="report only, no copy")
    mi.add_argument("--prefer-newer", action="store_true",
                     help="on a conflict, copy when the legacy file is the newer one")
    mi.set_defaults(func=cmd_migrate)

    su = sub.add_parser(
        "stub-legacy",
        help="replace the legacy MEMORY.md with a pointer stub",
        description=STUB_LEGACY_HELP,
        epilog=STUB_LEGACY_HELP,
    )
    su.add_argument("--yes", action="store_true", help="required to actually write")
    su.set_defaults(func=cmd_stub_legacy)

    ch = sub.add_parser("check", help="lint the resolved directory's MEMORY.md")
    ch.set_defaults(func=cmd_check)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
