#!/usr/bin/env python3
"""Hold the three plaintext-secret pattern sets to one list.

`skills/secrets/engine/patterns.py` is the source. Two other places scan for the
same thing and each carries its own copy, on purpose:

* `scripts/overlay.py` (`RAW_SECRET_PATTERNS`) refuses to write a raw secret
  into a file an overlay consumer receives. It runs inside a script that has to
  work without the skill.
* `rules/promote-safety.md` is read by whoever, or whatever, reviews a promote.
  It is prose with a table, because its reader is sometimes a person.

Measured on 2026-09-20, before this check existed, the three had drifted in
every direction: the promote table had no `AIza` and no `github_pat_`, the
overlay list had neither of those and no `Bearer`, and a third list lived in an
instance-only rule that never reached CORE at all and was the only one that knew
about personal data.

The comparison is by MARKER, not by regular expression. Two scanners can spell
the same pattern differently and both be right; what matters is that neither is
blind to a shape the other knows. Each pattern declares which copies must carry
it, because not every pattern belongs everywhere: the overlay scan deliberately
runs no key-and-value heuristic over code, and a promote scan is not where
personal data is decided.

    python3 scripts/check-secret-patterns.py            # compare, exit non-zero on a gap
    python3 scripts/check-secret-patterns.py --json
    python3 scripts/check-secret-patterns.py --mutate   # prove the comparison bites
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[1]

SOURCE = "skills/secrets/engine/patterns.py"
OVERLAY = "scripts/overlay.py"
PROMOTE = "rules/promote-safety.md"


def load_patterns(repo: Path = REPO):
    """The source list, imported from the skill by path.

    The skill must not import from the repo, because it has to keep working
    when its directory is copied out alone. The other direction is fine: this
    script belongs to the repo and may read the skill.
    """
    spec = importlib.util.spec_from_file_location("ob_secret_patterns", repo / SOURCE)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{SOURCE} is not importable, and it is the source of this list")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def overlay_block(text: str) -> str:
    """Just the `RAW_SECRET_PATTERNS` list, so an unrelated mention does not count."""
    # To the closing bracket at the START of a line. A non-greedy match to the
    # first `]` stops inside `[A-Z ]*PRIVATE KEY`, which made this extractor
    # report one pattern where there are eight, and the check green where it
    # should have been loud.
    match = re.search(r"RAW_SECRET_PATTERNS\s*=\s*\[\n(.*?)^\]", text, re.DOTALL | re.MULTILINE)
    return match.group(1) if match else ""


def promote_block(text: str) -> str:
    """The universal-pattern table of the promote rule."""
    match = re.search(r"### Hardcoded universal patterns.*?(?=\n### |\Z)", text, re.DOTALL)
    return match.group(0) if match else ""


@dataclass(frozen=True)
class Copy:
    name: str
    path: str
    extract: Callable[[str], str]


COPIES = (
    Copy("overlay", OVERLAY, overlay_block),
    Copy("promote", PROMOTE, promote_block),
)


def compare(repo: Path = REPO) -> tuple[dict, list]:
    patterns = load_patterns(repo)
    measured: dict = {"source": [p.marker for p in patterns.ALL]}
    problems: list = []

    for copy in COPIES:
        path = repo / copy.path
        if not path.exists():
            problems.append(f"{copy.path}: missing, and it is supposed to carry this list")
            measured[copy.name] = []
            continue
        block = copy.extract(path.read_text(encoding="utf-8"))
        if not block.strip():
            problems.append(f"{copy.path}: the pattern block was not found, so nothing was compared")
            measured[copy.name] = []
            continue
        carried, missing = [], []
        for pattern in patterns.ALL:
            if copy.name not in pattern.copies:
                continue
            spellings = (pattern.marker, *getattr(pattern, "aliases", ()))
            if any(spelling in block for spelling in spellings):
                carried.append(pattern.marker)
            else:
                missing.append(pattern)
        measured[copy.name] = carried
        for pattern in missing:
            problems.append(
                f"{copy.path}: does not know {pattern.name} ({pattern.marker!r}). "
                + (pattern.note or "a shape the other scanners catch and this one walks past."))
    return measured, problems


def render(measured: dict, problems: list) -> str:
    width = max(len(name) for name in measured)
    lines = [f"{name.ljust(width)}  {len(markers):>2}  {' '.join(markers)}"
             for name, markers in measured.items()]
    lines.append("")
    if problems:
        lines.append(f"{len(problems)} gap(s):")
        lines.extend(f"  - {problem}" for problem in problems)
    else:
        lines.append(f"every copy carries the patterns {SOURCE} declares for it")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# --mutate
# ---------------------------------------------------------------------------

NEEDLES = (
    ("the overlay scan loses the Google key", OVERLAY, "AIza", "AIzz",
     "AIza was missing here and in the promote table, and known only to a rule that never left one instance."),
    ("the overlay scan loses the fine-grained GitHub token", OVERLAY, "github_pat_", "github_pzt_",
     "the newer GitHub format, which the older prefix pattern does not match."),
    ("the promote table loses the AWS key", PROMOTE, "AKIA", "AKIZ",
     "the shape that is in every leaked-credential list there is."),
)


def mutate(repo: Path = REPO) -> int:
    failures = 0
    for name, path, search, replace, scar in NEEDLES:
        target = repo / path
        text = target.read_text(encoding="utf-8")
        if text.count(search) < 1:
            print(f"GREEN (anchor gone)  {name}: {search!r} is not in {path} any more")
            failures += 1
            continue
        original = text
        target.write_text(text.replace(search, replace), encoding="utf-8")
        try:
            _, problems = compare(repo)
        finally:
            target.write_text(original, encoding="utf-8")
        if problems:
            print(f"red   {name}")
        else:
            print(f"GREEN {name}: the check did not notice. {scar}")
            failures += 1
    print("")
    print(f"{len(NEEDLES)} needles, {len(NEEDLES) - failures} bit")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--mutate", action="store_true",
                        help="soften a copy and demand that this check goes red")
    parser.add_argument("--repo", default=str(REPO))
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()

    if args.mutate:
        return mutate(repo)

    measured, problems = compare(repo)
    if args.json:
        print(json.dumps({"markers": measured, "problems": problems}, indent=2))
    else:
        print(render(measured, problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
