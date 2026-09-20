#!/usr/bin/env python3
"""Hold the six copies of the secret-reference grammar to one list.

`rules/secret-placement.md` is the source: a table of schemes, written for
people. Five other places carry the same list in machine form, and they carry it
as a literal rather than an import, on purpose:

* `skills/secrets/engine/refs.py` parses references, and the skill has to keep
  working when its directory is copied out of the repo on its own.
* `skills/workload/engine/model.py` refuses an `execution.env` value that is not
  a locator, and that skill is detachable for the same reason.
* `workflow/workloads/_schema.yaml` repeats the engine's pattern character for
  character, because a declaration is validated by both gates and they once
  disagreed: `--strict` reported clean on what the plain run refused.
* `scripts/overlay.py` skips a locator when it scans for raw secrets. A scheme
  missing there is not a false alarm, it is a value that never gets reported.
* `identity/accounts/_schema.yaml` tells the person writing an account file
  which spellings exist.

So the copies are deliberate and the drift is not. Measured on 2026-09-20,
before this check ran for the first time: the rule named four schemes, the
overlay accepted six of which one was not in the rule, the workload accepted six
including a different one, and the account TEMPLATE used a seventh, `keeper://`,
that no list defined at all.

    python3 scripts/check-secret-grammar.py            # compare, report, exit non-zero on drift
    python3 scripts/check-secret-grammar.py --json     # the same as data
    python3 scripts/check-secret-grammar.py --mutate   # prove the comparison bites
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[1]

RULE = "rules/secret-placement.md"

#: A scheme that appears in the rule table only as prose, never as a locator a
#: machine has to accept. None today; the hook exists so a future documented
#: example does not have to become a parser rule.
RULE_ONLY: set = set()


@dataclass(frozen=True)
class Source:
    """One place that carries the list, and how to read it out of the text."""

    name: str
    path: str
    read: Callable[[str], set]
    #: A copy that may legitimately hold FEWER schemes than the rule, with the
    #: reason. Nothing may hold MORE: a scheme no rule names is the `keeper://`
    #: case, and that one sat in a template for months.
    may_lag: str = ""


def schemes_in_rule(text: str) -> set:
    """Every scheme spelled as a locator inside the rule's table."""
    found = set()
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        for match in re.finditer(r"`([a-z0-9][a-z0-9-]*)://", line):
            found.add(match.group(1))
    return found - RULE_ONLY


def schemes_in_refs(text: str) -> set:
    """`SchemeSpec("name", ...)` plus the ALIASES mapping of the skill."""
    found = set(re.findall(r'SchemeSpec\(\s*"([a-z0-9-]+)"', text))
    aliases = re.search(r"ALIASES\s*=\s*\{([^}]*)\}", text)
    if aliases:
        found |= set(re.findall(r'"([a-z0-9-]+)"\s*:', aliases.group(1)))
    return found


def schemes_in_tuple(text: str) -> set:
    """The `SECRET_URI_PREFIXES` tuple of the overlay."""
    match = re.search(r"SECRET_URI_PREFIXES\s*=\s*\(([^)]*)\)", text, re.DOTALL)
    if not match:
        return set()
    return set(re.findall(r'"([a-z0-9-]+)://"', match.group(1)))


def schemes_in_env_pattern(text: str) -> set:
    """The alternation inside the one `://` pattern of a file."""
    match = re.search(r"\^\(([a-z0-9|-]+)\)://", text)
    if not match:
        return set()
    return {part for part in match.group(1).split("|") if part}


def schemes_in_comment_block(text: str) -> set:
    """Locators written in a comment block, as the account schema does."""
    return set(re.findall(r"#\s+([a-z0-9][a-z0-9-]*)://", text))


SOURCES = (
    Source("secrets skill parser", "skills/secrets/engine/refs.py", schemes_in_refs),
    Source("overlay leak check", "scripts/overlay.py", schemes_in_tuple),
    Source("workload engine", "skills/workload/engine/model.py", schemes_in_env_pattern),
    Source("workload schema", "workflow/workloads/_schema.yaml", schemes_in_env_pattern),
    Source("account schema notes", "identity/accounts/_schema.yaml", schemes_in_comment_block,
           may_lag="advisory prose for a person writing an account file"),
)


def read(path: str, repo: Path) -> str:
    full = repo / path
    if not full.exists():
        return ""
    return full.read_text(encoding="utf-8")


def compare(repo: Path = REPO) -> tuple[dict, list]:
    """The measured lists, and one line per disagreement."""
    canonical = schemes_in_rule(read(RULE, repo))
    measured = {"rule": sorted(canonical)}
    problems = []
    if not canonical:
        problems.append(f"{RULE}: no scheme table found, so nothing can be compared against it")

    for source in SOURCES:
        text = read(source.path, repo)
        if not text:
            problems.append(f"{source.path}: missing, and {source.name} is supposed to carry the list")
            measured[source.name] = []
            continue
        found = source.read(text)
        measured[source.name] = sorted(found)
        extra = found - canonical
        missing = canonical - found
        if extra:
            problems.append(
                f"{source.path}: accepts {', '.join(sorted(extra))} which {RULE} does not list. "
                f"A scheme no rule names is the keeper:// case: written down, resolved by nothing."
            )
        if missing and not source.may_lag:
            problems.append(
                f"{source.path}: does not carry {', '.join(sorted(missing))}, which {RULE} lists. "
                f"{_why_missing_matters(source)}"
            )
    return measured, problems


def _why_missing_matters(source: Source) -> str:
    if "overlay" in source.path:
        return "A locator this list does not know is scanned as if it were a value."
    if "workload" in source.path:
        return "A declaration using it is refused by one gate and accepted by the other."
    return "A reference using it parses here and not there."


def render(measured: dict, problems: list) -> str:
    width = max(len(name) for name in measured)
    lines = []
    for name, schemes in measured.items():
        lines.append(f"{name.ljust(width)}  {len(schemes):>2}  {' '.join(schemes)}")
    lines.append("")
    if problems:
        lines.append(f"{len(problems)} disagreement(s):")
        lines.extend(f"  - {problem}" for problem in problems)
    else:
        lines.append("every copy carries the list in rules/secret-placement.md")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# --mutate: the proof over the proof
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Needle:
    name: str
    path: str
    search: str
    replace: str
    scar: str


NEEDLES = (
    Needle("a scheme drops out of the overlay skip list",
           "scripts/overlay.py", '"keepass://", ', "",
           "keepass:// was missing here from the day it was documented, so a keepass "
           "reference in a consumer file was scanned as if it might be a value."),
    Needle("the workload engine widens its closed list",
           "skills/workload/engine/model.py", "|keepass|", "|keepass|keeper|",
           "A scheme in the engine that the rule does not name is a locator nothing resolves."),
    Needle("the schema copy drifts from the engine",
           "workflow/workloads/_schema.yaml", "|keepass|", "|",
           "The schema and the engine disagreed once already: --strict reported clean on "
           "a declaration the plain run refuses."),
    Needle("the skill parser loses a scheme",
           "skills/secrets/engine/refs.py", 'SchemeSpec("keepass"', 'SchemeSpec("keepazz"',
           "A reference that the rule documents and the parser does not know fails at "
           "resolve time, in a wrapper script, at start, on a machine nobody is watching."),
)


def mutate(repo: Path = REPO) -> int:
    """Soften one copy at a time, in memory, and demand that the check goes red."""
    failures = 0
    for needle in NEEDLES:
        text = read(needle.path, repo)
        if text.count(needle.search) != 1:
            print(f"GREEN (anchor gone)  {needle.name}: {needle.search!r} appears "
                  f"{text.count(needle.search)} times in {needle.path}, so this needle "
                  f"has been proving nothing")
            failures += 1
            continue
        target = repo / needle.path
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace(needle.search, needle.replace, 1), encoding="utf-8")
        try:
            _, problems = compare(repo)
        finally:
            target.write_text(original, encoding="utf-8")
        if problems:
            print(f"red   {needle.name}")
        else:
            print(f"GREEN {needle.name}: the check did not notice. {needle.scar}")
            failures += 1
    print("")
    print(f"{len(NEEDLES)} needles, {len(NEEDLES) - failures} bit")
    return 1 if failures else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine readable output")
    parser.add_argument("--mutate", action="store_true",
                        help="soften each copy in turn and demand that this check goes red")
    parser.add_argument("--repo", default=str(REPO), help="repository root (default: this one)")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()

    if args.mutate:
        return mutate(repo)

    measured, problems = compare(repo)
    if args.json:
        print(json.dumps({"schemes": measured, "problems": problems}, indent=2))
    else:
        print(render(measured, problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
