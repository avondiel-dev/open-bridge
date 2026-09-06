#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hold the CORE/USER figure on docs/explore.html to the actual tree.

The figure draws one dot per tracked file: 791 on the CORE half, 27 on the USER
half, split by top level folder. Those numbers are true on the commit that wrote
them and quietly false on the next merge, which is worse than shipping no number
at all. This recomputes every one of them from `git ls-files` and fails when the
page has drifted.

It checks the totals, the per folder counts inside both JS arrays, and the two
numbers spelled out in the visible captions.

    python3 scripts/check-figure-counts.py            # report drift, exit 1
    python3 scripts/check-figure-counts.py --write     # rewrite the page to match

A strict census on a moving tree goes red on the next commit that adds a file,
including the commit that added this script. That is the point, but a gate is
only worth its friction if clearing it is one command, so --write exists.
"""
from __future__ import annotations

import collections
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs/explore.html"
USER_PREFIX = "examples/agency/"

# The example instance keeps three sub-agent definitions under .claude/agents/.
# The figure counts them under the root rather than giving them a folder of
# their own: sub-agents are the one Claude Code specific piece in the system,
# and a .claude/ label on the USER half would read as "this only works with
# Claude" on a page whose whole claim is that it does not.
USER_FOLD = {".claude/": "./"}


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    if not out:
        sys.exit("check-figure-counts: git ls-files returned nothing")
    return out


def family(path: str) -> str:
    head, _, rest = path.partition("/")
    return "./" if not rest else head + "/"


def counted(files: list[str]) -> collections.Counter:
    return collections.Counter(family(f) for f in files)


def parse(block: str, key: str) -> dict[str, int]:
    """Pull {n:"<folder>", ... <key>:<n> ...} pairs out of one JS array."""
    found: dict[str, int] = {}
    for entry in re.finditer(r"\{[^{}]*\}", block):
        text = entry.group(0)
        name = re.search(r'n\s*:\s*"([^"]+)"', text)
        num = re.search(rf"\b{key}\s*:\s*(\d+)", text)
        if name and num:
            found[name.group(1)] = int(num.group(1))
    return found


def section(src: str, var: str) -> str:
    start = src.index("var " + var + " = [")
    return src[start:src.index("\n  ];", start)]


def rewrite(src: str, real_core: dict, real_user: dict, core_total: int, user_total: int) -> str:
    """Put the recomputed numbers back into the page, in place."""
    def fix_array(block: str, key: str, real: dict) -> str:
        def one(m: re.Match) -> str:
            text = m.group(0)
            name = re.search(r'n\s*:\s*"([^"]+)"', text)
            if not name or name.group(1) not in real:
                return text
            want = real[name.group(1)]
            return re.sub(rf"(\b{key}\s*:\s*)\d+", rf"\g<1>{want}", text, count=1)
        return re.sub(r"\{[^{}]*\}", one, block)

    for var, key, real in (("CORE_ONLY", "c", real_core),
                           ("PAIRS", "core", real_core),
                           ("PAIRS", "user", real_user)):
        block = section(src, var)
        src = src.replace(block, fix_array(block, key, real), 1)

    # the numbers a reader sees: captions, headers, screen reader text
    src = re.sub(r"\b\d+ files ship\. \d+ are yours\.",
                 f"{core_total} files ship. {user_total} are yours.", src)
    src = re.sub(r"\b\d+ Dateien kommen mit, \d+ sind deine\.",
                 f"{core_total} Dateien kommen mit, {user_total} sind deine.", src)
    src = re.sub(r'"\d+ Dateien, alle mitgeliefert" : "\d+ files, all shipped"',
                 f'"{core_total} Dateien, alle mitgeliefert" : "{core_total} files, all shipped"', src)
    src = re.sub(r'"\d+ Dateien, alle deine" : "\d+ files, all yours"',
                 f'"{user_total} Dateien, alle deine" : "{user_total} files, all yours"', src)
    src = re.sub(r"\b\d+ tracked files, one dot each", f"{core_total} tracked files, one dot each", src)
    src = re.sub(r"\b\d+ versionierte Dateien, je Datei ein Punkt",
                 f"{core_total} versionierte Dateien, je Datei ein Punkt", src)
    return src


def main() -> int:
    write = "--write" in sys.argv
    files = tracked()
    core_files = [f for f in files if not f.startswith("examples/")]
    user_files = [f[len(USER_PREFIX):] for f in files if f.startswith(USER_PREFIX)]

    core_real = counted(core_files)
    user_real = collections.Counter()
    for fam, n in counted(user_files).items():
        user_real[USER_FOLD.get(fam, fam)] += n

    src = PAGE.read_text(encoding="utf-8")
    pairs = section(src, "PAIRS")
    core_only = section(src, "CORE_ONLY")

    drawn_core = parse(core_only, "c")
    drawn_core.update(parse(pairs, "core"))
    drawn_user = parse(pairs, "user")

    problems: list[str] = []

    for label, drawn, real in (("CORE", drawn_core, core_real),
                               ("USER", drawn_user, user_real)):
        for fam, n in sorted(drawn.items()):
            if real.get(fam, 0) != n:
                problems.append(
                    f"{label} {fam}: figure says {n}, tree has {real.get(fam, 0)}"
                )
        for fam, n in sorted(real.items()):
            if fam not in drawn:
                problems.append(f"{label} {fam}: {n} files in the tree, not drawn")

    core_total, user_total = len(core_files), len(user_files)
    if sum(drawn_core.values()) != core_total:
        problems.append(
            f"CORE total: figure sums to {sum(drawn_core.values())}, tree has {core_total}"
        )
    if sum(drawn_user.values()) != user_total:
        problems.append(
            f"USER total: figure sums to {sum(drawn_user.values())}, tree has {user_total}"
        )

    # every example path the figure names has to be a file that exists. A
    # renamed skill would otherwise leave a dead path on a public page, and the
    # page is making a point about claims being checkable.
    tracked_set = set(files)
    for m in re.finditer(r'\b(?:ex|cex|uex)\s*:\s*\[([^\]]*)\]', src):
        for raw in re.findall(r'"([^"]+)"', m.group(1)):
            path = raw if raw in tracked_set else USER_PREFIX + raw
            if path not in tracked_set:
                problems.append(f"example path not in the tree: {raw}")

    # the two numbers a reader actually sees, in both languages
    for phrase in (f"{core_total} files ship. {user_total} are yours.",
                   f"{core_total} Dateien kommen mit, {user_total} sind deine."):
        if phrase not in src:
            problems.append(f"caption missing or stale: {phrase!r}")

    if problems and write:
        PAGE.write_text(
            rewrite(src, dict(core_real), dict(user_real), core_total, user_total),
            encoding="utf-8",
        )
        print(f"docs/explore.html rewritten: {len(problems)} number(s) brought back to the tree.")
        print("Re-run without --write to confirm, and read the diff before committing:")
        for p in problems:
            print(f"  {p}")
        return 0

    if problems:
        print("docs/explore.html has drifted from the tree:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            "\nRun `python3 scripts/check-figure-counts.py --write` to bring the page "
            "back to the tree, then read the diff.",
            file=sys.stderr,
        )
        return 1

    print(
        f"docs/explore.html matches the tree: CORE {core_total} in "
        f"{len(drawn_core)} folders, USER {user_total} in {len(drawn_user)}, "
        f"{len(re.findall(chr(34), src))//2 and sum(len(re.findall(chr(34)+'([^'+chr(34)+']+)'+chr(34), m.group(1))) for m in re.finditer(r'\b(?:ex|cex|uex)\s*:\s*\[([^\]]*)\]', src))} example paths all present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
