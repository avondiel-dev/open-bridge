#!/usr/bin/env python3
"""Refuse a control character in a string that becomes markup, CSS or a script.

THE SCAR, 2026-08-24. A stylesheet lived inside a Python triple-quoted string.
It carried the CSS escape for a middle dot, written as a backslash and `00B7`.
Python parses that literal long before a browser parses CSS, and a backslash
followed by two zeros is an OCTAL escape, so the value carried a real NUL byte.
The generated page carried it too, and `workload publish` then died inside
`subprocess` with "embedded null byte" -- an error naming neither CSS, nor the
stylesheet, nor the character. The source looked correct and was; it was correct
in the wrong language.

THE GENERAL FORM: an escape written for a TARGET language that sits inside a
HOST language literal and is consumed by the host first. In Python the traps are
octal (backslash then a digit), and the `x`, `u`, `U` and `N` escapes.

WHY THIS IS NARROW ON PURPOSE. It does not flag escapes, it flags OUTCOMES, and
only in strings that look like markup, a stylesheet or a script. A NUL used as a
field separator, an ANSI sequence written for a terminal, an escape inside a
regular expression: each has the right consumer and is correct. There is no
legitimate control character inside generated markup, which is why this can be a
hard gate rather than an advisory. A guard that cries wolf gets switched off,
and then it guards nothing.

Contract + regression suite: scripts/tests/test_generated_output_escapes.py
Rule: rules/visual-output.md, Gate 4.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

#: Tab, newline and carriage return are the control characters with a job in
#: text. Everything else below 0x20, plus DEL, is a defect here.
CTRL_OK = frozenset("\t\n\r")

#: What makes a string "generated output" rather than data. Deliberately broad:
#: a false negative is a missed defect, a false positive is only a review.
MARKERS = (
    "<!doctype", "<html", "<head", "<body", "<div", "<span", "<table", "<td",
    "<tr", "<th", "<style", "<script", "<svg", "<p>", "<h1", "<h2", "<meta",
    "<link", "<a ", "</", "content:", "font-size", "font-family", "background",
    "border-", "color:", "margin", "padding", "document.", "querySelector",
    "addEventListener", "classList",
)

SKIP_PARTS = (
    ".git", "__pycache__", "node_modules", ".venv", "venv", "site-packages",
    # Materialised copies of OTHER repositories. Not ours to police, and a
    # finding there is unfixable from here.
    "workspaces", "overlays",
)


def _offending(value: str) -> list[str]:
    """Control characters in `value`, ignoring ANSI sequences.

    An ESC that starts a `[` sequence is a terminal colour and belongs to a
    terminal. Stripping the pair rather than every ESC keeps a lone ESC (which
    is never intentional) visible.
    """
    probe = value.replace("\x1b[", "")
    bad = {c for c in probe
           if (ord(c) < 0x20 and c not in CTRL_OK) or ord(c) == 0x7F}
    return sorted(bad, key=ord)


def _is_output(value: str) -> bool:
    low = value.lower()
    return any(m in low for m in MARKERS)


def scan_file(path: Path) -> tuple[list[tuple[int, list[str], str]], str | None]:
    """Findings for one file, plus why it could not be read if it could not."""
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [], f"{type(exc).__name__}: {exc}"
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return [], f"SyntaxError: line {exc.lineno}"
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        value = node.value
        # The markup markers are what separate output from prose, and they do
        # the docstring exclusion for free: this file and its tests DESCRIBE the
        # defect in words, carry no control character, and are not flagged. A
        # separate docstring rule would have been a second mechanism for the
        # same job, and the two would disagree eventually.
        if not _is_output(value):
            continue
        bad = _offending(value)
        if not bad:
            continue
        first = min(value.index(c) for c in bad)
        out.append((node.lineno,
                    [f"U+{ord(c):04X}" for c in bad],
                    repr(value[max(0, first - 50):first + 50])))
    return out, None


def iter_python(targets: list[Path]):
    for target in targets:
        if target.is_file():
            yield target
            continue
        for path in sorted(target.rglob("*.py")):
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            yield path


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv[1:]] or [Path(__file__).resolve().parent.parent]
    read = 0
    findings: list[tuple[Path, int, list[str], str]] = []
    unreadable: list[tuple[Path, str]] = []
    for path in iter_python(targets):
        hits, why = scan_file(path)
        if why:
            unreadable.append((path, why))
            continue
        read += 1
        for lineno, ctrl, context in hits:
            findings.append((path, lineno, ctrl, context))

    for path, why in unreadable:
        print(f"  not read: {path} ({why})")

    if findings:
        print(f"{len(findings)} control character(s) in generated output "
              f"({read} file(s) read):\n")
        for path, lineno, ctrl, context in findings:
            print(f"  {path}:{lineno}  {', '.join(ctrl)}")
            print(f"      {context}")
        print("\nAn escape written for CSS, HTML or JS is read by Python FIRST.")
        print("Write the character itself, or double the backslash.")
        return 1

    print(f"clean: {read} file(s) read, no control characters in generated output"
          + (f", {len(unreadable)} not readable" if unreadable else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
