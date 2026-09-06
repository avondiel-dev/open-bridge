#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Every inline script on every page in docs/ has to parse.

These pages are hand authored with no build step, so nothing between the editor
and the browser ever looks at the JavaScript. A broken inline script fails
silently: the block simply never runs, and the page still renders, still passes
an HTML well formedness check, and still looks right in a screenshot taken after
the rest of the page has drawn.

That is not hypothetical. A duplicated `try{` once killed the pre paint block on
eight pages at the same time, taking the theme AND the language with it, and it
survived an HTML parse check, a per page render, and a node --check that only
ever looked at the last script in the file.

Uses a real HTML parser rather than a regular expression, because `<script` also
appears inside CSS comments and inside strings, and a regex finds those too.

Run: python3 scripts/check-inline-scripts.py
"""
from __future__ import annotations

import html.parser
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"


class Scripts(html.parser.HTMLParser):
    """Collect the body of every <script> that has no src."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.found: list[tuple[int, str]] = []
        self._in = False
        self._line = 0
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        if any(k.lower() == "src" for k, _ in attrs):
            return
        typ = next((v for k, v in attrs if k.lower() == "type"), None)
        # a type we cannot run is not JavaScript and not ours to judge
        if typ and typ.lower() not in ("text/javascript", "module", "application/javascript"):
            return
        self._in = True
        self._line = self.getpos()[0]
        self._buf = []

    def handle_data(self, data):
        if self._in:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in:
            self.found.append((self._line, "".join(self._buf)))
            self._in = False


def check(body: str) -> str | None:
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(body)
        path = f.name
    try:
        r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
        if r.returncode == 0:
            return None
        for line in r.stderr.splitlines():
            if "SyntaxError" in line:
                return line.strip()
        return r.stderr.strip().splitlines()[0] if r.stderr.strip() else "node --check failed"
    finally:
        Path(path).unlink(missing_ok=True)


def main() -> int:
    if subprocess.run(["node", "--version"], capture_output=True).returncode != 0:
        print("check-inline-scripts: node is not available, skipping", file=sys.stderr)
        return 0

    pages = sorted(p for p in DOCS.glob("*.html") if not p.name.startswith("_"))
    if not pages:
        print("check-inline-scripts: no pages found in docs/", file=sys.stderr)
        return 1

    total = broken = 0
    for page in pages:
        parser = Scripts()
        parser.feed(page.read_text(encoding="utf-8"))
        for line, body in parser.found:
            if not body.strip():
                continue
            total += 1
            err = check(body)
            if err:
                broken += 1
                print(f"{page.relative_to(REPO)}:{line}  {err}", file=sys.stderr)

    if broken:
        print(
            f"\n{broken} of {total} inline scripts do not parse. A script that does not "
            f"parse never runs, and the page will look fine anyway.",
            file=sys.stderr,
        )
        return 1

    print(f"check-inline-scripts: {total} inline scripts across {len(pages)} pages all parse")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
