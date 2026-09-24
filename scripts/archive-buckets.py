#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The archive plan for work/log.md: every period in it, oldest first.

    python3 scripts/archive-buckets.py                 # human-readable plan
    python3 scripts/archive-buckets.py --json           # machine-readable
    python3 scripts/archive-buckets.py --force          # include the open period

WHY THIS IS CODE AND NOT PROSE. `/archive` used to tell an agent to map each
day-block to a period bucket and pick "the oldest". Two things went wrong with
that. The arithmetic is ISO-week arithmetic, which is got wrong by hand and by
shell alike: `date -j -f` with a stray token silently yields an empty week, and
the caller then sees no buckets rather than an error. And "the oldest" meant a
single one, so a log holding twelve periods archived one and reset the rest away.
Both are properties of a plan, so the plan is computed once, here, and the
workflow reads it.

THE YEAR COMES FROM THE ROWS, NOT FROM TODAY. A day-block header is `## Mon 14.04`
with no year on purpose. The rows inside it carry a full `| YYYY-MM-DD HH:MM |`
stamp, which is exactly why that format was frozen: the log self-dates. So each
block takes its year from its own first row, then from the file header's year,
and only then from today. Guessing the current year turns every January archive
of a December period into a block a year in the future.

Contract: scripts/tests/test_archive_buckets.py
"""
from __future__ import annotations

import argparse
import calendar
import datetime as _dt
import json
import re
import sys
from pathlib import Path

CADENCES = ("weekly", "bi-weekly", "monthly", "quarterly", "yearly")
DEFAULT_CADENCE = "weekly"

#: `## <weekday-token> DD.MM`. The token is locale-driven (Mon / Mo / lun.) and
#: display-only — never parsed. See rules/language-policy.md.
BLOCK_RE = re.compile(r"^## \S+ (\d{2})\.(\d{2})(?:[^0-9.]|$)", re.M)
#: A worklog row, which carries the full date the header omits.
ROW_RE = re.compile(r"^\|\s*(\d{4})-(\d{2})-(\d{2})[ T]", re.M)
#: A year in the file header, e.g. `# Week 27 — 2026-06-29 to 2026-07-05`.
HEADER_YEAR_RE = re.compile(r"^#\s+.*?(\d{4})-\d{2}-\d{2}", re.M)


def resolve_cadence(raw: object) -> str:
    """A recognised cadence, else the historical default.

    Never raises on a typo: an unrecognised value behaves as `weekly`, which is
    what an untouched config did before the key existed.
    """
    return raw if isinstance(raw, str) and raw in CADENCES else DEFAULT_CADENCE


def bucket_of(date: _dt.date, cadence: str) -> tuple:
    """An opaque, ORDERABLE key for the period `date` falls in.

    Ordering is what the caller needs (oldest first, and "is this one closed"),
    so every variant returns a tuple that sorts chronologically.
    """
    iso_year, iso_week, _ = date.isocalendar()
    if cadence == "weekly":
        return ("w", iso_year, iso_week)
    if cadence == "bi-weekly":
        # Odd week starts the pair, so weeks 27+28 share a bucket. Week 53 is
        # odd and has no partner: it stands alone (see _has_week).
        return ("w2", iso_year, iso_week if iso_week % 2 else iso_week - 1)
    if cadence == "monthly":
        return ("m", date.year, date.month)
    if cadence == "quarterly":
        return ("q", date.year, (date.month - 1) // 3 + 1)
    return ("y", date.year)


def _has_week(year: int, week: int) -> bool:
    """True if ISO `year` has a week `week` (52 or 53 weeks, never 54)."""
    try:
        _dt.date.fromisocalendar(year, week, 1)
        return True
    except ValueError:
        return False


def describe(key: tuple, cadence: str) -> dict:
    """Label, directory, filename stem and period bounds for one bucket key.

    `start`/`end` are the PERIOD, inclusive, not the first and last day-block:
    a commit on a day without a log row still belongs to the period.
    """
    if cadence == "weekly":
        _, y, w = key
        start = _dt.date.fromisocalendar(y, w, 1)
        return {"label": f"Week {w}", "dir": "work/archive/weeks", "stem": f"{y}-W{w:02d}",
                "start": start.isoformat(), "end": (start + _dt.timedelta(days=6)).isoformat()}
    if cadence == "bi-weekly":
        _, y, w = key
        start = _dt.date.fromisocalendar(y, w, 1)
        if not _has_week(y, w + 1):
            # ISO week 53: there is no week 54 to pair it with.
            return {"label": f"Week {w}", "dir": "work/archive/weeks", "stem": f"{y}-W{w:02d}",
                    "start": start.isoformat(),
                    "end": (start + _dt.timedelta(days=6)).isoformat()}
        return {"label": f"Weeks {w}+{w + 1}", "dir": "work/archive/weeks",
                "stem": f"{y}-W{w:02d}+W{w + 1:02d}",
                "start": start.isoformat(), "end": (start + _dt.timedelta(days=13)).isoformat()}
    if cadence == "monthly":
        _, y, m = key
        name = _dt.date(y, m, 1).strftime("%B")
        last = calendar.monthrange(y, m)[1]
        return {"label": f"{name} {y}", "dir": "work/archive/months", "stem": f"{y}-{m:02d}",
                "start": _dt.date(y, m, 1).isoformat(), "end": _dt.date(y, m, last).isoformat()}
    if cadence == "quarterly":
        _, y, q = key
        m_end = q * 3
        return {"label": f"Q{q} {y}", "dir": "work/archive/quarters", "stem": f"{y}-Q{q}",
                "start": _dt.date(y, m_end - 2, 1).isoformat(),
                "end": _dt.date(y, m_end, calendar.monthrange(y, m_end)[1]).isoformat()}
    _, y = key
    return {"label": f"{y}", "dir": "work/archive/years", "stem": f"{y}",
            "start": _dt.date(y, 1, 1).isoformat(), "end": _dt.date(y, 12, 31).isoformat()}


def _blocks(text: str):
    """Each day-block as (dd, mm, body), in file order."""
    out = []
    marks = list(BLOCK_RE.finditer(text))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append((m.group(1), m.group(2), text[m.end():end]))
    return out


def plan(text: str, cadence: str, today: _dt.date, force: bool = False) -> list[dict]:
    """Every period present in `text`, oldest first.

    A block whose DD.MM is not a real date is skipped rather than guessed at:
    `## Mon 31.02` is a typo, and inventing March 3rd for it would file real rows
    under a period they do not belong to.
    """
    header_year = None
    hm = HEADER_YEAR_RE.search(text)
    if hm:
        header_year = int(hm.group(1))

    buckets: dict[tuple, dict] = {}
    for dd, mm, body in _blocks(text):
        rows = ROW_RE.findall(body)
        if rows:
            year = int(rows[0][0])
        elif header_year is not None:
            year = header_year
        else:
            year = today.year
        try:
            date = _dt.date(year, int(mm), int(dd))
        except ValueError:
            continue
        if not rows and date > today:
            # A GUESSED year (header or today) that lands in the future is last
            # year's block: `## Mon 28.12` under a January header. A year a row
            # states is never second-guessed.
            try:
                date = _dt.date(year - 1, int(mm), int(dd))
            except ValueError:
                continue
        key = bucket_of(date, cadence)
        b = buckets.setdefault(key, {"key": key, "day_blocks": [], "rows": 0,
                                     "first": date, "last": date})
        b["day_blocks"].append(f"{dd}.{mm}")
        b["rows"] += len(rows)
        b["first"] = min(b["first"], date)
        b["last"] = max(b["last"], date)

    now_key = bucket_of(today, cadence)
    out = []
    for key in sorted(buckets):
        b = buckets[key]
        closed = key < now_key
        if not closed and not force:
            # The open period stays in the log. It is not a candidate, and saying
            # so explicitly is what lets a caller report "nothing closed" rather
            # than "nothing found".
            out.append({**describe(key, cadence), "closed": False, "archive": False,
                        "day_blocks": b["day_blocks"], "rows": b["rows"],
                        "first": b["first"].isoformat(), "last": b["last"].isoformat()})
            continue
        out.append({**describe(key, cadence), "closed": closed, "archive": True,
                    "day_blocks": b["day_blocks"], "rows": b["rows"],
                    "first": b["first"].isoformat(), "last": b["last"].isoformat()})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", default="work/log.md")
    ap.add_argument("--config", default="bridge-config.yaml")
    ap.add_argument("--cadence", help="override the configured cadence")
    ap.add_argument("--today", help="YYYY-MM-DD, for tests")
    ap.add_argument("--force", action="store_true",
                    help="also archive the current, unfinished period")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    log = Path(a.log)
    if not log.exists():
        sys.stderr.write(f"archive-buckets: no log at {a.log}\n")
        return 2
    cadence = a.cadence
    if not cadence:
        raw = None
        cfg = Path(a.config)
        if cfg.exists():
            try:
                import yaml
                data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
                raw = (data.get("work") or {}).get("archive_cadence")
            except Exception as exc:
                # Falling back to weekly is right; doing it silently is not. A
                # monthly instance would otherwise get weekly files without a word.
                sys.stderr.write(f"archive-buckets: could not read work.archive_cadence "
                                 f"from {a.config} ({type(exc).__name__}: {exc}); "
                                 f"using weekly. Pass --cadence to override.\n")
                raw = None
        cadence = resolve_cadence(raw)
    else:
        cadence = resolve_cadence(cadence)

    today = _dt.date.fromisoformat(a.today) if a.today else _dt.date.today()
    rows = plan(log.read_text(encoding="utf-8"), cadence, today, a.force)

    if a.json:
        print(json.dumps({"cadence": cadence, "today": today.isoformat(),
                          "buckets": rows}, indent=2))
        return 0

    todo = [r for r in rows if r["archive"]]
    print(f"cadence: {cadence} · today: {today.isoformat()}")
    if not rows:
        print("  no day-blocks in the log")
        return 0
    for r in rows:
        mark = "archive" if r["archive"] else "OPEN, stays"
        print(f"  {r['label']:<14} {r['rows']:>3} rows  {r['dir']}/{r['stem']}.md  "
              f"[{mark}]  {', '.join(r['day_blocks'])}")
    print(f"\n  {len(todo)} period(s) to archive in ONE run, "
          f"{sum(r['rows'] for r in todo)} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
