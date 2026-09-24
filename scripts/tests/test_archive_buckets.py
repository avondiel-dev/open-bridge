# SPDX-License-Identifier: MIT
"""Contract for scripts/archive-buckets.py — the archive plan for work/log.md.

The defect these pin: /archive used to take "the oldest bucket with content" and
reset the whole log, so a log holding twelve periods archived one and lost eleven.
The plan therefore has to name EVERY period, mark which are closed, and leave the
open one in the log.

The second defect: the arithmetic. ISO weeks by hand, or through `date -j -f`, come
out empty on a stray token, and an empty answer reads as "nothing to archive"
rather than as an error. So the bucketing is tested here rather than trusted.

Run: python3 -m pytest scripts/tests/test_archive_buckets.py -q
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "archive_buckets", REPO / "scripts" / "archive-buckets.py"
)
assert _spec and _spec.loader, "cannot load scripts/archive-buckets.py"
ab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ab)

TODAY = dt.date(2026, 9, 24)          # KW 39


def log(*blocks: str, header: str = "# Week 27 — 2026-06-29 to 2026-07-05") -> str:
    return header + "\n\n" + "\n\n".join(blocks) + "\n"


def block(weekday: str, dd: str, mm: str, *stamps: str) -> str:
    rows = "\n".join(f"| {s} | 💻 | x | y |" for s in stamps)
    return f"## {weekday} {dd}.{mm}\n\n{rows}"


def labels(rows):
    return [r["label"] for r in rows]


def to_archive(rows):
    return [r for r in rows if r["archive"]]


# --------------------------------------------------------------- the main defect

def test_every_closed_period_is_planned_not_only_the_oldest():
    text = log(
        block("Mon", "06", "07", "2026-07-06 09:00"),          # KW 28
        block("Mon", "13", "07", "2026-07-13 09:00"),          # KW 29
        block("Wed", "19", "08", "2026-08-19 09:00"),          # KW 34
    )
    rows = to_archive(ab.plan(text, "weekly", TODAY))
    assert labels(rows) == ["Week 28", "Week 29", "Week 34"], (
        "one run must name every closed period; taking only the oldest is the "
        "bug that reset eleven periods away"
    )


def test_the_open_period_stays_in_the_log():
    text = log(block("Thu", "24", "09", "2026-09-24 09:00"))    # KW 39 == today
    rows = ab.plan(text, "weekly", TODAY)
    assert len(rows) == 1
    assert rows[0]["closed"] is False
    assert rows[0]["archive"] is False, "today's half-written period is not a candidate"


def test_force_takes_the_open_period_too():
    text = log(block("Thu", "24", "09", "2026-09-24 09:00"))
    rows = to_archive(ab.plan(text, "weekly", TODAY, force=True))
    assert labels(rows) == ["Week 39"]


def test_an_open_period_is_reported_rather_than_dropped():
    """Absent and present-but-open must not look the same to the caller."""
    text = log(
        block("Mon", "13", "07", "2026-07-13 09:00"),           # closed
        block("Thu", "24", "09", "2026-09-24 09:00"),           # open
    )
    rows = ab.plan(text, "weekly", TODAY)
    assert labels(rows) == ["Week 29", "Week 39"]
    assert [r["archive"] for r in rows] == [True, False]


# ------------------------------------------------------------------- the maths

# `today` moves per cadence on purpose: Q3 2026 and the year 2026 are the CURRENT
# period on 2026-09-24, so under those two cadences the same rows are open and
# must NOT be archived. Asserting otherwise was this file's own first bug, and
# the script was right.
@pytest.mark.parametrize("cadence,today,expected", [
    ("weekly",    dt.date(2026, 9, 24),  ["Week 29", "Week 31", "Week 34"]),
    ("monthly",   dt.date(2026, 9, 24),  ["July 2026", "August 2026"]),
    ("quarterly", dt.date(2026, 11, 1),  ["Q3 2026"]),
    ("yearly",    dt.date(2027, 1, 5),   ["2026"]),
])
def test_cadence_decides_only_the_timeframe_a_file_covers(cadence, today, expected):
    text = log(
        block("Mon", "13", "07", "2026-07-13 09:00"),
        block("Mon", "27", "07", "2026-07-27 09:00"),
        block("Wed", "19", "08", "2026-08-19 09:00"),
    )
    assert labels(to_archive(ab.plan(text, cadence, today))) == expected


@pytest.mark.parametrize("cadence,today", [
    ("quarterly", dt.date(2026, 9, 24)),
    ("yearly",    dt.date(2026, 9, 24)),
])
def test_a_long_cadence_leaves_the_current_period_open(cadence, today):
    """A 40-week log is not overdue under `yearly`, which is the user's own setting."""
    text = log(block("Mon", "13", "07", "2026-07-13 09:00"))
    rows = ab.plan(text, cadence, today)
    assert [r["archive"] for r in rows] == [False]


def test_bi_weekly_pairs_on_the_odd_week():
    text = log(
        block("Mon", "06", "07", "2026-07-06 09:00"),           # KW 28
        block("Mon", "13", "07", "2026-07-13 09:00"),           # KW 29
        block("Mon", "20", "07", "2026-07-20 09:00"),           # KW 30
    )
    rows = to_archive(ab.plan(text, "bi-weekly", TODAY))
    assert labels(rows) == ["Weeks 27+28", "Weeks 29+30"]


def test_paths_and_stems_follow_the_cadence_table():
    text = log(block("Mon", "13", "07", "2026-07-13 09:00"))
    (w,) = to_archive(ab.plan(text, "weekly", dt.date(2026, 9, 24)))
    assert (w["dir"], w["stem"]) == ("work/archive/weeks", "2026-W29")
    (m,) = to_archive(ab.plan(text, "monthly", dt.date(2026, 9, 24)))
    assert (m["dir"], m["stem"]) == ("work/archive/months", "2026-07")
    (q,) = to_archive(ab.plan(text, "quarterly", dt.date(2026, 11, 1)))
    assert (q["dir"], q["stem"]) == ("work/archive/quarters", "2026-Q3")
    (y,) = to_archive(ab.plan(text, "yearly", dt.date(2027, 1, 5)))
    assert (y["dir"], y["stem"]) == ("work/archive/years", "2026")


def test_an_unrecognised_cadence_is_weekly_and_never_an_error():
    assert ab.resolve_cadence("fortnightly") == "weekly"
    assert ab.resolve_cadence(None) == "weekly"
    assert ab.resolve_cadence(7) == "weekly"


# --------------------------------------------------------------------- the year

def test_the_year_comes_from_the_rows_not_from_today():
    """A December period archived in January must not land a year ahead."""
    text = log(block("Mon", "29", "12", "2025-12-29 09:00"),
               header="# Week 1 — 2026-01-05 to 2026-01-11")
    rows = to_archive(ab.plan(text, "monthly", dt.date(2026, 1, 8)))
    assert labels(rows) == ["December 2025"], "the row said 2025; today said 2026"


def test_a_block_with_no_rows_falls_back_to_the_header_year():
    text = log("## Mon 13.07\n\n(no rows yet)",
               header="# Week 29 — 2026-07-13 to 2026-07-19")
    rows = to_archive(ab.plan(text, "weekly", TODAY))
    assert labels(rows) == ["Week 29"]


# ------------------------------------------------------------------- robustness

@pytest.mark.parametrize("token", ["Mon", "Mo", "lun.", "Do.", "週一"])
def test_the_weekday_token_is_display_only(token):
    """Locale-driven per rules/language-policy.md; the date comes from DD.MM."""
    text = log(block(token, "13", "07", "2026-07-13 09:00"))
    assert labels(to_archive(ab.plan(text, "weekly", TODAY))) == ["Week 29"]


def test_an_impossible_date_is_skipped_not_guessed():
    text = log(block("Mon", "31", "02", "2026-02-28 09:00"),
               block("Mon", "13", "07", "2026-07-13 09:00"))
    rows = to_archive(ab.plan(text, "weekly", TODAY))
    assert labels(rows) == ["Week 29"], "31.02 is a typo; inventing March 3rd files real rows wrong"


def test_an_empty_log_plans_nothing_and_does_not_raise():
    assert ab.plan("# Week 39 — 2026-09-21 to 2026-09-27\n", "weekly", TODAY) == []


def test_rows_are_counted_per_period():
    text = log(
        block("Mon", "13", "07", "2026-07-13 09:00", "2026-07-13 10:00"),
        block("Tue", "14", "07", "2026-07-14 09:00"),
        block("Wed", "19", "08", "2026-08-19 09:00"),
    )
    rows = to_archive(ab.plan(text, "weekly", TODAY))
    assert [(r["label"], r["rows"]) for r in rows] == [("Week 29", 3), ("Week 34", 1)]


def test_buckets_come_out_oldest_first():
    text = log(
        block("Wed", "19", "08", "2026-08-19 09:00"),
        block("Mon", "06", "07", "2026-07-06 09:00"),
        block("Mon", "13", "07", "2026-07-13 09:00"),
    )
    assert labels(to_archive(ab.plan(text, "weekly", TODAY))) == [
        "Week 28", "Week 29", "Week 34"], "file order is not chronological order"
