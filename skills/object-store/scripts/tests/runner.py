#!/usr/bin/env python3
"""Run the suite and report one line per case, taken from unittest's own result.

Why this exists instead of reading unittest's verbose transcript (the way the
secrets skill does with tally.awk): the transcript puts every verdict on stderr,
and so does everything else that writes to stderr, a ResourceWarning emitted by
the garbage collector at whatever moment it runs included. On CI (Linux) one
such write landed in the middle of a verdict line and the tally lost that case:
63 ran, 62 were counted. On macOS the same suite counted all 63. A tally that
parses a shared stream can only be as reliable as the timing of the garbage
collector.

So the verdicts come from a TestResult, one line per case on STDOUT, flushed as
it happens. Warnings and anything else stay on stderr. Nothing can split a
verdict line because nothing else writes to that stream.

    runner.py [pattern]     exit 0 only when something ran and nothing failed
"""

from __future__ import annotations

import sys
import unittest
import warnings

# Surface leaks where they can be read, on stderr, instead of letting them
# vanish; they never touch the verdict stream.
warnings.simplefilter("default", ResourceWarning)


def _name(test) -> str:
    ident = test.id()
    return ident[len("tests."):] if ident.startswith("tests.") else ident


class Recorder(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.verdicts: dict[str, str] = {}

    def _record(self, test, verdict: str) -> None:
        name = _name(test)
        if name in self.verdicts:      # a failing subtest already spoke for this case
            return
        self.verdicts[name] = verdict
        print(f"  {verdict:<5} {name}", flush=True)

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, "ok")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "ERROR")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, "skip")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._record(test, "FAIL")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, "FAIL")


def main(argv: list) -> int:
    loader = unittest.TestLoader()
    if argv and argv[0]:
        loader.testNamePatterns = [f"*{argv[0]}*"]
    suite = loader.discover("tests", top_level_dir=".")
    result = Recorder()
    suite.run(result)

    counts = {v: list(result.verdicts.values()).count(v) for v in ("ok", "FAIL", "ERROR", "skip")}
    bad = counts["FAIL"] + counts["ERROR"]
    ran = result.testsRun
    print()
    if ran == 0:
        print("no test cases were collected, which is itself a failure")
        return 1
    if len(result.verdicts) != ran:
        print(f"{len(result.verdicts)} verdicts for {ran} cases; a case without a verdict proves nothing")
        return 1
    if bad:
        print(f"{bad} of {ran} FAILED")
    elif counts["ok"] == 0:
        print(f"0 of {ran} ran: every case was skipped, so this run says nothing")
        return 1
    elif counts["skip"]:
        print(f"{counts['ok']}/{ran} green, {counts['skip']} skipped")
    else:
        print(f"{counts['ok']}/{ran} green")
    if bad:
        print("\nfirst failures in detail:")
        for test, trace in (result.failures + result.errors)[:5]:
            print(f"--- {_name(test)}\n{trace}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
