"""The suite is a package, because the runner needs it to be one.

`run-tests.sh` starts `python3 -m unittest discover -s tests -t .`, and
discovery refuses a start directory it cannot import: on Python 3.14 the
message is "Start directory is not importable" and NOTHING is collected, which
the tally then reports as a run that says nothing rather than as a missing
file. The workload suite carries the same file for the same reason.

It also makes `from tests.conftest import ...` mean one module rather than
whatever a namespace package happens to resolve to when the suite is run from
another directory.
"""
