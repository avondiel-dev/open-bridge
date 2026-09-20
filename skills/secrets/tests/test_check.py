"""check: what a row is allowed to say, and what it may never say.

Three properties are measured here and nothing else is.

1. A ROW IS EVIDENCE, NOT A CLAIM. `security find-generic-password` exits 0 for
   an item that holds zero bytes, so "the entry is there" and "a value came
   back" are two different measurements and only the second one is green. The
   byte count and the fingerprint in an ok row are what makes the difference
   visible: a row with a fingerprint read something, a row without one did not.

2. A SESSION PROBLEM IS NOT A ROTATION PROBLEM. The same keychain item is
   readable from a desktop session and refused over ssh. `not readable here` and
   `missing` therefore have to stay apart in the report, because a daemon that
   reads the second one starts rotating a secret that was never gone.

3. NO VALUE REACHES THE TABLE. `render` prints references, lengths and
   fingerprints. Every case that builds a row from a real reading also asserts
   that the synthetic value behind it appears nowhere in the output, because the
   agent reading this table keeps it in context for the rest of the session.

Nothing here reaches a store. The keychain backend is driven through the
`runner=` seam with the stderr shapes `conftest.keychain_report` records, and
`engine.exec.which` is answered rather than consulted so that a Linux runner and
a Mac measure the same thing. `MachineGuard` refuses the real `security` binary
in either case.
"""

from __future__ import annotations

import json
from unittest import mock

from tests.conftest import (
    FakeRunner,
    MachineGuard,
    completed,
    keychain_attributes,
    keychain_report,
    mod,
    synthetic_token,
)

check_mod = mod("engine.check")
base = mod("engine.backends.base")
resolve = mod("engine.resolve")
values = mod("engine.values")

SERVICE = "suite-service"
ACCOUNT = "suite-account"
REF = "keychain://" + SERVICE + "/" + ACCOUNT

#: Assembled at runtime rather than pasted, so this tree holds no credential
#: shaped literal at all. Comfortably longer than `values.MIN_REDACTABLE`.
TOKEN = synthetic_token("check")  # pragma: allowlist secret

#: The scheme the grammar accepts and no backend in this Bridge answers. Taken
#: from `rules/secret-placement.md`, which tells people to write exactly this.
UNBACKED_REF = "azure-keyvault://suite-vault/suite-secret"

#: What `security` says when the session has no unlocked keychain. The exit code
#: is deliberately not 44: a refusal is not a miss, and the backend has to reach
#: the stderr check rather than stopping at the "no such item" code.
REFUSAL_STDERR = ("security: SecKeychainSearchCopyNext "
                  "(suite-service): User interaction is not allowed.")


def answers(stderr: str, rc: int = 0) -> FakeRunner:
    """A runner that answers the one keychain read this suite performs."""
    return FakeRunner().add(
        "find-generic-password",
        completed(rc=rc, stdout=keychain_attributes(SERVICE, ACCOUNT), stderr=stderr),
    )


def answers_with_value(value: str = TOKEN) -> FakeRunner:
    return answers(keychain_report(value=value))


def answers_empty() -> FakeRunner:
    """An item that exists and holds no bytes. The tool exits 0 for it."""
    return answers(keychain_report(empty=True))


def answers_missing() -> FakeRunner:
    """Exit code 44 is the only one that means "no such item"."""
    return answers("security: SecKeychainSearchCopyNext: The specified item "
                   "could not be found in the keychain.", rc=44)


def answers_refused() -> FakeRunner:
    return answers(REFUSAL_STDERR, rc=36)


def no_git() -> FakeRunner:
    """Discovery's git probe, answered so the walk is what gets measured.

    A temporary directory is not a git checkout, so `git ls-files` would fail
    there anyway. Answering it keeps the case off the real binary and off the
    question of whether this machine has git at all.
    """
    return FakeRunner().add("ls-files", completed(rc=1, stderr="not a git repository"))


class CheckCase(MachineGuard):
    """Shared wiring: a resolver over the seam, and a session to read from."""

    def desktop(self):
        """A logged-in Mac. The keychain backend answers in this session."""
        return base.Context(platform="darwin", interactive=True,
                            over_ssh=False, display=True)

    def over_ssh(self):
        """The same Mac, reached over ssh. Same entry, no unlocked keychain."""
        return base.Context(platform="darwin", interactive=False,
                            over_ssh=True, display=True)

    def security(self, present: bool = True):
        """Answer `which`, rather than asking the machine the suite runs on.

        `Backend.available()` consults `engine.exec.which`, so without this a
        case would report "no backend here" on a Linux runner and "ok" on a Mac
        for the same input. Patching the lookup is what makes the two agree.
        """
        answer = (lambda binary: "/usr/bin/" + binary) if present else (lambda binary: None)
        return mock.patch("engine.exec.which", answer)

    def resolver(self, runner, *, context=None, **options):
        return resolve.Resolver(resolve.Options(**options), runner=runner,
                                context=context or self.desktop())

    def row_for(self, runner, reference=REF, *, context=None, places=None, **options):
        with self.security():
            return check_mod.check_one(
                self.resolver(runner, context=context, **options), reference, places)

    def tree(self, files: dict):
        """A throwaway directory holding the given files, parents made as needed."""
        root = self.tmpdir()
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root


# ---------------------------------------------------------------------------
# ok
# ---------------------------------------------------------------------------

class AReadingThatCameBackCarriesItsOwnEvidence(CheckCase):
    """An ok row says how much was read and which value it was.

    Without those two fields "ok" is a claim about the code path rather than a
    measurement of the store, and the empty-entry case below is indistinguishable
    from it.
    """

    def test_the_status_is_ok(self):
        self.assertEqual(self.row_for(answers_with_value()).status, check_mod.OK)

    def test_the_row_reports_the_byte_count_the_store_returned(self):
        self.assertEqual(self.row_for(answers_with_value()).length, len(TOKEN))

    def test_the_row_carries_the_fingerprint_of_the_value(self):
        self.assertEqual(self.row_for(answers_with_value()).fingerprint,
                         values.fingerprint(TOKEN))

    def test_an_ok_row_does_not_count_as_failed(self):
        self.assertFalse(self.row_for(answers_with_value()).failed)

    def test_the_row_says_where_a_human_would_look_for_the_entry(self):
        self.assertEqual(self.row_for(answers_with_value()).where,
                         "login keychain: service %s, account %s" % (SERVICE, ACCOUNT))

    def test_no_field_of_the_row_holds_the_value(self):
        row = self.row_for(answers_with_value())
        self.assertNotIn(TOKEN, json.dumps(row.as_dict()))

    def test_the_value_did_not_travel_in_the_argv_of_the_read(self):
        # argv is world readable through `ps` for every process of the same
        # user. This is the one assertion the whole skill exists for.
        runner = answers_with_value()
        self.row_for(runner)
        self.assertFalse(runner.argv_carried(TOKEN), runner.joined_calls)


# ---------------------------------------------------------------------------
# empty
# ---------------------------------------------------------------------------

class AnEmptyKeychainItemIsAMissNotAHit(CheckCase):
    """Zero bytes behind a present entry is the case this column exists for.

    `security` exits 0 for it, so a check that tested the exit code reported
    green while the caller received an empty string and failed one layer later,
    where it looked like a permission problem.
    """

    def test_the_report_says_empty_rather_than_ok(self):
        self.assertEqual(self.row_for(answers_empty()).status, check_mod.EMPTY)

    def test_an_empty_entry_counts_as_failed(self):
        self.assertTrue(self.row_for(answers_empty()).failed)

    def test_no_byte_count_is_reported_for_an_entry_with_no_bytes(self):
        self.assertEqual(self.row_for(answers_empty()).length, 0)

    def test_no_fingerprint_is_invented_for_an_entry_with_no_bytes(self):
        # The fingerprint of b"" is a perfectly good sha256, and printing it
        # would make an empty row look like a read that succeeded.
        self.assertEqual(self.row_for(answers_empty()).fingerprint, "")

    def test_the_note_says_the_item_is_there_and_holds_nothing(self):
        self.assertIn("no bytes", self.row_for(answers_empty()).note)


# ---------------------------------------------------------------------------
# missing
# ---------------------------------------------------------------------------

class AnEntryNobodyCanFindIsMissing(CheckCase):
    """Exit code 44 is the only answer that means the entry is gone."""

    def test_the_report_says_missing(self):
        self.assertEqual(self.row_for(answers_missing()).status, check_mod.MISSING)

    def test_a_missing_entry_counts_as_failed(self):
        self.assertTrue(self.row_for(answers_missing()).failed)

    def test_the_row_still_says_where_it_looked(self):
        # The location is what turns "missing" into something actionable: it
        # names the keychain and the service to put the entry back into.
        self.assertIn(SERVICE, self.row_for(answers_missing()).where)


# ---------------------------------------------------------------------------
# bad reference
# ---------------------------------------------------------------------------

class AReferenceNobodyCanParseIsItsOwnVerdict(CheckCase):
    """A URI that does not parse never reaches a backend, so it has no status.

    It gets one of its own, because a broken locator in a declaration is a typo
    somebody has to fix and not a vault that has to be opened.
    """

    def test_the_report_says_bad_reference(self):
        row = self.row_for(answers_with_value(), "vault://onlyone")
        self.assertEqual(row.status, check_mod.BAD_REFERENCE)

    def test_a_bad_reference_counts_as_failed(self):
        self.assertTrue(self.row_for(answers_with_value(), "vault://onlyone").failed)

    def test_the_note_repeats_what_the_parser_objected_to(self):
        row = self.row_for(answers_with_value(), "vault://onlyone")
        self.assertIn("at least 2 segments", row.note)

    def test_nothing_was_asked_of_any_backend(self):
        runner = answers_with_value()
        self.row_for(runner, "vault://onlyone")
        self.assertEqual(runner.calls, [], runner.joined_calls)

    def test_the_places_survive_a_reference_that_does_not_parse(self):
        # The whole use of the row is that it names the file to edit.
        row = self.row_for(answers_with_value(), "vault://onlyone",
                           places=["infra/channels/mailer.yaml:12"])
        self.assertEqual(row.places, ["infra/channels/mailer.yaml:12"])


class AWellFormedReferenceWithNoBackendIsNotABadReference(CheckCase):
    """A scheme this Bridge cannot read today is a capability gap, not a typo.

    `check` has a status for it, `no backend here`, and the same status is what a
    missing `security` binary produces. The difference matters at the exit code:
    a bad reference exits 78, which tells a wrapper that the DECLARATION is
    wrong, and `rules/secret-placement.md` tells people to write exactly this
    reference.
    """

    def test_the_report_says_no_backend_here(self):
        row = self.row_for(answers_with_value(), UNBACKED_REF)
        self.assertEqual(row.status, check_mod.NO_BACKEND)


class AToolThatIsNotInstalledIsNoBackendHere(CheckCase):
    """The same status from the other direction, and this one the engine gets right."""

    def test_a_missing_binary_is_reported_as_no_backend_here(self):
        with self.security(present=False):
            row = check_mod.check_one(self.resolver(answers_with_value()), REF)
        self.assertEqual(row.status, check_mod.NO_BACKEND)

    def test_the_note_names_the_binary_that_is_not_there(self):
        with self.security(present=False):
            row = check_mod.check_one(self.resolver(answers_with_value()), REF)
        self.assertIn("security", row.note)


# ---------------------------------------------------------------------------
# not readable here
# ---------------------------------------------------------------------------

class ASessionProblemIsNotARotationProblem(CheckCase):
    """`not readable here` and `missing` are the two answers that must not merge.

    Both were one silent empty string before this skill existed, and the daemon
    that could not tell them apart rotated a token that was sitting right there.
    """

    def test_an_ssh_session_is_reported_as_not_readable_here(self):
        row = self.row_for(answers_with_value(), context=self.over_ssh())
        self.assertEqual(row.status, check_mod.UNREADABLE)

    def test_the_ssh_session_is_not_reported_as_missing(self):
        row = self.row_for(answers_with_value(), context=self.over_ssh())
        self.assertNotEqual(row.status, check_mod.MISSING)

    def test_the_note_says_what_would_make_the_read_work(self):
        row = self.row_for(answers_with_value(), context=self.over_ssh())
        self.assertIn("desktop session", row.note)

    def test_nothing_is_asked_of_the_tool_in_a_session_that_cannot_answer(self):
        # A read that is known to fail is not worth a process, and running it
        # anyway is how an ssh session collects keychain prompts nobody sees.
        runner = answers_with_value()
        self.row_for(runner, context=self.over_ssh())
        self.assertEqual(runner.calls, [], runner.joined_calls)

    def test_a_refusal_raised_by_the_tool_itself_is_not_reported_as_missing(self):
        # The other route to the same status: the session looked answerable, the
        # read ran, and the keychain refused it without a user at the screen.
        row = self.row_for(answers_refused())
        self.assertEqual(row.status, check_mod.UNREADABLE)

    def test_not_readable_here_does_not_count_as_failed(self):
        # `check` exits 0 over it on purpose: the vault is fine, this session is
        # not, and a red exit here would make every ssh cron job look broken.
        self.assertFalse(self.row_for(answers_refused()).failed)


# ---------------------------------------------------------------------------
# check_tree
# ---------------------------------------------------------------------------

class TheTreeIsReadOncePerReferenceAndNotOncePerLine(CheckCase):
    """One row per reference, carrying every place that writes it down.

    The store is asked once however often a reference is written, and the row is
    what tells you which files to edit when the answer is bad.
    """

    REAL_TREE = {
        "infra/channels/mailer.yaml": "token: %s\n" % REF,
        "infra/channels/agent.yaml": "name: agent\ntoken: %s\n" % REF,
        "workflow/workloads/report.yaml": "env:\n  TOKEN: %s\n" % REF,
        "docs/placement.md": "Write keychain://my-service/<account> for a keychain item.\n",
    }

    def rows_for(self, files, runner=None):
        root = self.tree(files)
        with self.security():
            rows, findings = check_mod.check_tree(
                self.resolver(runner or answers_with_value()), str(root), runner=no_git())
        return rows, findings

    def test_a_reference_written_in_three_files_is_one_row(self):
        rows, _ = self.rows_for(self.REAL_TREE)
        self.assertEqual([row.ref for row in rows], [REF])

    def test_that_row_names_every_place_it_is_written_down(self):
        rows, _ = self.rows_for(self.REAL_TREE)
        self.assertEqual(sorted(rows[0].places), [
            "infra/channels/agent.yaml:2",
            "infra/channels/mailer.yaml:1",
            "workflow/workloads/report.yaml:2",
        ])

    def test_the_store_is_asked_once_and_not_once_per_place(self):
        runner = answers_with_value()
        self.rows_for(self.REAL_TREE, runner)
        self.assertEqual(len(runner.calls), 1, runner.joined_calls)

    def test_a_documentation_example_is_not_a_row(self):
        # Measured on the open-bridge tree: half the hits are placeholders in
        # prose, and a report that called those broken would bury the real ones.
        rows, _ = self.rows_for(self.REAL_TREE)
        self.assertNotIn("my-service", " ".join(row.ref for row in rows))

    def test_the_example_is_still_a_finding_so_it_can_be_counted_elsewhere(self):
        _, findings = self.rows_for(self.REAL_TREE)
        self.assertEqual([f.raw for f in findings if f.example],
                         ["keychain://my-service/"])

    def test_a_reference_that_does_not_parse_becomes_a_row_of_its_own(self):
        rows, _ = self.rows_for({"infra/channels/one.yaml": "a: vault://onlyone\n"})
        self.assertEqual([(row.ref, row.status) for row in rows],
                         [("vault://onlyone", check_mod.BAD_REFERENCE)])

    def test_a_reference_that_does_not_parse_is_one_row_however_often_it_is_written(self):
        # Same promise as for a reference that resolves. Two rows for one typo
        # also make the count line say "2 references" where there is one.
        rows, _ = self.rows_for({
            "infra/channels/one.yaml": "a: vault://onlyone\n",
            "infra/channels/two.yaml": "b: vault://onlyone\n",
        })
        self.assertEqual(len(rows), 1, [row.places for row in rows])

    def test_an_empty_tree_produces_no_rows(self):
        rows, _ = self.rows_for({"docs/readme.md": "nothing to see here\n"})
        self.assertEqual(rows, [])


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

#: Rows assembled by hand, so the expected table below is a literal rather than
#: a second copy of the code that builds it.
def sample_rows():
    return [
        check_mod.Row(ref=REF, scheme="keychain", status=check_mod.OK,
                      where="login keychain: service %s" % SERVICE,
                      length=38, fingerprint="b0807f69"),
        check_mod.Row(ref="keepass://work/acme/api-token/password", scheme="keepass",
                      status=check_mod.MISSING, where="work.kdbx: acme/api-token",
                      note="no such entry in this database"),
    ]


EXPECTED_CELLS = (
    (REF, "ok", "38", "b0807f69", "login keychain: service %s" % SERVICE),
    ("keepass://work/acme/api-token/password", "missing", "", "",
     "work.kdbx: acme/api-token"),
)


class TheTableLinesUpAndCarriesNoValue(CheckCase):
    """The report is read off a terminal, so the columns have to be columns.

    The layout is derived from the output itself rather than recomputed here:
    the rule line under the header says how wide each column is, and every row
    has to obey it. A report built with single spaces, or with one field left
    unpadded, fails that without anybody having to pin the widths in a literal.
    """

    def table(self, rows=None, **kwargs):
        return check_mod.render(rows if rows is not None else sample_rows(), **kwargs)

    def layout(self, text):
        """Column widths and start offsets, read out of the rule line."""
        rule = text.splitlines()[1]
        widths = [len(chunk) for chunk in rule.split("  ")]
        offsets, cursor = [], 0
        for width in widths:
            offsets.append(cursor)
            cursor += width + 2
        return widths, offsets

    def body_lines(self, text):
        """The row lines: not the header, not the rule, not a note, not the tally."""
        lines = text.splitlines()
        return [line for line in lines[2:-2] if not line.startswith(" ")]

    def test_the_header_names_the_five_columns(self):
        self.assertEqual(self.table().splitlines()[0].split(),
                         ["reference", "status", "bytes", "sha256", "where"])

    def test_every_cell_starts_at_the_offset_its_column_declares(self):
        text = self.table()
        widths, offsets = self.layout(text)
        lines = self.body_lines(text)
        self.assertEqual(len(lines), len(EXPECTED_CELLS))
        for line, cells in zip(lines, EXPECTED_CELLS):
            for offset, cell in zip(offsets, cells):
                self.assertEqual(line[offset:offset + len(cell)], cell,
                                 "column does not start where the rule line says")

    def test_nothing_but_padding_stands_between_two_cells(self):
        text = self.table()
        widths, offsets = self.layout(text)
        for line, cells in zip(self.body_lines(text), EXPECTED_CELLS):
            for width, offset, cell in zip(widths, offsets, cells):
                filler = line[offset + len(cell):offset + width + 2]
                self.assertEqual(filler.strip(), "",
                                 "a cell ran past its column and pushed the next one")

    def test_the_last_line_counts_what_was_measured(self):
        self.assertEqual(self.table().splitlines()[-1],
                         "2 references, 1 resolved, 1 to look at")

    def test_the_note_of_a_failed_row_is_printed_under_it(self):
        self.assertIn("    no such entry in this database", self.table())

    def test_the_places_are_printed_only_when_they_were_asked_for(self):
        rows = sample_rows()
        rows[0].places = ["infra/channels/mailer.yaml:1"]
        self.assertNotIn("mailer.yaml", self.table(rows))
        self.assertIn("mailer.yaml", self.table(rows, verbose=True))

    def test_an_empty_report_says_so_instead_of_printing_a_header(self):
        self.assertEqual(check_mod.render([]), "no references found")

    def test_no_value_reaches_the_table(self):
        # Built from a real reading rather than from the literals above, so the
        # value is genuinely in play while the table is rendered.
        text = check_mod.render([self.row_for(answers_with_value())])
        self.assertNotIn(TOKEN, text)

    def test_the_fingerprint_is_what_stands_in_for_the_value(self):
        text = check_mod.render([self.row_for(answers_with_value())])
        self.assertIn(values.fingerprint(TOKEN), text)


# ---------------------------------------------------------------------------
# the machine readable shape
# ---------------------------------------------------------------------------

#: The keys `secrets check --json` promises. Anything reading that output keys
#: off these names, so renaming one is a breaking change and gets a red line.
DOCUMENTED_KEYS = ("ref", "scheme", "status", "where", "bytes", "fingerprint",
                   "note", "places")


class TheJsonShapeIsTheContract(CheckCase):
    """`as_dict` is what a wrapper script parses, so its keys are frozen."""

    def test_a_row_serialises_to_the_documented_keys(self):
        row = self.row_for(answers_with_value())
        self.assertEqual(sorted(row.as_dict()), sorted(DOCUMENTED_KEYS))

    def test_the_byte_count_is_called_bytes_and_not_length(self):
        # The attribute is `length` and the key is `bytes`. A serialiser that
        # simply dumped the dataclass would silently rename the column.
        row = self.row_for(answers_with_value())
        self.assertEqual(row.as_dict()["bytes"], len(TOKEN))

    def test_the_places_come_out_as_a_plain_list(self):
        row = self.row_for(answers_with_value(), places=["infra/channels/a.yaml:1"])
        self.assertEqual(row.as_dict()["places"], ["infra/channels/a.yaml:1"])

    def test_the_places_list_is_a_copy_and_not_the_rows_own(self):
        # A caller that sorts the list it got back must not reorder the row.
        row = self.row_for(answers_with_value(), places=["a.yaml:1"])
        row.as_dict()["places"].append("b.yaml:2")
        self.assertEqual(row.places, ["a.yaml:1"])

    def test_the_whole_document_is_json_serialisable(self):
        row = self.row_for(answers_with_value())
        self.assertEqual(json.loads(json.dumps(row.as_dict()))["status"], check_mod.OK)

    def test_no_key_of_the_document_holds_the_value(self):
        rows = [self.row_for(answers_with_value()), self.row_for(answers_empty())]
        self.assertNotIn(TOKEN, json.dumps([row.as_dict() for row in rows]))
