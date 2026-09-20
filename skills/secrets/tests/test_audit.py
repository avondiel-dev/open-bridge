"""audit: the value that never became a reference, and where it belongs.

The other two slices measure references that exist. This one measures the
values that never became one, which is a different failure: a maintainer copied
an instance to a second machine and found small text files holding tokens in
working folders and temp directories, because an agent handed a secret had
nowhere declared to put it and chose for itself.

Four properties are measured here and nothing else is.

1. A FINDING IS A LOCATION, NEVER A VALUE. Every case that plants something
   token shaped also asserts that the planted string appears nowhere in the
   report. The excerpt is capped at eight characters for the same reason a
   `check` row prints a fingerprint: a report that quotes the match writes the
   secret into the log that exists to protect it, and that has happened here.

2. A HIT INSIDE A DECLARED STORE IS THE STORE WORKING. A `file` store is a
   directory full of values on purpose. Reporting its contents as findings is
   how a scanner teaches its reader to skim the report, and the next thing
   skimmed is a real one. Those hits are marked `expected`, kept out of
   `Report.credentials`, and shown only when the reader asks.

3. A FINDING SAYS WHERE THE VALUE BELONGS, or says that nothing declares a home
   for it. The suggestion comes out of the placement policy in the store
   declarations, so it is the same answer every time and it is reviewable in a
   file rather than decided per session by whoever is holding the token.

4. PERSONAL DATA IS REPORTED AND NEVER MOVED. An IBAN is on every invoice and
   unlocks nothing. Worth knowing where it lies in a tree that ships, worth
   nothing in a vault, so it carries its own kind and no suggestion.

Every tree scanned here is built in a temporary directory, with one deliberate
exception at the end of the file that scans the real tree this skill lives in.
Discovery's git probe is answered through the `runner=` seam rather than run,
so a tmpdir that is not a checkout measures the walk rather than measuring
whether the machine has git.

The irony this file has to live with: it is a suite about a scanner, so it is
full of strings that look like credentials, and the scanner reads this file too
when the last case runs. Nothing here is a literal worth copying. Every token
shaped string is assembled at runtime from `synthetic_token`, and the lines
that still read like one carry the allowlist pragma.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from tests.conftest import (
    SKILL_DIR,
    FakeRunner,
    MachineGuard,
    completed,
    mod,
    synthetic_token,
)

audit = mod("engine.audit")
patterns = mod("engine.patterns")
stores_mod = mod("engine.stores")


# ---------------------------------------------------------------------------
# values, all assembled rather than pasted
# ---------------------------------------------------------------------------

def github_token(prefix: str = "audit", length: int = 36) -> str:
    """A string the `github-token` pattern recognises, built here at runtime.

    The prefix is split across two literals so that this tree holds no line
    that reads as a token to the scan in `test_acceptance.py`, and so that the
    line is not a copyable shape even for a reader.
    """
    body = synthetic_token(prefix, length).partition("_")[2]
    return "gh" + "p_" + body                              # pragma: allowlist secret


#: The one planted through most of this file.
TOKEN = github_token("audit")                              # pragma: allowlist secret

#: Deliberately long, for the case that asks what the report does NOT print.
LONG_TOKEN = github_token("excerpt", 64)                   # pragma: allowlist secret

#: An AWS shaped key, for the tree that is scanned as a second root. A second
#: pattern rather than a second GitHub token, so a finding from the extra root
#: cannot be confused with one from the first.
AWS_KEY = "AK" + "IA" + "".join("QRSTUVWXYZ234567"[(step * 5) % 16]
                                for step in range(16))     # pragma: allowlist secret

#: IBAN shaped, assembled from repeated digits so nothing here resembles an
#: account somebody holds. The pattern reads two letters, two digits and then
#: groups of four.
IBAN = "DE00 " + " ".join(digit * 4 for digit in "1234") + " 99"

#: What `discover.readable_text` refuses to decode: a NUL inside the first
#: 4096 bytes is the test it applies.
BINARY_BLOB = b"\x00PNG\x00" + TOKEN.encode("utf-8") + b"\x00"


def no_git() -> FakeRunner:
    """Discovery's git probe, answered so the walk is what gets measured.

    A temporary directory is not a checkout, so `git ls-files` would fail there
    anyway. Answering it keeps the case off the real binary and off the
    question of whether the machine running the suite has git at all.
    """
    return FakeRunner().add("ls-files", completed(rc=1, stderr="not a git repository"))


def keychain_store(kind: str = "personal-token", naming: str = "bridge-github",
                   name: str = "login-keychain"):
    """A store that declares it holds a kind, which is what a suggestion needs.

    Built as an object rather than as a YAML file: `audit.run(stores=...)` takes
    the loaded list, and going through the parser would make every case here
    depend on PyYAML being installed, which is exactly the dependency
    `stores.load` is careful to keep optional.
    """
    return stores_mod.Store(name=name, backend="keychain", addresses=("*",),
                            holds=({"kind": kind, "naming": naming},))


def file_store(path, name: str = "deploy-drop"):
    """A `file` store: a declared directory whose contents ARE values."""
    return stores_mod.Store(name=name, backend="file", addresses=("deploy",),
                            location={"path": str(path)},
                            holds=({"kind": "service-runtime", "naming": "<service>"},))


class AuditCase(MachineGuard):
    """A throwaway tree, and a scan driven over the seam rather than over git."""

    def tree(self, files: dict) -> Path:
        """A temporary directory holding the given files, parents made as needed.

        A `bytes` value is written as bytes, which is how the binary case gets a
        file with a NUL in it without a second helper.
        """
        root = self.tmpdir()
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        return root

    def scan(self, root, *, stores=(), runner=None, **options):
        """`audit.run` over a tree, with no declaration loaded from disk.

        `stores=()` and not `stores=None`: None means "read the declarations out
        of the tree", and a case that fell through to that would measure the
        machine's own `infra/secret-stores/` rather than the fixture in front of
        it.
        """
        return audit.run(str(root), stores=list(stores),
                         runner=runner or no_git(), **options)

    def only(self, findings):
        """The single finding, or a failure that says what was found instead."""
        self.assertEqual(len(findings), 1,
                         "expected one finding, got: %s" % [f.as_dict() for f in findings])
        return findings[0]


# ---------------------------------------------------------------------------
# the hit itself
# ---------------------------------------------------------------------------

class APlantedCredentialIsFoundWhereItLies(AuditCase):
    """The base measurement: a value in a file, reported with its place.

    Four fields make a finding actionable, and each one is asserted on its own
    so that a failure names the field rather than dumping a dataclass: the path
    to open, the line to go to, the pattern that recognised it, and enough of
    the match to find it on that line.
    """

    def planted(self):
        root = self.tree({
            "notes/handover.md": "left behind by a run\n%s\nend of file\n" % TOKEN,
        })
        return self.scan(root)

    def test_the_value_is_found_at_all(self):
        self.assertEqual(len(self.planted().credentials), 1)

    def test_the_finding_names_the_file_it_stands_in(self):
        self.assertEqual(self.only(self.planted().credentials).path, "notes/handover.md")

    def test_the_path_is_relative_to_the_tree_that_was_scanned(self):
        # An absolute path here would carry the temporary directory of whoever
        # ran the scan into a report meant to be pasted into an issue.
        self.assertFalse(Path(self.only(self.planted().credentials).path).is_absolute())

    def test_the_finding_carries_the_line_the_value_stands_on(self):
        self.assertEqual(self.only(self.planted().credentials).line, 2)

    def test_the_line_numbers_start_at_one_and_not_at_zero(self):
        # An editor opens line 1 first. A report counting from zero sends every
        # reader one line up, which on a file of key and value pairs is another
        # key and another value.
        root = self.tree({"first.md": "%s\n" % TOKEN})
        self.assertEqual(self.only(self.scan(root).credentials).line, 1)

    def test_the_finding_names_the_pattern_that_recognised_it(self):
        self.assertEqual(self.only(self.planted().credentials).pattern, "github-token")

    def test_the_finding_is_a_credential_and_not_personal_data(self):
        self.assertEqual(self.only(self.planted().credentials).kind, "credential")

    def test_the_excerpt_carries_at_most_eight_characters_of_the_match(self):
        # The cap is the point of the field. Eight characters recognise the hit
        # on the line; they do not authenticate anything.
        excerpt = self.only(self.planted().credentials).excerpt
        self.assertLessEqual(len(excerpt.rstrip("…")), 8, excerpt)

    def test_the_excerpt_is_the_beginning_of_the_match_so_it_can_be_found(self):
        excerpt = self.only(self.planted().credentials).excerpt
        self.assertTrue(TOKEN.startswith(excerpt.rstrip("…")), excerpt)

    def test_a_tree_with_nothing_planted_in_it_reports_nothing(self):
        # The control. Without it every case above is also green over a scan
        # that reports everything it reads.
        root = self.tree({"notes/handover.md": "an ordinary sentence about work\n"})
        self.assertEqual(self.scan(root).findings, [])

    def test_the_file_was_read_even_when_it_held_nothing(self):
        root = self.tree({"notes/handover.md": "an ordinary sentence about work\n"})
        self.assertEqual(self.scan(root).files_read, 1)


# ---------------------------------------------------------------------------
# what the report may never carry
# ---------------------------------------------------------------------------

class TheReportNamesThePlaceAndNeverTheValue(AuditCase):
    """The rule the whole skill exists for, applied to its own output.

    A long value is planted on purpose: with a short one the excerpt would BE
    the value and the case would pass without measuring the cap. A verify pass
    in this repo once decoded a base64 credential into a transcript while
    checking whether the credential was really there, which is the same mistake
    one layer up.
    """

    def planted(self, **options):
        root = self.tree({"deploy/stray.env": "GH" + "_TOKEN=%s\n" % LONG_TOKEN})
        return self.scan(root, **options)

    def test_the_long_value_is_found(self):
        self.assertEqual(len(self.planted().credentials), 1)

    def test_the_rendered_report_does_not_carry_the_value(self):
        self.assertNotIn(LONG_TOKEN, audit.render(self.planted()))

    def test_the_verbose_report_does_not_carry_it_either(self):
        # Verbose adds the reason for each pattern and the hits inside stores.
        # It is the flag a reader reaches for when the plain report is not
        # enough, which is exactly when a value would slip out unnoticed.
        self.assertNotIn(LONG_TOKEN, audit.render(self.planted(), verbose=True))

    def test_no_field_of_the_finding_carries_the_value(self):
        document = json.dumps([f.as_dict() for f in self.planted().findings])
        self.assertNotIn(LONG_TOKEN, document)

    def test_the_excerpt_is_far_shorter_than_the_value_it_stands_for(self):
        excerpt = self.only(self.planted().credentials).excerpt
        self.assertLess(len(excerpt), len(LONG_TOKEN))

    def test_the_excerpt_says_it_was_cut(self):
        # Without the mark a reader takes the excerpt for the whole match and
        # searches the file for a string that is not in it.
        self.assertTrue(self.only(self.planted().credentials).excerpt.endswith("…"))

    def test_the_report_still_says_which_line_to_open(self):
        self.assertIn("deploy/stray.env:1", audit.render(self.planted()))


# ---------------------------------------------------------------------------
# the pragma
# ---------------------------------------------------------------------------

class ALineThatDeclaresItselfAFixtureIsNotAFinding(AuditCase):
    """The allowlist pragma, spelled the way `detect-secrets` spells it.

    A suite about a scanner is full of token shaped strings, and so is a
    template, and so is a documentation example. Without an opt out the report
    is mostly its own fixtures and stops being read. A real secret never
    carries the marker, which is the whole contract.
    """

    def marked(self, marker=None):
        marker = patterns.PRAGMA if marker is None else marker
        root = self.tree({"tests/fixture.py": "token = \"%s\"  # %s\n" % (TOKEN, marker)})
        return self.scan(root)

    def test_the_marked_line_is_not_reported(self):
        self.assertEqual(self.marked().findings, [])

    def test_the_file_was_read_although_nothing_was_reported(self):
        # Otherwise the case above is equally green over a file the walk never
        # opened, which is a different bug wearing the same green.
        self.assertEqual(self.marked().files_read, 1)

    def test_the_same_line_without_the_marker_is_reported(self):
        # The control that makes the two cases above mean something: this
        # fixture really does hold something the scan recognises.
        self.assertTrue(self.marked(marker="just an ordinary comment").credentials)

    def test_the_marker_covers_only_the_line_it_stands_on(self):
        root = self.tree({"tests/fixture.py":
                          "token = \"%s\"  # %s\nloose = \"%s\"\n"
                          % (TOKEN, patterns.PRAGMA, TOKEN)})
        self.assertEqual([f.line for f in self.scan(root).credentials], [2])


# ---------------------------------------------------------------------------
# the declared store
# ---------------------------------------------------------------------------

class AValueInsideADeclaredFileStoreIsTheStoreWorking(AuditCase):
    """A `file` store is a directory of values by declaration, not by accident.

    This is the case that keeps the report readable. A scanner that reports the
    contents of its own store trains its reader to skim, and a reader who skims
    a report of eleven expected hits skims the twelfth one too.
    """

    def scanned(self, **options):
        root = self.tree({
            "vault/deploy.token": "%s\n" % TOKEN,
            "notes/loose.md": "someone pasted %s here\n" % TOKEN,
        })
        return root, self.scan(root, stores=[file_store(root / "vault")], **options)

    def inside(self, report):
        return self.only([f for f in report.findings if f.path.startswith("vault/")])

    def test_the_hit_inside_the_declared_directory_is_marked_expected(self):
        _, report = self.scanned()
        self.assertTrue(self.inside(report).expected)

    def test_it_is_kept_out_of_the_credentials_to_deal_with(self):
        _, report = self.scanned()
        self.assertEqual([f.path for f in report.credentials], ["notes/loose.md"])

    def test_it_is_counted_among_the_expected_hits(self):
        _, report = self.scanned()
        self.assertEqual(len(report.expected), 1)

    def test_the_note_says_why_it_is_not_a_finding(self):
        _, report = self.scanned()
        self.assertEqual(self.inside(report).note, audit.EXPECTED_IN_STORE)

    def test_nothing_is_suggested_for_a_value_that_is_already_where_it_belongs(self):
        _, report = self.scanned()
        self.assertEqual(self.inside(report).suggestion, "")

    def test_the_same_value_outside_the_store_is_still_a_credential(self):
        # The control: the store marks a PLACE, not a value. Without this the
        # case above would also pass if the scan had simply stopped recognising
        # the token.
        _, report = self.scanned()
        self.assertFalse(self.only(report.credentials).expected)

    def test_the_plain_report_does_not_name_the_expected_hit(self):
        _, report = self.scanned()
        self.assertNotIn("vault/deploy.token", audit.render(report))

    def test_the_verbose_report_counts_the_expected_hits(self):
        _, report = self.scanned()
        self.assertIn("1 hit(s) inside declared file stores", audit.render(report, verbose=True))

    def test_the_count_line_counts_only_what_is_left_to_deal_with(self):
        _, report = self.scanned()
        self.assertIn("1 credential(s) to deal with", audit.render(report))

    def test_without_the_declaration_the_same_directory_is_an_ordinary_finding(self):
        # The store is what makes the difference, and nothing else is.
        root = self.tree({"vault/deploy.token": "%s\n" % TOKEN})
        self.assertEqual(len(self.scan(root).credentials), 1)

    def test_a_store_on_another_backend_declares_no_directory(self):
        # `declared_file_roots` exists to answer exactly one question. A
        # keychain store has a `location` too, and reading a path out of it
        # would exempt a directory nobody declared as a store.
        self.assertEqual(audit.declared_file_roots([keychain_store()]), [])

    def test_the_declared_directory_is_resolved_before_it_is_compared(self):
        # A declared path travels through `~` and `${VAR}` expansion and through
        # the symlink that makes `/tmp` and `/private/tmp` the same directory on
        # one of the two platforms this runs on. Comparing the strings rather
        # than the resolved paths made a store look like somebody else's
        # directory on a Mac and like itself on Linux.
        root = self.tree({"vault/deploy.token": "%s\n" % TOKEN})
        declared = audit.declared_file_roots([file_store(root / "vault")])
        self.assertEqual(declared, [str(Path(root / "vault").resolve())])

    def test_a_neighbour_whose_name_starts_with_the_store_is_still_outside(self):
        # `vault-old` is the directory somebody makes while rotating, and a
        # containment test without the separator declares it part of `vault`.
        # The stale copy then lands in the one place the scan calls expected,
        # which is the same prefix bug the file backend carries a case for.
        root = self.tree({
            "vault/deploy.token": "%s\n" % TOKEN,
            "vault-old/deploy.token": "%s\n" % TOKEN,
        })
        report = self.scan(root, stores=[file_store(root / "vault")])
        self.assertEqual([f.path for f in report.credentials],
                         ["vault-old/deploy.token"])

    def test_a_store_on_another_backend_declares_none_even_when_it_names_a_path(self):
        # The case above cannot fail while the keychain fixture carries no path
        # at all, so it measures the backend filter only against a store that
        # has nothing to offer it. A keychain store declares the keychain FILE
        # it reads, and taking a path out of every location would exempt the
        # directory that file sits in, where every other keychain of the
        # account sits too.
        holder = stores_mod.Store(
            name="login-keychain", backend="keychain", addresses=("*",),
            location={"path": "/home/opuser/keychains/login.keychain-db"},
            holds=({"kind": "personal-token", "naming": "bridge-github"},))
        self.assertEqual(audit.declared_file_roots([holder]), [])


# ---------------------------------------------------------------------------
# personal data
# ---------------------------------------------------------------------------

class PersonalDataIsReportedAndNeverMoved(AuditCase):
    """An IBAN is identifying, not authenticating, and a vault ruins it.

    It belongs on every invoice the user writes, so locking it away makes it
    useless for its own purpose and buys no security. It is still worth knowing
    that it lies in a tree that ships, which is why it is reported at all. The
    two properties together are why `kind` exists.
    """

    def mixed(self, **options):
        root = self.tree({
            "invoices/2026-09.md": "Bankverbindung %s\n" % IBAN,
            "notes/loose.md": "%s\n" % TOKEN,
        })
        return self.scan(root, **options)

    def test_the_iban_is_reported(self):
        self.assertEqual(len(self.mixed().pii), 1)

    def test_it_is_reported_as_personal_data_and_not_as_a_credential(self):
        self.assertEqual(self.only(self.mixed().pii).kind, "pii")

    def test_it_does_not_count_among_the_credentials(self):
        self.assertEqual([f.pattern for f in self.mixed().credentials], ["github-token"])

    def test_no_store_is_proposed_for_it(self):
        self.assertEqual(self.only(self.mixed().pii).suggestion, "")

    def test_no_store_is_named_for_it_either(self):
        self.assertEqual(self.only(self.mixed().pii).store, "")

    def test_even_a_store_that_would_take_everything_gets_no_personal_data(self):
        # A store declaring `holds: personal-token` with a wildcard address is
        # the shape that would swallow an IBAN if the suggestion were driven by
        # the store rather than by the kind of the finding.
        root = self.tree({"invoices/2026-09.md": "Bankverbindung %s\n" % IBAN})
        report = self.scan(root, stores=[keychain_store()])
        self.assertEqual(self.only(report.pii).suggestion, "")

    def test_the_report_says_that_this_one_is_not_moved(self):
        self.assertIn("is not moved", audit.render(self.mixed()))

    def test_the_report_does_not_print_the_number_itself(self):
        self.assertNotIn(IBAN, audit.render(self.mixed()))

    def test_no_pii_drops_it(self):
        self.assertEqual(self.mixed(include_pii=False).pii, [])

    def test_no_pii_drops_it_from_the_findings_and_not_only_from_the_bucket(self):
        # `Report.pii` filters, so a scan that still collected the hit would
        # pass the case above and carry the number into the JSON output.
        document = json.dumps([f.as_dict() for f in self.mixed(include_pii=False).findings])
        self.assertNotIn("iban", document)

    def test_no_pii_leaves_the_credentials_alone(self):
        self.assertEqual(len(self.mixed(include_pii=False).credentials), 1)

    def test_the_count_line_reports_personal_data_separately(self):
        self.assertIn("1 personal-data hit(s)", audit.render(self.mixed()))


# ---------------------------------------------------------------------------
# where it belongs
# ---------------------------------------------------------------------------

class ASuggestionComesFromThePlacementPolicyAndNotFromTheScanner(AuditCase):
    """"This is a GitHub token, it belongs in X, call it Y" beats "suspicious string".

    The policy lives in the store declarations, so the answer is the same every
    time and a person can review it in a file. The alternative is the one this
    module was written against: an agent handed a token decides for itself, and
    the decision is a file in a working folder.
    """

    def suggested(self, stores):
        root = self.tree({"notes/loose.md": "%s\n" % TOKEN})
        return self.only(self.scan(root, stores=stores).credentials)

    def test_the_finding_names_the_store_that_declares_this_kind(self):
        self.assertEqual(self.suggested([keychain_store()]).store, "login-keychain")

    def test_the_suggestion_carries_the_naming_shape_the_store_declares(self):
        self.assertIn("bridge-github", self.suggested([keychain_store()]).suggestion)

    def test_the_suggestion_is_a_reference_of_the_stores_own_scheme(self):
        # A proposal a person is meant to paste has to parse as a reference, so
        # the scheme comes from the store rather than from the pattern.
        self.assertTrue(self.suggested([keychain_store()]).suggestion.startswith("keychain://"))

    def test_the_rendered_line_says_where_it_belongs_and_in_which_store(self):
        root = self.tree({"notes/loose.md": "%s\n" % TOKEN})
        text = audit.render(self.scan(root, stores=[keychain_store()]))
        self.assertIn("belongs in login-keychain: keychain://bridge-github/", text)

    def test_with_nothing_declared_the_suggestion_is_to_declare_something(self):
        self.assertEqual(self.suggested([]).suggestion,
                         "declare a store that holds personal-token")

    def test_with_nothing_declared_no_store_is_named(self):
        self.assertEqual(self.suggested([]).store, "")

    def test_a_store_that_holds_another_kind_is_not_proposed(self):
        # The policy is per kind. A store that takes CI secrets is not where a
        # personal token goes, and a suggestion that ignored the kind would
        # send every finding to whichever store was declared first.
        elsewhere = keychain_store(kind="ci-secret", name="ci-vault")
        self.assertEqual(self.suggested([elsewhere]).suggestion,
                         "declare a store that holds personal-token")

    def test_a_pattern_that_declares_no_kind_gets_no_suggestion(self):
        # `password-assignment` is the hand written shape. It says a value is
        # here, never what the value is for, so the policy has nothing to route
        # on and the report says nothing rather than something invented.
        root = self.tree({"config/app.ini": "password = %s\n" % synthetic_token("plain")})
        finding = self.only(self.scan(root, stores=[keychain_store()]).credentials)
        self.assertEqual((finding.pattern, finding.suggestion, finding.store),
                         ("password-assignment", "", ""))

    def test_the_policy_is_asked_once_per_kind_and_not_once_per_finding(self):
        # Three hits of one kind in one tree. The cache is not the property
        # under test; the property is that three findings get the same answer,
        # because a report that proposed two different homes for one kind is a
        # report nobody can act on.
        root = self.tree({"a.md": "%s\n" % TOKEN, "b.md": "%s\n" % TOKEN,
                          "c.md": "%s\n" % TOKEN})
        report = self.scan(root, stores=[keychain_store()])
        self.assertEqual({f.suggestion for f in report.credentials},
                         {"keychain://bridge-github/<account>"})


# ---------------------------------------------------------------------------
# what cannot be read
# ---------------------------------------------------------------------------

class WhatCannotBeReadIsCountedRatherThanPassedOver(AuditCase):
    """A skip that is not counted is indistinguishable from a clean file.

    Both halves of this matter. The scan must not try to regex a megabyte of
    binary, and the reader must be able to see that the scan looked at fewer
    files than the tree holds, because a value inside a skipped file is a value
    nobody has looked at.
    """

    def mixed(self):
        big = "%s\n%s" % (TOKEN, "x" * (2 * 1024 * 1024))
        root = self.tree({
            "assets/logo.png": BINARY_BLOB,
            "dumps/large.log": big,
            "notes/plain.md": "%s\n" % TOKEN,
        })
        return self.scan(root)

    def test_the_readable_file_is_still_read(self):
        self.assertEqual(self.mixed().files_read, 1)

    def test_the_value_in_the_binary_file_is_not_reported(self):
        self.assertEqual([f.path for f in self.mixed().credentials], ["notes/plain.md"])

    def test_both_kinds_of_skip_reach_the_counter(self):
        # The binary file and the oversized one. One counter for both, which is
        # the engine's choice; what must not happen is a skip that leaves no
        # trace at all.
        self.assertEqual(self.mixed().skipped_binary, 2)

    def test_a_file_at_the_size_limit_is_still_read(self):
        # The boundary, from the readable side. A limit that excluded the file
        # exactly at it would shrink by one byte every time somebody reasoned
        # about it.
        body = "y" * (2 * 1024 * 1024 - len(TOKEN) - 1)
        root = self.tree({"dumps/at-limit.log": "%s\n%s" % (TOKEN, body)})
        report = self.scan(root)
        self.assertEqual((report.files_read, report.skipped_binary), (1, 0))

    def test_the_value_in_the_file_at_the_limit_is_reported(self):
        body = "y" * (2 * 1024 * 1024 - len(TOKEN) - 1)
        root = self.tree({"dumps/at-limit.log": "%s\n%s" % (TOKEN, body)})
        self.assertEqual(len(self.scan(root).credentials), 1)

    def test_an_unreadable_encoding_is_a_skip_and_not_a_crash(self):
        # A file that is neither valid UTF-8 nor obviously binary: no NUL in the
        # first block, and a stray byte later. The scan has to survive it,
        # because a tree that ships holds one sooner or later.
        root = self.tree({"docs/latin1.txt": "Kündigung".encode("latin-1")})
        report = self.scan(root)
        self.assertEqual((report.files_read, report.skipped_binary), (0, 1))


class ASymlinkIsNotFollowed(AuditCase):
    """Following one counts the same file twice, or walks out of the tree.

    This repo carries three committed symlinks (`.claude/skills` and friends)
    that point back into itself, and `discover.find` learned the same lesson
    when following them counted every skill three times. A link out of the tree
    is the worse half: it makes a scan of a repository read a home directory.
    """

    def linked(self):
        outside = self.tmpdir()
        target = outside / "secrets.env"
        target.write_text("%s\n" % TOKEN, encoding="utf-8")
        root = self.tree({"notes/keep.md": "nothing planted here\n"})
        (root / "shortcut.env").symlink_to(target)
        return root, target

    def test_the_value_behind_the_link_is_not_reported(self):
        root, _ = self.linked()
        self.assertEqual(self.scan(root).findings, [])

    def test_the_link_is_not_counted_as_a_file_that_was_read(self):
        root, _ = self.linked()
        self.assertEqual(self.scan(root).files_read, 1)

    def test_the_link_is_not_counted_as_a_skipped_binary_either(self):
        # It is not a file that could not be read, it is a file that is a
        # pointer. Counting it under `skipped_binary` would tell a reader that
        # a value might be hiding in something unreadable.
        root, _ = self.linked()
        self.assertEqual(self.scan(root).skipped_binary, 0)

    def test_the_target_scanned_directly_does_hold_something(self):
        # The control. Without it the three cases above are green over a
        # fixture that simply holds nothing findable.
        _, target = self.linked()
        self.assertEqual(len(self.scan(target.parent).credentials), 1)


# ---------------------------------------------------------------------------
# a second root
# ---------------------------------------------------------------------------

class APathTheCallerNamesIsScannedTooAndSaysWhereItIs(AuditCase):
    """`--also` exists because the stray values were never in the repo.

    They were in working folders and temp directories next to it. A finding
    from there carries its absolute path, because a path relative to a tree it
    does not live in names a file that does not exist.
    """

    def both(self, **options):
        outside = self.tmpdir()
        (outside / "deploy.env").write_text("AWS_ACCESS_KEY_ID=%s\n" % AWS_KEY,
                                            encoding="utf-8")
        root = self.tree({"notes/loose.md": "%s\n" % TOKEN})
        return outside, root, self.scan(root, also=[str(outside)], **options)

    def test_the_tree_outside_the_root_is_scanned(self):
        _, _, report = self.both()
        self.assertIn("aws-access-key", [f.pattern for f in report.credentials])

    def test_the_finding_from_outside_carries_an_absolute_path(self):
        outside, _, report = self.both()
        found = self.only([f for f in report.credentials if f.pattern == "aws-access-key"])
        self.assertEqual(found.path, str(outside / "deploy.env"))

    def test_the_finding_inside_the_root_stays_relative(self):
        _, _, report = self.both()
        found = self.only([f for f in report.credentials if f.pattern == "github-token"])
        self.assertEqual(found.path, "notes/loose.md")

    def test_the_root_is_still_scanned_when_a_second_one_is_named(self):
        # An extra root that replaced the first one rather than adding to it
        # would report a clean repository while scanning somebody's desktop.
        _, _, report = self.both()
        self.assertEqual(report.files_read, 2)

    def test_the_report_records_which_extra_roots_were_walked(self):
        outside, _, report = self.both()
        self.assertEqual(report.extra_roots, [str(outside)])

    def test_the_extra_root_is_recorded_as_an_absolute_path(self):
        # It is printed and pasted. A relative one means something different in
        # every directory a reader happens to stand in.
        _, _, report = self.both()
        self.assertTrue(Path(report.extra_roots[0]).is_absolute())

    def test_a_store_declared_inside_the_extra_tree_still_exempts_its_contents(self):
        # The store rule is about a place, and `--also` is a second place. A
        # declared store directory that the caller names explicitly is still
        # the store working.
        outside = self.tmpdir()
        (outside / "deploy.env").write_text("%s\n" % TOKEN, encoding="utf-8")
        root = self.tree({"notes/keep.md": "nothing planted here\n"})
        report = self.scan(root, also=[str(outside)], stores=[file_store(outside)])
        self.assertEqual((len(report.credentials), len(report.expected)), (0, 1))


class AnExtraPathThatNamesAFileIsNeverRead(AuditCase):
    """RED ON PURPOSE: `--also <file>` scans nothing and reports a clean tree.

    `audit.run` walks each extra root with `discover._walked`, which is
    `os.walk`, and `os.walk` over a path that is not a directory yields nothing
    at all (engine/audit.py:102-104). The named file is never opened, nothing is
    counted, and the report ends in "0 credential(s) to deal with" with no hint
    that the path the caller pointed at was never read.

    The flag's own help calls it "a place outside the tree to scan as well" and
    its metavar is PATH, and a stray `deploy.env` in a temp directory is exactly
    the artefact the module docstring says this verb was written for. Naming that
    file is the obvious thing to type, and it answers "clean".

    A nonexistent path answers the same way, which is the sharper half of the
    same hole: a typo in an extra path is indistinguishable from a tree that
    holds nothing.

    The second case below is the control: the same file, scanned by naming its
    directory, is found. So this is about the shape of the path and not about
    the fixture.
    """

    def stray(self):
        outside = self.tmpdir()
        stray = outside / "deploy.env"
        stray.write_text("GH" + "_TOKEN=%s\n" % TOKEN, encoding="utf-8")
        root = self.tree({"notes/keep.md": "nothing planted here\n"})
        return root, stray

    def test_a_file_named_as_an_extra_path_is_read(self):
        root, stray = self.stray()
        report = self.scan(root, also=[str(stray)])
        self.assertEqual([f.path for f in report.credentials], [str(stray)])

    def test_the_same_file_is_found_when_its_directory_is_named(self):
        root, stray = self.stray()
        report = self.scan(root, also=[str(stray.parent)])
        self.assertEqual([f.path for f in report.credentials], [str(stray)])


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

class TheReportSaysWhatItMeasuredAndWhatItCannotPromise(AuditCase):
    """A count and a disclaimer, because absence of evidence is the failure mode.

    Every scanner in this repo reads the files it can with the patterns it has.
    A report that ended on "no findings" would be read as "there are no secrets
    in this tree", and the difference between those two sentences is the whole
    reason `--with-gitleaks` exists.
    """

    def mixed(self):
        root = self.tree({
            "notes/loose.md": "%s\n" % TOKEN,
            "invoices/2026-09.md": "Bankverbindung %s\n" % IBAN,
            "assets/logo.png": BINARY_BLOB,
        })
        return self.scan(root)

    def test_the_count_line_names_the_files_that_were_read(self):
        self.assertIn("2 file(s) read", audit.render(self.mixed()))

    def test_the_count_line_names_the_credentials_to_deal_with(self):
        self.assertIn("1 credential(s) to deal with", audit.render(self.mixed()))

    def test_the_count_line_names_the_personal_data_hits(self):
        self.assertIn("1 personal-data hit(s)", audit.render(self.mixed()))

    def test_the_report_refuses_to_read_as_a_proof_of_absence(self):
        self.assertIn("A clean scan is not a proof", audit.render(self.mixed()))

    def test_a_clean_scan_carries_that_sentence_too(self):
        # This is the run where it matters. A disclaimer printed only next to
        # findings is a disclaimer nobody reads when it counts.
        root = self.tree({"notes/keep.md": "an ordinary sentence about work\n"})
        self.assertIn("A clean scan is not a proof", audit.render(self.scan(root)))

    def test_a_clean_scan_still_says_how_much_it_read(self):
        root = self.tree({"notes/keep.md": "an ordinary sentence about work\n"})
        self.assertIn("1 file(s) read", audit.render(self.scan(root)))

    def test_no_planted_value_appears_anywhere_in_the_report(self):
        text = audit.render(self.mixed(), verbose=True)
        for value in (TOKEN, IBAN):
            with self.subTest(value=value[:4]):
                self.assertNotIn(value, text)

    def test_the_two_kinds_are_reported_under_separate_headings(self):
        # A reader acts on one of them and files the other. Mixing them into
        # one list means rotating an IBAN or filing a token.
        text = audit.render(self.mixed())
        self.assertLess(text.index("credentials in plain text:"),
                        text.index("personal data"))

    def test_the_second_opinion_is_printed_when_there_is_one(self):
        report = self.mixed()
        report.gitleaks = "gitleaks reported 3 finding(s)"
        self.assertIn("gitleaks reported 3 finding(s)", audit.render(report))

    def test_nothing_is_printed_about_a_second_opinion_nobody_asked_for(self):
        self.assertNotIn("gitleaks", audit.render(self.mixed()))


# ---------------------------------------------------------------------------
# the optional second opinion
# ---------------------------------------------------------------------------

class TheSecondOpinionIsOptionalAndSaysWhenItDidNotRun(AuditCase):
    """gitleaks knows several hundred shapes; the built-in set knows fourteen.

    Neither proves the absence of a secret, so the interesting property is not
    the count. It is that a missing binary produces a sentence saying the check
    did not run, rather than a zero that reads exactly like a clean tree.
    """

    def installed(self, present: bool = True):
        """Answer the `which` probe rather than asking the machine.

        `gitleaks_available` consults `engine.exec.which` directly, so without
        this a case would measure whether the developer happens to have the
        binary installed, and the two answers are different cases.
        """
        answer = (lambda binary: "/usr/local/bin/" + binary) if present else (lambda binary: None)
        return mock.patch("engine.exec.which", answer)

    def ask(self, *, stdout: str = "[]", rc: int = 0, present: bool = True):
        runner = FakeRunner().add("gitleaks", completed(rc=rc, stdout=stdout))
        with self.installed(present):
            count, message = audit.gitleaks(str(self.tmpdir()), runner=runner)
        return count, message, runner

    def test_an_absent_binary_is_reported_rather_than_counted_as_clean(self):
        _, message, _ = self.ask(present=False)
        self.assertEqual(message, "gitleaks is not installed here")

    def test_nothing_runs_when_the_binary_is_absent(self):
        _, _, runner = self.ask(present=False)
        self.assertEqual(runner.calls, [], runner.joined_calls)

    def test_the_count_is_read_from_what_the_tool_answered(self):
        count, _, _ = self.ask(stdout=json.dumps([{"RuleID": "a"}, {"RuleID": "b"}]), rc=1)
        self.assertEqual(count, 2)

    def test_the_message_carries_the_same_count(self):
        _, message, _ = self.ask(stdout=json.dumps([{"RuleID": "a"}, {"RuleID": "b"}]), rc=1)
        self.assertEqual(message, "gitleaks reported 2 finding(s)")

    def test_an_exit_code_of_one_is_findings_and_not_a_failure(self):
        # gitleaks exits 1 when it found something. A wrapper that treated a
        # non-zero code as a broken tool would drop exactly the runs that had
        # something to say.
        count, message, _ = self.ask(stdout=json.dumps([{"RuleID": "a"}]), rc=1)
        self.assertEqual((count, message), (1, "gitleaks reported 1 finding(s)"))

    def test_a_clean_answer_is_reported_as_a_clean_answer(self):
        self.assertEqual(self.ask(stdout="[]", rc=0)[:2], (0, "gitleaks reported 0 finding(s)"))

    def test_the_tool_is_asked_for_json_on_standard_output(self):
        _, _, runner = self.ask()
        self.assertIn("--report-format json --report-path -", runner.joined_calls)

    def test_the_tool_is_pointed_at_the_tree_that_was_named(self):
        root = str(self.tmpdir())
        runner = FakeRunner().add("gitleaks", completed(rc=0, stdout="[]"))
        with self.installed():
            audit.gitleaks(root, runner=runner)
        self.assertIn(root, runner.calls[0]["argv"])

    def test_an_answer_that_is_not_json_is_reported_rather_than_raised(self):
        # Measured failure mode of every tool that writes a banner: the report
        # arrives with a line of prose in front of it. A traceback here would
        # take the whole audit down over an optional second opinion.
        _, message, _ = self.ask(stdout="gitleaks version 8.18.0\n", rc=0)
        self.assertEqual(message, "gitleaks answered something that is not JSON")

    def test_an_answer_that_is_not_json_counts_nothing(self):
        count, _, _ = self.ask(stdout="gitleaks version 8.18.0\n", rc=0)
        self.assertEqual(count, 0)

    def test_a_tool_that_failed_outright_says_so_with_its_exit_code(self):
        _, message, _ = self.ask(stdout="", rc=2)
        self.assertEqual(message, "gitleaks exited 2")

    def test_a_tool_that_failed_outright_counts_nothing(self):
        count, _, _ = self.ask(stdout="", rc=2)
        self.assertEqual(count, 0)

    def test_the_scan_itself_never_asks_for_the_second_opinion(self):
        # `audit.run` and `audit.gitleaks` are two calls on purpose: the caller
        # decides whether a second binary runs over the tree. A scan that
        # reached for it by itself would shell out on every session start.
        root = self.tree({"notes/loose.md": "%s\n" % TOKEN})
        with self.installed():
            report = self.scan(root)
        self.assertEqual(report.gitleaks, "")


# ---------------------------------------------------------------------------
# the real tree
# ---------------------------------------------------------------------------

def real_tree() -> Path:
    """The repository this skill lives in, or the skill alone when it stands alone.

    `run-tests.sh` can be pointed at a scratch copy of this directory, and the
    parent of a scratch copy is a temporary directory holding whatever else the
    machine put there. Scanning that would measure something different on every
    run, so the fallback is the skill itself, which is a real tree either way.
    """
    candidate = SKILL_DIR.parents[1]
    return candidate if (candidate / ".git").exists() else SKILL_DIR


class TheRealTreeIsScannedOnceBecauseFixturesAreNotTrees(AuditCase):
    """Every other case here builds its own three files. This one does not.

    A tmpdir has no submodule, no committed symlink pointing back into itself,
    no 40 MB asset, no file whose name is a colon, and no Latin-1 leftover from
    2014. The walk meets all of those in a real checkout, and each of them has
    stopped a scanner in this repo at some point.

    NOT a case about being clean. This tree holds deliberate fixtures, planted
    so that the overlay and promote scans can be proved to bite, and a case that
    demanded zero findings would be red the day somebody adds another one. What
    is measured is that the walk terminates, that it says how much it read, and
    that every finding it reports names a file a reader can open.
    """

    def scanned(self):
        # No `runner=`, and no `stores=`: the point of this case is the real
        # thing, including the git probe and whatever the tree declares.
        return real_tree(), audit.run(str(real_tree()))

    def test_the_scan_completes_over_a_tree_nobody_built_for_it(self):
        _, report = self.scanned()
        self.assertIsInstance(report.findings, list)

    def test_it_says_how_many_files_it_read(self):
        _, report = self.scanned()
        self.assertGreater(report.files_read, 20,
                           "the walk read %d files, which is not a real tree"
                           % report.files_read)

    def test_the_count_line_carries_the_number_it_measured(self):
        _, report = self.scanned()
        self.assertIn("%d file(s) read" % report.files_read, audit.render(report))

    def test_every_finding_names_a_path_that_exists(self):
        root, report = self.scanned()
        missing = [f.path for f in report.findings
                   if not (Path(f.path) if Path(f.path).is_absolute()
                           else root / f.path).exists()]
        self.assertEqual(missing, [],
                         "these findings name files nobody can open: %s" % missing)

    def test_every_finding_carries_a_line_number_inside_the_file(self):
        root, report = self.scanned()
        wrong = []
        for finding in report.findings:
            path = Path(finding.path) if Path(finding.path).is_absolute() else root / finding.path
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if not 1 <= finding.line <= len(lines):
                wrong.append("%s:%d of %d" % (finding.path, finding.line, len(lines)))
        self.assertEqual(wrong, [], "these line numbers are outside their file: %s" % wrong)

    def test_no_excerpt_anywhere_in_the_real_report_exceeds_the_cap(self):
        # The cap is enforced in one function, and this is the run that puts
        # every pattern in the list past it rather than the two a fixture uses.
        _, report = self.scanned()
        long_ones = [f.excerpt for f in report.findings
                     if len(f.excerpt.rstrip("…")) > 8]
        self.assertEqual(long_ones, [], "these excerpts carry more than eight characters")

    def test_the_rendered_report_of_the_real_tree_carries_no_whole_line(self):
        # A finding prints a path, a line number, a pattern name and an
        # excerpt. If a rendered line ever grew past that shape it would be
        # quoting the file, and the file is where the values are.
        _, report = self.scanned()
        for line in audit.render(report).splitlines():
            with self.subTest(line=line[:40]):
                self.assertLessEqual(len(line), 200)
