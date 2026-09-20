"""`secrets audit`: the values that never became a reference, and where they go.

The other three verbs measure references that exist. This one looks for the
values that never became one, which is the direction the finding came from: a
maintainer copied an instance to a second machine and found small text files
holding tokens in working folders and temp directories, because an agent handed
a secret had nowhere declared to put it and chose for itself.

WHAT THE CASES BELOW ARE ACTUALLY GUARDING.

**The exit code is a verdict a wrapper acts on.** A loose credential exits 3 and
a clean tree exits 0. Personal data changes neither, and that is a decision with
a reason: a repository holding an invoice with an IBAN in it is not broken, and
a scanner that called it broken would be switched off in a week, taking the
credential half with it.

**A finding is a location, never a value.** The excerpt is capped at eight
characters and the value itself never reaches either stream, under any
combination of flags. That is not a style preference: an agent reads this
output, so anything printed here is in the model's context for the rest of the
session, in the transcript, and in whatever log the harness keeps, and none of
the three can be unprinted.

**A hit inside a declared file store is the store working.** Reporting it would
train the reader to skim the report, which is how the real hit gets skimmed too.

HOW THE CASES ARE DRIVEN. `engine.cli.main(argv, out=..., err=...)` with two
`StringIO` buffers, `engine.cli.Resolver` replaced by a factory that hands the
real resolver the declarations a case is about, and `engine.exec.run` replaced
by the `FakeRunner` from `conftest.py`. Everything between the command line and
the report then runs for real.

The process seam is installed at the module attribute rather than passed in,
because `command_audit` starts two processes and offers a `runner=` for
neither: `git ls-files`, which decides whether the scan reads the tracked set or
walks the tree, and `gitleaks`, when it is asked for. Answering both here is
also what makes these cases hermetic. A temporary directory that happened to sit
inside a checkout would otherwise be scanned as that checkout, and the case
would measure this repository instead of its own fixture.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from unittest import mock

from tests.conftest import (
    FakeRunner,
    MachineGuard,
    completed,
    mod,
    synthetic_token,
)

#: The verbs this file drives with a live value in play.
#: `test_acceptance.EveryVerbIsDrivenWithALiveValueSomewhere` unions this with
#: the lists of the sibling files and holds the result against `cli.COMMANDS`.
COVERED_VERBS = {"audit"}

audit_mod = mod("engine.audit")
cli = mod("engine.cli")
exec_mod = mod("engine.exec")
patterns_mod = mod("engine.patterns")
resolve = mod("engine.resolve")
stores_mod = mod("engine.stores")

#: The two codes this verb answers with. A wrapper reads numbers: 0 is "nothing
#: loose", 3 is "at least one credential is lying in a file", and the repair for
#: the second one is to move a value and rotate it.
EX_OK = 0
EX_MISSING = 3

#: No character class with a lower case letter in it, so this literal is not
#: itself the high entropy shape the acceptance scan looks for.
_UPPER_AND_DIGITS = "ABCDEFGHIJKLMNPQRSTUVWXYZ23456789"


def aws_key_shaped(seed: str) -> str:
    """A string of the shape `AKIA` plus sixteen, assembled at runtime.

    Nothing in this tree is a credential, not even a revoked one, and the way
    to keep that true is to have no literal worth copying. The prefix is split
    across the concatenation so that no LINE of this file carries the shape
    either: the acceptance scan reads every line of every file in the skill,
    and a fixture that had to be excused from it would be one more exception
    nobody re-reads.
    """
    offset = sum(ord(character) for character in seed)
    body = "".join(_UPPER_AND_DIGITS[(offset + step * 7) % len(_UPPER_AND_DIGITS)]
                   for step in range(16))
    return "AK" + "IA" + body


#: The planted credential most cases use. It resolves to `org-credential`, which
#: is what makes the suggestion cases possible.
PLANTED = aws_key_shaped("audit")

#: A second one, so a case can tell "the report found something" from "the
#: report found the thing in the file it names".
OTHER = aws_key_shaped("second")

#: A value with no vendor prefix at all, for the line shape a person writes by
#: hand. `patterns.looks_opaque` is what decides whether it counts.
TYPED_BY_HAND = synthetic_token("handwritten")      # pragma: allowlist secret

#: A private key header. Split for the same reason as the AWS prefix, and used
#: where a case needs a pattern that carries a `note`, since the note is half of
#: what `-v` adds.
KEY_HEADER = "-----BE" + "GIN OPENSSH PRIVATE KEY-----"

#: An IBAN shaped string whose check digits belong to no account anywhere. It is
#: personal data rather than a secret: it is printed on every invoice its owner
#: writes, and locking it in a vault would make it useless for its own purpose
#: while buying no security at all.
IBAN_SHAPED = "DE02" + " 1111 2222 3333 4444"

#: What the report says about itself, last line, always. A scan that found
#: nothing has not proved anything, and the sentence is there so that a reader
#: who greps for "0 credential" does not read it as a clearance.
DISCLAIMER = "A clean scan is not a proof"


class AuditCase(MachineGuard):
    """Drives `audit` with both streams captured and no process started."""

    def setUp(self):
        super().setUp()
        self.fake = FakeRunner()
        # A temporary directory is not a git work tree, and this is the answer
        # git gives for one. Without the route the scan would take whatever the
        # real git said about wherever TMPDIR happens to live.
        self.fake.add("ls-files", completed(rc=128, stderr="not a git repository"))
        self.gitleaks_here = False

    # -- the seams ----------------------------------------------------------

    def install_gitleaks(self, *, rc: int = 0, stdout: str = "[]") -> None:
        """Make `gitleaks` present on this machine, answering with `stdout`."""
        self.gitleaks_here = True
        self.fake.add("gitleaks", completed(rc=rc, stdout=stdout))

    def which(self, binary: str):
        if binary == "gitleaks":
            return "/usr/bin/gitleaks" if self.gitleaks_here else None
        return "/usr/bin/" + binary

    def exec_replacement(self):
        """`engine.exec.run`, answered by the house double.

        Built rather than patched with a lambda so that the `Invocation` the
        fake records is the one the engine would have built, which is what the
        argv assertions in this file are worth anything against.
        """
        fake = self.fake

        def run(argv, *, stdin_bytes=None, env=None, timeout_sec=30,
                cwd=None, runner=None):
            argv = tuple(str(item) for item in argv)
            invocation = exec_mod.Invocation(argv=argv, stdin_bytes=stdin_bytes,
                                             env=env, timeout_sec=timeout_sec, cwd=cwd)
            return (runner or fake)(argv, invocation=invocation)

        return run

    def resolver_factory(self, declared):
        def build(options=None, **kwargs):
            kwargs.setdefault("runner", self.fake)
            if declared is not None:
                kwargs.setdefault("stores", list(declared))
            return resolve.Resolver(options, **kwargs)
        return build

    def run_cli(self, argv, *, declared=()):
        """Run one command line. Returns (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch("engine.cli.Resolver",
                                           self.resolver_factory(declared)))
            stack.enter_context(mock.patch("engine.exec.which", self.which))
            stack.enter_context(mock.patch("engine.exec.run", self.exec_replacement()))
            code = cli.main(argv, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def audit(self, root, *flags, declared=()):
        return self.run_cli(["audit", "--root", str(root), *flags], declared=declared)

    def payload(self, root, *flags, declared=()):
        """The `--json` form, parsed, with the exit code beside it."""
        code, out, err = self.audit(root, "--json", *flags, declared=declared)
        return code, json.loads(out), err

    # -- fixtures -----------------------------------------------------------

    def tree(self, files):
        """A throwaway directory holding `files`, a mapping of path to text."""
        root = self.tmpdir()
        for name, text in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return root

    def planted_tree(self, also=None):
        """The ordinary fixture: one credential in a deploy script."""
        files = {"deploy.sh": "export AWS_ACCESS_KEY_ID=%s\n" % PLANTED,
                 "README.md": "nothing to see in this one\n"}
        files.update(also or {})
        return self.tree(files)

    def store_object(self, **fields):
        fields.setdefault("source", "infra/secret-stores/%s.yaml" % fields["name"])
        return stores_mod.Store(**fields)

    def vault_store(self, name="bridge-vault"):
        """A store that declares it holds `org-credential`, which is what the
        AWS shape suggests, so a finding can resolve to a real placement."""
        return self.store_object(
            name=name, backend="azure-keyvault", addresses=(name,),
            summary="The service principal vault",
            location={"vault_url": "https://%s.vault.azure.net/" % name},
            unlock={"method": "cli-login"}, reachable_from={},
            holds=({"kind": "org-credential", "naming": "<owner>-<service>"},),
            recovery={})

    def file_store(self, folder, name="runtime-files"):
        """A `file` store over a directory. The directory IS the store, so what
        lies in it is not a finding."""
        return self.store_object(
            name=name, backend="file", addresses=(str(folder) + "/*",),
            summary="Where a machine with no keychain keeps its runtime secrets",
            location={"path": str(folder)}, unlock={"method": "none"},
            reachable_from={}, holds=({"kind": "service-runtime"},), recovery={})


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------

class APlantedCredentialIsFoundAndSaysWhereItStands(AuditCase):
    """The ordinary run, and the four things a reader needs from it."""

    def setUp(self):
        super().setUp()
        self.root = self.planted_tree()
        self.code, self.out, self.err = self.audit(self.root)

    def test_it_exits_the_code_that_means_a_value_is_lying_in_a_file(self):
        self.assertEqual(self.code, EX_MISSING, self.out + self.err)

    def test_the_report_names_the_file_and_the_line_it_stands_on(self):
        self.assertIn("deploy.sh:1", self.out)

    def test_the_report_names_the_pattern_that_fired(self):
        # Without it the reader cannot tell a real AWS key id from the
        # key-and-value heuristic, and those two have different repairs.
        self.assertIn("aws-access-key", self.out)

    def test_the_path_is_relative_to_the_root_that_was_scanned(self):
        # An absolute path here would carry the home directory of whoever ran
        # the scan into a report that is often pasted somewhere else.
        self.assertNotIn(str(self.root), self.out)

    def test_the_file_with_nothing_in_it_is_not_named(self):
        self.assertNotIn("README.md", self.out)

    def test_neither_stream_carries_the_value(self):
        self.assertNotIn(PLANTED, self.out + self.err)

    def test_the_excerpt_is_the_first_eight_characters_and_no_more(self):
        # The cap is the rule that has already been broken once: a verify pass
        # decoded a base64 credential into a transcript while checking whether
        # the credential was really there.
        self.assertIn(patterns_mod.excerpt(PLANTED), self.out)
        self.assertNotIn(PLANTED[:9], self.out)

    def test_the_tally_counts_the_files_it_read(self):
        self.assertIn("2 file(s) read", self.out)

    def test_the_tally_counts_the_credentials_to_deal_with(self):
        self.assertIn("1 credential(s) to deal with", self.out)

    def test_the_report_says_a_clean_scan_would_not_have_been_a_proof(self):
        self.assertIn(DISCLAIMER, self.out)

    def test_nothing_was_written_to_the_error_stream(self):
        self.assertEqual(self.err, "")


class ACleanTreeExitsZeroAndStillSaysWhatItRead(AuditCase):
    """The green case, which has to stay distinguishable from a scan that
    read nothing at all. Both print no findings; only one read any files."""

    def setUp(self):
        super().setUp()
        self.root = self.tree({"notes.md": "a repository with nothing loose in it\n",
                               "config.yaml": "token: keychain://svc-mailer/agent\n"})
        self.code, self.out, self.err = self.audit(self.root)

    def test_it_exits_zero(self):
        self.assertEqual(self.code, EX_OK, self.out + self.err)

    def test_the_tally_says_how_many_files_were_actually_opened(self):
        self.assertIn("2 file(s) read", self.out)

    def test_it_counts_no_credentials(self):
        self.assertIn("0 credential(s) to deal with", self.out)

    def test_a_reference_is_not_a_finding(self):
        # The whole point of the skill is that the tree is full of these.
        self.assertNotIn("keychain://svc-mailer", self.out)

    def test_the_green_run_still_carries_the_disclaimer(self):
        self.assertIn(DISCLAIMER, self.out)


class PersonalDataIsReportedAndNeverProposedForAVault(AuditCase):
    """An IBAN is on every invoice its owner writes.

    It is worth REPORTING where it lies in a repository that ships, and it may
    not be proposed for a store: moving it makes it useless for its own purpose
    and buys no security. So it carries `kind: pii`, it gets no suggestion, and
    it does not change the verdict.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({"invoice.md": "Bank details: %s\n" % IBAN_SHAPED})
        self.code, self.out, self.err = self.audit(self.root)

    def test_a_repository_holding_an_invoice_is_not_broken(self):
        self.assertEqual(self.code, EX_OK, self.out)

    def test_the_hit_is_still_reported(self):
        self.assertIn("invoice.md:1", self.out)
        self.assertIn("iban", self.out)

    def test_the_heading_says_it_is_not_moved(self):
        self.assertIn("personal data, which is not a secret and is not moved", self.out)

    def test_it_stands_under_its_own_heading_and_not_among_the_credentials(self):
        self.assertNotIn("credentials in plain text", self.out)

    def test_no_store_is_proposed_for_it(self):
        _, payload, _ = self.payload(self.root, declared=[self.vault_store()])
        finding = payload["findings"][0]
        self.assertEqual(finding["kind"], "pii")
        self.assertEqual(finding["suggestion"], "")
        self.assertEqual(finding["store"], "")

    def test_a_credential_beside_it_is_what_changes_the_verdict(self):
        # The control. Without it "personal data does not change the code" is
        # also true of a scanner that found nothing in this tree at all.
        both = self.tree({"invoice.md": "Bank details: %s\n" % IBAN_SHAPED,
                          "deploy.sh": "export KEY=%s\n" % PLANTED})
        code, out, _ = self.audit(both)
        self.assertEqual(code, EX_MISSING)
        self.assertIn("1 personal-data hit(s)", out)


# ---------------------------------------------------------------------------
# what is declared is not a finding
# ---------------------------------------------------------------------------

class WhatLiesInsideADeclaredFileStoreIsTheStoreWorking(AuditCase):
    """The difference between this and a grep.

    A value inside a directory that a store declares as a `file` store is not a
    finding. Reporting it would train the reader to skim the report, which is
    the failure mode of every scanner that cries about its own fixtures.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tmpdir()
        self.runtime = self.root / "var" / "run" / "secrets"
        self.runtime.mkdir(parents=True)
        (self.runtime / "mailer.token").write_text(PLANTED + "\n", encoding="utf-8")
        (self.root / "README.md").write_text("ordinary prose\n", encoding="utf-8")
        self.declared = [self.file_store(self.runtime)]

    def test_the_declared_directory_holding_a_value_is_not_a_verdict(self):
        code, out, _ = self.audit(self.root, declared=self.declared)
        self.assertEqual(code, EX_OK, out)
        self.assertNotIn("credentials in plain text", out)

    def test_the_same_bytes_one_directory_higher_are_a_finding(self):
        # Otherwise the case above would also pass for a scanner that had
        # stopped reading that subtree at all.
        (self.root / "loose.env").write_text(PLANTED + "\n", encoding="utf-8")
        code, out, _ = self.audit(self.root, declared=self.declared)
        self.assertEqual(code, EX_MISSING)
        self.assertIn("loose.env:1", out)
        self.assertNotIn("mailer.token", out)

    def test_the_hit_is_kept_in_the_json_and_marked_rather_than_dropped(self):
        # A reader who wants to know what is in the store can still see it. The
        # flag says it is expected; nothing says it is not there.
        _, payload, _ = self.payload(self.root, declared=self.declared)
        inside = [finding for finding in payload["findings"] if finding["expected"]]
        self.assertEqual(len(inside), 1)
        self.assertIn("mailer.token", inside[0]["path"])
        self.assertEqual(payload["credentials"], 0)

    def test_the_note_on_an_expected_hit_says_why_it_is_not_a_problem(self):
        _, payload, _ = self.payload(self.root, declared=self.declared)
        self.assertEqual(payload["findings"][0]["note"], audit_mod.EXPECTED_IN_STORE)

    def test_without_the_declaration_the_same_tree_is_a_finding(self):
        code, out, _ = self.audit(self.root, declared=[])
        self.assertEqual(code, EX_MISSING)
        self.assertIn("mailer.token", out)


class TheSuggestionSaysWhereTheValueBelongsAndWhatToCallIt(AuditCase):
    """A finding reads "this is an AWS key, it belongs in X, call it Y".

    "Suspicious string" is what a grep says, and it leaves the reader with the
    same question the missing declaration created: where does this go. The kind
    each pattern carries resolves through the placement policy of the declared
    stores, so the answer is the same answer `where` gives.
    """

    def setUp(self):
        super().setUp()
        self.root = self.planted_tree()

    def test_it_names_the_declared_store(self):
        _, out, _ = self.audit(self.root, declared=[self.vault_store()])
        self.assertIn("belongs in bridge-vault", out)

    def test_it_names_the_reference_shape_with_the_naming_rule_in_it(self):
        _, out, _ = self.audit(self.root, declared=[self.vault_store()])
        self.assertIn("azure-keyvault://bridge-vault/<owner>-<service>", out)

    def test_with_nothing_declared_it_names_the_kind_that_is_missing(self):
        # The honest answer when no store holds this kind. It is a job for the
        # reader, not a reference that resolves to nowhere.
        _, out, _ = self.audit(self.root, declared=[])
        self.assertIn("declare a store that holds org-credential", out)

    def test_a_store_for_another_kind_does_not_attract_the_finding(self):
        _, out, _ = self.audit(self.root, declared=[self.file_store(self.tmpdir())])
        self.assertIn("declare a store that holds org-credential", out)
        self.assertNotIn("belongs in runtime-files", out)

    def test_the_suggestion_travels_in_the_json_as_two_fields(self):
        _, payload, _ = self.payload(self.root, declared=[self.vault_store()])
        finding = payload["findings"][0]
        self.assertEqual(finding["store"], "bridge-vault")
        self.assertTrue(finding["suggestion"].startswith("azure-keyvault://"))


class ALineThatDeclaresItselfAFixtureIsNotAFinding(AuditCase):
    """The pragma, spelled the way `detect-secrets` spells it.

    One convention covers both tools. A synthetic fixture carries it and a real
    secret never does, which is the whole contract. This suite depends on it:
    every file here that has to look like a credential says so on its own line.
    """

    def test_the_marked_line_is_walked_past(self):
        root = self.tree({"fixture.py": 'KEY = "%s"  # %s\n' % (PLANTED, patterns_mod.PRAGMA)})
        code, out, _ = self.audit(root)
        self.assertEqual(code, EX_OK, out)

    def test_the_same_line_without_the_mark_is_reported(self):
        root = self.tree({"fixture.py": 'KEY = "%s"\n' % PLANTED})
        self.assertEqual(self.audit(root)[0], EX_MISSING)

    def test_the_mark_excuses_its_own_line_and_not_the_one_below(self):
        root = self.tree({"fixture.py": 'FIRST = "%s"  # %s\nSECOND = "%s"\n'
                                        % (PLANTED, patterns_mod.PRAGMA, OTHER)})
        code, out, _ = self.audit(root)
        self.assertEqual(code, EX_MISSING)
        self.assertIn("fixture.py:2", out)
        self.assertNotIn("fixture.py:1", out)


class AValueTypedByHandIsMeasuredBeforeItIsBelieved(AuditCase):
    """The key-and-value shape, which no prefix pattern catches.

    It is also the shape that is wrong most often: measured over this repo, the
    assignment pattern alone produced 106 findings and 5 of them were real. So
    the value is asked a second question, and a line whose right hand side is
    code, a placeholder or a short uniform string is not a finding.
    """

    def test_an_opaque_value_behind_a_secret_shaped_name_is_reported(self):
        root = self.tree({"settings.yaml": "client_secret: %s\n" % TYPED_BY_HAND})
        code, out, _ = self.audit(root)
        self.assertEqual(code, EX_MISSING, out)
        self.assertIn("password-assignment", out)

    def test_a_value_that_is_a_call_rather_than_a_literal_is_not(self):
        root = self.tree({"app.py": "token = request.headers['Authorization']\n"})
        self.assertEqual(self.audit(root)[0], EX_OK)

    def test_a_placeholder_a_person_wrote_as_a_stand_in_is_not(self):
        root = self.tree({"example.yaml": "api_key: your-key-goes-here-example\n"})
        self.assertEqual(self.audit(root)[0], EX_OK)

    def test_an_interpolation_is_not(self):
        root = self.tree({"deploy.yaml": "password: ${VAULT_PASSWORD}\n"})
        self.assertEqual(self.audit(root)[0], EX_OK)


# ---------------------------------------------------------------------------
# the flags, one class each
# ---------------------------------------------------------------------------

class NoPiiNarrowsTheReportToCredentialsOnly(AuditCase):
    """`--no-pii`. Personal data is reported by default, never moved, and can
    be switched off by whoever is looking for credentials alone."""

    def setUp(self):
        super().setUp()
        self.root = self.tree({"deploy.sh": "export KEY=%s\n" % PLANTED,
                               "invoice.md": "Bank details: %s\n" % IBAN_SHAPED})

    def test_by_default_both_halves_are_in_the_report(self):
        _, out, _ = self.audit(self.root)
        self.assertIn("1 personal-data hit(s)", out)

    def test_the_flag_removes_the_personal_data_heading(self):
        _, out, _ = self.audit(self.root, "--no-pii")
        self.assertNotIn("personal data", out)

    def test_the_flag_takes_the_hit_out_of_the_tally_rather_than_hiding_it(self):
        _, out, _ = self.audit(self.root, "--no-pii")
        self.assertIn("0 personal-data hit(s)", out)

    def test_the_credential_half_is_untouched(self):
        code, out, _ = self.audit(self.root, "--no-pii")
        self.assertEqual(code, EX_MISSING)
        self.assertIn("deploy.sh:1", out)

    def test_the_findings_are_gone_from_the_json_and_not_merely_uncounted(self):
        _, payload, _ = self.payload(self.root, "--no-pii")
        self.assertEqual([f["kind"] for f in payload["findings"]], ["credential"])
        self.assertEqual(payload["pii"], 0)

    def test_a_tree_holding_only_an_invoice_reports_nothing_and_exits_zero(self):
        only = self.tree({"invoice.md": "Bank details: %s\n" % IBAN_SHAPED})
        code, out, _ = self.audit(only, "--no-pii")
        self.assertEqual(code, EX_OK)
        self.assertIn("0 credential(s) to deal with", out)


class AlsoReachesAPlaceOutsideTheTree(AuditCase):
    """`--also`. The tree is not where the loose values were found.

    They were in working folders and temporary directories, which is exactly
    what a scan rooted at the repository never sees. The flag is repeatable
    because there is never only one such place.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({"README.md": "a clean repository\n"})
        self.outside = self.tree({"notes.txt": "key %s\n" % PLANTED})
        self.second = self.tree({"scratch.env": "KEY=%s\n" % OTHER})

    def test_the_named_place_is_scanned_and_changes_the_verdict(self):
        code, out, _ = self.audit(self.root, "--also", str(self.outside))
        self.assertEqual(code, EX_MISSING, out)
        self.assertIn("notes.txt", out)

    def test_a_path_outside_the_tree_is_printed_in_full(self):
        # Relative to what, otherwise. The root is not its parent.
        _, out, _ = self.audit(self.root, "--also", str(self.outside))
        self.assertIn(str(self.outside / "notes.txt"), out)

    def test_the_flag_is_repeatable(self):
        _, out, _ = self.audit(self.root, "--also", str(self.outside),
                               "--also", str(self.second))
        self.assertIn("notes.txt", out)
        self.assertIn("scratch.env", out)

    def test_the_tree_itself_is_still_read(self):
        _, out, _ = self.audit(self.root, "--also", str(self.outside))
        self.assertIn("2 file(s) read", out)

    def test_the_value_does_not_reach_either_stream_from_out_there_either(self):
        _, out, err = self.audit(self.root, "--also", str(self.outside))
        self.assertNotIn(PLANTED, out + err)

    # KNOWN RED, and reported rather than worked around. `audit.run` walks an
    # extra root with `discover._walked`, and `os.walk` over a FILE yields
    # nothing at all, so `--also ~/.aws/credentials` reads that file never,
    # reports nothing, and exits 0. The tally still says "1 file(s) read",
    # because the tree was read, so nothing in the output says the named path
    # was skipped. That is the worst shape a scanner has: green, and it
    # examined none of what it was asked to examine. A single credentials file
    # is the most obvious thing anybody passes to this flag.
    def test_also_naming_a_single_file_reads_that_file(self):
        loose = self.outside / "notes.txt"
        code, out, _ = self.audit(self.root, "--also", str(loose))
        self.assertEqual(code, EX_MISSING,
                         "--also named a file and the scan walked past it in silence: " + out)


class VerboseAddsTheReasonAndWhatTheStoresAbsorbed(AuditCase):
    """`-v`. Two additions, and both are the answer to a question the short
    form provokes: why is this a pattern, and what did the scan decide not to
    tell me about."""

    def setUp(self):
        super().setUp()
        self.root = self.tmpdir()
        self.runtime = self.root / "run"
        self.runtime.mkdir()
        (self.runtime / "mailer.token").write_text(PLANTED + "\n", encoding="utf-8")
        (self.root / "id_ed25519").write_text(KEY_HEADER + "\n", encoding="utf-8")
        self.declared = [self.file_store(self.runtime)]

    def test_the_short_form_carries_neither(self):
        _, out, _ = self.audit(self.root, declared=self.declared)
        self.assertNotIn("inside declared file stores", out)
        self.assertNotIn("disclosed the moment the repo is cloned", out)

    def test_it_prints_the_reason_the_pattern_exists(self):
        _, out, _ = self.audit(self.root, "-v", declared=self.declared)
        self.assertIn("disclosed the moment the repo is cloned", out)

    def test_it_counts_what_the_declared_stores_absorbed(self):
        _, out, _ = self.audit(self.root, "-v", declared=self.declared)
        self.assertIn("1 hit(s) inside declared file stores", out)

    def test_the_long_form_spelling_is_the_same_flag(self):
        _, short, _ = self.audit(self.root, "-v", declared=self.declared)
        _, long_form, _ = self.audit(self.root, "--verbose", declared=self.declared)
        self.assertEqual(short, long_form)

    def test_it_does_not_change_the_verdict(self):
        quiet = self.audit(self.root, declared=self.declared)[0]
        loud = self.audit(self.root, "-v", declared=self.declared)[0]
        self.assertEqual(quiet, loud)

    def test_it_prints_no_value_either(self):
        _, out, err = self.audit(self.root, "-v", declared=self.declared)
        self.assertNotIn(PLANTED, out + err)


class GitleaksIsASecondOpinionAndNeverTheVerdict(AuditCase):
    """`--with-gitleaks`. A deliberate second opinion, not a replacement.

    The built-in set is small, readable and ships with the skill; gitleaks knows
    several hundred more shapes and is a static binary anybody can install.
    Neither proves the absence of a secret. So its count is reported beside the
    tally and is not allowed to decide the exit code: a verdict that depended on
    whether an optional binary happened to be installed would mean two different
    things on two machines.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({"README.md": "a clean repository\n"})

    def test_without_the_flag_no_second_process_is_started(self):
        self.install_gitleaks(stdout=json.dumps([{"RuleID": "aws-access-key"}]))
        self.audit(self.root)
        self.assertFalse(self.fake.called_with("gitleaks"),
                         "the optional scanner ran without being asked:\n"
                         + self.fake.joined_calls)

    def test_a_machine_without_it_is_told_so_rather_than_left_guessing(self):
        _, out, _ = self.audit(self.root, "--with-gitleaks")
        self.assertIn("gitleaks is not installed here", out)

    def test_a_machine_without_it_still_exits_on_its_own_findings(self):
        planted = self.planted_tree()
        self.assertEqual(self.audit(planted, "--with-gitleaks")[0], EX_MISSING)

    def test_the_count_it_reports_is_printed_beside_the_tally(self):
        self.install_gitleaks(stdout=json.dumps([{"RuleID": "a"}, {"RuleID": "b"}]))
        _, out, _ = self.audit(self.root, "--with-gitleaks")
        self.assertIn("gitleaks reported 2 finding(s)", out)

    def test_its_findings_do_not_decide_the_exit_code(self):
        self.install_gitleaks(rc=1, stdout=json.dumps([{"RuleID": "a"}]))
        code, out, _ = self.audit(self.root, "--with-gitleaks")
        self.assertEqual(code, EX_OK, out)

    def test_it_is_asked_for_json_on_standard_output_and_named_the_root(self):
        # `--report-path -` is what keeps the report out of a file in the tree
        # being scanned, which is where the default would put it.
        self.install_gitleaks()
        self.audit(self.root, "--with-gitleaks")
        call = self.fake.calls[self.fake.index_of("gitleaks")]
        self.assertIn(str(self.root), call["argv"])
        self.assertIn("--report-format", call["argv"])
        self.assertIn("-", call["argv"])

    def test_an_answer_that_is_not_json_is_reported_rather_than_raised(self):
        self.install_gitleaks(stdout="panic: something went wrong")
        code, out, _ = self.audit(self.root, "--with-gitleaks")
        self.assertEqual(code, EX_OK)
        self.assertIn("gitleaks answered something that is not JSON", out)

    def test_an_exit_code_it_does_not_understand_is_named(self):
        # 0 and 1 are "clean" and "found something". Anything else is the tool
        # failing, and a failure reported as zero findings reads as clearance.
        self.install_gitleaks(rc=2, stdout="")
        _, out, _ = self.audit(self.root, "--with-gitleaks")
        self.assertIn("gitleaks exited 2", out)

    def test_the_value_is_never_handed_to_the_second_scanner_in_argv(self):
        self.install_gitleaks()
        planted = self.planted_tree()
        self.audit(planted, "--with-gitleaks")
        self.assertFalse(self.fake.argv_carried(PLANTED),
                         "the value stood in argv, where ps shows it to the machine")


# ---------------------------------------------------------------------------
# the machine readable form
# ---------------------------------------------------------------------------

class TheJsonFormCarriesEveryFieldAReaderWouldParse(AuditCase):
    """`--json`. The same measurement, for something that is not a person.

    A workload that runs this on a schedule reads the numbers; a person reads
    the text. Both come out of one report, so a field that exists in one form
    and not the other is a difference nobody notices until the schedule is the
    only thing still running.
    """

    def setUp(self):
        super().setUp()
        self.root = self.planted_tree({"invoice.md": "IBAN %s\n" % IBAN_SHAPED})
        self.code, self.payload_, self.err = self.payload(
            self.root, declared=[self.vault_store()])

    def test_it_carries_the_five_top_level_fields(self):
        self.assertEqual(set(self.payload_),
                         {"findings", "files_read", "credentials", "pii", "gitleaks"})

    def test_the_counts_agree_with_the_findings_they_summarise(self):
        kinds = [finding["kind"] for finding in self.payload_["findings"]]
        self.assertEqual(self.payload_["credentials"], kinds.count("credential"))
        self.assertEqual(self.payload_["pii"], kinds.count("pii"))

    def test_files_read_is_the_number_of_files_actually_opened(self):
        self.assertEqual(self.payload_["files_read"], 3)

    def test_every_finding_carries_the_nine_fields_of_the_record(self):
        for finding in self.payload_["findings"]:
            with self.subTest(pattern=finding.get("pattern")):
                self.assertEqual(set(finding),
                                 {"path", "line", "pattern", "excerpt", "kind",
                                  "suggestion", "store", "expected", "note"})

    def test_the_gitleaks_field_is_empty_when_it_was_not_asked(self):
        self.assertEqual(self.payload_["gitleaks"], "")

    def test_the_gitleaks_field_carries_the_sentence_when_it_was(self):
        self.install_gitleaks(stdout=json.dumps([{"RuleID": "a"}]))
        _, payload, _ = self.payload(self.root, "--with-gitleaks")
        self.assertIn("gitleaks reported 1 finding(s)", payload["gitleaks"])

    def test_the_exit_code_is_the_same_as_the_text_form(self):
        self.assertEqual(self.code, self.audit(self.root,
                                               declared=[self.vault_store()])[0])

    def test_the_excerpt_is_capped_here_as_well(self):
        for finding in self.payload_["findings"]:
            with self.subTest(pattern=finding["pattern"]):
                self.assertLessEqual(len(finding["excerpt"]), 9)

    def test_no_field_of_it_carries_the_value(self):
        self.assertNotIn(PLANTED, json.dumps(self.payload_))


# ---------------------------------------------------------------------------
# the property that holds across every flag
# ---------------------------------------------------------------------------

#: Every combination worth running, including the ones nobody would type. The
#: value may not appear under any of them, and a property that held for the
#: flags somebody thought of is not a property.
FLAG_COMBINATIONS = (
    (),
    ("-v",),
    ("--json",),
    ("--no-pii",),
    ("--with-gitleaks",),
    ("-v", "--json"),
    ("-v", "--no-pii"),
    ("--json", "--no-pii"),
    ("--json", "--with-gitleaks"),
    ("-v", "--json", "--no-pii", "--with-gitleaks"),
)


class NoFlagCombinationOfThisVerbPrintsTheValue(AuditCase):
    """The constraint the whole skill is built on, measured over the matrix.

    An agent reads this output. `audit` is the one verb that reads plaintext
    values out of files by design, so it is also the one verb whose report is
    assembled FROM secrets, and a formatting change here is one line away from
    writing the thing into the transcript that this skill exists to keep out.
    """

    def setUp(self):
        super().setUp()
        self.install_gitleaks(stdout=json.dumps([{"RuleID": "a"}]))
        self.outside = self.tree({"scratch.env": "KEY=%s\n" % OTHER})
        self.root = self.planted_tree({
            "invoice.md": "IBAN %s\n" % IBAN_SHAPED,
            "settings.yaml": "client_secret: %s\n" % TYPED_BY_HAND,
            "id_ed25519": KEY_HEADER + "\n",
        })

    def test_no_combination_of_flags_puts_a_value_into_either_stream(self):
        for flags in FLAG_COMBINATIONS:
            with self.subTest(flags=" ".join(flags) or "(none)"):
                _, out, err = self.audit(self.root, *flags,
                                         "--also", str(self.outside),
                                         declared=[self.vault_store()])
                both = out + err
                for value in (PLANTED, OTHER, TYPED_BY_HAND):
                    self.assertNotIn(value, both)

    def test_every_combination_still_reported_the_credential(self):
        # Otherwise the case above is also green over a verb that printed
        # nothing at all, which is not the property claimed here.
        for flags in FLAG_COMBINATIONS:
            with self.subTest(flags=" ".join(flags) or "(none)"):
                code, out, _ = self.audit(self.root, *flags,
                                          "--also", str(self.outside),
                                          declared=[self.vault_store()])
                self.assertEqual(code, EX_MISSING)
                self.assertIn("deploy.sh", out)

    def test_the_verb_is_registered_under_the_name_this_file_claims(self):
        self.assertLessEqual(COVERED_VERBS, set(cli.COMMANDS))


class TheScanReadsWhatItCanAndSaysNothingAboutTheRest(AuditCase):
    """The edges of "every file", each one a place a scan quietly stops.

    None of these is a finding, and each of them is a reason the closing
    sentence of the report is not decoration.
    """

    def test_a_binary_file_is_skipped_rather_than_decoded(self):
        root = self.tmpdir()
        (root / "blob.bin").write_bytes(b"\x00\x01" + PLANTED.encode("utf-8"))
        (root / "notes.md").write_text("prose\n", encoding="utf-8")
        code, out, _ = self.audit(root)
        self.assertEqual(code, EX_OK)
        self.assertIn("1 file(s) read", out)

    def test_a_symlink_is_not_followed(self):
        # The discovery symlinks point back into the tree. Following them
        # counted every skill three times when `refs` first walked this repo.
        root = self.tmpdir()
        (root / "real.env").write_text("KEY=%s\n" % PLANTED, encoding="utf-8")
        os.symlink(root / "real.env", root / "alias.env")
        _, out, _ = self.audit(root)
        self.assertIn("real.env:1", out)
        self.assertNotIn("alias.env", out)

    def test_two_values_on_one_line_are_two_findings(self):
        root = self.tree({"pair.env": "A=%s B=%s\n" % (PLANTED, KEY_HEADER)})
        _, out, _ = self.audit(root)
        self.assertIn("aws-access-key", out)
        self.assertIn("private-key", out)

    def test_the_same_value_on_two_lines_is_reported_at_both(self):
        root = self.tree({"twice.env": "A=%s\nB=%s\n" % (PLANTED, PLANTED)})
        _, out, _ = self.audit(root)
        self.assertIn("twice.env:1", out)
        self.assertIn("twice.env:2", out)


if __name__ == "__main__":
    import unittest

    unittest.main()
