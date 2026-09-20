"""The command line: the exit code a wrapper reads, and the value it never sees.

Everything here goes through `engine.cli.main(argv, out=..., err=...)` with two
`StringIO` buffers, so no case writes to the terminal and both streams can be
asserted on separately. That split is load bearing rather than tidy: the header
lines that name an injected variable belong on stderr, because stdout is what a
caller pipes into another program, and a header on stdout would corrupt it.

THE SEAM. `command_check` and `command_run` build their own `Resolver` with no
runner, so the smallest patch that reaches a backend from outside is
`engine.cli.Resolver`, replaced by a factory that returns the REAL resolver with
a `runner=` and a `context=` filled in. Everything below the CLI then runs for
real, including the keychain backend and its stderr parser, and only the process
is a double. Patching `Resolver.read` instead would have skipped
`readable_here` and `locate`, which is where two of the statuses come from.
`engine.exec.which` is answered as well, so a Linux runner and a Mac measure the
same thing rather than one of them reporting "no backend here".

The child of `secrets run` is a REAL process, and deliberately so: the value has
to reach a foreign program's environment and come back through a pipe for the
redaction to mean anything. It is this interpreter running a two line program,
never a tool from the denylist, and `MachineGuard` still refuses every binary
that could reach a live store.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
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

cli = mod("engine.cli")
base = mod("engine.backends.base")
resolve = mod("engine.resolve")
values = mod("engine.values")

SERVICE = "suite-service"
ACCOUNT = "suite-account"
REF = "keychain://" + SERVICE + "/" + ACCOUNT
NAME = "SUITE_TOKEN"

#: Assembled rather than pasted. Long enough that the redactor takes it: the
#: short-value case below is the one that wants the other side of that line.
TOKEN = synthetic_token("cli")  # pragma: allowlist secret

#: Under `values.MIN_REDACTABLE`, so the redactor refuses to cover it. Built out
#: of pieces for the same reason as the token above.
SHORT_VALUE = "a" + "b" + "1"

#: The exit codes this file pins, from `engine.errors`. Spelled out here because
#: they are the contract with every wrapper script, and a wrapper reads numbers.
EX_OK = 0
EX_MISSING = 3
EX_USAGE = 64
EX_CONFIG = 78

CHILD_ECHOES_THE_VARIABLE = (
    "import os, sys\n"
    "value = os.environ.get('%s', '<unset>')\n"
    "sys.stdout.write(value)\n"
    "sys.stderr.write('child says ' + value)\n" % NAME
)

CHILD_LEAVES_A_MARK = (
    "import pathlib, sys\n"
    "pathlib.Path(sys.argv[1]).write_text('the child ran')\n"
)

CHILD_FAILS = "import sys\nsys.stdout.write('done')\nsys.exit(7)\n"


def answers(stderr: str, rc: int = 0) -> FakeRunner:
    return FakeRunner().add(
        "find-generic-password",
        completed(rc=rc, stdout=keychain_attributes(SERVICE, ACCOUNT), stderr=stderr),
    )


def answers_with_value(value: str = TOKEN) -> FakeRunner:
    return answers(keychain_report(value=value))


def answers_missing() -> FakeRunner:
    return answers("security: SecKeychainSearchCopyNext: The specified item "
                   "could not be found in the keychain.", rc=44)


def leaky_redactor():
    """A redactor that registers a value and then does not remove it.

    The belt in `_emit` is `holds()` on the ALREADY SCRUBBED text, and the only
    way to watch it fire is a scrubber that misses. In production the miss is an
    encoding nobody anticipated; here it is this subclass, because inventing an
    encoding the redactor does not know would also be an encoding `holds()` does
    not know, and then nothing would notice the leak at all.

    A factory rather than a class statement, for two reasons: every class in a
    test file has to stand under the machine guard, and a class statement at
    module level would import `engine.values` during collection, which is what
    the lazy module proxy exists to avoid.
    """
    def scrub(self, text):
        return text

    return type("LeakyRedactor", (values.Redactor,), {"scrub": scrub})


class CliCase(MachineGuard):
    """Drives `cli.main` with both streams captured and the backend faked."""

    def desktop(self):
        return base.Context(platform="darwin", interactive=True,
                            over_ssh=False, display=True)

    def resolver_factory(self, runner, context):
        def build(options=None, **kwargs):
            kwargs.setdefault("runner", runner)
            kwargs.setdefault("context", context)
            return resolve.Resolver(options, **kwargs)
        return build

    def run_cli(self, argv, *, runner=None, context=None, redactor=None):
        """Run one command line. Returns (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch("engine.exec.which",
                                           lambda binary: "/usr/bin/" + binary))
            if runner is not None:
                stack.enter_context(mock.patch(
                    "engine.cli.Resolver",
                    self.resolver_factory(runner, context or self.desktop())))
            if redactor is not None:
                stack.enter_context(mock.patch("engine.cli.Redactor", redactor))
            code = cli.main(argv, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def child(self, program, *arguments):
        """The command line tail that runs `program` in this interpreter."""
        return ["--", sys.executable, "-c", program, *arguments]

    def tree(self, files: dict):
        root = self.tmpdir()
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root


# ---------------------------------------------------------------------------
# refs
# ---------------------------------------------------------------------------

TREE = {
    "infra/channels/mailer.yaml": "token: %s\n" % REF,
    "infra/channels/agent.yaml": "name: agent\ntoken: %s\n" % REF,
    "identity/accounts/work.yaml": "password: keepass://work/acme/api-token#password\n",
    "workflow/workloads/report.yaml": "env:\n  BROKEN: vault://onlyone\n",
    "docs/placement.md": "Write keychain://my-service/<account> for a keychain item.\n",
}


class TheReferenceListNamesEveryPlaceAndCountsExamplesApart(CliCase):
    """`refs` is the inventory, derived from the tree and never from a registry.

    A registry would be wrong within a week and wrong in the direction that
    matters: the reference nobody registered is the one nobody checks.
    """

    def listing(self):
        code, out, err = self.run_cli(["refs", "--root", str(self.tree(TREE))])
        self.assertEqual(code, EX_OK, err)
        return out

    def test_a_reference_is_printed_once_however_many_files_write_it_down(self):
        self.assertEqual(self.listing().count(REF + "\n"), 1)

    def test_every_file_and_line_that_writes_it_down_is_listed_under_it(self):
        out = self.listing()
        self.assertIn("    infra/channels/agent.yaml:2", out)
        self.assertIn("    infra/channels/mailer.yaml:1", out)

    def test_the_hash_form_of_a_field_is_printed_in_the_canonical_form(self):
        # `keepass://work/acme/api-token#password` and the slash form address the
        # same field, so the inventory has to spell them the same way or one
        # entry becomes two.
        self.assertIn("keepass://work/acme/api-token/password", self.listing())

    def test_a_reference_that_does_not_parse_is_marked_where_it_stands(self):
        self.assertIn("vault://onlyone   <- does not parse:", self.listing())

    def test_the_tally_counts_the_references_and_the_files(self):
        self.assertIn("3 references in 4 files, 1 do not parse", self.listing())

    def test_examples_in_prose_are_counted_apart_from_references(self):
        # Measured on the open-bridge tree: half the hits carry a placeholder,
        # and counting those as references buries the ones that are real.
        self.assertIn("1 more carry a placeholder and are read as examples in prose",
                      self.listing())

    def test_an_example_is_not_listed_as_a_reference(self):
        self.assertNotIn("my-service", self.listing().splitlines()[0])

    def test_a_tree_with_no_references_says_so(self):
        root = self.tree({"docs/readme.md": "nothing to see here\n"})
        code, out, _ = self.run_cli(["refs", "--root", str(root)])
        self.assertEqual((code, out.strip()), (EX_OK, "no secret references in this tree"))


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

class TheExitCodeOfCheckIsWhatAWrapperReads(CliCase):
    """Three numbers, and telling them apart is the point of the whole skill.

    0 means every reference resolved. 3 means an entry is gone, which is a
    rotation somebody has to finish. 78 means a declaration is wrong, which is a
    file somebody has to edit. A wrapper that saw one number for all three
    started without a secret and said nothing.
    """

    def test_a_reference_that_resolves_exits_zero(self):
        code, _, err = self.run_cli(["check", REF], runner=answers_with_value())
        self.assertEqual(code, EX_OK, err)

    def test_an_entry_that_is_gone_exits_three(self):
        code, _, _ = self.run_cli(["check", REF], runner=answers_missing())
        self.assertEqual(code, EX_MISSING)

    def test_a_reference_that_does_not_parse_exits_seventy_eight(self):
        code, _, _ = self.run_cli(["check", "vault://onlyone"],
                                  runner=answers_with_value())
        self.assertEqual(code, EX_CONFIG)

    def test_a_broken_reference_outranks_a_missing_entry(self):
        # Both are wrong and only one of them is fixable by editing a file, so
        # that is the number the run reports.
        code, _, _ = self.run_cli(["check", REF, "vault://onlyone"],
                                  runner=answers_missing())
        self.assertEqual(code, EX_CONFIG)

    def test_the_table_is_printed_on_standard_output(self):
        _, out, err = self.run_cli(["check", REF], runner=answers_with_value())
        self.assertIn(REF, out)
        self.assertEqual(err, "")

    def test_the_places_are_printed_only_under_the_verbose_flag(self):
        root = self.tree(TREE)
        plain = self.run_cli(["check", "--root", str(root)],
                             runner=answers_with_value())[1]
        loud = self.run_cli(["check", "--root", str(root), "-v"],
                            runner=answers_with_value())[1]
        self.assertNotIn("mailer.yaml", plain)
        self.assertIn("infra/channels/mailer.yaml:1", loud)


class TheMachineReadableFormDoesNotChangeTheVerdict(CliCase):
    """`--json` changes the shape of the output and nothing else."""

    def test_the_json_form_exits_the_same_way_as_the_table(self):
        table = self.run_cli(["check", REF], runner=answers_missing())[0]
        document = self.run_cli(["check", "--json", REF], runner=answers_missing())[0]
        self.assertEqual((table, document), (EX_MISSING, EX_MISSING))

    def test_the_json_form_carries_the_documented_keys(self):
        _, out, _ = self.run_cli(["check", "--json", REF], runner=answers_with_value())
        self.assertEqual(sorted(json.loads(out)[0]),
                         ["bytes", "fingerprint", "note", "places", "ref", "scheme",
                          "status", "where"])

    def test_the_json_form_carries_the_fingerprint_and_not_the_value(self):
        _, out, err = self.run_cli(["check", "--json", REF], runner=answers_with_value())
        self.assertEqual(json.loads(out)[0]["fingerprint"], values.fingerprint(TOKEN))
        self.assertNotIn(TOKEN, out + err)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

class RunHandsTheValueToTheChildAndScrubsWhatComesBack(CliCase):
    """The one verb that moves a value, and the only one that could leak it.

    The value goes into the child's environment, never into its argv, and
    whatever the child says on the way back is cleaned before the agent reads it.
    """

    def echo(self, runner=None, **kwargs):
        return self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF),
             *self.child(CHILD_ECHOES_THE_VARIABLE)],
            runner=runner or answers_with_value(), **kwargs)

    def test_the_child_reads_the_value_out_of_its_own_environment(self):
        # It printed something other than `<unset>`, and what it printed came
        # back as the placeholder, which is only possible if it had the value.
        _, out, _ = self.echo()
        self.assertEqual(out.strip(), "[redacted:%s]" % NAME)

    def test_the_childs_standard_error_is_scrubbed_too(self):
        _, _, err = self.echo()
        self.assertIn("child says [redacted:%s]" % NAME, err)

    def test_the_value_appears_in_neither_stream(self):
        _, out, err = self.echo()
        self.assertNotIn(TOKEN, out + err)

    def test_the_placeholder_names_the_variable_so_the_reader_knows_which_one(self):
        _, out, _ = self.echo()
        self.assertIn(NAME, out)

    def test_the_exit_code_of_the_child_is_the_exit_code_of_the_run(self):
        code, out, _ = self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF), *self.child(CHILD_FAILS)],
            runner=answers_with_value())
        self.assertEqual((code, out.strip()), (7, "done"))

    def test_the_value_never_travels_in_the_argv_of_the_keychain_read(self):
        runner = answers_with_value()
        self.echo(runner)
        self.assertFalse(runner.argv_carried(TOKEN), runner.joined_calls)

    def test_a_child_that_says_nothing_produces_no_output(self):
        code, out, err = self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF), *self.child("pass\n")],
            runner=answers_with_value())
        self.assertEqual((code, out), (EX_OK, ""))
        self.assertNotIn("[redacted", err)


class AStreamThatStillHoldsAValueIsNotPrinted(CliCase):
    """The belt over the braces: `_emit` checks its own work before printing.

    Scrubbing is pattern replacement and patterns can miss. When the cleaned
    text still holds a registered value, printing it is the one thing that must
    not happen, so the stream is dropped and the caller is told which one.
    """

    def leaky(self):
        return self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF),
             *self.child(CHILD_ECHOES_THE_VARIABLE)],
            runner=answers_with_value(), redactor=leaky_redactor())

    def test_the_standard_output_of_the_child_is_dropped_entirely(self):
        _, out, _ = self.leaky()
        self.assertEqual(out, "")

    def test_the_refusal_names_the_stream_it_dropped(self):
        _, _, err = self.leaky()
        self.assertIn("refused to print the child's standard output", err)

    def test_the_standard_error_of_the_child_is_dropped_as_well(self):
        _, _, err = self.leaky()
        self.assertIn("refused to print the child's standard error", err)
        self.assertNotIn("child says", err)

    def test_the_refusal_itself_carries_no_value(self):
        _, out, err = self.leaky()
        self.assertNotIn(TOKEN, out + err)

    def test_the_exit_code_of_the_child_still_comes_back(self):
        # Dropping the output is not the same as losing the verdict.
        code, _, _ = self.leaky()
        self.assertEqual(code, EX_OK)


class AValueTooShortToRedactIsAnnouncedRatherThanHidden(CliCase):
    """Under `values.MIN_REDACTABLE` the replacement would fire on ordinary words.

    So the run does not redact, and it says so instead of pretending the output
    was covered. This is the documented exception to "no verb prints a value",
    and the loud line is the whole reason it is allowed to exist.
    """

    def short(self):
        return self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF),
             *self.child(CHILD_ECHOES_THE_VARIABLE)],
            runner=answers_with_value(SHORT_VALUE))

    def test_the_run_names_the_variable_it_could_not_cover(self):
        _, _, err = self.short()
        self.assertIn("too short to redact safely", err)
        self.assertIn(NAME, err)

    def test_the_childs_output_is_printed_as_it_came(self):
        _, out, _ = self.short()
        self.assertEqual(out.strip(), SHORT_VALUE)

    def test_no_placeholder_is_printed_for_a_value_nobody_replaced(self):
        _, out, _ = self.short()
        self.assertNotIn("[redacted", out)


class TheThreeAnswersToAReferenceThatResolvesToNothing(CliCase):
    """`--if-missing` is a policy, and the three settings have to differ.

    A wrapper whose secret is gone wants the run to stop. A tool that treats an
    absent variable as a default wants the run to continue and be told. A
    third, on a machine where the store is simply not provisioned, wants
    silence. One flag, three behaviours, and each one is a different day.
    """

    def with_policy(self, policy, *arguments, program=CHILD_ECHOES_THE_VARIABLE):
        return self.run_cli(
            ["run", "--if-missing", policy, "--env", "%s=%s" % (NAME, REF),
             *self.child(program, *arguments)],
            runner=answers_missing())

    def test_error_exits_three(self):
        code, _, _ = self.with_policy("error")
        self.assertEqual(code, EX_MISSING)

    def test_error_says_which_reference_resolved_to_nothing(self):
        _, _, err = self.with_policy("error")
        self.assertIn(REF, err)
        self.assertIn("no value behind this reference", err)

    def test_error_does_not_start_the_child(self):
        # The point of the policy. A child started without its credential gets
        # halfway through the work before it fails, and sometimes not even then.
        mark = self.tmpdir() / "the-child-ran"
        self.with_policy("error", str(mark), program=CHILD_LEAVES_A_MARK)
        self.assertFalse(mark.exists())

    def test_warn_starts_the_child_anyway(self):
        code, out, _ = self.with_policy("warn")
        self.assertEqual((code, out.strip()), (EX_OK, "<unset>"))

    def test_warn_says_what_was_not_injected(self):
        _, _, err = self.with_policy("warn")
        self.assertIn("no value behind this reference", err)

    def test_ignore_starts_the_child_and_says_nothing_about_it(self):
        code, out, err = self.with_policy("ignore")
        self.assertEqual((code, out.strip()), (EX_OK, "<unset>"))
        self.assertNotIn("no value behind this reference", err)

    def test_neither_warn_nor_ignore_invents_an_empty_variable(self):
        # An empty string in the environment is not the same as an absent one,
        # and a tool that checks `if os.environ.get(NAME)` cannot tell them
        # apart from a value that failed to arrive.
        for policy in ("warn", "ignore"):
            self.assertEqual(self.with_policy(policy)[1].strip(), "<unset>")


class RunWithoutACommandIsAUsageError(CliCase):
    """64 is EX_USAGE: the command line is wrong, nothing was attempted."""

    def test_the_exit_code_is_sixty_four(self):
        code, _, _ = self.run_cli(["run"])
        self.assertEqual(code, EX_USAGE)

    def test_the_message_shows_the_shape_of_the_command(self):
        _, _, err = self.run_cli(["run"])
        self.assertIn("secrets run --env NAME=ref -- your-command", err)

    def test_nothing_is_written_to_standard_output(self):
        _, out, _ = self.run_cli(["run"])
        self.assertEqual(out, "")

    def test_no_reference_is_resolved_before_the_command_line_is_checked(self):
        runner = answers_with_value()
        code, _, _ = self.run_cli(["run", "--env", "%s=%s" % (NAME, REF)], runner=runner)
        self.assertEqual((code, runner.calls), (EX_USAGE, []))

    def test_a_variable_spelled_without_a_reference_is_a_usage_error(self):
        code, _, err = self.run_cli(["run", "--env", NAME, *self.child("pass\n")],
                                    runner=answers_with_value())
        self.assertEqual(code, EX_USAGE)
        self.assertIn("expected NAME=reference", err)


class TheHelpFlagIsNotAUsageError(CliCase):
    """`secrets --help` answered the question it was asked, so it exits 0.

    A wrapper that runs `secrets --help` to probe whether the tool is installed
    reads 64 today, which is the code for "your command line is wrong".
    """

    def test_asking_for_help_exits_zero(self):
        # argparse prints the help text to the real stdout rather than to the
        # buffer, so that stream is swallowed here and only the code is read.
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["--help"], out=io.StringIO(), err=io.StringIO())
        self.assertEqual(code, EX_OK)


class TheHeaderLinesGoToStandardErrorAndCarryNoValue(CliCase):
    """Each injected variable is announced, because silent injection is worse.

    The announcement has to be readable next to the child's own output without
    corrupting it, and it has to be enough to tell two live tokens apart, which
    is what the fingerprint is for.
    """

    def header(self):
        return self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF), *self.child("pass\n")],
            runner=answers_with_value())

    def test_the_header_names_the_variable_and_the_reference_it_came_from(self):
        _, _, err = self.header()
        self.assertIn("secrets: %s <- %s" % (NAME, REF), err)

    def test_the_header_carries_the_byte_count_and_the_fingerprint(self):
        _, _, err = self.header()
        self.assertIn("(%d bytes, sha256 %s)" % (len(TOKEN), values.fingerprint(TOKEN)),
                      err)

    def test_the_header_is_not_on_standard_output(self):
        # stdout is what a caller pipes into another program.
        _, out, _ = self.header()
        self.assertNotIn(NAME, out)

    def test_the_header_carries_no_value(self):
        _, out, err = self.header()
        self.assertNotIn(TOKEN, out + err)

    def test_a_value_handed_over_on_standard_input_is_announced_too(self):
        code, out, err = self.run_cli(
            ["run", "--stdin", REF,
             *self.child("import sys\nsys.stdin.read()\n")],
            runner=answers_with_value())
        self.assertEqual(code, EX_OK, err)
        self.assertIn("secrets: standard input <- %s" % REF, err)
        self.assertNotIn(TOKEN, out + err)


# ---------------------------------------------------------------------------
# the property that holds across every verb
# ---------------------------------------------------------------------------

#: Every verb THIS file drives with a live value in play. The verbs of the
#: second slice are driven the same way in test_where.py and test_store_cli.py,
#: and `test_acceptance.EveryVerbIsDrivenWithALiveValueSomewhere` unions the
#: three lists and holds them against `cli.COMMANDS`, so a new verb still
#: cannot arrive without a case anywhere.
COVERED_VERBS = {"refs", "check", "run"}


class NoVerbOfThisCommandLinePrintsAValue(CliCase):
    """The constraint the whole skill is built on, measured once per verb.

    An agent reads this output. Anything printed here is in the model's context
    for the rest of the session, in the transcript, and in whatever log the
    harness keeps, and none of those three can be unprinted.
    """

    def test_refs_prints_no_value(self):
        # `refs` never opens a store, which is itself the claim: the inventory
        # is built out of locators and the fake below is never consulted.
        runner = answers_with_value()
        _, out, err = self.run_cli(["refs", "--root", str(self.tree(TREE))],
                                   runner=runner)
        self.assertNotIn(TOKEN, out + err)
        self.assertEqual(runner.calls, [])

    def test_check_prints_no_value(self):
        _, out, err = self.run_cli(["check", "--root", str(self.tree(TREE))],
                                   runner=answers_with_value())
        self.assertNotIn(TOKEN, out + err)

    def test_check_prints_the_fingerprint_instead(self):
        # Otherwise "no value was printed" would also be true of a run that
        # printed nothing at all, and that is not the property being claimed.
        _, out, _ = self.run_cli(["check", REF], runner=answers_with_value())
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_run_prints_no_value(self):
        _, out, err = self.run_cli(
            ["run", "--env", "%s=%s" % (NAME, REF),
             *self.child(CHILD_ECHOES_THE_VARIABLE)],
            runner=answers_with_value())
        self.assertNotIn(TOKEN, out + err)

    def test_every_verb_this_file_claims_to_cover_exists(self):
        self.assertLessEqual(COVERED_VERBS, set(cli.COMMANDS))
