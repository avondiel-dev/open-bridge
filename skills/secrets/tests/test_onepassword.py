"""1password: one address in two spellings, one read, and one refusal.

Every case here is driven through the `runner=` seam. `op` is on the deny list
in `tests/conftest.py`, and it is there for a reason that has nothing to do with
this file: whoever runs this suite has a signed-in CLI and a real vault behind
it, so a backend that reached around the seam would read a live credential and
the case would go green on the strength of it.

Three properties carry this file.

* READING IS SAFE AND WRITING IS NOT, AND THE ASYMMETRY IS THE POINT. `op read`
  takes the address in argv and prints the value on stdout, so nothing secret is
  ever in a command line. `op item create` and `op item edit` take the value AS
  an argument, which puts it in `ps` for every process of the same user. So this
  Bridge reads 1Password and refuses to write it, and says why rather than
  failing at the first call.
* ONE ITEM, TWO SPELLINGS. `1password://` is what `rules/secret-placement.md`
  writes and `op://` is what the CLI itself understands, and people have both in
  their files. They address the same item and they have to resolve to the same
  call, or a reference that was copied out of the CLI would quietly address
  nothing.
* A FAILED READ IS EITHER A MISS OR A FAULT. A missing item is a fact about the
  vault. A CLI with no session is a fact about this terminal, and a daemon that
  reads the second as the first rotates a secret that was never gone: the item
  is there, and this process simply may not ask.
"""

from __future__ import annotations

from tests.conftest import FakeRunner, MachineGuard, completed, mod, synthetic_token

base = mod("engine.backends.base")
errors = mod("engine.errors")
onepassword = mod("engine.backends.onepassword")
refs = mod("engine.refs")
values = mod("engine.values")

#: The same item, in the two spellings people have in their files.
CANONICAL = "1password://Shared/storecove-api/credential"
CLI_SPELLING = "op://Shared/storecove-api/credential"

#: An account as `op` wants it: the sign-in address of the tenant, not a person.
ACCOUNT = "bkslab.1password.eu"


class OnePasswordCase(MachineGuard):
    """A backend wired to a fake process, never to a vault."""

    VAULT = "Shared"
    ITEM = "storecove-api"
    FIELD = "credential"

    def setUp(self):
        super().setUp()
        self.value = synthetic_token("opitem")  # pragma: allowlist secret

    # -- builders -----------------------------------------------------------

    def ref(self, uri: str = CANONICAL):
        return refs.parse(uri)

    def session(self):
        """A fixed session rather than a detected one.

        This backend does not read the context, but `Context.detect()` asks
        whether stdin is a terminal, and a case whose answer depends on how the
        suite was started behaves differently in CI than on a laptop.
        """
        return base.Context(platform="linux", interactive=False, over_ssh=False,
                            display=False)

    def secret(self, text=None):
        return values.Secret(self.value if text is None else text, origin=CANONICAL)

    def backend(self, runner=None, *, account=None):
        return onepassword.OnePasswordBackend(
            account=account, runner=runner, context=self.session(),
            # `op` is not installed on the runner this suite has to stay green
            # on, and the PATH probe is the one step of a read that does not go
            # through the runner seam. Without this every read case below would
            # fail on the probe rather than on the behaviour it is named after.
            assume_available=True)

    # -- one read -----------------------------------------------------------

    def runner(self, *, rc=0, stdout="", stderr="") -> FakeRunner:
        fake = FakeRunner()
        fake.add("op read", completed(rc=rc, stdout=stdout, stderr=stderr))
        return fake

    def reading(self, *, rc=0, stdout="", stderr="", uri=CANONICAL, account=None):
        fake = self.runner(rc=rc, stdout=stdout, stderr=stderr)
        return self.backend(fake, account=account).read(self.ref(uri)), fake

    def raised(self, exception_type, **kwargs):
        with self.assertRaises(exception_type) as caught:
            self.reading(**kwargs)
        return caught.exception


class TheReadArgvIsTheAddressTheCliItselfUnderstands(OnePasswordCase):
    """`op read op://<vault>/<item>/<field> --no-newline`.

    Pinned as a whole list rather than by substring. A backend that lost the
    flag deciding how the value is terminated would still contain every
    substring a looser case looks for.
    """

    def test_the_whole_command_is_the_verb_and_one_address(self):
        self.assertEqual(self.backend().argv_read(self.ref()),
                         ["op", "read", CLI_SPELLING, "--no-newline"])

    def test_the_address_is_spelled_the_way_the_cli_spells_it(self):
        # `op read` does not know the word `1password://`. The translation
        # happens here, once, rather than in every caller that writes a
        # reference down.
        self.assertEqual(self.backend().op_reference(self.ref()), CLI_SPELLING)

    def test_the_flag_that_suppresses_the_trailing_newline_is_always_there(self):
        # Without it `op read` prints the value AND a newline, and there is no
        # marker saying which of the two the item holds. A token that grew a
        # newline fails an Authorization header and looks perfectly right in a
        # terminal, which is the worst combination there is.
        self.assertIn("--no-newline", self.backend().argv_read(self.ref()))

    def test_the_account_is_named_when_the_store_declares_one(self):
        # A CLI signed in to two tenants resolves an unqualified address in the
        # first one it finds, so an item of the same name in the other tenant is
        # what comes back, with no indication that it happened.
        argv = self.backend(account=ACCOUNT).argv_read(self.ref())
        self.assertIn("--account", argv)
        self.assertEqual(argv[argv.index("--account") + 1], ACCOUNT)

    def test_without_a_declared_account_the_flag_is_absent_entirely(self):
        # Not the flag with an empty value: `op` reads the next word as the
        # account, which here would be nothing at all.
        self.assertNotIn("--account", self.backend().argv_read(self.ref()))

    def test_the_read_runs_the_argv_this_backend_says_it_runs(self):
        # argv_read() is worth nothing as a promise if read() assembles its own.
        expected = self.backend(account=ACCOUNT).argv_read(self.ref())
        _, fake = self.reading(stdout=self.value, account=ACCOUNT)
        self.assertEqual(fake.calls[0]["argv"], tuple(expected))

    def test_exactly_one_process_runs_for_one_read(self):
        _, fake = self.reading(stdout=self.value)
        self.assertEqual(len(fake.calls), 1, fake.joined_calls)

    def test_an_item_inside_a_section_keeps_every_segment(self):
        # `op://vault/item/section/field` is a real address, so the segments
        # between the item and the field are carried rather than collapsed.
        deep = self.backend().op_reference(
            self.ref("1password://Shared/storecove-api/api/credential"))
        self.assertEqual(deep, "op://Shared/storecove-api/api/credential")

    def test_a_reference_with_no_item_is_refused_before_anything_runs(self):
        # The grammar refuses this one first, so it has to be built by hand to
        # reach the backend at all. It is still worth a case: the backstop is
        # what stands between a hand assembled Ref and an address whose field
        # segment is the vault.
        headless = refs.Ref(scheme="1password", store=self.VAULT, path=(),
                            field="password", raw="1password://" + self.VAULT)
        fake = self.runner()
        with self.assertRaises(errors.Refused) as caught:
            self.backend(fake).read(headless)
        self.assertIn("no item", str(caught.exception))
        self.assertEqual(fake.calls, [], "the refusal came after a call to op")


class TheTwoSpellingsAddressTheSameItem(OnePasswordCase):
    """`1password://` is what the rules write, `op://` is what the CLI prints.

    Both are in people's files, because the second is what the 1Password app
    puts on the clipboard. They have to be one address: a reference copied out
    of the app and pasted into a YAML file must reach the same item as the one
    somebody typed from the documentation.
    """

    def test_both_spellings_parse_to_the_same_canonical_reference(self):
        self.assertEqual(refs.parse(CLI_SPELLING).canonical,
                         refs.parse(CANONICAL).canonical)

    def test_the_canonical_spelling_is_never_the_alias(self):
        # One spelling leaves this skill, whichever went in. Otherwise `check`
        # groups the same item under two names and reads it twice.
        self.assertTrue(refs.parse(CLI_SPELLING).canonical.startswith("1password://"))

    def test_both_spellings_build_the_same_argv(self):
        self.assertEqual(self.backend().argv_read(self.ref(CLI_SPELLING)),
                         self.backend().argv_read(self.ref(CANONICAL)))

    def test_the_reading_carries_the_canonical_spelling_whichever_was_typed(self):
        reading, _ = self.reading(stdout=self.value, uri=CLI_SPELLING)
        self.assertEqual(reading.ref, CANONICAL)

    def test_a_reference_that_names_no_field_addresses_the_password(self):
        # The default the grammar declares, spelled out here because it decides
        # which field of a login item a bare reference reaches.
        self.assertEqual(
            self.backend().op_reference(self.ref("1password://Shared/storecove-api")),
            "op://Shared/storecove-api/password")

    def test_the_hash_form_names_the_field_and_leaves_the_path_alone(self):
        # The escape hatch for an item that is itself called `password`: with
        # the slash form the last segment is the field, and `#` overrides that.
        address = self.backend().op_reference(
            self.ref("1password://Shared/storecove-api/password#credential"))
        self.assertEqual(address, "op://Shared/storecove-api/password/credential")


class TheValueComesBackExactlyAsTheCliPrintedIt(OnePasswordCase):
    """With `--no-newline` the output is the value and nothing else.

    So this backend strips nothing, and that is a decision rather than an
    omission: the flag is what makes it safe. Take the flag away and every value
    grows a newline that nobody stored, and a backend that then stripped one
    would eat a newline that somebody did.
    """

    def read_printing(self, stdout: str):
        reading, _ = self.reading(stdout=stdout)
        return reading

    def test_the_value_arrives_byte_for_byte(self):
        self.assertEqual(self.read_printing(self.value).secret.expose(),
                         self.value.encode("utf-8"))

    def test_a_trailing_newline_belongs_to_the_value_because_the_cli_added_none(self):
        self.assertEqual(self.read_printing(self.value + "\n").secret.expose(),
                         self.value.encode("utf-8") + b"\n")

    def test_a_value_with_spaces_arrives_whole(self):
        self.assertEqual(self.read_printing("two words here").secret.expose(),
                         b"two words here")

    def test_a_value_outside_ascii_arrives_whole(self):
        self.assertEqual(self.read_printing("Straße").secret.expose(),
                         "Straße".encode("utf-8"))

    def test_the_reading_names_the_vault_it_came_from(self):
        self.assertEqual(self.read_printing(self.value).store, self.VAULT)

    def test_the_wrapped_value_knows_where_it_came_from(self):
        self.assertEqual(self.read_printing(self.value).secret.origin, CANONICAL)

    def test_the_backend_hands_back_a_wrapped_value_and_not_a_string(self):
        # The wrapper is what makes printing a value an explicit act. A backend
        # that returned a str would put the value into the next log line that
        # interpolates a Reading.
        with self.assertRaises(TypeError):
            str(self.read_printing(self.value).secret)

    def test_the_value_that_came_back_was_never_in_an_argv(self):
        _, fake = self.reading(stdout=self.value)
        self.assertFalse(fake.argv_carried(self.value),
                         "the value appeared in argv:\n" + fake.joined_calls)

    def test_a_field_that_exists_with_no_bytes_in_it_is_a_miss(self):
        # `op` exits 0 and prints nothing at all. Every caller that tested
        # existence rather than length carried the emptiness one layer further
        # before anything failed.
        reading = self.read_printing("")
        self.assertFalse(reading.present)
        self.assertIn("empty", reading.note)

    def test_the_empty_reading_still_carries_a_secret_of_zero_bytes(self):
        reading = self.read_printing("")
        self.assertIsNotNone(reading.secret)
        self.assertEqual(reading.length, 0)


class StderrDecidesWhetherAFailedReadIsAMissOrAFault(OnePasswordCase):
    """The split the exit code contract rests on.

    The wordings below are the BRANCHES this backend takes, not a claim about
    which version of `op` prints which sentence. What matters is that a miss and
    a session that cannot ask leave the backend by different doors.
    """

    def read_failing(self, stderr: str, rc: int = 1):
        reading, _ = self.reading(rc=rc, stderr=stderr)
        return reading

    def raises_from(self, exception_type, stderr: str, rc: int = 1):
        return self.raised(exception_type, rc=rc, stderr=stderr)

    def test_a_missing_item_comes_back_as_a_reading_rather_than_an_error(self):
        reading = self.read_failing(
            '[ERROR] 2026/09/20 09:12:03 "storecove-api" isn\'t an item. '
            "Specify the item with its UUID, name, or domain.\n")
        self.assertFalse(reading.present)

    def test_the_miss_says_there_is_no_such_item_or_field_in_this_vault(self):
        reading = self.read_failing('[ERROR] "storecove-api" isn\'t an item.\n')
        self.assertIn("no such item", reading.note)

    def test_a_miss_carries_no_secret_at_all(self):
        # Not an empty one. A caller that tests the secret rather than `present`
        # must not find an object it can hand on as if it were a value.
        self.assertIsNone(self.read_failing('[ERROR] "x" isn\'t an item.\n').secret)

    def test_the_miss_still_names_the_vault_it_looked_in(self):
        self.assertEqual(self.read_failing('[ERROR] "x" isn\'t an item.\n').store,
                         self.VAULT)

    def test_every_wording_that_means_the_item_is_not_there(self):
        for stderr in ('[ERROR] "storecove-api" isn\'t an item.',
                       "[ERROR] could not read secret: item not found",
                       "[ERROR] no item matches that query"):
            with self.subTest(stderr=stderr):
                self.assertFalse(self.read_failing(stderr + "\n").present)

    def test_a_signed_out_cli_is_not_readable_here_and_not_a_miss(self):
        # RED ON PURPOSE, and the finding is one word wide.
        # `engine/backends/onepassword.py:60` tests for "not signed in". The
        # sentence the CLI prints when there is no session reads "you are not
        # CURRENTLY signed in. Please run `op signin --help` for instructions",
        # and "not signed in" is not a substring of it. So the most common
        # failure of this backend falls through to the unclassified branch: a
        # SecretsError carrying the configuration code rather than the
        # unavailable one, and the raw stderr line in place of the hint that
        # says `op signin`. It is still not reported as a miss, so nothing
        # rotates a secret over it; what is lost is the exit code a wrapper
        # switches on and the sentence that tells a person what to do.
        #
        # The wording above could not be measured here: `op` is on the deny list
        # in `tests/conftest.py`, which is the right trade. It is the wording
        # the CLI's own sign-in instructions use, and it is plainly the sentence
        # the pattern was written for, which is why this reads as one word
        # missing rather than as a branch nobody meant to have. A build that
        # prints something else is an argument for widening the pattern, not for
        # narrowing this case.
        error = self.raises_from(
            errors.NotReadableHere,
            "[ERROR] 2026/09/20 09:12:03 you are not currently signed in. "
            "Please run `op signin --help` for instructions\n")
        self.assertEqual(error.exit_code, errors.EX_UNAVAILABLE)

    def test_the_refusal_says_how_this_session_gets_one(self):
        error = self.raises_from(errors.NotReadableHere,
                                 "[ERROR] session expired, sign in again\n")
        self.assertIn("op signin", error.hint)
        self.assertIn("desktop app", error.hint)

    def test_the_refusal_says_the_item_is_probably_fine(self):
        # The sentence that keeps a rotation watcher from acting: nothing has
        # been lost, this terminal simply has no session.
        error = self.raises_from(errors.NotReadableHere,
                                 "[ERROR] session expired, sign in again\n")
        self.assertIn("probably fine", error.hint)

    def test_every_wording_that_means_this_session_cannot_ask(self):
        # The wordings this backend classifies today. The one it does not is the
        # subject of the red case above, and it is kept out of this list so that
        # one finding shows up as one failure rather than as four.
        for stderr in ("[ERROR] session expired, please sign in again",
                       "[ERROR] authorization required for this vault"):
            with self.subTest(stderr=stderr):
                self.raises_from(errors.NotReadableHere, stderr + "\n")

    def test_anything_else_raises_rather_than_returning_a_reading(self):
        self.raises_from(errors.SecretsError,
                         "[ERROR] connecting to desktop app: timed out\n", rc=2)

    def test_an_unclassified_failure_names_the_exit_code_the_tool_left(self):
        error = self.raises_from(errors.SecretsError, "[ERROR] timed out\n", rc=7)
        self.assertIn("7", str(error))

    def test_the_first_line_of_stderr_becomes_the_hint(self):
        # `op` prints the failure first and the usage block after it. The first
        # non-empty line is the sentence a person needs, and blank leading lines
        # are skipped rather than passed on as an empty hint.
        error = self.raises_from(
            errors.SecretsError,
            "\n  [ERROR] connecting to desktop app: timed out\n"
            "Usage: op read <reference>\n", rc=2)
        self.assertEqual(error.hint, "[ERROR] connecting to desktop app: timed out")

    def test_a_failure_with_a_silent_stderr_still_says_something(self):
        self.assertIn("no message on stderr",
                      self.raises_from(errors.SecretsError, "", rc=2).hint)

    def test_an_unclassified_failure_is_never_reported_as_a_miss(self):
        # The one sentence this class exists for, stated as its own case so a
        # softening of the classification cannot pass unnoticed.
        error = self.raises_from(errors.SecretsError, "[ERROR] timed out\n", rc=2)
        self.assertNotIsInstance(error, errors.SecretMissing)

    def test_a_failed_read_carries_the_reference_and_never_the_value(self):
        error = self.raises_from(errors.SecretsError, "[ERROR] timed out\n", rc=2)
        self.assertEqual(error.ref, CANONICAL)
        self.assertNotIn(self.value, error.report())


class WritingIsRefusedBecauseTheCliTakesTheValueInArgv(OnePasswordCase):
    """The refusal is the feature, and it is the reason this file exists.

    `op item create login password=<value>` and `op item edit <item>
    password=<value>` both take the value as a command line argument. That puts
    it in `ps` for every process of the same user for as long as the call runs,
    and in the shell history of whoever typed it. The template form reads a
    file, and a file with a value in it is the thing this skill exists to stop
    people creating by hand.

    So the answer is no, said up front, with the two commands named. A refusal
    that arrives after the value has been handed over is not a refusal.
    """

    def setUp(self):
        super().setUp()
        self.fake = self.runner()
        with self.assertRaises(errors.Refused) as caught:
            self.backend(self.fake).write(self.ref(), self.secret())
        self.error = caught.exception

    def test_a_write_is_refused(self):
        self.assertIsInstance(self.error, errors.Refused)

    def test_nothing_ran_on_the_way_to_the_refusal(self):
        # The load bearing half. A refusal that came back from `op` would mean
        # the value had already been handed to a process, and by then the damage
        # is done whatever the exit code says.
        self.assertEqual(self.fake.calls, [],
                         "something ran before the refusal:\n" + self.fake.joined_calls)

    def test_the_value_was_never_in_an_argv(self):
        self.assertFalse(self.fake.argv_carried(self.value))

    def test_the_refusal_names_the_two_commands_that_would_have_done_it(self):
        # Named so the reader can check the claim rather than take it on trust.
        self.assertIn("op item create", self.error.hint)
        self.assertIn("op item edit", self.error.hint)

    def test_the_refusal_says_what_is_wrong_with_them(self):
        self.assertIn("command line", self.error.hint)
        self.assertIn("process list", self.error.hint)

    def test_the_refusal_says_what_to_do_instead(self):
        # A refusal with no way forward gets worked around, and the workaround
        # is somebody typing the value into a terminal.
        self.assertIn("secrets check", self.error.hint)

    def test_the_message_says_this_bridge_does_not_write_to_this_store(self):
        self.assertIn("does not write", str(self.error))

    def test_the_exit_code_is_the_one_for_a_refusal(self):
        self.assertEqual(self.error.exit_code, errors.EX_REFUSED)

    def test_the_refusal_is_not_a_missing_backend(self):
        # The difference decides what the caller does next. An unavailable
        # backend is fixed by installing something; this one never will be, and
        # a caller that retried it would retry for ever.
        self.assertNotIsInstance(self.error, errors.BackendUnavailable)

    def test_the_refusal_names_the_reference_and_never_the_value(self):
        self.assertEqual(self.error.ref, CANONICAL)
        self.assertNotIn(self.value, self.error.report())

    def test_asking_to_replace_changes_nothing(self):
        # `op item edit` is the replace path and it is refused for exactly the
        # same reason, so the flag must not open a second door.
        fake = self.runner()
        with self.assertRaises(errors.Refused):
            self.backend(fake).write(self.ref(), self.secret(), replace=True)
        self.assertEqual(fake.calls, [])

    def test_the_refusal_does_not_depend_on_the_cli_being_installed(self):
        # A machine without `op` must give the same answer as one with it.
        # Otherwise the policy reads as an environment problem and somebody
        # installs their way around it.
        backend = onepassword.OnePasswordBackend(runner=self.runner(),
                                                 context=self.session(),
                                                 assume_available=False)
        with self.assertRaises(errors.Refused):
            backend.write(self.ref(), self.secret())


class LocateNamesThePlaceAndNeverTheValue(OnePasswordCase):
    """Where a person would click, printed into a report an agent may read."""

    def test_the_vault_and_the_item_and_the_field_are_all_named(self):
        where = self.backend().locate(self.ref())
        for part in (self.VAULT, self.ITEM, self.FIELD):
            with self.subTest(part=part):
                self.assertIn(part, where)

    def test_the_account_is_named_when_there_is_one(self):
        # Two tenants hold a vault called Shared, and the item a person is being
        # sent to is in exactly one of them.
        self.assertIn(ACCOUNT, self.backend(account=ACCOUNT).locate(self.ref()))

    def test_a_reference_with_no_field_says_which_one_it_means(self):
        self.assertIn("password",
                      self.backend().locate(self.ref("1password://Shared/storecove-api")))

    def test_the_value_is_not_in_it(self):
        # `locate` runs nothing, so it cannot have the value. The case is the
        # tripwire for the day somebody makes it helpful.
        self.assertNotIn(self.value, self.backend().locate(self.ref()))
