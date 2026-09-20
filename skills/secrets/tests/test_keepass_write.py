"""keepass, the writing direction: two lines on stdin, in one order, under no lock.

`test_keepass.py` covers the read. This file covers the write, which is the
direction that can destroy something: KDBX has no journal, so a save rewrites
the whole encrypted file, and the merge KeePassXC offers happens in the GUI, on
reload, with a person present. Every case here is driven through the `runner=`
seam, and no case anywhere in this suite opens a real database.

Four properties, and most of the file is one of them in a different shape.

* THE TWO LINES ON STDIN HAVE AN ORDER, AND THE ORDER IS THE CONTRACT. The
  master password opens the database, then `--password-prompt` asks for the
  password of the entry. Swap them and the tool tries to open the database with
  the new secret as its master password: the failure reads as a wrong master
  password, the value that was about to be stored has been typed at an unlock
  prompt, and nobody is any the wiser.
* NEITHER LINE IS EVER IN ARGV. A KeePass master password is not one credential,
  it is every credential in the database at once, and argv is readable through
  `ps` by every process of the same user for as long as the call runs.
* A LOCK FILE STOPS THE WRITE. Two writers are a real conflict here, not a
  transaction. And a lock is weaker evidence than it looks: across a WSL mount
  the lock of the Windows side is not reliably visible to the Linux side, so the
  refusal says so rather than implying a guarantee the filesystem cannot give.
* THE REPLACE IS A VERB, NOT A FLAG. `keepassxc-cli add` refuses an entry that
  is already there, and `edit` is what overwrites one. A wrapper that passed a
  `--replace` flag through to the tool would be passing a flag the tool does not
  have.
"""

from __future__ import annotations

from tests.conftest import FakeRunner, MachineGuard, completed, mod, synthetic_token

base = mod("engine.backends.base")
errors = mod("engine.errors")
keepass = mod("engine.backends.keepass")
refs = mod("engine.refs")
values = mod("engine.values")

#: Distinguishes "the case said nothing about this" from "the case said None".
#: `password=None` is a real configuration, a database keyed by a file alone, so
#: a plain default of None would swallow the cases that are about it.
UNSET = object()

#: The reference most cases write. Five segments: the database, two groups, the
#: entry, and the field, which the grammar takes from the last segment.
ACME = "keepass://work/customers/acme/api-token/password"

#: A help text that advertises the stdin flag. Only the read path consults it,
#: and it is here because a write reads back through that path when it is done.
#: The full measured help block lives in `test_keepass.py`; what the backend
#: looks for is the one line.
HELP_WITH_PW_STDIN = """Usage: keepassxc-cli show [options] database entry
Options:
  -q, --quiet                   Silence password prompt and other outputs.
  --pw-stdin                    Read the database password from standard input.
"""


class KeePassWriteCase(MachineGuard):
    """A declared database on disk, a fake process, and nothing else.

    The file on disk is bytes and not a KDBX. Nothing here opens it; the backend
    only asks whether it is there, because a reference carries a logical name
    and the path is a property of the machine.
    """

    def setUp(self):
        super().setUp()
        self.folder = self.tmpdir()
        self.database = self.folder / "work.kdbx"
        self.database.write_bytes(b"not a kdbx, and nothing here ever opens one\n")
        self.master = synthetic_token("kdbxmaster")  # pragma: allowlist secret
        self.value = synthetic_token("acmetoken")  # pragma: allowlist secret

    # -- builders -----------------------------------------------------------

    def ref(self, uri: str = ACME):
        return refs.parse(uri)

    def session(self):
        """A fixed session rather than a detected one.

        This backend does not read the context, but `Context.detect()` asks
        whether stdin is a terminal, and a case whose result depends on how the
        suite was started behaves differently in CI than on a laptop.
        """
        return base.Context(platform="linux", interactive=False, over_ssh=False,
                            display=False)

    def secret(self, text=None):
        return values.Secret(self.value if text is None else text, origin=ACME)

    def master_secret(self):
        return values.Secret(self.master, origin="keychain://suite/kdbx-master")

    def backend(self, runner=None, *, password=UNSET, key_file=None, databases=UNSET):
        if databases is UNSET:
            databases = {"work": str(self.database)}
        if password is UNSET:
            password = self.master_secret()
        return keepass.KeePassBackend(
            databases=databases, password=password, key_file=key_file,
            runner=runner, context=self.session(),
            # KeePassXC is on no machine in this fleet, and the PATH probe is
            # the one step of a write that does not go through the runner seam.
            # Without this every case below would fail on the probe rather than
            # on the behaviour it is named after.
            assume_available=True)

    # -- one write ----------------------------------------------------------

    def runner(self, *, rc=0, stderr="", read_back=None) -> FakeRunner:
        """A fake process: the help probe, the read back, and the write itself.

        Routes are matched in the order they were added and the write carries
        neither `--help` nor `--attributes`, so the three cannot be confused for
        one another however the argv is phrased.
        """
        fake = FakeRunner(default=completed(rc=rc, stderr=stderr))
        fake.add("--help", completed(stdout=HELP_WITH_PW_STDIN))
        fake.add("--attributes",
                 completed(stdout=(self.value if read_back is None else read_back) + "\n"))
        return fake

    def writing(self, value=None, *, replace=False, rc=0, stderr="", uri=ACME,
                key_file=None, password=UNSET, read_back=None, runner=None):
        fake = self.runner(rc=rc, stderr=stderr, read_back=read_back) if runner is None \
            else runner
        backend = self.backend(fake, password=password, key_file=key_file)
        secret = self.secret(self.value if value is None else value)
        reading = backend.write(self.ref(uri), secret, replace=replace)
        return reading, fake

    def refusing(self, exception_type, **kwargs):
        """The exception one write raised, plus the runner that saw nothing."""
        fake = kwargs.pop("runner", None) or self.runner()
        with self.assertRaises(exception_type) as caught:
            self.writing(runner=fake, **kwargs)
        return caught.exception, fake

    # -- reading the recording ----------------------------------------------

    @staticmethod
    def write_call(fake: FakeRunner) -> dict:
        """The recorded call that stored something, not the probe or the read."""
        return fake.calls[fake.index_of("--password-prompt")]

    def write_argv(self, fake: FakeRunner) -> tuple:
        return self.write_call(fake)["argv"]

    @staticmethod
    def read_backs(fake: FakeRunner) -> list:
        return [call for call in fake.calls if "--attributes" in call["joined"]]


class TheMasterPasswordAndTheValueBothTravelOnStdinInThatOrder(KeePassWriteCase):
    """The order is the contract, and getting it wrong is silent.

    `keepassxc-cli add --password-prompt` asks twice: first for the password
    that opens the database, then for the password of the new entry. Swapped,
    the tool tries to open the database with the value as its master password.
    It fails, the failure reads exactly like a wrong master password, and the
    value has been offered at an unlock prompt on the way. Nothing in the output
    would tell anyone which of the two happened.
    """

    def setUp(self):
        super().setUp()
        self.reading, self.fake = self.writing()
        self.stdin = self.write_call(self.fake)["stdin_bytes"] or b""

    def test_the_master_password_is_the_first_line(self):
        self.assertEqual(self.stdin.split(b"\n")[0], self.master.encode("utf-8"))

    def test_the_value_is_the_second_line(self):
        self.assertEqual(self.stdin.split(b"\n")[1], self.value.encode("utf-8"))

    def test_the_two_lines_are_the_whole_payload_and_in_that_order(self):
        self.assertEqual(self.stdin,
                         self.master.encode("utf-8") + b"\n" + self.value.encode("utf-8") + b"\n")

    def test_each_line_ends_in_a_newline_so_the_tool_reads_a_whole_line(self):
        # Without the second newline the tool waits for the rest of the line and
        # the write hangs until the timeout, which reads like a broken database.
        self.assertTrue(self.stdin.endswith(b"\n"))
        self.assertEqual(self.stdin.count(b"\n"), 2)

    def test_the_master_password_is_never_in_argv(self):
        self.assertFalse(self.fake.argv_carried(self.master),
                         "the master password appeared in argv:\n" + self.fake.joined_calls)

    def test_the_value_is_never_in_argv(self):
        self.assertFalse(self.fake.argv_carried(self.value),
                         "the value appeared in argv:\n" + self.fake.joined_calls)

    def test_neither_line_travels_in_the_environment_either(self):
        # The third door out of a process, and the quiet one: an environment is
        # readable from /proc on Linux and inherited by every child.
        for call in self.fake.calls:
            with self.subTest(argv=call["joined"]):
                self.assertNotIn(self.master, str(call["env"] or {}))
                self.assertNotIn(self.value, str(call["env"] or {}))

    def test_a_value_with_a_space_in_it_still_arrives_as_one_line(self):
        _, fake = self.writing("two words here")
        self.assertEqual(self.write_call(fake)["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n" + b"two words here\n")

    def test_the_payload_the_backend_names_is_the_payload_it_sends(self):
        # stdin_for_write() is worth nothing as a promise if write() assembles
        # its own bytes.
        expected = self.backend().stdin_for_write(self.secret())
        self.assertEqual(self.stdin, expected)


class TheWriteArgvIsWhatTheMeasuredCommandTakes(KeePassWriteCase):
    """`keepassxc-cli add --quiet --password-prompt <db> <entry>`.

    Pinned as a whole list rather than by substring. A backend that grew an
    extra flag, or lost the one that makes the tool ask for the entry password
    on stdin, would still contain every substring a looser case looks for.
    """

    def test_the_whole_command_is_the_verb_the_flags_and_two_operands(self):
        argv = self.backend().argv_write(self.ref(), replace=False)
        self.assertEqual(argv, ["keepassxc-cli", "add", "--quiet", "--password-prompt",
                                str(self.database), "customers/acme/api-token"])

    def test_the_database_and_the_entry_are_the_last_two_operands_in_that_order(self):
        # Positional, so a flag appended after them would be read as part of the
        # entry path rather than as a flag.
        argv = self.backend().argv_write(self.ref(), replace=False)
        self.assertEqual(argv[-2:], [str(self.database), "customers/acme/api-token"])

    def test_the_entry_is_addressed_by_the_group_path_of_the_reference(self):
        argv = self.backend().argv_write(self.ref(), replace=False)
        self.assertEqual(argv[-1], "customers/acme/api-token")

    def test_the_prompt_flag_is_what_makes_the_tool_read_the_value_from_stdin(self):
        # Without it the tool generates a password of its own and the value this
        # whole call exists for is never stored, while the exit code says zero.
        self.assertIn("--password-prompt", self.backend().argv_write(self.ref(), replace=False))

    def test_the_quiet_flag_keeps_the_prompts_out_of_the_captured_output(self):
        # The prompts are written to the terminal, and a captured "Enter
        # password to unlock" is a line that a caller parsing output has to know
        # about. Quiet removes the class of problem rather than the instance.
        self.assertIn("--quiet", self.backend().argv_write(self.ref(), replace=False))

    def test_the_write_runs_the_argv_this_backend_says_it_runs(self):
        expected = self.backend().argv_write(self.ref(), replace=False)
        _, fake = self.writing()
        self.assertEqual(list(self.write_argv(fake)), expected)

    def test_exactly_one_call_writes(self):
        _, fake = self.writing()
        writes = [call for call in fake.calls if "--password-prompt" in call["joined"]]
        self.assertEqual(len(writes), 1,
                         "a second write is a second save:\n" + fake.joined_calls)

    def test_the_help_probe_belongs_to_the_read_back_and_not_to_the_write(self):
        # The write consults no help text: it uses the flags that every build
        # has. The probe in the recording is the read that follows it, and the
        # order is what says so.
        _, fake = self.writing()
        self.assertLess(fake.index_of("--password-prompt"), fake.index_of("--help"))


class TheReplaceIsAVerbAndNotAFlag(KeePassWriteCase):
    """`add` creates, `edit` overwrites, and the tool has no `--replace`.

    Passing the wrapper's own flag through would be passing a flag KeePassXC
    does not take, and the tool would exit on the command line rather than on
    anything about the database.
    """

    def test_a_write_without_replace_uses_the_add_verb(self):
        self.assertEqual(self.backend().argv_write(self.ref(), replace=False)[1], "add")

    def test_a_write_with_replace_uses_the_edit_verb(self):
        self.assertEqual(self.backend().argv_write(self.ref(), replace=True)[1], "edit")

    def test_the_replace_flag_itself_never_reaches_the_tool(self):
        argv = self.backend().argv_write(self.ref(), replace=True)
        self.assertNotIn("--replace", argv)

    def test_both_verbs_ask_for_the_password_on_stdin(self):
        for replace in (False, True):
            with self.subTest(replace=replace):
                self.assertIn("--password-prompt",
                              self.backend().argv_write(self.ref(), replace=replace))

    def test_both_verbs_address_the_same_database_and_entry(self):
        adding = self.backend().argv_write(self.ref(), replace=False)
        editing = self.backend().argv_write(self.ref(), replace=True)
        self.assertEqual(adding[-2:], editing[-2:])

    def test_the_verb_is_the_only_difference_between_the_two(self):
        adding = self.backend().argv_write(self.ref(), replace=False)
        editing = self.backend().argv_write(self.ref(), replace=True)
        self.assertEqual([part for part in adding if part != "add"],
                         [part for part in editing if part != "edit"])

    def test_an_edit_carries_the_same_two_lines_on_stdin(self):
        _, fake = self.writing(replace=True)
        self.assertEqual(self.write_call(fake)["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n" + self.value.encode("utf-8") + b"\n")

    def test_an_edit_still_keeps_both_lines_out_of_argv(self):
        _, fake = self.writing(replace=True)
        self.assertFalse(fake.argv_carried(self.master))
        self.assertFalse(fake.argv_carried(self.value))


class ALockFileRefusesTheWriteAlthoughAReadWouldStillWork(KeePassWriteCase):
    """A save rewrites the whole file, so two writers are how one of them loses.

    KDBX has no journal. KeePassXC merges a file that changed underneath it when
    it notices, on reload, in the GUI, with a person present. None of that is
    available to a wrapper, so the wrapper refuses rather than picking a winner.
    """

    def setUp(self):
        super().setUp()
        self.lock = self.folder / "work.kdbx.lock"
        self.lock.write_text("", encoding="utf-8")

    def test_the_write_is_refused(self):
        error, _ = self.refusing(errors.Refused)
        self.assertEqual(error.exit_code, errors.EX_REFUSED)

    def test_nothing_ran_on_the_way_to_the_refusal(self):
        # The load bearing half: a refusal that came back from the tool would
        # mean the master password had already been handed to a process, and a
        # save may already have started.
        _, fake = self.refusing(errors.Refused)
        self.assertEqual(fake.calls, [],
                         "something ran before the refusal:\n" + fake.joined_calls)

    def test_the_refusal_says_the_database_is_open_in_another_client(self):
        error, _ = self.refusing(errors.Refused)
        self.assertIn("open in another client", str(error))

    def test_the_refusal_names_the_lock_file_as_the_evidence(self):
        # Evidence rather than a claim, so the person can look at the thing that
        # caused the refusal instead of guessing which client it means.
        error, _ = self.refusing(errors.Refused)
        self.assertIn(str(self.database) + ".lock", error.hint)

    def test_the_refusal_says_a_wsl_mount_may_not_show_the_lock_at_all(self):
        # The honest half. Across `/mnt/c/...` the lock of the Windows side is
        # not reliably visible here, so the absence of a lock is weaker evidence
        # than it looks and the message must not promise otherwise.
        error, _ = self.refusing(errors.Refused)
        self.assertIn("WSL", error.hint)
        self.assertIn("collide", error.hint)

    def test_the_refusal_carries_the_reference_and_never_the_value(self):
        error, _ = self.refusing(errors.Refused)
        self.assertEqual(error.ref, ACME)
        self.assertNotIn(self.value, error.report())
        self.assertNotIn(self.master, error.report())

    def test_a_read_is_still_allowed_while_the_same_lock_is_there(self):
        # The asymmetry is the point: a read opens the file read only and
        # disturbs nothing, so refusing one would buy nothing and cost a lot.
        fake = self.runner()
        reading = self.backend(fake).read(self.ref())
        self.assertTrue(reading.present)
        self.assertIn("open elsewhere", reading.note)

    def test_without_the_lock_file_the_same_write_goes_through(self):
        # Otherwise every case above is green over a write that was refused for
        # some other reason entirely.
        self.lock.unlink()
        reading, fake = self.writing()
        self.assertTrue(reading.present)
        self.assertTrue(fake.called_with("--password-prompt"))


class OnlyThePasswordFieldIsWritten(KeePassWriteCase):
    """One field, because the tool takes one prompt.

    `--password-prompt` stores the password of the entry. A reference naming
    `username` or a custom attribute would be written to the password field by a
    wrapper that ignored the field, which is a silent overwrite of the wrong
    thing in an encrypted file that has no history.
    """

    USERNAME = "keepass://work/customers/acme/api-token/username"

    def test_a_reference_naming_another_field_is_refused(self):
        error, _ = self.refusing(errors.Refused, uri=self.USERNAME)
        self.assertEqual(error.exit_code, errors.EX_REFUSED)

    def test_nothing_ran_on_the_way_to_that_refusal(self):
        _, fake = self.refusing(errors.Refused, uri=self.USERNAME)
        self.assertEqual(fake.calls, [],
                         "something ran before the refusal:\n" + fake.joined_calls)

    def test_the_refusal_names_the_field_that_was_asked_for(self):
        error, _ = self.refusing(errors.Refused, uri=self.USERNAME)
        self.assertIn("username", error.hint)

    def test_the_refusal_says_where_that_field_can_be_written(self):
        error, _ = self.refusing(errors.Refused, uri=self.USERNAME)
        self.assertIn("KeePassXC", error.hint)

    def test_a_custom_attribute_is_refused_in_the_same_way(self):
        self.refusing(errors.Refused,
                      uri="keepass://work/customers/acme/api-token/totp-seed")

    def test_the_password_field_is_the_one_that_goes_through(self):
        reading, fake = self.writing()
        self.assertTrue(reading.present)
        self.assertTrue(fake.called_with("--password-prompt"))

    def test_the_check_does_not_depend_on_how_the_field_was_capitalised(self):
        # `#Password` is the same field, and a refusal there would send somebody
        # hunting for a difference that is not there.
        reading, _ = self.writing(uri="keepass://work/customers/acme/api-token#Password")
        self.assertTrue(reading.present)

    def test_a_lock_is_answered_before_the_field_is(self):
        # Both refuse, and the order decides which sentence a person reads. The
        # lock is the one that says somebody else is in the file right now.
        self.lock = self.folder / "work.kdbx.lock"
        self.lock.write_text("", encoding="utf-8")
        error, _ = self.refusing(errors.Refused, uri=self.USERNAME)
        self.assertIn("open in another client", str(error))


class StderrDecidesWhetherAFailedWriteIsARefusalOrAFault(KeePassWriteCase):
    """An entry that is already there is not a failure, it is the wrong verb.

    The wordings below are the BRANCHES this backend takes, not a claim about
    which KeePassXC version prints which sentence.
    """

    def failing(self, stderr: str, rc: int = 1):
        fake = self.runner(rc=rc, stderr=stderr)
        with self.assertRaises(errors.SecretsError) as caught:
            self.writing(runner=fake)
        return caught.exception, fake

    def test_an_entry_that_is_already_there_is_a_refusal(self):
        error, _ = self.failing("Entry customers/acme/api-token already exists.\n")
        self.assertIsInstance(error, errors.Refused)

    def test_the_refusal_names_the_flag_that_would_have_overwritten_it(self):
        # A refusal with no way forward gets worked around, and the workaround
        # here is somebody opening the GUI and pasting the value into it.
        error, _ = self.failing("Entry customers/acme/api-token already exists.\n")
        self.assertIn("--replace", error.hint)

    def test_the_refusal_leaves_the_exit_code_for_a_refusal(self):
        error, _ = self.failing("Entry already exists.\n")
        self.assertEqual(error.exit_code, errors.EX_REFUSED)

    def test_an_already_existing_entry_is_never_reported_as_a_write_that_landed(self):
        error, _ = self.failing("Entry already exists.\n")
        self.assertIsInstance(error, errors.SecretsError)

    def test_anything_else_is_a_fault_carrying_what_the_tool_said(self):
        error, _ = self.failing("Unexpected failure in the database plugin.\n", rc=3)
        self.assertNotIsInstance(error, errors.Refused)
        self.assertEqual(error.hint, "Unexpected failure in the database plugin.")

    def test_an_unclassified_failure_names_the_exit_code_the_tool_left(self):
        error, _ = self.failing("Unexpected failure.\n", rc=3)
        self.assertIn("3", str(error))

    def test_a_failure_with_a_silent_stderr_still_says_something(self):
        error, _ = self.failing("", rc=2)
        self.assertIn("no message on stderr", error.hint)

    def test_a_database_that_did_not_open_is_a_fault_and_not_a_silent_success(self):
        # Worth knowing which direction you are in: `read()` classifies this
        # same stderr as BackendUnavailable, the code that means "not usable
        # from here", while `write()` has no such branch and leaves the
        # configuration code behind instead. Both raise and neither pretends the
        # write landed, so this case asserts the half that is load bearing.
        error, fake = self.failing("Invalid credentials were provided, please try again.\n")
        self.assertIn("Invalid credentials", error.hint)
        self.assertEqual(self.read_backs(fake), [])

    def test_a_failed_write_never_reads_back(self):
        # A read after a failed write answers with whatever was there before and
        # looks exactly like a write that worked.
        _, fake = self.failing("Unexpected failure.\n", rc=3)
        self.assertEqual(self.read_backs(fake), [],
                         "a failed write still asked the database what is in it")

    def test_a_failed_write_carries_the_reference_and_never_the_value(self):
        error, _ = self.failing("Unexpected failure.\n", rc=3)
        self.assertEqual(error.ref, ACME)
        self.assertNotIn(self.value, error.report())
        self.assertNotIn(self.master, error.report())


class TheCredentialsOfTheDatabaseAreCheckedBeforeAnythingRuns(KeePassWriteCase):
    """A key file is passed through; no source at all is refused up front.

    The refusal is the interesting half. Without a master password and without a
    key file there is nothing to open the database with, and running the tool
    anyway would hand it an empty line at an unlock prompt and report whatever
    it said about that.
    """

    def key_file(self):
        path = self.folder / "work.keyx"
        path.write_bytes(b"not a key file, and nothing here ever reads one\n")
        return str(path)

    def test_the_key_file_is_passed_through_to_the_tool(self):
        path = self.key_file()
        argv = self.backend(key_file=path).argv_write(self.ref(), replace=False)
        self.assertIn("--key-file", argv)
        self.assertEqual(argv[argv.index("--key-file") + 1], path)

    def test_the_key_file_stands_before_the_two_operands(self):
        # Positional arguments come last, so a flag after them would be read as
        # part of the entry path.
        path = self.key_file()
        argv = self.backend(key_file=path).argv_write(self.ref(), replace=False)
        self.assertLess(argv.index("--key-file"), argv.index(str(self.database)))

    def test_without_a_key_file_the_flag_is_absent_entirely(self):
        self.assertNotIn("--key-file",
                         self.backend().argv_write(self.ref(), replace=False))

    def test_a_write_with_a_key_file_and_a_password_carries_both(self):
        path = self.key_file()
        _, fake = self.writing(key_file=path)
        argv = self.write_argv(fake)
        self.assertIn(path, argv)
        self.assertEqual(self.write_call(fake)["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n" + self.value.encode("utf-8") + b"\n")

    def test_the_key_file_path_is_not_a_secret_and_the_value_still_is(self):
        # A path is an address and may stand in argv. The two things that may
        # not are the two that do not.
        path = self.key_file()
        _, fake = self.writing(key_file=path)
        self.assertTrue(fake.argv_carried(path))
        self.assertFalse(fake.argv_carried(self.master))
        self.assertFalse(fake.argv_carried(self.value))

    def test_a_database_with_no_password_and_no_key_file_is_refused(self):
        error, _ = self.refusing(errors.BackendUnavailable, password=None)
        self.assertIn("master password", str(error))

    def test_nothing_ran_on_the_way_to_that_refusal(self):
        _, fake = self.refusing(errors.BackendUnavailable, password=None)
        self.assertEqual(fake.calls, [],
                         "something ran before the refusal:\n" + fake.joined_calls)

    def test_the_refusal_says_where_a_master_password_could_come_from(self):
        # The bootstrap this backend is built for: the keychain holds the
        # password of the database, so the agent never sees either of them.
        error, _ = self.refusing(errors.BackendUnavailable, password=None)
        self.assertIn("keychain", str(error))

    def test_that_refusal_leaves_the_unavailable_code_and_not_the_refusal_one(self):
        # Deliberately a different code from the lock and the field: those two
        # are decisions about an operation that could be done. This one says the
        # operation cannot be attempted from here at all.
        error, _ = self.refusing(errors.BackendUnavailable, password=None)
        self.assertEqual(error.exit_code, errors.EX_UNAVAILABLE)

    def test_a_key_file_alone_is_a_credential_source(self):
        # The unattended case: a database keyed by a file needs no person, and
        # refusing it would make every scheduled write need a terminal.
        ok, why = self.backend(password=None, key_file=self.key_file()).readable_here(self.ref())
        self.assertTrue(ok, why)


class AWriteReadsBackWhatItStored(KeePassWriteCase):
    """A write that was not read back is a write nobody checked.

    The read back is also what gives the caller a fingerprint to compare, which
    is how `resolve.store()` tells a write that landed from one that went
    somewhere else entirely.
    """

    def setUp(self):
        super().setUp()
        self.reading, self.fake = self.writing()

    def test_the_write_returns_a_reading_of_what_is_now_in_the_database(self):
        self.assertTrue(self.reading.present)
        self.assertEqual(self.reading.secret.expose(), self.value.encode("utf-8"))

    def test_the_read_back_carries_the_fingerprint_of_the_stored_value(self):
        self.assertEqual(self.reading.fingerprint,
                         values.fingerprint(self.value.encode("utf-8")))

    def test_the_read_back_asks_for_the_password_attribute_by_its_keepass_name(self):
        argv = self.fake.calls[self.fake.index_of("--attributes")]["argv"]
        self.assertEqual(argv[argv.index("--attributes") + 1], "Password")

    def test_the_read_back_happens_after_the_write_and_not_before(self):
        self.assertLess(self.fake.index_of("--password-prompt"),
                        self.fake.index_of("--attributes"))

    def test_exactly_one_read_back_happens(self):
        self.assertEqual(len(self.read_backs(self.fake)), 1)

    def test_the_read_back_opens_the_database_with_the_master_password_again(self):
        self.assertEqual(self.fake.calls[self.fake.index_of("--attributes")]["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n")

    def test_a_read_back_that_finds_something_else_is_visible_to_the_caller(self):
        # The backend does not judge; it hands back what the database answered,
        # and the fingerprint is what makes the difference visible one layer up.
        other = synthetic_token("someother")  # pragma: allowlist secret
        reading, _ = self.writing(read_back=other)
        self.assertNotEqual(reading.fingerprint,
                            values.fingerprint(self.value.encode("utf-8")))

    def test_the_reading_carries_the_canonical_reference(self):
        self.assertEqual(self.reading.ref, ACME)

    def test_neither_line_was_in_an_argv_on_either_leg(self):
        self.assertFalse(self.fake.argv_carried(self.master))
        self.assertFalse(self.fake.argv_carried(self.value))
