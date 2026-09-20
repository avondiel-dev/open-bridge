"""keepass: what reaches argv, what reaches stdin, and what a failure means.

Every case here is driven through the `runner=` seam. No machine in this fleet
has KeePassXC installed, and none of these cases wants it: a suite that opened a
real database would need a real master password to do it, which is the one thing
this skill exists to keep out of a test tree.

The three properties worth stating up front, because most of the file is one of
them in a different shape:

* THE MASTER PASSWORD GOES ON STDIN. A KeePass master password is not one
  credential, it is every credential in the database at once, and argv is
  readable through `ps` by every process of the same user. `argv_carried()` is
  asserted false in the first class and again wherever a value is in play.
* THE REFERENCE IS A LOGICAL NAME, NOT A PATH. `keepass://work/...` says which
  database, and where that database lives is a property of the machine. A name
  nobody declared here is a configuration error that names what IS declared,
  rather than a read that fails later with a path nobody recognises.
* A FAILED READ IS EITHER A MISS OR A FAULT, AND NEVER BOTH. "no such entry" is
  a miss a caller may act on; a wrong key is a fault that must not be reported
  as a rotation somebody forgot to finish. The whole `errors.py` exit code
  contract rests on that split, so stderr classification gets its own class.
"""

from __future__ import annotations

import os

from tests.conftest import FakeRunner, MachineGuard, completed, mod, synthetic_token

refs = mod("engine.refs")
errors = mod("engine.errors")
values = mod("engine.values")
base = mod("engine.backends.base")
keepass = mod("engine.backends.keepass")

#: Distinguishes "the case said nothing about this" from "the case said None".
#: `password=None` is a real configuration (key file only) and has to be
#: expressible, so a plain default of None would swallow half the cases.
UNSET = object()

#: The reference most cases read. Five segments: the database, three groups and
#: the entry, with the field taken from the last segment by the grammar.
ACME = "keepass://work/customers/acme/api-token/password"

# The two help texts are the two BRANCHES the backend takes, not a claim about
# which KeePassXC version prints which. The engine deliberately asks the build
# in front of it rather than comparing a version string, so the fixtures are
# "a build that advertises the flag" and "a build that does not". Everything
# outside the one line under test is the same in both, so a case that goes red
# has exactly one candidate for why.
_HELP_HEAD = """Usage: keepassxc-cli show [options] database entry
Show a password.

Options:
  -h, --help                    Displays help on commandline options.
  -q, --quiet                   Silence password prompt and other secondary outputs.
  -k, --key-file <path>         Key file of the database.
  --no-password                 Deactivate password key for the database.
"""

_HELP_TAIL = """  -a, --attributes <attribute>  Names of the attributes to show.
  -s, --show-protected          Show the protected attributes in clear text.
  -t, --totp                    Show the current TOTP of the entry.

Arguments:
  database                      Path of the database.
  entry                         Path of the entry to show.
"""

HELP_WITH_PW_STDIN = _HELP_HEAD + "  --pw-stdin                    Read the database password from standard input.\n" + _HELP_TAIL
HELP_WITHOUT_PW_STDIN = _HELP_HEAD + _HELP_TAIL


class KeePassCase(MachineGuard):
    """A declared database on disk, a stub binary on PATH, and a fake process.

    The stub is scaffolding and nothing else. The backend probes with
    `shutil.which` before it reads, so without a file of that name every case in
    this file would fail on the probe rather than on the behaviour it is named
    after, and the one class that WANTS the probe to fail overrides this. The
    stub is never executed: every case passes `runner=`, and the machine guard
    refuses to exec `keepassxc-cli` at all, so a backend that reached around the
    seam fails loudly here instead of quietly opening somebody's database.
    """

    def setUp(self):
        super().setUp()
        self.folder = self.tmpdir()
        self.database = self.folder / "work.kdbx"
        # Bytes, not a KDBX. Nothing in this file opens it; the cases that care
        # only ask whether the file is there.
        self.database.write_bytes(b"not a kdbx, and nothing here ever opens one\n")
        self.master = synthetic_token("kdbxmaster")  # pragma: allowlist secret
        self.put_the_binary_on_path()

    # -- scaffolding --------------------------------------------------------

    def put_the_binary_on_path(self) -> None:
        folder = self.tmpdir()
        stub = folder / "keepassxc-cli"
        stub.write_text("#!/bin/sh\necho 'the suite never runs this' >&2\nexit 97\n",
                        encoding="utf-8")
        stub.chmod(0o755)
        previous = os.environ.get("PATH")
        os.environ["PATH"] = str(folder) + os.pathsep + (previous or "")
        self.addCleanup(self.restore_path, previous)

    @staticmethod
    def restore_path(previous) -> None:
        if previous is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous

    def session(self):
        """A fixed session rather than a detected one.

        This backend does not read the context, but `Context.detect()` asks
        whether stdin is a terminal, and a case whose result depends on how the
        suite was started is a case that behaves differently in CI.
        """
        return base.Context(platform="linux", interactive=False, over_ssh=False,
                            display=False)

    def secret(self, text=None):
        return values.Secret(self.master if text is None else text,
                             origin="keychain://suite/kdbx-master")

    def backend(self, runner=None, *, password=UNSET, key_file=None, databases=UNSET):
        if databases is UNSET:
            databases = {"work": str(self.database)}
        if password is UNSET:
            password = self.secret()
        return keepass.KeePassBackend(databases=databases, password=password,
                                      key_file=key_file, runner=runner,
                                      context=self.session())

    def runner(self, *, stdout="", rc=0, stderr="", help_text=HELP_WITH_PW_STDIN,
               help_on_stderr=False, help_rc=0) -> FakeRunner:
        """A fake process: one answer for the help probe, one for everything else.

        Routes are matched in order and `--help` appears in no other call this
        backend makes, so the probe and the read cannot be confused for each
        other however the argv is phrased.
        """
        fake = FakeRunner(default=completed(rc=rc, stdout=stdout, stderr=stderr))
        if help_on_stderr:
            fake.add("--help", completed(rc=help_rc, stderr=help_text))
        else:
            fake.add("--help", completed(rc=help_rc, stdout=help_text))
        return fake

    def ref(self, uri: str = ACME):
        return refs.parse(uri)

    # -- reading the recording ----------------------------------------------

    def read_call(self, fake: FakeRunner) -> dict:
        """The recorded call that asked for an attribute, not the help probe."""
        return fake.calls[fake.index_of("--attributes")]

    def read_argv(self, fake: FakeRunner) -> tuple:
        return self.read_call(fake)["argv"]

    def help_probes(self, fake: FakeRunner) -> int:
        return sum(1 for call in fake.calls if "--help" in call["joined"])


class TheMasterPasswordTravelsOnStdinAndNeverInArgv(KeePassCase):
    """The case this whole skill exists for.

    Everything in argv is visible through `ps` to every process of the same user
    for as long as the call runs, which is how tokens ended up in the process
    list of two machines in this fleet before anyone looked. A master password
    there is worse than a token: it discloses every entry in the database at
    once, and it does so whether or not the call succeeds.
    """

    def setUp(self):
        super().setUp()
        self.value = synthetic_token("acmetoken")  # pragma: allowlist secret
        self.fake = self.runner(stdout=self.value + "\n")
        self.reading = self.backend(self.fake).read(self.ref())

    def test_the_password_is_written_to_the_standard_input_of_the_tool(self):
        self.assertIn(self.master.encode("utf-8"),
                      self.read_call(self.fake)["stdin_bytes"] or b"")

    def test_the_password_ends_in_a_newline_so_the_tool_reads_a_whole_line(self):
        # Without the newline the tool waits for the rest of the line and the
        # read hangs until the timeout, which reads like a broken database.
        self.assertEqual(self.read_call(self.fake)["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n")

    def test_no_recorded_call_carries_the_password_in_argv(self):
        self.assertFalse(
            self.fake.argv_carried(self.master),
            "the master password appeared in argv:\n" + self.fake.joined_calls)

    def test_the_password_does_not_reach_the_child_environment_either(self):
        # The third channel into a child, and the one a reviewer forgets: an
        # environment is readable from /proc on Linux for the same user.
        for call in self.fake.calls:
            for value in (call["env"] or {}).values():
                self.assertNotIn(self.master, str(value))

    def test_the_value_still_comes_back(self):
        self.assertTrue(self.reading.present)
        self.assertEqual(self.reading.secret.expose(), self.value.encode("utf-8"))

    def test_the_value_of_the_entry_is_not_in_argv_either(self):
        # It cannot be, since nothing sends it in, and that is the point: a
        # backend that echoed the entry name as the value would show up here.
        self.assertFalse(self.fake.argv_carried(self.value))


class ThePwStdinFlagFollowsTheHelpTextOfTheBuildInFrontOfIt(KeePassCase):
    """The flag is added when this build advertises it, and left out otherwise.

    Older builds read the password from stdin anyway when stdin is not a
    terminal, so omitting the flag there still works, while passing a flag a
    build does not know is a usage error and exits before it reads anything.
    That is why the build is asked rather than assumed.
    """

    def read_with(self, **kw) -> FakeRunner:
        fake = self.runner(stdout=synthetic_token("entry") + "\n", **kw)
        self.backend(fake).read(self.ref())
        return fake

    def test_the_flag_is_added_when_show_help_advertises_it(self):
        fake = self.read_with(help_text=HELP_WITH_PW_STDIN)
        self.assertIn("--pw-stdin", self.read_argv(fake))

    def test_the_flag_is_left_out_when_show_help_does_not_mention_it(self):
        fake = self.read_with(help_text=HELP_WITHOUT_PW_STDIN)
        self.assertNotIn("--pw-stdin", self.read_argv(fake))

    def test_the_password_still_reaches_stdin_on_a_build_without_the_flag(self):
        fake = self.read_with(help_text=HELP_WITHOUT_PW_STDIN)
        self.assertEqual(self.read_call(fake)["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n")

    def test_a_help_text_printed_on_standard_error_counts_too(self):
        # Several command line tools print help on stderr, and a probe that read
        # only stdout would decide the flag does not exist on a build that has
        # it. The backend concatenates both streams; this case is what says so.
        fake = self.read_with(help_text=HELP_WITH_PW_STDIN, help_on_stderr=True)
        self.assertIn("--pw-stdin", self.read_argv(fake))

    def test_the_build_is_asked_before_the_read_rather_than_after(self):
        fake = self.read_with()
        self.assertLess(fake.index_of("--help"), fake.index_of("--attributes"))

    def test_the_help_text_is_probed_once_and_then_remembered(self):
        # Two reads through one backend. A probe per read doubles the process
        # count of every wrapper that resolves several references at start.
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        backend = self.backend(fake)
        backend.read(self.ref())
        backend.read(self.ref("keepass://work/customers/acme/api-token/username"))
        self.assertEqual(self.help_probes(fake), 1)

    def test_a_help_probe_that_fails_leaves_the_flag_off_and_still_types_the_password(self):
        # A build that cannot even print its own help is not a build that should
        # be handed an unknown flag, and the password still has to go in, since
        # stdin is how the old builds take it.
        fake = self.read_with(help_text="", help_rc=1)
        self.assertNotIn("--pw-stdin", self.read_argv(fake))
        self.assertEqual(self.read_call(fake)["stdin_bytes"],
                         self.master.encode("utf-8") + b"\n")


class AKeyFileWithoutAPasswordOpensTheDatabaseWithNoPassword(KeePassCase):
    """A database keyed by a file alone, which is the unattended case.

    There is nothing to type, so the tool has to be told not to ask. Without
    `--no-password` it prompts, and a prompt in a launchd agent is a job that
    hangs until its deadline with no message anywhere saying why.
    """

    def setUp(self):
        super().setUp()
        self.key_file = str(self.folder / "work.keyx")
        self.fake = self.runner(stdout=synthetic_token("entry") + "\n")
        self.reading = self.backend(self.fake, password=None,
                                    key_file=self.key_file).read(self.ref())

    def test_no_password_is_named_in_argv(self):
        self.assertIn("--no-password", self.read_argv(self.fake))

    def test_the_key_file_follows_its_own_flag(self):
        argv = self.read_argv(self.fake)
        self.assertEqual(argv[argv.index("--key-file") + 1], self.key_file)

    def test_nothing_is_written_to_standard_input(self):
        self.assertIsNone(self.read_call(self.fake)["stdin_bytes"])

    def test_the_help_text_is_not_probed_when_there_is_nothing_to_type(self):
        # The probe exists to decide how to hand a password over. With no
        # password there is no decision, and a process that buys nothing is a
        # process that should not be started.
        self.assertEqual(self.help_probes(self.fake), 0)

    def test_the_read_works(self):
        self.assertTrue(self.reading.present)

    def test_a_password_and_a_key_file_together_do_not_add_no_password(self):
        # Both halves of a composite key. Saying --no-password here would tell
        # the tool to open with the key file alone, which fails on a database
        # that wants both.
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        self.backend(fake, key_file=self.key_file).read(self.ref())
        argv = self.read_argv(fake)
        self.assertNotIn("--no-password", argv)
        self.assertIn("--key-file", argv)


class TheEntryIsAddressedByTheGroupPathOfTheReference(KeePassCase):
    """Groups joined with slashes, database first, entry last.

    `keepassxc-cli show` takes the database and the entry as the two positional
    arguments in that order. Swapping them is not a usage error the tool
    catches: it tries to open the entry path as a database file.
    """

    def argv_for(self, uri: str) -> tuple:
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        self.backend(fake).read(self.ref(uri))
        return self.read_argv(fake)

    def test_the_groups_and_the_entry_are_joined_with_slashes(self):
        self.assertIn("customers/acme/api-token", self.argv_for(ACME))

    def test_the_field_is_not_part_of_the_entry_path(self):
        self.assertNotIn("customers/acme/api-token/password", self.argv_for(ACME))

    def test_the_last_segment_is_the_field_unless_a_hash_says_otherwise(self):
        # An entry literally called "password" is the ambiguity the grammar was
        # built around, and it is not hypothetical: it is what a generated
        # database calls the entry under a customer group.
        slashed = self.argv_for("keepass://work/customers/acme/password")
        hashed = self.argv_for("keepass://work/customers/acme/password#notes")
        self.assertEqual(slashed[-1], "customers/acme")
        self.assertEqual(hashed[-1], "customers/acme/password")

    def test_the_database_path_comes_before_the_entry_path(self):
        argv = self.argv_for(ACME)
        self.assertEqual(argv[-2], str(self.database))
        self.assertEqual(argv[-1], "customers/acme/api-token")

    def test_the_entry_path_is_the_last_argument(self):
        self.assertEqual(self.argv_for(ACME)[-1], "customers/acme/api-token")

    def test_a_tilde_in_a_declared_path_is_expanded_before_it_is_used(self):
        home = os.path.expanduser("~")
        if home == "~":
            self.skipTest("this account has no home directory to expand")
        backend = self.backend(databases={"work": "~/nowhere/work.kdbx"})
        path = backend.database_path(self.ref())
        self.assertNotIn("~", path)
        self.assertTrue(path.startswith(home), path)


class TheAttributeIsAskedForByItsKeePassName(KeePassCase):
    """Our field names are not KeePass field names, and the gap is silent.

    `show -a password` on a database that stores the value under `Password`
    fails with a message about a missing attribute, which reads like a rotation
    that was never finished rather than like a spelling difference.
    """

    #: Our spelling, and what KeePass calls the same thing.
    KNOWN = (("password", "Password"), ("username", "UserName"),
             ("user", "UserName"), ("url", "URL"),
             ("notes", "Notes"), ("title", "Title"))

    def attribute_for(self, uri: str) -> str:
        return self.backend().attribute(self.ref(uri))

    def test_each_known_field_is_asked_for_by_its_keepass_name(self):
        for ours, theirs in self.KNOWN:
            with self.subTest(field=ours):
                self.assertEqual(
                    self.attribute_for(f"keepass://work/customers/acme/api-token#{ours}"),
                    theirs)

    def test_a_custom_attribute_is_passed_through_unchanged(self):
        # Custom attributes are ordinary names a person typed into the GUI, so
        # anything not in the table has to survive exactly as written.
        self.assertEqual(
            self.attribute_for("keepass://work/customers/acme/api-token#totp-seed"),
            "totp-seed")

    def test_a_custom_attribute_keeps_the_case_it_was_written_in(self):
        self.assertEqual(
            self.attribute_for("keepass://work/customers/acme/api-token#Tenant-ID"),
            "Tenant-ID")

    def test_the_mapping_ignores_the_case_of_a_known_field(self):
        self.assertEqual(
            self.attribute_for("keepass://work/customers/acme/api-token#UserName"),
            "UserName")
        self.assertEqual(
            self.attribute_for("keepass://work/customers/acme/api-token#URL"),
            "URL")

    def test_a_reference_without_a_field_asks_for_the_password(self):
        # Two segments is the shortest reference the grammar takes, and there
        # the second one is the entry rather than the field, so the field falls
        # back to the default. The grammar fills it in and the backend fills it
        # in again; both are load bearing, because `attribute()` is public and
        # `locate()` reaches it with whatever Ref it was handed.
        self.assertEqual(self.attribute_for("keepass://work/api-token"), "Password")

    def test_the_attribute_follows_the_attributes_flag_in_argv(self):
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        self.backend(fake).read(self.ref("keepass://work/customers/acme/api-token#username"))
        argv = self.read_argv(fake)
        self.assertEqual(argv[argv.index("--attributes") + 1], "UserName")

    def test_the_value_is_asked_for_in_clear_text(self):
        # Without --show-protected the tool prints the word PROTECTED where the
        # value would be, with exit code 0. A caller would store that string and
        # find out weeks later, when the credential it replaced stopped working.
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        self.backend(fake).read(self.ref())
        self.assertIn("--show-protected", self.read_argv(fake))

    def test_the_secondary_output_of_the_tool_is_silenced(self):
        # --quiet keeps the password prompt and the banner off the streams the
        # backend then parses as the value.
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        self.backend(fake).read(self.ref())
        self.assertIn("--quiet", self.read_argv(fake))


class ADatabaseNobodyDeclaredHereIsNamedInTheRefusal(KeePassCase):
    """A reference carries a logical name; the path is a property of the machine.

    So the failure is not "file not found", which would send a person looking at
    the disk. It is "this machine does not know that name", and it says which
    names it does know, because the usual cause is a database declared under a
    different word on this box.
    """

    def raised(self, *, databases=UNSET):
        backend = self.backend(databases=databases)
        with self.assertRaises(errors.ReferenceError_) as caught:
            backend.database_path(self.ref("keepass://archive/customers/acme/api-token"))
        return caught.exception

    def test_addressing_an_undeclared_database_raises_a_reference_error(self):
        self.assertIsInstance(self.raised(), errors.ReferenceError_)

    def test_the_message_names_the_database_that_was_asked_for(self):
        self.assertIn("archive", str(self.raised()))

    def test_the_hint_lists_the_databases_that_are_declared_here(self):
        known = {"work": str(self.database), "personal": str(self.folder / "p.kdbx")}
        hint = self.raised(databases=known).hint
        self.assertIn("personal", hint)
        self.assertIn("work", hint)

    def test_the_hint_says_none_when_this_machine_declares_nothing(self):
        # The empty case is the one a person meets first, on a machine where the
        # declaration has not landed yet, and an empty list reads like a bug in
        # the message rather than like an answer.
        self.assertIn("none", self.raised(databases={}).hint)

    def test_the_failure_is_a_configuration_error_and_not_a_missing_secret(self):
        # 78 sends a person to the declaration. 3 would say the entry is gone,
        # which is what a rotation watcher acts on.
        self.assertEqual(self.raised().exit_code, errors.EX_CONFIG)

    def test_a_read_of_an_undeclared_database_starts_no_process_at_all(self):
        fake = self.runner()
        with self.assertRaises(errors.BackendUnavailable):
            self.backend(fake).read(self.ref("keepass://archive/customers/acme/api-token"))
        self.assertEqual(fake.calls, [])


class AReferenceThatNamesOnlyADatabaseIsRefused(KeePassCase):
    """A database name with nothing after it addresses no entry.

    Two doors, and both are closed. The grammar refuses a one segment reference
    outright, so `keepass://work` never becomes a Ref by parsing. The backend
    refuses a Ref whose path is empty however that Ref was built, and that is
    the door worth testing here: `Ref` is an ordinary frozen dataclass, the
    check is the backend's own, and without it the empty entry path would reach
    the tool as an empty positional argument. `keepassxc-cli` does not treat
    that as a usage error, so the refusal has to happen on this side.
    """

    def bare(self):
        """A Ref that names a database and nothing else, built rather than parsed."""
        return refs.Ref(scheme="keepass", store="work", path=(), field="password",
                        raw="keepass://work")

    def raised(self, fake=None):
        with self.assertRaises(errors.ReferenceError_) as caught:
            self.backend(fake).read(self.bare())
        return caught.exception

    def test_the_grammar_refuses_a_reference_with_nothing_after_the_database(self):
        with self.assertRaises(errors.ReferenceError_) as caught:
            refs.parse("keepass://work")
        self.assertIn("at least 2 segments", str(caught.exception))

    def test_the_refusal_says_the_reference_names_a_database_but_no_entry(self):
        self.assertIn("no entry", str(self.raised(self.runner())))

    def test_the_hint_shows_the_shape_a_reference_has(self):
        self.assertIn("keepass://", self.raised(self.runner()).hint)

    def test_the_refusal_is_a_configuration_error_and_not_a_miss(self):
        self.assertEqual(self.raised(self.runner()).exit_code, errors.EX_CONFIG)

    def test_the_backend_refuses_it_on_its_own_without_a_read(self):
        with self.assertRaises(errors.ReferenceError_):
            self.backend().entry_path(self.bare())

    def test_the_tool_is_never_asked_to_read_anything(self):
        fake = self.runner()
        self.raised(fake)
        self.assertFalse(fake.called_with("--attributes"), fake.joined_calls)

    def test_naming_the_entry_makes_the_same_database_readable(self):
        # The contrast case, so the refusal above is pinned to the missing entry
        # and not to anything else about this database.
        fake = self.runner(stdout=synthetic_token("entry") + "\n")
        reading = self.backend(fake).read(self.ref("keepass://work/api-token/password"))
        self.assertTrue(reading.present)


class StderrDecidesWhetherAFailedReadIsAMissOrAFault(KeePassCase):
    """The split the exit code contract rests on.

    A miss is a fact about the database that a caller may act on. A fault is a
    fact about this machine or these credentials, and reporting it as a miss is
    how a rotation watcher deletes and recreates a secret that was never gone.
    """

    def read_failing(self, stderr: str, rc: int = 1):
        fake = self.runner(rc=rc, stderr=stderr)
        return self.backend(fake).read(self.ref())

    def raises_from(self, exception_type, stderr: str, rc: int = 1):
        with self.assertRaises(exception_type) as caught:
            self.read_failing(stderr, rc)
        return caught.exception

    def test_a_missing_entry_comes_back_as_a_reading_rather_than_an_error(self):
        reading = self.read_failing("Could not find entry with path customers/acme/api-token.\n")
        self.assertFalse(reading.present)

    def test_the_miss_says_there_is_no_such_entry_in_this_database(self):
        reading = self.read_failing("Could not find entry with path customers/acme/api-token.\n")
        self.assertIn("no such entry", reading.note)

    def test_a_miss_carries_no_secret_at_all(self):
        # Not an empty one. A caller that tests the secret rather than `present`
        # must not find an object it can hand on as if it were a value.
        reading = self.read_failing("Could not find entry with path x.\n")
        self.assertIsNone(reading.secret)

    def test_the_miss_still_names_the_database_it_looked_in(self):
        reading = self.read_failing("Could not find entry with path x.\n")
        self.assertEqual(reading.store, "work")

    def test_the_other_wording_for_a_missing_entry_is_a_miss_too(self):
        self.assertFalse(self.read_failing("No such entry in this database.\n").present)

    def test_a_wrong_key_is_unavailable_and_not_a_miss(self):
        error = self.raises_from(errors.BackendUnavailable,
                                 "Error while reading the database: wrong key or database file is corrupt.\n")
        self.assertEqual(error.exit_code, errors.EX_UNAVAILABLE)

    def test_the_wrong_key_refusal_names_what_could_have_caused_it(self):
        error = self.raises_from(errors.BackendUnavailable, "Invalid credentials were provided.\n")
        for cause in ("master password", "key file", "database"):
            self.assertIn(cause, error.hint)

    def test_every_wording_that_means_the_database_did_not_open(self):
        for stderr in ("wrong key or database file is corrupt",
                       "Could not open the database file.",
                       "Invalid credentials were provided, please try again."):
            with self.subTest(stderr=stderr):
                self.raises_from(errors.BackendUnavailable, stderr + "\n")

    def test_anything_else_raises_rather_than_returning_a_reading(self):
        self.raises_from(errors.SecretsError, "Unexpected failure in the database plugin.\n", rc=3)

    def test_an_unclassified_failure_names_the_exit_code_the_tool_left(self):
        error = self.raises_from(errors.SecretsError,
                                 "Unexpected failure in the database plugin.\n", rc=3)
        self.assertIn("3", str(error))

    def test_the_first_line_of_stderr_becomes_the_hint(self):
        # A KeePassXC failure can print several lines, and the later ones are
        # usually the usage block. The first non-empty line is the sentence a
        # person needs, and blank leading lines are skipped rather than passed
        # on as an empty hint.
        error = self.raises_from(
            errors.SecretsError,
            "\n   Unexpected failure in the database plugin.\nUsage: keepassxc-cli show\n", rc=3)
        self.assertEqual(error.hint, "Unexpected failure in the database plugin.")

    def test_a_failure_with_a_silent_stderr_still_says_something(self):
        error = self.raises_from(errors.SecretsError, "", rc=2)
        self.assertIn("no message on stderr", error.hint)

    def test_an_unclassified_failure_is_never_reported_as_a_miss(self):
        # The one sentence this class exists for, stated as its own case so a
        # softening of the classification cannot pass unnoticed.
        with self.assertRaises(errors.SecretsError) as caught:
            self.read_failing("Unexpected failure in the database plugin.\n", rc=3)
        self.assertNotIsInstance(caught.exception, errors.SecretMissing)


class AnEmptyAttributeIsAMissNotAHit(KeePassCase):
    """An attribute that exists with nothing in it is not a value.

    The tool exits 0 and prints a bare newline, so every caller that tested
    existence rather than length carried the emptiness one layer further before
    anything failed.
    """

    def read_printing(self, stdout: str):
        fake = self.runner(stdout=stdout)
        return self.backend(fake).read(self.ref())

    def test_the_reading_says_the_value_is_not_present(self):
        self.assertFalse(self.read_printing("\n").present)

    def test_the_note_says_the_attribute_exists_and_is_empty(self):
        # The distinction a person needs: the entry is there and the field is
        # blank, which is a half finished rotation rather than a typo.
        self.assertIn("empty", self.read_printing("\n").note)

    def test_the_reading_still_carries_a_secret_of_zero_bytes(self):
        reading = self.read_printing("\n")
        self.assertIsNotNone(reading.secret)
        self.assertEqual(reading.length, 0)

    def test_no_output_at_all_is_empty_as_well(self):
        self.assertFalse(self.read_printing("").present)

    def test_an_empty_value_is_not_handed_out_as_a_hit(self):
        reading = self.read_printing("")
        self.assertFalse(reading.present and bool(reading.secret))


class TheValueComesBackAsTheToolPrintedIt(KeePassCase):
    """`show --attributes` prints the value and one newline.

    That newline belongs to the tool, not to the value, and every byte after
    stripping it does belong to the value. Both halves matter: a stripped
    trailing newline that was part of a private key breaks the key, and a kept
    one breaks an HTTP header.
    """

    def read_printing(self, stdout: str, uri: str = ACME):
        fake = self.runner(stdout=stdout)
        return self.backend(fake).read(self.ref(uri))

    def test_the_newline_the_tool_adds_is_removed(self):
        value = synthetic_token("plain")  # pragma: allowlist secret
        self.assertEqual(self.read_printing(value + "\n").secret.expose(),
                         value.encode("utf-8"))

    def test_a_value_that_itself_ends_in_a_newline_keeps_it(self):
        value = synthetic_token("multi")  # pragma: allowlist secret
        reading = self.read_printing(value + "\n\n")
        self.assertEqual(reading.secret.expose(), value.encode("utf-8") + b"\n")

    def test_a_value_with_spaces_arrives_whole(self):
        reading = self.read_printing("two words here\n")
        self.assertEqual(reading.secret.expose(), b"two words here")

    def test_a_value_outside_ascii_arrives_whole(self):
        reading = self.read_printing("Straße\n")
        self.assertEqual(reading.secret.expose(), "Straße".encode("utf-8"))

    def test_the_reading_names_the_database_it_came_from(self):
        self.assertEqual(self.read_printing("x\n").store, "work")

    def test_the_reading_carries_the_canonical_reference(self):
        self.assertEqual(self.read_printing("x\n").ref, ACME)

    def test_the_backend_hands_back_a_wrapped_value_and_not_a_string(self):
        # The wrapper is what makes printing a value an explicit act. A backend
        # that returned a str would put the value into the next log line that
        # interpolates a Reading.
        reading = self.read_printing("x\n")
        with self.assertRaises(TypeError):
            str(reading.secret)

    def test_the_wrapped_value_knows_where_it_came_from(self):
        self.assertEqual(self.read_printing("x\n").secret.origin, ACME)


class ALockFileMeansOpenElsewhereAndNotRefused(KeePassCase):
    """Reading under a lock is safe; the note says the state anyway.

    KDBX has no journal, so a save rewrites the whole file and two writers are a
    real conflict. A read opens the file read only and does not disturb the GUI,
    so a lock is not a reason to refuse. It IS a reason to say so: a value read
    while somebody has the database open in the GUI may be one edit behind what
    that person is looking at.
    """

    def setUp(self):
        super().setUp()
        self.lock = self.folder / "work.kdbx.lock"
        self.lock.write_text("", encoding="utf-8")

    def read_printing(self, stdout: str):
        fake = self.runner(stdout=stdout)
        return self.backend(fake).read(self.ref())

    def test_a_read_still_works_while_the_database_is_open_elsewhere(self):
        self.assertTrue(self.read_printing(synthetic_token("entry") + "\n").present)

    def test_the_note_says_the_database_is_open_elsewhere(self):
        self.assertIn("open elsewhere", self.read_printing("x\n").note)

    def test_the_note_names_the_lock_file_as_the_evidence(self):
        # Evidence rather than a guess, because on a WSL mount the lock is not
        # reliably visible to both sides and a bare claim would be wrong there.
        self.assertIn(".lock", self.read_printing("x\n").note)

    def test_the_lock_file_is_the_database_path_with_lock_appended(self):
        backend = self.backend()
        self.assertEqual(backend.lock_file(self.ref()), str(self.database) + ".lock")
        self.assertTrue(backend.locked(self.ref()))

    def test_without_a_lock_file_the_note_stays_empty(self):
        self.lock.unlink()
        reading = self.read_printing("x\n")
        self.assertEqual(reading.note, "")
        self.assertFalse(self.backend().locked(self.ref()))

    def test_an_empty_attribute_under_a_lock_carries_both_halves_of_the_note(self):
        # The combination is the interesting one: somebody has the database open
        # AND the field is blank, which is what a rotation in progress looks
        # like from the outside.
        note = self.read_printing("\n").note
        self.assertIn("open elsewhere", note)
        self.assertIn("empty", note)

    def test_a_missing_entry_under_a_lock_is_still_a_miss(self):
        fake = self.runner(rc=1, stderr="Could not find entry with path x.\n")
        self.assertFalse(self.backend(fake).read(self.ref()).present)


class ReadableHereAnswersBeforeAnyProcessStarts(KeePassCase):
    """Whether a read can work in THIS session, answered from what is on disk.

    It exists so a caller can ask before it spends a process, and so a refusal
    says which of the three preconditions is missing instead of handing back
    whatever the tool happened to print.
    """

    def test_a_declared_database_with_a_password_is_readable_here(self):
        ok, why = self.backend().readable_here(self.ref())
        self.assertTrue(ok)
        self.assertEqual(why, "")

    def test_a_database_nobody_declared_is_not_readable_here(self):
        ok, why = self.backend().readable_here(
            self.ref("keepass://archive/customers/acme/api-token"))
        self.assertFalse(ok)
        self.assertIn("no path is known", why)

    def test_a_database_file_that_is_not_here_is_not_readable_here(self):
        ok, why = self.backend(databases={"work": str(self.folder / "gone.kdbx")}
                               ).readable_here(self.ref())
        self.assertFalse(ok)

    def test_that_reason_names_the_path_it_looked_for(self):
        # The declaration and the disk disagree, and only the path shows which
        # of the two is wrong.
        missing = str(self.folder / "gone.kdbx")
        _, why = self.backend(databases={"work": missing}).readable_here(self.ref())
        self.assertIn(missing, why)

    def test_a_database_without_any_password_source_is_not_readable_here(self):
        ok, why = self.backend(password=None).readable_here(self.ref())
        self.assertFalse(ok)
        self.assertIn("master password", why)

    def test_the_missing_password_points_at_where_one_comes_from(self):
        # The bootstrap this skill is built on: the keychain holds the master
        # password, so the agent sees neither it nor anything in the database.
        _, why = self.backend(password=None).readable_here(self.ref())
        self.assertIn("keychain", why)

    def test_a_key_file_alone_counts_as_a_password_source(self):
        ok, _ = self.backend(password=None, key_file=str(self.folder / "work.keyx")
                             ).readable_here(self.ref())
        self.assertTrue(ok)

    def test_the_answer_costs_no_process(self):
        fake = self.runner()
        self.backend(fake).readable_here(self.ref())
        self.assertEqual(fake.calls, [])

    def test_a_read_that_cannot_work_here_is_refused_rather_than_attempted(self):
        fake = self.runner()
        with self.assertRaises(errors.BackendUnavailable):
            self.backend(fake, password=None).read(self.ref())
        self.assertEqual(fake.calls, [])


class LocateNamesTheFileAndTheEntryAndNeverTheValue(KeePassCase):
    """Where a person would click, printed into a report an agent can read.

    So it has to be complete enough to find the entry by hand, and it has to be
    safe to print next to the reference in a check table.
    """

    def test_the_database_file_is_named(self):
        self.assertIn(str(self.database), self.backend().locate(self.ref()))

    def test_the_entry_path_is_named(self):
        self.assertIn("customers/acme/api-token", self.backend().locate(self.ref()))

    def test_the_attribute_is_named_in_keepass_spelling(self):
        self.assertIn("Password", self.backend().locate(self.ref()))

    def test_no_value_appears_anywhere_in_the_location(self):
        value = synthetic_token("acmetoken")  # pragma: allowlist secret
        fake = self.runner(stdout=value + "\n")
        backend = self.backend(fake)
        backend.read(self.ref())
        where = backend.locate(self.ref())
        self.assertNotIn(value, where)
        self.assertNotIn(self.master, where)

    def test_an_undeclared_database_says_so_rather_than_inventing_a_path(self):
        where = self.backend(databases={}).locate(self.ref())
        self.assertIn("not declared here", where)
        self.assertIn("work", where)

    def test_locating_costs_no_process(self):
        fake = self.runner()
        self.backend(fake).locate(self.ref())
        self.assertEqual(fake.calls, [])


class TheStubOnPathIsScaffoldingAndNotADoor(KeePassCase):
    """The stub makes the probe say yes. It must not make a read possible.

    Every other class here passes `runner=`, so nothing is ever executed. This
    one leaves the seam out on purpose, because the scaffolding that makes those
    cases runnable is exactly the kind of helper that quietly opens a door: on a
    developer machine `keepassxc-cli` may resolve to the real tool with a real
    database behind it. The machine guard refuses to exec that name at all, and
    this case is what says the guard still holds with the stub in place.
    """

    def refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.backend(None).read(self.ref())
        return str(caught.exception)

    def test_a_read_without_the_seam_is_refused(self):
        self.assertIn("tried to exec", self.refused())

    def test_the_refusal_names_the_binary_it_stopped(self):
        self.assertIn("keepassxc-cli", self.refused())


class WithoutTheToolAReadIsUnavailableAndNotAMiss(KeePassCase):
    """No KeePassXC on this machine is a machine problem, with its own code.

    The one class here that wants the probe to fail, so it replaces the stub
    with an empty directory on PATH rather than removing it afterwards.
    """

    def put_the_binary_on_path(self) -> None:
        folder = self.tmpdir()
        previous = os.environ.get("PATH")
        os.environ["PATH"] = str(folder)
        self.addCleanup(self.restore_path, previous)

    def raised(self, fake=None):
        with self.assertRaises(errors.BackendUnavailable) as caught:
            self.backend(fake).read(self.ref())
        return caught.exception

    def test_the_read_refuses_because_the_tool_is_not_installed(self):
        self.assertIn("not installed", str(self.raised(self.runner())))

    def test_the_refusal_names_the_binary_it_looked_for(self):
        self.assertIn("keepassxc-cli", str(self.raised(self.runner())))

    def test_the_refusal_carries_the_install_hint(self):
        self.assertIn("KeePassXC", self.raised(self.runner()).hint)

    def test_the_code_says_unavailable_rather_than_missing(self):
        # A wrapper that read this as "the entry is gone" would rotate a secret
        # because a package was not installed.
        self.assertEqual(self.raised(self.runner()).exit_code, errors.EX_UNAVAILABLE)

    def test_nothing_was_run(self):
        fake = self.runner()
        self.raised(fake)
        self.assertEqual(fake.calls, [])
