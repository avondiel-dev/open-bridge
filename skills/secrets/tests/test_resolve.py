"""resolve: one value per run, one bootstrap link, and no loops.

Everything here is driven through the `runner=` seam, which is why a case can
assert on the argv of a real Keychain call on a machine that has no Keychain,
and why the guard in `tests/conftest.py` can refuse `security` and
`keepassxc-cli` outright. Nothing in this file reaches a store.

The bootstrap is the part with a scar behind it. A KeePass database needs a
master password, and the point of this skill is that the agent never sees one,
so the master password is itself a reference, normally into the OS keychain.
That makes the ORDER of two calls load bearing: the keychain is asked first and
its answer goes to `keepassxc-cli` over stdin, never in argv, because argv is
world readable through `ps` for every process of the same user.

The chain is one link deep on purpose. Both ways of making it longer are
refused rather than followed: a database whose password lives in a database is
refused by scheme, and a reference that is needed to resolve itself is refused
by the resolver before it can recurse. The second refusal cannot be reached
through the two shipped backends today, and the case that measures it says so
and builds the loop where a future backend would build it.
"""

from __future__ import annotations

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

resolve = mod("engine.resolve")
errors = mod("engine.errors")
backends = mod("engine.backends")
base = mod("engine.backends.base")

#: What `security` writes to stderr when there is no such item. rc 44 is the
#: code that means it, and the text is here so a case reads like the terminal.
NO_SUCH_ITEM = ("security: SecKeychainSearchCopyNext: The specified item could "
                "not be found in the keychain.\n")

#: Enough of `keepassxc-cli show --help` for the backend to decide whether this
#: build names the stdin path explicitly. Older builds read the password from
#: stdin anyway when stdin is not a terminal, so the flag is added when it
#: exists and omitted when it does not.
KEEPASS_HELP = ("Usage: keepassxc-cli show [options] database entry\n"
                "  --pw-stdin        read the database password from standard input\n"
                "  --show-protected  show the protected attributes\n")


class ResolverCase(MachineGuard):
    """Shared scaffolding: a deterministic context and an answerable tool probe.

    `Backend.available()` asks `engine.exec.which`, and on a Linux runner
    `security` is genuinely absent, so every case here would fail there for a
    reason that has nothing to do with the resolver. `which` is a wrapped probe
    rather than a bare `shutil.which` call precisely so a test can answer it.
    Nothing is executed either way: the machine guard refuses that, and every
    case passes a FakeRunner.

    The context is spelled out rather than detected for the same reason: run
    over ssh, the same case meets a different Context and, for the keychain, a
    different answer. A suite whose verdict depends on how the developer
    happened to open the terminal is not a suite.
    """

    def setUp(self):
        super().setUp()
        self.runner = FakeRunner()

    def context(self, **overrides):
        fields = {"platform": "darwin", "interactive": True,
                  "over_ssh": False, "display": True}
        fields.update(overrides)
        return base.Context(**fields)

    def tool_is_here(self, *binaries):
        """Answer the binary probe for `binaries`, and for nothing else."""
        present = set(binaries)
        patcher = mock.patch(
            "engine.exec.which",
            lambda binary: "/usr/bin/" + binary if binary in present else None,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def build(self, context=None, **options):
        return resolve.Resolver(resolve.Options(**options), runner=self.runner,
                                context=context or self.context())

    def a_database_file(self, name="work.kdbx"):
        """A file where a .kdbx would be. Its bytes are never opened.

        `readable_here` checks that the database EXISTS before it says a read
        can work, so the path has to be real. Nothing ever parses it: the
        `keepassxc-cli` call that would is answered by the FakeRunner.
        """
        path = self.tmpdir() / name
        path.write_bytes(b"not a KDBX file, and never opened by this suite\n")
        return path

    def calls_matching(self, needle):
        return [call for call in self.runner.calls if needle in call["joined"]]


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------

class AReadingIsFetchedOnceAndThenRemembered(ResolverCase):
    """A value is fetched once per run rather than once per use.

    Not an optimisation. Every read of a keychain item is another chance for
    the session to refuse it, so a command that resolves the same reference
    three times has three chances to fail halfway through its own work, and the
    second failure looks nothing like the first.
    """

    def setUp(self):
        super().setUp()
        self.tool_is_here("security")
        self.token = synthetic_token("ghp")
        self.runner.add("find-generic-password",
                        completed(stdout=keychain_attributes("github", "token"),
                                  stderr=keychain_report(value=self.token)))
        self.resolver = self.build()

    def test_two_reads_of_one_reference_issue_one_call(self):
        self.resolver.read("keychain://github/token")
        self.resolver.read("keychain://github/token")
        self.assertEqual(len(self.runner.calls), 1, self.runner.joined_calls)

    def test_the_second_read_hands_back_the_first_reading(self):
        first = self.resolver.read("keychain://github/token")
        second = self.resolver.read("keychain://github/token")
        self.assertIs(first, second)

    def test_require_reads_through_the_same_cache(self):
        self.resolver.read("keychain://github/token")
        secret = self.resolver.require("keychain://github/token")
        self.assertEqual(len(self.runner.calls), 1, self.runner.joined_calls)
        self.assertEqual(secret.expose_text(), self.token)

    def test_two_spellings_of_one_reference_share_the_reading(self):
        # The cache key is the canonical form, so an empty segment or a
        # trailing slash is the same entry rather than a second call to a
        # store that may ask the user something.
        self.resolver.read("keychain://github/token")
        self.resolver.read("keychain://github//token/")
        self.assertEqual(len(self.runner.calls), 1, self.runner.joined_calls)

    def test_a_different_reference_does_reach_the_tool_again(self):
        # Without this the assertions above would also pass against a resolver
        # that never ran anything at all.
        self.resolver.read("keychain://github/token")
        self.resolver.read("keychain://gitlab/token")
        self.assertEqual(len(self.runner.calls), 2, self.runner.joined_calls)


# ---------------------------------------------------------------------------
# require
# ---------------------------------------------------------------------------

class RequireNamesWhatWasMissing(ResolverCase):
    """`read` reports, `require` refuses, and an empty entry is a miss for both.

    `security find-generic-password` exits 0 for an item that holds zero bytes,
    and every caller that tested existence rather than length carried that
    emptiness one layer further, where it surfaced as a permission problem
    somewhere else entirely.
    """

    def setUp(self):
        super().setUp()
        self.tool_is_here("security")
        self.reference = "keychain://github/token"

    def absent(self):
        self.runner.add("find-generic-password", completed(rc=44, stderr=NO_SUCH_ITEM))
        return self.build()

    def holds_no_bytes(self):
        self.runner.add("find-generic-password",
                        completed(stdout=keychain_attributes("github", "token"),
                                  stderr=keychain_report(empty=True)))
        return self.build()

    def test_an_absent_entry_raises_secret_missing(self):
        with self.assertRaises(errors.SecretMissing):
            self.absent().require(self.reference)

    def test_the_refusal_names_the_reference_it_could_not_resolve(self):
        with self.assertRaises(errors.SecretMissing) as caught:
            self.absent().require(self.reference)
        self.assertEqual(caught.exception.ref, self.reference)
        self.assertIn(self.reference, caught.exception.report())

    def test_the_hint_carries_the_note_the_backend_left(self):
        # The hint is the difference between "the vault is not reachable from
        # here" and "the entry is gone", which is a machine problem and a
        # rotation nobody finished. Both were one silent empty string before.
        with self.assertRaises(errors.SecretMissing) as caught:
            self.absent().require(self.reference)
        self.assertEqual(caught.exception.hint, "no such item in this keychain")

    def test_an_entry_that_holds_no_bytes_is_missing_too(self):
        with self.assertRaises(errors.SecretMissing) as caught:
            self.holds_no_bytes().require(self.reference)
        self.assertEqual(caught.exception.hint, "the item exists and holds no bytes")

    def test_read_reports_that_same_empty_entry_rather_than_raising(self):
        # The two verbs differ here and only here: `read` is what a report
        # calls, so it has to be able to say "found, and empty", which is a
        # different row from "not found".
        reading = self.holds_no_bytes().read(self.reference)
        self.assertFalse(reading.present)
        self.assertIsNotNone(reading.secret)
        self.assertTrue(reading.secret.is_empty())

    def test_the_exit_code_says_missing_and_not_a_configuration_problem(self):
        # A wrapper script reads the code, not the sentence. 3 is "the entry is
        # not there"; 78 would send somebody to look at the YAML instead.
        with self.assertRaises(errors.SecretMissing) as caught:
            self.absent().require(self.reference)
        self.assertEqual(caught.exception.exit_code, errors.EX_MISSING)

    def test_a_present_entry_comes_back_as_the_value(self):
        # The distinguishing half: the refusals above say nothing unless the
        # same path returns the value when the value is there.
        token = synthetic_token("ghp")
        self.runner.add("find-generic-password",
                        completed(stdout=keychain_attributes("github", "token"),
                                  stderr=keychain_report(value=token)))
        self.assertEqual(self.build().require(self.reference).expose_text(), token)


# ---------------------------------------------------------------------------
# The KeePass bootstrap
# ---------------------------------------------------------------------------

class TheKeePassBootstrapResolvesTheMasterPasswordFirst(ResolverCase):
    """The keychain is asked first, and its answer opens the database.

    This is the whole reason the skill exists: the agent never sees either
    value, and the one that travels between two processes travels on stdin.
    """

    def setUp(self):
        super().setUp()
        self.tool_is_here("security", "keepassxc-cli")
        self.master = synthetic_token("kdbx")
        self.value = synthetic_token("acme")
        self.database = self.a_database_file()
        self.runner.add("find-generic-password",
                        completed(stdout=keychain_attributes("keepass-work", "master"),
                                  stderr=keychain_report(value=self.master)))
        self.runner.add("show --help", completed(stdout=KEEPASS_HELP))
        self.runner.add("--attributes", completed(stdout=self.value + "\n"))
        self.resolver = self.build(databases={"work": str(self.database)},
                                   db_password_ref="keychain://keepass-work/master")
        self.reference = "keepass://work/customers/acme/api-token#password"

    def test_the_keychain_is_asked_before_the_database(self):
        self.resolver.require(self.reference)
        self.assertLess(self.runner.index_of("find-generic-password"),
                        self.runner.index_of("--attributes"),
                        self.runner.joined_calls)

    def test_the_master_password_reaches_the_database_on_stdin(self):
        self.resolver.require(self.reference)
        call = self.runner.calls[self.runner.index_of("--attributes")]
        self.assertEqual(call["stdin_bytes"], self.master.encode("utf-8") + b"\n")

    def test_the_master_password_never_travels_in_argv(self):
        # argv is visible in `ps` to every process of the same user, so a value
        # there is disclosed to the whole machine the moment the call runs,
        # whether or not the call succeeds. Two machines in this fleet had
        # tokens in their process lists before anybody looked.
        self.resolver.require(self.reference)
        self.assertFalse(self.runner.argv_carried(self.master), self.runner.joined_calls)

    def test_the_value_that_came_back_never_travels_in_argv_either(self):
        self.resolver.require(self.reference)
        self.assertFalse(self.runner.argv_carried(self.value), self.runner.joined_calls)

    def test_the_database_and_the_entry_do_travel_in_argv(self):
        # The two assertions above would also hold against a resolver that ran
        # nothing. A path and an entry name are locators, not values, and they
        # have to be in the call for the call to mean anything.
        self.resolver.require(self.reference)
        self.assertTrue(self.runner.argv_carried(str(self.database)), self.runner.joined_calls)
        self.assertTrue(self.runner.argv_carried("customers/acme/api-token"),
                        self.runner.joined_calls)

    def test_the_value_comes_back(self):
        self.assertEqual(self.resolver.require(self.reference).expose_text(), self.value)

    def test_the_master_password_is_read_once_for_two_entries(self):
        # The backend is built once per run, so the bootstrap is paid once. A
        # rebuild per entry would ask the keychain again for every reference in
        # a check run, and on a locked session that is one prompt per row.
        self.resolver.require(self.reference)
        self.resolver.require("keepass://work/customers/acme/deploy-key#password")
        self.assertEqual(len(self.calls_matching("find-generic-password")), 1,
                         self.runner.joined_calls)
        self.assertEqual(len(self.calls_matching("--attributes")), 2,
                         self.runner.joined_calls)

    def test_a_master_password_that_is_not_there_is_reported_as_missing(self):
        # The failure that reads as the wrong thing if it is not named: the
        # database is fine, the entry is fine, and the keychain item holding
        # the master password is gone.
        runner = FakeRunner()
        runner.add("find-generic-password", completed(rc=44, stderr=NO_SUCH_ITEM))
        resolver = resolve.Resolver(
            resolve.Options(databases={"work": str(self.database)},
                            db_password_ref="keychain://keepass-work/master"),
            runner=runner, context=self.context())
        with self.assertRaises(errors.SecretMissing) as caught:
            resolver.require(self.reference)
        self.assertEqual(caught.exception.ref, "keychain://keepass-work/master")
        self.assertFalse(runner.called_with("keepassxc-cli"), runner.joined_calls)


class AMasterPasswordInsideTheDatabaseItOpensIsRefused(ResolverCase):
    """One link deep on purpose.

    A database whose password lives in a database is a loop waiting to happen,
    and an error that says so is worth more than a recursion that ends in a
    stack trace with a vault path in it.
    """

    def setUp(self):
        super().setUp()
        self.tool_is_here("security", "keepassxc-cli")
        self.database = self.a_database_file()
        self.resolver = self.build(
            databases={"work": str(self.database)},
            db_password_ref="keepass://work/vault/master#password")
        self.reference = "keepass://work/customers/acme/api-token#password"

    def refusal(self):
        with self.assertRaises(errors.Refused) as caught:
            self.resolver.read(self.reference)
        return caught.exception

    def test_it_raises_refused(self):
        self.assertIsInstance(self.refusal(), errors.Refused)

    def test_the_message_says_a_keepass_database_may_not_hold_it(self):
        self.assertIn("may not live in a KeePass database", str(self.refusal()))

    def test_the_hint_points_at_a_store_that_needs_no_second_secret(self):
        self.assertIn("keychain", self.refusal().hint)

    def test_the_refusal_names_the_offending_reference_and_not_the_one_asked_for(self):
        # The caller asked for an api-token and the problem is in the
        # declaration of the master password. A refusal that named the
        # api-token would send somebody to look at the wrong line.
        self.assertEqual(self.refusal().ref, "keepass://work/vault/master/password")

    def test_the_exit_code_says_refused(self):
        self.assertEqual(self.refusal().exit_code, errors.EX_REFUSED)

    def test_nothing_was_executed(self):
        # Refused before anything ran, which is the difference between a
        # refusal and a failure: no prompt, no lock file, no half open
        # database.
        self.refusal()
        self.assertEqual(self.runner.calls, [], self.runner.joined_calls)


class AReferenceThatIsNeededToResolveItselfIsRefusedRatherThanRecursed(ResolverCase):
    """A store whose credential lives in that same store cannot be opened.

    The two shipped backends cannot express this loop: the only bootstrap is
    KeePass, and a KeePass password pointing into KeePass is refused one step
    earlier by the scheme check. So the loop is built where the next backend
    would build it, by letting the backend for a scheme re-enter the resolver
    for the reference it is in the middle of reading. Without the guard that is
    a RecursionError, which is not a sentence anybody can act on, and it
    arrives with a traceback naming every store on the way down.
    """

    def a_backend_that_needs_its_own_value(self, holder):
        # Defined inside the case rather than at module level: `base` is a lazy
        # proxy, and subclassing at import time would import the engine during
        # collection, which is the thing the proxy exists to avoid.
        class AStoreThatNeedsItsOwnValue(base.Backend):
            scheme = "keychain"
            binary = None

            def __init__(self, *, keychain_path=None, **kwargs):
                super().__init__(**kwargs)

            def read(self, ref):
                return holder["resolver"].read(ref)

        return AStoreThatNeedsItsOwnValue

    def refusal(self):
        holder = {}
        resolver = self.build()
        holder["resolver"] = resolver
        stand_in = self.a_backend_that_needs_its_own_value(holder)
        with mock.patch.dict(backends.REGISTRY, {"keychain": stand_in}):
            with self.assertRaises(errors.Refused) as caught:
                resolver.read("keychain://github/token")
        return caught.exception

    def test_it_raises_refused_rather_than_running_out_of_stack(self):
        self.assertIsInstance(self.refusal(), errors.Refused)

    def test_the_message_says_the_reference_is_needed_to_resolve_itself(self):
        self.assertIn("needed to resolve itself", str(self.refusal()))

    def test_the_refusal_names_the_reference_that_closed_the_loop(self):
        self.assertEqual(self.refusal().ref, "keychain://github/token")

    def test_the_hint_says_why_that_cannot_work(self):
        self.assertIn("cannot be opened", self.refusal().hint)

    def test_nothing_was_executed(self):
        self.refusal()
        self.assertEqual(self.runner.calls, [], self.runner.joined_calls)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

class WithDatabaseTakesNameEqualsPathAndRefusesTheRest(ResolverCase):
    """`--db work=/path/to.kdbx` is where a logical name meets a path.

    A reference names the database and never the path, because the path is a
    property of the machine. This is the one place the two meet, so a spec that
    parses wrongly here is a reference that resolves to nothing on one machine
    and to the wrong file on the next.
    """

    def test_it_records_the_mapping(self):
        options = resolve.Options().with_database("work=/home/opuser/Vaults/work.kdbx")
        self.assertEqual(options.databases, {"work": "/home/opuser/Vaults/work.kdbx"})

    def test_it_returns_the_options_so_two_flags_can_chain(self):
        options = resolve.Options()
        returned = options.with_database("work=/Vaults/work.kdbx")
        self.assertIs(returned, options)
        returned.with_database("personal=/Vaults/personal.kdbx")
        self.assertEqual(options.databases,
                         {"work": "/Vaults/work.kdbx", "personal": "/Vaults/personal.kdbx"})

    def test_whitespace_around_either_half_is_trimmed(self):
        # A shell quoting accident, and one that would otherwise produce a
        # database named " work" that no reference can ever address.
        options = resolve.Options().with_database("  work = /Vaults/work.kdbx  ")
        self.assertEqual(options.databases, {"work": "/Vaults/work.kdbx"})

    def test_only_the_first_equals_separates_the_name_from_the_path(self):
        # A path may contain an equals sign. Splitting on every one of them
        # would truncate the path and report a file that is not there.
        options = resolve.Options().with_database("work=/Vaults/team=acme/work.kdbx")
        self.assertEqual(options.databases, {"work": "/Vaults/team=acme/work.kdbx"})

    def test_a_spec_without_an_equals_is_refused(self):
        with self.assertRaises(ValueError):
            resolve.Options().with_database("/Vaults/work.kdbx")

    def test_a_spec_with_no_name_is_refused(self):
        with self.assertRaises(ValueError):
            resolve.Options().with_database("=/Vaults/work.kdbx")

    def test_a_spec_with_no_path_is_refused(self):
        with self.assertRaises(ValueError):
            resolve.Options().with_database("work=")

    def test_a_spec_that_is_only_whitespace_around_an_equals_is_refused(self):
        with self.assertRaises(ValueError):
            resolve.Options().with_database("   =   ")

    def test_the_message_names_the_shape_it_wanted(self):
        # The caller is a person who has just typed the flag, so the refusal
        # shows the flag rather than the parser's opinion of it.
        with self.assertRaises(ValueError) as caught:
            resolve.Options().with_database("work")
        self.assertIn("name=/path/to.kdbx", str(caught.exception))

    def test_a_refused_spec_leaves_no_half_written_entry_behind(self):
        options = resolve.Options()
        with self.assertRaises(ValueError):
            options.with_database("work=")
        self.assertEqual(options.databases, {})


# ---------------------------------------------------------------------------
# Description, without reading anything
# ---------------------------------------------------------------------------

class ReadableHereAnswersFromTheSessionBeforeAnythingRuns(ResolverCase):
    """Readability is a property of the entry AND of the session asking.

    The same keychain item answers from a desktop session and is refused over
    ssh. A report that says "ok" on the laptop and "missing" on the same laptop
    over ssh is measuring the session rather than the vault, and the wrapper
    that could not tell those apart rotated a secret that was never gone.
    """

    def test_a_missing_tool_is_named_rather_than_guessed(self):
        self.tool_is_here()
        readable, why = self.build().readable_here("keychain://github/token")
        self.assertFalse(readable)
        self.assertIn("security", why)
        self.assertEqual(self.runner.calls, [], self.runner.joined_calls)

    def test_the_login_keychain_over_ssh_is_refused_with_the_reason(self):
        self.tool_is_here("security")
        resolver = self.build(context=self.context(over_ssh=True))
        readable, why = resolver.readable_here("keychain://github/token")
        self.assertFalse(readable)
        self.assertIn("ssh", why)
        self.assertEqual(self.runner.calls, [], self.runner.joined_calls)

    def test_the_same_reference_is_readable_from_a_desktop_session(self):
        # The pair is the point. A "no" that is also a "no" at the screen would
        # be measuring the tool, not the session.
        self.tool_is_here("security")
        readable, why = self.build().readable_here("keychain://github/token")
        self.assertTrue(readable, why)

    def test_a_keychain_file_of_its_own_is_readable_over_ssh(self):
        # A declared keychain file is not the login keychain and does not need
        # an unlocked session, which is how a daemon reads one at all.
        self.tool_is_here("security")
        resolver = self.build(context=self.context(over_ssh=True),
                              keychain_path=str(self.tmpdir() / "service.keychain-db"))
        readable, why = resolver.readable_here("keychain://github/token")
        self.assertTrue(readable, why)

    def test_a_database_nobody_declared_here_is_named_as_such(self):
        self.tool_is_here("keepassxc-cli")
        readable, why = self.build().readable_here("keepass://work/customers/acme/api-token#password")
        self.assertFalse(readable)
        self.assertIn("no path is known", why)

    def test_a_database_with_no_password_source_is_named_as_such(self):
        # Declared, present on disk, and still not readable: there is nothing
        # to open it with. That is a different repair from a missing file.
        self.tool_is_here("keepassxc-cli")
        resolver = self.build(databases={"work": str(self.a_database_file())})
        readable, why = resolver.readable_here("keepass://work/customers/acme/api-token#password")
        self.assertFalse(readable)
        self.assertIn("master password", why)


class LocateSaysWhereToLookAndReachesNothing(ResolverCase):
    """`where` is the column that tells a person which vault to open.

    It is rendered on machines where the store is absent, so it is built from
    the reference and the declarations and never from a read.
    """

    def test_the_keychain_entry_is_named_by_service_and_account(self):
        self.tool_is_here("security")
        where = self.build().locate("keychain://github/token")
        self.assertIn("github", where)
        self.assertIn("token", where)
        self.assertIn("login keychain", where)

    def test_a_declared_keychain_file_is_named_instead_of_the_login_one(self):
        self.tool_is_here("security")
        path = str(self.tmpdir() / "service.keychain-db")
        where = self.build(keychain_path=path).locate("keychain://github/token")
        self.assertIn(path, where)
        self.assertNotIn("login keychain", where)

    def test_a_keepass_entry_is_named_by_path_and_attribute(self):
        self.tool_is_here("keepassxc-cli")
        database = self.a_database_file()
        where = self.build(databases={"work": str(database)}).locate(
            "keepass://work/customers/acme/api-token#password")
        self.assertIn(str(database), where)
        self.assertIn("customers/acme/api-token", where)
        self.assertIn("Password", where)

    def test_nothing_was_executed(self):
        self.tool_is_here("security")
        self.build().locate("keychain://github/token")
        self.assertEqual(self.runner.calls, [], self.runner.joined_calls)
