"""keychain backend: the argv it builds, the shapes it parses, the two refusals.

Three tiers live in this file and they are not equally strong, so they are named
rather than mixed.

The ARGV TIER drives `KeychainBackend` through `FakeRunner` and runs everywhere.
It asserts the two things that cost something when they are wrong: the argv is
exactly what the measured tool takes, and no value ever travels in it. Anything
in argv is readable through `ps` by every process of this user, so a value there
is disclosed to the whole machine the moment the call runs.

The PARSE TIER feeds the backend the stderr that `security find-generic-password
-g` actually prints. Every shape here was measured against a throwaway keychain
on macOS 26 on 2026-09-20, the same run that produced the table in
`tests/conftest.py`, and `keychain_report()` is what keeps a fixture from being
prettier than the tool. A parser tested against a shape the tool never emits is
a parser tested against nothing.

The MACOS TIER is one case. It creates its own throwaway keychain, stores a
synthetic value through `security -i` on stdin, reads it back through the
backend, and skips everywhere else. Because it skips, the meta case at the
bottom of this file counts the argv tier and refuses a run in which the tier
that always runs has quietly shrunk to nothing.

Two notes on the seam, both of them the reason a case reads the way it does:

  * `Backend.available()` probes the filesystem with `shutil.which`, which is the
    one thing in the read path that does NOT go through `runner=`. Left alone,
    every read case below would raise `BackendUnavailable` on a machine without
    `security` and the argv tier would be a macOS tier in disguise. The probe is
    answered in `setUp` and nothing is executed either way. The one case that
    wants the other answer patches it the other way and says so.
  * `security` itself is denied by `MachineGuard` in every tier but the last.
    That guard is what keeps a suite run on this developer's laptop off his real
    login keychain, which sits one unqualified lookup away.
"""

from __future__ import annotations

import hashlib
import os
import sys
import unittest
from unittest import mock

from tests.conftest import (
    FakeRunner,
    MachineGuard,
    completed,
    keychain_attributes,
    keychain_report,
    mod,
    requires_real_keychain,
    synthetic_token,
    temporary_keychain,
    unguarded_security,
)

keychain = mod("engine.backends.keychain")
base = mod("engine.backends.base")
errors = mod("engine.errors")
refs = mod("engine.refs")

#: A value that is ten characters of hex and nothing else. Stored through `-w`
#: the tool prints it exactly the way it prints five bytes that happen to spell
#: those characters, which is the whole reason this backend reads `-g`.
LOOKS_LIKE_HEX = "6c310a6c32"  # pragma: allowlist secret

#: The five bytes those same ten characters name, newline included. Measured:
#: `password: 0x6C310A6C32  "l1\012l2"`.
HEX_BYTES = b"l1\nl2"


class KeychainCase(MachineGuard):
    """The argv tier: a backend wired to a fake process, never to a store."""

    SERVICE = "bridge-suite"
    ACCOUNT = "suite-account"

    def setUp(self):
        super().setUp()
        # See the module docstring: the availability probe is the one call the
        # runner seam does not cover, so it is answered here rather than left to
        # whatever the host happens to have installed.
        patcher = mock.patch("engine.exec.which", return_value="/usr/bin/security")
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- builders -----------------------------------------------------------

    def ref(self, uri=None):
        return refs.parse(uri or "keychain://%s/%s" % (self.SERVICE, self.ACCOUNT))

    def context(self, platform="darwin", interactive=True, over_ssh=False,
                display=True):
        return base.Context(platform=platform, interactive=interactive,
                            over_ssh=over_ssh, display=display)

    def backend(self, runner=None, *, keychain_path=None, **context_overrides):
        return keychain.KeychainBackend(
            keychain_path=keychain_path,
            runner=runner,
            context=self.context(**context_overrides),
        )

    def answering(self, *, rc=0, stdout="", stderr=""):
        """A runner that answers any find-generic-password call with one result."""
        runner = FakeRunner()
        runner.add("find-generic-password", completed(rc=rc, stdout=stdout,
                                                      stderr=stderr))
        return runner

    def reading(self, *, rc=0, stdout="", stderr="", uri=None, keychain_path=None):
        """One read through the whole backend, plus the runner that saw it."""
        runner = self.answering(rc=rc, stdout=stdout, stderr=stderr)
        backend = self.backend(runner, keychain_path=keychain_path)
        return backend.read(self.ref(uri)), runner

    def raised(self, exception_type, **kwargs):
        """The exception one read raised, for a case that asserts on its parts."""
        with self.assertRaises(exception_type) as caught:
            self.reading(**kwargs)
        return caught.exception


class TheArgvIsWhatTheMeasuredToolTakes(KeychainCase):
    """`security find-generic-password -s <service> [-a <account>] -g [keychain]`.

    Pinned as a whole list rather than by substring. A backend that grew an
    extra flag, or lost the one that decides how the value is printed, would
    still contain every substring a looser case looks for.
    """

    def test_the_service_and_the_account_are_both_named(self):
        argv = self.backend().argv_read(self.ref())
        self.assertEqual(argv, ["security", "find-generic-password",
                                "-s", self.SERVICE, "-a", self.ACCOUNT, "-g"])

    def test_a_reference_without_an_account_omits_the_flag_entirely(self):
        argv = self.backend().argv_read(self.ref("keychain://%s" % self.SERVICE))
        self.assertEqual(argv, ["security", "find-generic-password",
                                "-s", self.SERVICE, "-g"])
        # Not "-a" with an empty value: `security` reads the next word as the
        # account, so an empty one would silently search for the entry whose
        # account is the string that followed.
        self.assertNotIn("-a", argv)

    def test_a_configured_keychain_file_is_the_last_argument(self):
        path = "/tmp/suite.keychain-db"
        argv = self.backend(keychain_path=path).argv_read(self.ref())
        self.assertEqual(argv[-1], path,
                         "security takes the keychain as a trailing operand, not a flag")
        self.assertEqual(argv, ["security", "find-generic-password",
                                "-s", self.SERVICE, "-a", self.ACCOUNT, "-g", path])

    def test_without_a_configured_file_nothing_follows_the_g_flag(self):
        argv = self.backend().argv_read(self.ref())
        self.assertEqual(argv[-1], "-g",
                         "a trailing operand here would address a keychain nobody named")

    def test_the_g_flag_is_there_and_the_w_flag_is_not(self):
        # `-w` prints the value with no marker on it, so a value that contains a
        # newline and a value that spells ten characters of hex come back
        # identical. `-g` marks the hex form with 0x, which is the only thing
        # that tells the two apart.
        argv = self.backend().argv_read(self.ref())
        self.assertIn("-g", argv)
        self.assertNotIn("-w", argv)

    def test_the_read_runs_the_argv_this_backend_says_it_runs(self):
        # argv_read() is worth nothing as a promise if read() assembles its own.
        expected = self.backend().argv_read(self.ref())
        _, runner = self.reading(stderr=keychain_report(value="abc"))
        self.assertEqual(runner.calls[0]["argv"], tuple(expected))


class NoValueEverTravelsInArgv(KeychainCase):
    """The one assertion this skill exists for, on every path that has a value."""

    def test_the_value_that_came_back_was_never_in_an_argv(self):
        token = synthetic_token("keychain-read")
        reading, runner = self.reading(stderr=keychain_report(value=token))
        self.assertEqual(reading.secret.expose(), token.encode("utf-8"))
        self.assertFalse(runner.argv_carried(token),
                         "argv is world readable through ps for this user")

    def test_a_hex_encoded_value_is_not_in_argv_in_that_spelling_either(self):
        reading, runner = self.reading(stderr=keychain_report(hex_value=HEX_BYTES))
        self.assertEqual(reading.secret.expose(), HEX_BYTES)
        self.assertFalse(runner.argv_carried(HEX_BYTES.hex()))
        self.assertFalse(runner.argv_carried(HEX_BYTES.hex().upper()))

    def test_the_read_hands_nothing_over_on_stdin_or_in_the_environment(self):
        # A read sends no value anywhere. The case exists so that a future write
        # path cannot quietly start sending one through the read call.
        _, runner = self.reading(stderr=keychain_report(value="abc"))
        self.assertIsNone(runner.calls[0]["stdin_bytes"])
        self.assertIsNone(runner.calls[0]["env"])

    def test_the_write_path_carries_the_value_on_stdin_and_never_in_argv(self):
        # `security add-generic-password -w` takes the value as an ARGUMENT, so
        # a write implemented the obvious way discloses it to every process of
        # the same user. This backend feeds the whole command line to
        # `security -i` on stdin instead, and this case is what holds it there.
        token = synthetic_token("keychain-write")
        secret = mod("engine.values").Secret(token)
        runner = FakeRunner()
        runner.add("security -i", completed(rc=0))
        runner.add("find-generic-password", completed(stderr=keychain_report(value=token)))
        backend = self.backend(runner)

        reading = backend.write(self.ref(), secret)

        self.assertFalse(runner.argv_carried(token),
                         "the value stood in a command line: " + runner.joined_calls)
        written = runner.calls[0]
        self.assertIn("security -i", written["joined"])
        self.assertIsNotNone(written["stdin_bytes"])
        self.assertIn(token.encode(), written["stdin_bytes"])
        # And the write is proved by reading it back, not by an exit code: an
        # entry can exist, be empty, and still exit 0.
        self.assertTrue(reading.present)
        self.assertEqual(reading.fingerprint, mod("engine.values").fingerprint(token))

    def test_a_value_with_a_newline_goes_as_hex_and_still_not_in_argv(self):
        # The quoted form cannot carry a control character. `-X <hex>` can, and
        # it travels on the same stdin line, so the property holds for a PEM
        # key as well as for a token.
        secret = mod("engine.values").Secret("line1\nline2")
        runner = FakeRunner()
        runner.add("security -i", completed(rc=0))
        runner.add("find-generic-password",
                   completed(stderr=keychain_report(hex_value=b"line1\nline2")))
        backend = self.backend(runner)

        backend.write(self.ref(), secret)

        line = runner.calls[0]["stdin_bytes"].decode()
        self.assertIn(" -X ", line)
        self.assertNotIn("line1", line.split(" -X ")[0])
        self.assertFalse(runner.argv_carried("line1"))


class TheMeasuredParseShapes(KeychainCase):
    """One case per shape `security -g` actually prints, and none it does not."""

    def test_a_quoted_plain_value_is_read_as_its_characters(self):
        token = synthetic_token("plain")
        reading, _ = self.reading(stderr=keychain_report(value=token))
        self.assertTrue(reading.present)
        self.assertEqual(reading.secret.expose(), token.encode("utf-8"))

    def test_a_hex_value_decodes_to_the_bytes_it_names(self):
        # The measured line is `password: 0x6C310A6C32  "l1\012l2"`. Five bytes,
        # one of them a newline, which is why the tool refuses to print it plain.
        reading, _ = self.reading(stderr=keychain_report(hex_value=HEX_BYTES))
        self.assertEqual(reading.secret.expose(), HEX_BYTES)
        self.assertIn(b"\n", reading.secret.expose())
        self.assertEqual(reading.length, 5)

    def test_an_empty_password_line_is_zero_bytes_and_not_a_parse_failure(self):
        # `password: ` with a trailing space and nothing after it. A parser that
        # reported None here would turn an entry with no bytes into a failure of
        # this skill rather than a finding about the vault.
        reading, _ = self.reading(stderr=keychain_report(empty=True))
        self.assertIsNotNone(reading.secret)
        self.assertEqual(reading.secret.expose(), b"")

    def test_a_quoted_value_keeps_an_escaped_quote_and_a_backslash(self):
        # Fed to the parser directly rather than through `keychain_report`, which
        # refuses it: the tool prints a value holding a backslash in the HEX
        # form, so this exact line never comes off the measured tool. The engine
        # accepts the shape anyway, and the branch that does is worth measuring
        # because it is what decides where the closing quote is.
        raw = keychain.parse_password('password: "a\\"b\\\\c"' + "\n")
        self.assertEqual(raw, b'a"b\\c')

    def test_an_octal_escape_becomes_the_byte_it_names(self):
        # `\012` is how the tool spells a newline in the quoted half of a hex
        # line. Ten characters in, one byte out.
        raw = keychain.parse_password('password: "l1\\012l2"' + "\n")
        self.assertEqual(raw, b"l1\nl2")

    def test_the_attribute_dump_on_stdout_is_not_where_the_value_is(self):
        # Both streams carry something on a real call. The value is on stderr and
        # the attributes are on stdout, which is the detail every script that
        # pipes only one of the two gets wrong.
        token = synthetic_token("stderr-side")
        reading, _ = self.reading(
            stdout=keychain_attributes(self.SERVICE, self.ACCOUNT),
            stderr=keychain_report(value=token),
        )
        self.assertEqual(reading.secret.expose(), token.encode("utf-8"))
        self.assertNotIn(b"genp", reading.secret.expose())

    def test_a_password_line_on_stdout_alone_is_a_parser_problem_not_a_miss(self):
        # rc 0 and no password line on stderr. The entry is there; something
        # about the reading is wrong. Reporting that as absence is how a rotation
        # gets started over a secret that never moved.
        error = self.raised(errors.SecretsError,
                            stdout=keychain_report(value="abc"), stderr="")
        self.assertIn("without a password line", str(error))
        self.assertIn("parser problem", error.hint)
        self.assertNotIsInstance(error, errors.SecretMissing)


class AValueHoldingADoubleQuoteComesBackWhole(KeychainCase):
    """MEASURED AND RED: the quoted branch truncates at an inner double quote.

    `security` does not escape a double quote inside a value. Measured on
    macOS 26 on 2026-09-20 against a throwaway keychain, the three character
    value `a"b` comes back as

        password: "a"b"

    and `keychain_report(value='a"b')` reproduces that line, which is what the
    note in `tests/conftest.py` means by "the fixture reproduces it so that a
    case can be written against it".

    `_closing_quote` stops at the FIRST unescaped quote, so the read returns one
    byte, reports `present=True` and says nothing about it. A truncated secret is
    worse than a missing one: it is used, it is rejected at the far end, and
    nobody goes looking in the keychain. The ambiguity is the tool's, and it is
    resolvable: in the quoted form the value runs to the LAST quote on the line,
    because the tool prints nothing after it, and the hex form is taken by the
    `0x` branch before this one is reached.

    The engine is not touched by this suite, so this case stays red until the
    parser is fixed.
    """

    VALUE = 'a"b'

    def test_the_read_returns_all_three_bytes(self):
        reading, _ = self.reading(stderr=keychain_report(value=self.VALUE))
        self.assertEqual(reading.secret.expose(), self.VALUE.encode("ascii"))

    def test_the_same_value_in_the_hex_form_is_read_correctly(self):
        # Green, and it is what isolates the defect: the hex branch answers
        # before the quoted one, so only values the tool prints quoted are hurt.
        reading, _ = self.reading(
            stderr=keychain_report(hex_value=self.VALUE.encode("ascii")))
        self.assertEqual(reading.secret.expose(), self.VALUE.encode("ascii"))


class TheHexMarkerIsWhyTheGFlagIsUsed(KeychainCase):
    """Ten characters of output, two different values, and `0x` tells them apart.

    This is the ambiguity the backend's own docstring is about. Under `-w` both
    of the readings below print `6c310a6c32` and no caller can tell which one it
    holds. Every wrapper in this fleet that guessed got away with it only because
    its tokens were ASCII.
    """

    def test_a_plain_value_that_looks_like_hex_is_read_as_its_characters(self):
        reading, _ = self.reading(stderr=keychain_report(value=LOOKS_LIKE_HEX))
        self.assertEqual(reading.secret.expose(), LOOKS_LIKE_HEX.encode("ascii"))
        self.assertEqual(reading.length, 10, "ten characters, not five bytes")

    def test_the_same_ten_characters_marked_with_0x_are_five_bytes(self):
        reading, _ = self.reading(stderr=keychain_report(hex_value=LOOKS_LIKE_HEX))
        self.assertEqual(reading.secret.expose(), HEX_BYTES)
        self.assertEqual(reading.length, 5)

    def test_the_two_readings_are_not_the_same_secret(self):
        plain, _ = self.reading(stderr=keychain_report(value=LOOKS_LIKE_HEX))
        hexed, _ = self.reading(stderr=keychain_report(hex_value=LOOKS_LIKE_HEX))
        self.assertNotEqual(plain.secret.expose(), hexed.secret.expose())
        self.assertNotEqual(plain.fingerprint, hexed.fingerprint)


class AMissingItemIsAMissAndNotAFailure(KeychainCase):
    """rc 44 is `SecKeychainSearchCopyNext`: the search ran and found nothing."""

    def test_rc_44_reports_absence_rather_than_raising(self):
        reading, _ = self.reading(rc=44, stderr=(
            "security: SecKeychainSearchCopyNext: "
            "The specified item could not be found in the keychain.\n"))
        self.assertFalse(reading.present)

    def test_the_note_says_which_kind_of_absence_this_is(self):
        reading, _ = self.reading(rc=44, stderr="")
        self.assertIn("no such item", reading.note)

    def test_the_reading_carries_no_secret_at_all(self):
        # Not an empty Secret: a caller that injected one would hand a downstream
        # process the empty string as if it were a value.
        reading, _ = self.reading(rc=44, stderr="")
        self.assertIsNone(reading.secret)
        self.assertEqual(reading.length, 0)
        self.assertEqual(reading.fingerprint, "")

    def test_the_reading_names_the_store_that_answered(self):
        reading, _ = self.reading(rc=44, stderr="")
        self.assertEqual(reading.store, "login.keychain-db")
        configured, _ = self.reading(rc=44, stderr="",
                                     keychain_path="/tmp/suite.keychain-db")
        self.assertEqual(configured.store, "/tmp/suite.keychain-db")


class AnEntryWithZeroBytesIsAMissThatSaysSo(KeychainCase):
    """rc 0, an entry, and nothing in it. The tool calls that success.

    An empty value is a hit for the store and a miss for the caller, and the
    difference is the whole reason this case exists: an empty string once
    travelled three layers before anything failed over it.
    """

    def test_an_empty_entry_is_not_present(self):
        reading, _ = self.reading(stderr=keychain_report(empty=True))
        self.assertFalse(reading.present)

    def test_the_note_separates_it_from_an_item_that_is_not_there(self):
        empty, _ = self.reading(stderr=keychain_report(empty=True))
        absent, _ = self.reading(rc=44, stderr="")
        self.assertIn("holds no bytes", empty.note)
        self.assertNotEqual(empty.note, absent.note,
                            "two different findings need two different notes")

    def test_the_empty_secret_is_kept_so_a_report_can_measure_it(self):
        reading, _ = self.reading(stderr=keychain_report(empty=True))
        self.assertIsNotNone(reading.secret)
        self.assertEqual(reading.length, 0)
        self.assertEqual(reading.fingerprint,
                         hashlib.sha256(b"").hexdigest()[:8])


class TheSshRefusalIsNeverReportedAsAMiss(KeychainCase):
    """"User interaction is not allowed" means present and unreachable.

    The login keychain over ssh is the case the whole `NotReadableHere` class
    exists for. A daemon that reads this as absence rotates a secret that was
    never gone, and rotating a live credential is a great deal more expensive
    than failing loudly.
    """

    STDERR = ("security: SecKeychainSearchCopyNext: "
              "User interaction is not allowed.\n")

    def test_the_refusal_raises_not_readable_here(self):
        # The exit status is the low eight bits of errSecInteractionNotAllowed
        # (-25308), which is 36. rc 1 is in the loop because the message is what
        # the branch reads, and a tool that changed its status would still be
        # saying the same thing.
        for rc in (36, 1):
            with self.subTest(rc=rc):
                error = self.raised(errors.NotReadableHere, rc=rc, stderr=self.STDERR)
                self.assertIn("refused to answer", str(error))

    def test_the_hint_says_the_entry_may_well_be_there(self):
        error = self.raised(errors.NotReadableHere, rc=36, stderr=self.STDERR)
        self.assertIn("may well be there", error.hint)

    def test_the_hint_names_the_two_sessions_that_can_read_it(self):
        error = self.raised(errors.NotReadableHere, rc=36, stderr=self.STDERR)
        self.assertIn("logged-in session", error.hint)
        self.assertIn("gui/", error.hint)

    def test_it_is_unavailability_and_not_absence(self):
        error = self.raised(errors.NotReadableHere, rc=36, stderr=self.STDERR)
        self.assertNotIsInstance(error, errors.SecretMissing)
        self.assertEqual(error.exit_code, errors.EX_UNAVAILABLE)
        self.assertNotEqual(error.exit_code, errors.EX_MISSING)


class AnyOtherFailureCarriesWhatTheToolSaid(KeychainCase):
    """A non-zero rc that is neither 44 nor a refusal is a failure, with a reason."""

    def test_a_nonzero_rc_raises_and_names_the_status(self):
        error = self.raised(errors.SecretsError, rc=51, stderr="security: broken\n")
        self.assertIn("51", str(error))

    def test_the_hint_is_the_first_non_empty_line_of_stderr(self):
        # Multi line stderr with a blank first line, because that is what a tool
        # that prints a usage block after its message looks like.
        error = self.raised(errors.SecretsError, rc=2,
                            stderr="\nsecurity: the keychain is locked\nUsage: ...\n")
        self.assertEqual(error.hint, "security: the keychain is locked")

    def test_silence_on_stderr_is_reported_as_silence(self):
        error = self.raised(errors.SecretsError, rc=2, stderr="")
        self.assertEqual(error.hint, "no message on stderr")

    def test_the_error_names_the_reference_and_carries_no_value(self):
        error = self.raised(errors.SecretsError, rc=2, stderr="security: broken\n")
        self.assertEqual(error.ref, self.ref().canonical)
        self.assertIn(self.SERVICE, error.report())
        self.assertNotIsInstance(error, errors.SecretMissing)


class WithoutTheToolTheAnswerIsUnavailableAndNotAbsence(KeychainCase):
    """No `security` on this machine is a machine problem, not a rotation."""

    def test_a_missing_binary_raises_backend_unavailable_before_anything_runs(self):
        with mock.patch("engine.exec.which", return_value=None):
            runner = FakeRunner()
            backend = self.backend(runner)
            with self.assertRaises(errors.BackendUnavailable) as caught:
                backend.read(self.ref())
        self.assertEqual(runner.calls, [])
        self.assertEqual(caught.exception.exit_code, errors.EX_UNAVAILABLE)

    def test_the_hint_says_what_to_use_on_the_other_platforms(self):
        with mock.patch("engine.exec.which", return_value=None):
            backend = self.backend(FakeRunner())
            with self.assertRaises(errors.BackendUnavailable) as caught:
                backend.read(self.ref())
        self.assertIn("macOS", caught.exception.hint)
        self.assertNotIsInstance(caught.exception, errors.SecretMissing)


class ReadableHereAnswersForTheSessionAndNotForTheEntry(KeychainCase):
    """Whether a read can work here is a property of the session as well.

    The same item is readable from a desktop session and refused over ssh, and a
    wrapper that could not tell those apart rotated a secret that was never gone.
    """

    def test_linux_has_no_macos_keychain(self):
        ok, reason = self.backend(platform="linux").readable_here(self.ref())
        self.assertFalse(ok)
        self.assertIn("macOS", reason)

    def test_an_ssh_session_without_a_keychain_file_is_refused(self):
        ok, reason = self.backend(over_ssh=True).readable_here(self.ref())
        self.assertFalse(ok)
        self.assertIn("ssh", reason)

    def test_the_refusal_says_what_to_do_instead(self):
        # A reason that only says no leaves the reader with the same question
        # they arrived with. This one names both ways out.
        _, reason = self.backend(over_ssh=True).readable_here(self.ref())
        self.assertIn("desktop session", reason)
        self.assertIn("launchd", reason)
        self.assertGreater(len(reason), 40)

    def test_a_desktop_session_is_readable_and_says_nothing_further(self):
        ok, reason = self.backend().readable_here(self.ref())
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_an_ssh_session_with_a_keychain_file_is_not_refused(self):
        # The refusal is about the LOGIN keychain, which an ssh session has no
        # unlocked copy of. A file the caller named is a different thing, and a
        # wrong no here would hide a path that works.
        ok, reason = self.backend(keychain_path="/tmp/suite.keychain-db",
                                  over_ssh=True).readable_here(self.ref())
        self.assertTrue(ok)
        self.assertEqual(reason, "")


class LocateNamesThePlaceAndNeverTheValue(KeychainCase):
    """What a human would open, in words they can act on."""

    def test_it_names_the_login_keychain_when_none_is_configured(self):
        where = self.backend().locate(self.ref())
        self.assertIn("login keychain", where)
        self.assertIn(self.SERVICE, where)

    def test_it_names_the_configured_file_instead(self):
        path = "/tmp/suite.keychain-db"
        where = self.backend(keychain_path=path).locate(self.ref())
        self.assertIn(path, where)
        self.assertNotIn("login keychain", where)

    def test_it_names_the_account_only_when_the_reference_has_one(self):
        with_account = self.backend().locate(self.ref())
        self.assertIn(self.ACCOUNT, with_account)
        without = self.backend().locate(self.ref("keychain://%s" % self.SERVICE))
        self.assertNotIn("account", without)

    def test_it_carries_no_value_even_after_one_was_read(self):
        token = synthetic_token("locate")
        runner = self.answering(stderr=keychain_report(value=token))
        backend = self.backend(runner)
        backend.read(self.ref())
        self.assertNotIn(token, backend.locate(self.ref()))


# ---------------------------------------------------------------------------
# The macOS tier
# ---------------------------------------------------------------------------

def feed_security_on_stdin(command_line: str):
    """Hand one command line to `security -i`, with the value out of argv.

    `unguarded_security()` is the single door through the machine guard and it
    inherits this process's stdin, so the command line is handed over by
    pointing fd 0 at a pipe for the duration of the call. A pipe rather than a
    temporary file, so the value never touches a disk either.

    This is the same reason the skill's own write path is `security -i`:
    `add-generic-password -w` takes the value as an argument, and an argument is
    readable through `ps` by every process of this user.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, command_line.encode("utf-8"))
        os.close(write_fd)
        saved_stdin = os.dup(0)
        try:
            os.dup2(read_fd, 0)
            return unguarded_security("-i")
        finally:
            os.dup2(saved_stdin, 0)
            os.close(saved_stdin)
    finally:
        os.close(read_fd)


class TheRealKeychainTierReadsBackWhatItStored(MachineGuard):
    """One case against the real tool, in a keychain this case made itself.

    Everything above is a recording of `security`. A recording nobody
    re-measures is a guess that has been written down, so exactly one case runs
    the tool for real: it stores a synthetic value through stdin, reads it back
    through the backend's own argv, and compares the bytes. It skips wherever
    the tool is not, and the meta case below is what keeps that skip from
    hiding an argv tier that has stopped running.
    """

    @requires_real_keychain
    def test_a_value_stored_through_stdin_comes_back_byte_exact(self):
        service = "bridge-secrets-suite"
        account = "tier-account"
        value = synthetic_token("tier")
        seen_argv = []

        def real_runner(argv, *, invocation=None):
            """Runs the argv the BACKEND built, through the one guarded door."""
            argv = tuple(str(a) for a in argv)
            seen_argv.append(argv)
            if argv[0] != "security":
                raise AssertionError("the backend built argv for %r" % (argv[0],))
            return unguarded_security(*argv[1:], check=False)

        with temporary_keychain() as path:
            feed_security_on_stdin(
                "add-generic-password -s %s -a %s -w %s %s\n"
                % (service, account, value, path)
            )
            backend = keychain.KeychainBackend(
                keychain_path=path,
                runner=real_runner,
                context=base.Context(platform="darwin", interactive=True,
                                     over_ssh=False, display=True),
            )
            reading = backend.read(refs.parse("keychain://%s/%s" % (service, account)))

        self.assertTrue(reading.present, reading.note)
        self.assertEqual(reading.secret.expose(), value.encode("utf-8"),
                         "the parser is a recording of this tool, and this is the tool")
        self.assertEqual(
            reading.fingerprint,
            hashlib.sha256(value.encode("utf-8")).hexdigest()[:8],
            "the fingerprint two machines compare has to be a plain sha256 prefix")
        self.assertEqual(reading.store, path)
        # The read path stayed out of argv on the real tool too, not only in the
        # fake one. Everything here is visible in ps while the call runs.
        self.assertTrue(seen_argv, "the backend never called its runner")
        for argv in seen_argv:
            self.assertNotIn(value, " ".join(argv))


# ---------------------------------------------------------------------------
# The meta case over the two tiers
# ---------------------------------------------------------------------------

class TheArgvTierRunsWhereverTheSuiteRuns(MachineGuard):
    """A skipped tier is honest. A suite that is ALL skip says nothing.

    The macOS tier above skips on Linux, and the tally prints skips separately
    so a run cannot score green on them. That leaves one hole: if the argv tier
    ever shrank, a green run on Linux would report a keychain backend as covered
    while running almost nothing against it. This counts the cases that carry no
    skip at all.
    """

    MINIMUM = 25

    def _argv_tier_classes(self):
        module = sys.modules[__name__]
        return [obj for obj in vars(module).values()
                if isinstance(obj, type)
                and issubclass(obj, KeychainCase)
                and obj is not KeychainCase]

    def test_the_argv_tier_is_more_than_a_handful_of_cases(self):
        loader = unittest.defaultTestLoader
        total = sum(len(loader.getTestCaseNames(cls))
                    for cls in self._argv_tier_classes())
        self.assertGreaterEqual(
            total, self.MINIMUM,
            "the tier that runs everywhere has shrunk to %d cases" % total)

    def test_no_case_in_the_argv_tier_carries_a_skip(self):
        loader = unittest.defaultTestLoader
        skipped = []
        for cls in self._argv_tier_classes():
            if getattr(cls, "__unittest_skip__", False):
                skipped.append(cls.__name__)
                continue
            for name in loader.getTestCaseNames(cls):
                if getattr(getattr(cls, name), "__unittest_skip__", False):
                    skipped.append("%s.%s" % (cls.__name__, name))
        self.assertEqual(skipped, [],
                         "these would leave the argv tier smaller than it looks")
