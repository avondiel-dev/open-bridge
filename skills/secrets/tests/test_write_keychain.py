"""The keychain WRITE path: what stands on stdin, and what never stands in argv.

Reading a keychain item is measured in `test_keychain.py`. This file measures
the other direction, and the other direction is where the disclosure lives.

`security add-generic-password -w` takes the value as an ARGUMENT. Measured on
2026-09-04: a piped value is discarded in silence and the flag that follows is
stored instead, so the obvious implementation is wrong twice over. It stores the
wrong thing, and while it runs, the right thing is readable in `ps` by every
process of this user. That is how tokens ended up in the process list of two
machines in this fleet. The backend therefore feeds a whole command line to
`security -i` on stdin, and the cases below are what hold it there.

Three tiers, named rather than mixed.

The ARGV TIER drives `KeychainBackend` through `FakeRunner` and runs everywhere.
It pins the stdin line character for character, pins the process argv to
`security -i` and nothing else, and asserts for a plain value, a value with a
quote, a value with a backslash and a value with a newline that the value was
never in an argv.

The QUOTING TIER is the same seam pointed at the two characters the tool cares
about. A quote and a backslash each take exactly ONE backslash. Two would
lengthen the value, none would shorten it, and both failures look like a wrong
password at the far end rather than like a quoting fault here.

The MACOS TIER is one case. It makes its own throwaway keychain, writes four
values through the backend's real command line, reads each one back and compares
bytes and fingerprint. Three of the four carry a quote, a backslash and a
newline, because those are the three the quoting rules decide; everything above
is a recording of this tool, and a recording nobody re-measures is a guess that
has been written down.

The seam note from `test_keychain.py` applies here unchanged: `Backend.available()`
probes the filesystem with `shutil.which`, which is the one call in the write
path that does NOT go through `runner=`, so it is answered in `setUp`. Nothing is
executed either way, because `MachineGuard` refuses to exec `security` in every
tier but the last.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import unittest
from unittest import mock

from tests.conftest import (
    FakeRunner,
    MachineGuard,
    completed,
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
values = mod("engine.values")

#: What `security -i` writes to stderr when the item is already there, measured
#: on macOS 26 on 2026-09-20 in a throwaway keychain. The exit code is 45. The
#: path is a neutral one: the real line names the keychain file, and the shape
#: that matters to the backend is the phrase, not the location.
ALREADY_THERE = (
    "security: SecKeychainItemCreateFromContent (/home/opuser/suite.keychain-db): "
    "The specified item already exists in the keychain.\n"
    "add-generic-password: the item already exists\n"
)


def measured_report(raw: bytes) -> str:
    """The stderr `security -g` leaves for this value, in the form it really uses.

    The rule is the one recorded in `tests/conftest.py`: the quoted form when
    every byte is printable ASCII and none is a backslash, the hex form
    otherwise. It is spelled out here rather than guessed per case, so a write
    case cannot hand its readback a shape the tool would never print.
    """
    quoted = all(0x20 <= byte < 0x7F for byte in raw) and 0x5C not in raw
    if quoted:
        return keychain_report(value=raw.decode("ascii"))
    return keychain_report(hex_value=raw)


class WriteCase(MachineGuard):
    """The argv tier: a backend wired to a fake process, never to a store."""

    SERVICE = "bridge-suite"
    ACCOUNT = "suite-account"

    def setUp(self):
        super().setUp()
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

    def line_for(self, value, *, replace=False, keychain_path=None, uri=None):
        """The stdin command line alone, without running a write."""
        backend = self.backend(keychain_path=keychain_path)
        return backend.write_line(self.ref(uri), values.Secret(value), replace=replace)

    def writing(self, value, *, replace=False, keychain_path=None, uri=None,
                write_rc=0, write_stderr="", readback=None):
        """One write through the whole backend, plus the runner that saw it.

        Two routes, in the order the backend calls them: the write goes to
        `security -i`, the readback to `find-generic-password`. The readback
        answers with the shape the tool would really print for this value unless
        a case says otherwise.
        """
        secret = values.Secret(value)
        runner = FakeRunner()
        runner.add("security -i", completed(rc=write_rc, stderr=write_stderr))
        runner.add("find-generic-password", completed(
            stderr=measured_report(secret.expose()) if readback is None else readback))
        backend = self.backend(runner, keychain_path=keychain_path)
        reading = backend.write(self.ref(uri), secret, replace=replace)
        return reading, runner

    def stdin_line(self, runner) -> str:
        """The command line the backend handed to `security -i`, as text."""
        raw = runner.calls[0]["stdin_bytes"]
        self.assertIsNotNone(raw, "the write sent nothing on stdin")
        return raw.decode("utf-8")

    def refused_by(self, **kwargs):
        """The exception one write raised, for a case that asserts on its parts."""
        with self.assertRaises(errors.SecretsError) as caught:
            self.writing(**kwargs)
        return caught.exception


class TheStdinLineIsTheMeasuredCommandLine(WriteCase):
    """`add-generic-password -s "<s>" -a "<a>" -w "<v>" -A`, and argv is two words.

    Pinned as one string rather than by substring. A line that grew a flag, or
    lost the one that decides whether an unattended read can reach the item,
    still contains every substring a looser case looks for.
    """

    def test_a_plain_value_produces_exactly_the_measured_line(self):
        token = synthetic_token("kc-line")
        self.assertEqual(
            self.line_for(token),
            'add-generic-password -s "%s" -a "%s" -w "%s" -A'
            % (self.SERVICE, self.ACCOUNT, token))

    def test_the_process_argv_is_security_dash_i_and_nothing_else(self):
        # Every word of an argv is visible in `ps` to every process of this
        # user. Two words is the whole budget: the binary and the flag that
        # tells it to read its command lines from stdin.
        _, runner = self.writing(synthetic_token("kc-argv"))
        self.assertEqual(runner.calls[0]["argv"], ("security", "-i"))

    def test_the_line_the_backend_builds_is_the_line_it_sends(self):
        # write_line() is worth nothing as a promise if write() assembles a
        # second one on its way to the process.
        token = synthetic_token("kc-same")
        expected = self.line_for(token)
        _, runner = self.writing(token)
        self.assertEqual(self.stdin_line(runner), expected + "\n")

    def test_the_line_ends_with_a_newline_because_the_tool_reads_lines(self):
        # `security -i` reads whole command lines. Without the terminator the
        # last line is never executed and the call exits 0 having done nothing.
        _, runner = self.writing(synthetic_token("kc-eol"))
        self.assertTrue(self.stdin_line(runner).endswith("\n"))

    def test_the_service_and_the_account_are_both_quoted(self):
        line = self.line_for(synthetic_token("kc-quoted"))
        self.assertIn('-s "%s"' % self.SERVICE, line)
        self.assertIn('-a "%s"' % self.ACCOUNT, line)

    def test_a_reference_without_an_account_still_names_one(self):
        # `add-generic-password` accepts an item with no account, and an item
        # with no account cannot be addressed again except by service. The
        # backend names one rather than leaving that hole.
        line = self.line_for(synthetic_token("kc-noacct"),
                             uri="keychain://%s" % self.SERVICE)
        self.assertIn('-a "default"', line)


class NoValueEverTravelsInArgvOnTheWritePath(WriteCase):
    """The one assertion this skill exists for, on all four shapes of value."""

    def test_a_plain_value_is_never_in_argv(self):
        token = synthetic_token("kc-plain")
        _, runner = self.writing(token)
        self.assertFalse(runner.argv_carried(token),
                         "the value stood in a command line: " + runner.joined_calls)
        self.assertIn(token, self.stdin_line(runner))

    def test_a_value_holding_a_double_quote_is_never_in_argv(self):
        value = synthetic_token("kc-dq") + '"tail'
        _, runner = self.writing(value)
        self.assertFalse(runner.argv_carried(value))
        # Nor the half of it that survives the quoting, which is what a case
        # matching only the whole value would miss.
        self.assertFalse(runner.argv_carried(synthetic_token("kc-dq")))

    def test_a_value_holding_a_backslash_is_never_in_argv(self):
        value = synthetic_token("kc-bs") + "\\tail"
        _, runner = self.writing(value)
        self.assertFalse(runner.argv_carried(value))
        self.assertFalse(runner.argv_carried(synthetic_token("kc-bs")))

    def test_a_value_holding_a_newline_is_never_in_argv_in_either_spelling(self):
        # This one goes as hex, so there are two spellings that would disclose
        # it and both are checked.
        value = synthetic_token("kc-nl") + "\ntail"
        _, runner = self.writing(value)
        self.assertFalse(runner.argv_carried(value))
        self.assertFalse(runner.argv_carried(value.encode("utf-8").hex()))
        self.assertFalse(runner.argv_carried(value.encode("utf-8").hex().upper()))

    def test_the_readback_carries_no_value_in_argv_either(self):
        # The write is only half the call sequence. The read that proves it runs
        # with the same visibility.
        token = synthetic_token("kc-readback")
        _, runner = self.writing(token)
        self.assertEqual(len(runner.calls), 2)
        self.assertFalse(runner.argv_carried(token))

    def test_the_value_is_not_handed_over_in_the_environment_either(self):
        # stdin is the channel. An environment block is readable through
        # /proc on Linux and survives into every child of the process.
        token = synthetic_token("kc-env")
        _, runner = self.writing(token)
        for call in runner.calls:
            self.assertIsNone(call["env"])


class TheQuotingIsExactlyOneBackslashPerCharacter(WriteCase):
    """Two characters decide the length of what arrives, so both are pinned.

    Measured on 2026-09-04: a double quote or a backslash that is not escaped
    makes the value arrive short by two characters or the command fail with rc
    2. An escape too many makes it arrive long. Both failures show up at the far
    end as a rejected credential, which reads like a rotation nobody finished
    rather than like a quoting rule that is off by one.
    """

    def payload(self, value) -> str:
        """The bit between the quotes after `-w`."""
        line = self.line_for(value)
        head, marker, rest = line.partition(' -w "')
        self.assertTrue(marker, "this value did not take the quoted form: " + line)
        return rest[:rest.rindex('" -A')]

    def test_a_double_quote_gets_one_backslash_and_not_two(self):
        self.assertEqual(self.payload('a"b'), 'a\\"b')

    def test_a_backslash_gets_one_backslash_and_not_three(self):
        self.assertEqual(self.payload("a\\b"), "a\\\\b")

    def test_a_backslash_in_front_of_a_quote_keeps_both_escapes_apart(self):
        # The order of the two replacements is what decides this. Escaping the
        # quote first and the backslash second would escape the backslash that
        # the first replacement had just added.
        self.assertEqual(self.payload('a\\"b'), 'a\\\\\\"b')

    def test_a_value_with_neither_character_is_passed_through_untouched(self):
        token = synthetic_token("kc-clean")
        self.assertEqual(self.payload(token), token)

    def test_the_escaped_value_still_names_every_byte_of_the_original(self):
        # Escaping adds characters and must remove none. Undoing it here is the
        # cheapest independent statement of that.
        value = 'a"b\\c'
        undone = self.payload(value).replace('\\"', '"').replace("\\\\", "\\")
        self.assertEqual(undone, value)

    def test_a_single_quote_is_not_escaped_because_the_tool_does_not_need_it(self):
        # An escape the tool does not ask for is two extra bytes in the value.
        self.assertEqual(self.payload("a'b"), "a'b")


class AControlCharacterGoesAsHexAndStaysOutOfArgv(WriteCase):
    """The quoted form cannot carry a newline, so those values take `-X <hex>`.

    A PEM key and a multi-line service account JSON are both this case, and both
    are values somebody will eventually hand to `secrets store`.
    """

    def test_a_newline_value_uses_the_x_flag_and_not_the_w_flag(self):
        line = self.line_for("line1\nline2")
        self.assertIn(" -X ", line)
        self.assertNotIn(" -w ", line)

    def test_the_hex_on_the_line_decodes_back_to_the_value(self):
        value = "line1\nline2"
        line = self.line_for(value)
        digits = line.split(" -X ")[1].split(" ")[0]
        self.assertEqual(bytes.fromhex(digits), value.encode("utf-8"))

    def test_the_hex_line_carries_no_readable_spelling_of_the_value(self):
        line = self.line_for("line1\nline2")
        self.assertNotIn("line1", line)
        self.assertNotIn("line2", line)

    def test_a_tab_is_a_control_character_too(self):
        self.assertIn(" -X ", self.line_for("a\tb"))

    def test_a_value_that_is_not_utf8_at_all_goes_as_hex(self):
        # A raw key file is bytes, not text, and encoding it as text would
        # either fail or change it.
        raw = b"\xff\xfe" + synthetic_token("kc-bin").encode("ascii")
        line = self.line_for(raw)
        self.assertIn(" -X ", line)
        digits = line.split(" -X ")[1].split(" ")[0]
        self.assertEqual(bytes.fromhex(digits), raw)

    def test_a_printable_value_does_not_take_the_hex_path(self):
        # The other direction, so the case above cannot pass by sending
        # everything as hex.
        line = self.line_for(synthetic_token("kc-printable"))
        self.assertIn(" -w ", line)
        self.assertNotIn(" -X ", line)

    def test_the_hex_write_still_reads_back_as_the_value_that_went_in(self):
        value = "line1\nline2"
        reading, _ = self.writing(value)
        self.assertTrue(reading.present, reading.note)
        self.assertEqual(reading.secret.expose(), value.encode("utf-8"))


class TheAccessorFlagIsOnEveryWrite(WriteCase):
    """`-A`, always, and never `-T`.

    The reason belongs in this file rather than in a commit message. `-T <app>`
    adds one application to the item's trust list, and the accessor of an
    unattended read is not the application: it is the `security` binary itself.
    So a trust list built for the caller does not cover the read, and in a
    launchd context the read does not fail either. It blocks on a dialog nobody
    can answer, for ten seconds, and then falls back to nothing. A daemon that
    starts at boot reports a missing secret, which is the one answer that sends
    somebody to rotate a credential that was never gone.
    """

    def test_a_plain_write_carries_the_accessor_flag(self):
        self.assertIn(" -A", self.line_for(synthetic_token("kc-a")))

    def test_a_hex_write_carries_it_too(self):
        self.assertIn(" -A", self.line_for("a\nb"))

    def test_a_replace_write_carries_it_too(self):
        self.assertIn(" -A", self.line_for(synthetic_token("kc-a2"), replace=True))

    def test_the_application_trust_flag_is_not_used(self):
        line = self.line_for(synthetic_token("kc-t"))
        self.assertNotIn(" -T ", line)

    def test_the_flag_stands_after_the_value_and_not_inside_it(self):
        # `-A` before `-w` would make the flag the stored value, which exits 0.
        line = self.line_for(synthetic_token("kc-order"))
        self.assertLess(line.index(" -w "), line.index(" -A"))


class ReplaceIsTheOnlyWayToOverwriteAnItem(WriteCase):
    """`-U` on request, and a refusal that names the flag when it is missing."""

    def test_replace_adds_the_upsert_flag(self):
        self.assertIn(" -U", self.line_for(synthetic_token("kc-u"), replace=True))

    def test_without_replace_the_flag_is_absent(self):
        # Present by default it would overwrite a live credential on a typo, and
        # the old value is not recoverable from anywhere.
        self.assertNotIn(" -U", self.line_for(synthetic_token("kc-nou")))

    def test_an_item_that_is_already_there_is_refused_and_not_reported_as_an_error(self):
        problem = self.refused_by(value=synthetic_token("kc-dup"), write_rc=45,
                                  write_stderr=ALREADY_THERE)
        self.assertIsInstance(problem, errors.Refused)

    def test_the_hint_names_the_flag_that_would_have_worked(self):
        problem = self.refused_by(value=synthetic_token("kc-dup2"), write_rc=45,
                                  write_stderr=ALREADY_THERE)
        self.assertIn("--replace", problem.hint)

    def test_the_refusal_carries_the_reference_and_no_value(self):
        token = synthetic_token("kc-dup3")
        problem = self.refused_by(value=token, write_rc=45, write_stderr=ALREADY_THERE)
        self.assertIn(self.SERVICE, problem.ref)
        self.assertNotIn(token, problem.report())

    def test_a_refusal_is_not_a_missing_entry(self):
        # The two exit codes are the whole point of `errors.py`: a wrapper has to
        # tell "would be unsafe" from "the entry is gone" without reading prose.
        problem = self.refused_by(value=synthetic_token("kc-dup4"), write_rc=45,
                                  write_stderr=ALREADY_THERE)
        self.assertEqual(problem.exit_code, errors.EX_REFUSED)

    def test_nothing_is_read_back_after_a_write_that_failed(self):
        # A readback here would report the value that is ALREADY in the item and
        # the caller would believe its own write landed.
        runner = FakeRunner()
        runner.add("security -i", completed(rc=45, stderr=ALREADY_THERE))
        runner.add("find-generic-password",
                   completed(stderr=keychain_report(value="somebody-elses-value")))
        backend = self.backend(runner)
        with self.assertRaises(errors.Refused):
            backend.write(self.ref(), values.Secret(synthetic_token("kc-dup5")))
        self.assertEqual(len(runner.calls), 1, runner.joined_calls)

    def test_any_other_failure_keeps_what_the_tool_said_and_drops_the_hint(self):
        problem = self.refused_by(value=synthetic_token("kc-other"), write_rc=1,
                                  write_stderr="security: the keychain is locked\n")
        self.assertNotIsInstance(problem, errors.Refused)
        self.assertIn("the keychain is locked", problem.hint)
        self.assertIn("1", str(problem))


class TheKeychainFileIsTheLastArgumentOfTheLine(WriteCase):
    """`security` takes the keychain as a trailing operand, not as a flag.

    Anywhere but last it is read as the value of the flag before it, and the
    item lands in the login keychain while every message says otherwise.
    """

    PATH = "/home/opuser/suite.keychain-db"

    def test_a_configured_file_stands_last(self):
        line = self.line_for(synthetic_token("kc-path"), keychain_path=self.PATH)
        self.assertTrue(line.endswith('"%s"' % self.PATH), line)

    def test_it_stands_after_the_accessor_flag(self):
        line = self.line_for(synthetic_token("kc-path2"), keychain_path=self.PATH)
        self.assertLess(line.index(" -A"), line.index(self.PATH))

    def test_it_stands_after_the_replace_flag_too(self):
        line = self.line_for(synthetic_token("kc-path3"), keychain_path=self.PATH,
                             replace=True)
        self.assertLess(line.index(" -U"), line.index(self.PATH))
        self.assertTrue(line.endswith('"%s"' % self.PATH), line)

    def test_a_hex_write_puts_it_last_as_well(self):
        line = self.line_for("a\nb", keychain_path=self.PATH)
        self.assertTrue(line.endswith('"%s"' % self.PATH), line)

    def test_without_one_the_line_ends_with_the_accessor_flag(self):
        # A trailing operand here would address a keychain nobody named.
        line = self.line_for(synthetic_token("kc-nopath"))
        self.assertTrue(line.endswith(" -A"), line)

    def test_the_readback_addresses_the_same_file(self):
        _, runner = self.writing(synthetic_token("kc-path4"), keychain_path=self.PATH)
        self.assertEqual(runner.calls[1]["argv"][-1], self.PATH)


class TheWriteIsProvedByAValueAndNotByAnExitCode(WriteCase):
    """Every tool in this chain exits 0 for an item that holds nothing.

    So the write is followed by a read of the same entry, and what comes back is
    what the caller is handed. An exit code says the command was understood; it
    says nothing about what is now in the store.
    """

    def test_a_second_call_reads_the_entry_back(self):
        _, runner = self.writing(synthetic_token("kc-proof"))
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("find-generic-password", runner.calls[1]["joined"])

    def test_the_readback_uses_the_read_argv_of_this_backend(self):
        _, runner = self.writing(synthetic_token("kc-proof2"))
        expected = self.backend().argv_read(self.ref())
        self.assertEqual(runner.calls[1]["argv"], tuple(expected))

    def test_the_fingerprint_that_comes_back_is_the_fingerprint_that_went_in(self):
        token = synthetic_token("kc-fp")
        reading, _ = self.writing(token)
        self.assertTrue(reading.present, reading.note)
        self.assertEqual(reading.fingerprint, values.fingerprint(token))

    def test_an_entry_that_exits_zero_and_holds_nothing_is_not_present(self):
        # The failure that travelled three layers before this skill existed.
        reading, _ = self.writing(synthetic_token("kc-empty"),
                                  readback=keychain_report(empty=True))
        self.assertFalse(reading.present)
        self.assertIn("no bytes", reading.note)

    def test_a_value_that_came_back_different_is_visible_to_the_caller(self):
        # The backend hands the reading up rather than comparing; the comparison
        # belongs to `resolve.store`. What matters here is that the reading
        # carries the value the STORE has, not the value the caller sent.
        sent = synthetic_token("kc-sent")
        other = synthetic_token("kc-other-value")
        reading, _ = self.writing(sent, readback=keychain_report(value=other))
        self.assertEqual(reading.secret.expose(), other.encode("utf-8"))
        self.assertNotEqual(reading.fingerprint, values.fingerprint(sent))

    def test_the_reading_names_the_store_it_came_from(self):
        reading, _ = self.writing(synthetic_token("kc-store"))
        self.assertEqual(reading.store, "login.keychain-db")


class DeleteBuildsTheArgvAndSaysWhatHappened(WriteCase):
    """Used by the replace path, and never on its own without a user saying so."""

    def deleting(self, *, rc=0, uri=None, keychain_path=None):
        runner = FakeRunner()
        runner.add("delete-generic-password", completed(rc=rc))
        backend = self.backend(runner, keychain_path=keychain_path)
        return backend.delete(self.ref(uri)), runner

    def test_the_argv_names_the_service_and_the_account(self):
        _, runner = self.deleting()
        self.assertEqual(runner.calls[0]["argv"],
                         ("security", "delete-generic-password",
                          "-s", self.SERVICE, "-a", self.ACCOUNT))

    def test_a_reference_without_an_account_omits_the_flag_entirely(self):
        # `-a` with nothing after it reads the next word as the account, so an
        # empty one deletes by a name nobody typed.
        _, runner = self.deleting(uri="keychain://%s" % self.SERVICE)
        self.assertEqual(runner.calls[0]["argv"],
                         ("security", "delete-generic-password", "-s", self.SERVICE))

    def test_a_configured_keychain_file_is_the_last_argument(self):
        path = "/home/opuser/suite.keychain-db"
        _, runner = self.deleting(keychain_path=path)
        self.assertEqual(runner.calls[0]["argv"][-1], path)

    def test_a_zero_exit_reports_that_something_was_removed(self):
        removed, _ = self.deleting(rc=0)
        self.assertIs(removed, True)

    def test_a_missing_item_reports_false_rather_than_raising(self):
        # rc 44 is "no such item". Deleting something that is already gone is
        # not a failure worth an exception, and the caller still has to know.
        removed, _ = self.deleting(rc=keychain.RC_ITEM_NOT_FOUND)
        self.assertIs(removed, False)

    def test_nothing_travels_on_stdin_for_a_delete(self):
        # A delete has no value, so anything on stdin here would be a leftover.
        _, runner = self.deleting()
        self.assertIsNone(runner.calls[0]["stdin_bytes"])

    def test_the_delete_is_one_call_and_reads_nothing_back(self):
        _, runner = self.deleting()
        self.assertEqual(len(runner.calls), 1, runner.joined_calls)


class AWriteWithoutTheToolIsUnavailableAndNotAFailedWrite(WriteCase):
    """The probe answers before a command line is built, let alone sent."""

    def test_a_missing_binary_raises_before_anything_is_handed_over(self):
        runner = FakeRunner()
        with mock.patch("engine.exec.which", return_value=None):
            backend = self.backend(runner)
            with self.assertRaises(errors.BackendUnavailable):
                backend.write(self.ref(), values.Secret(synthetic_token("kc-gone")))
        self.assertEqual(runner.calls, [], "a value was handed to a tool that is not here")

    def test_the_hint_says_what_to_use_on_the_other_platforms(self):
        with mock.patch("engine.exec.which", return_value=None):
            backend = self.backend(FakeRunner())
            with self.assertRaises(errors.BackendUnavailable) as caught:
                backend.write(self.ref(), values.Secret(synthetic_token("kc-gone2")))
        self.assertIn("Linux", caught.exception.hint)

    def test_assume_available_is_what_lets_this_tier_run_on_a_linux_runner(self):
        # Said out loud because it is the seam the whole file depends on: the
        # PATH probe is the one call the runner does not cover.
        backend = keychain.KeychainBackend(runner=FakeRunner(), assume_available=True,
                                           context=self.context())
        self.assertTrue(backend.available())


# ---------------------------------------------------------------------------
# The macOS tier
# ---------------------------------------------------------------------------

def security_with_stdin(args, stdin_bytes: bytes):
    """Run `security` with `stdin_bytes` on fd 0, through the one guarded door.

    `unguarded_security()` inherits this process's stdin, so the command line is
    handed over by pointing fd 0 at a pipe for the duration of the call. A pipe
    rather than a temporary file, so the value never touches a disk on the way.

    This is the same reason the backend writes through `security -i` at all: an
    argument is readable through `ps` by every process of this user, and stdin
    is not.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, stdin_bytes)
        os.close(write_fd)
        saved_stdin = os.dup(0)
        try:
            os.dup2(read_fd, 0)
            return unguarded_security(*args, check=False)
        finally:
            os.dup2(saved_stdin, 0)
            os.close(saved_stdin)
    finally:
        os.close(read_fd)


class TheRealKeychainTierStoresAndReadsBackWhatItWrote(MachineGuard):
    """One case against the real tool, in a keychain this case made itself.

    Four values, in one throwaway keychain that is deleted in a `finally`. One
    is a plain token; the other three carry a double quote, a backslash and a
    newline, which are exactly the three characters the quoting rules above
    decide. Everything in this file up to here is a recording of `security`, and
    a recording nobody re-measures is a guess that has been written down.
    """

    @requires_real_keychain
    def test_four_values_survive_the_write_and_the_read_byte_for_byte(self):
        stem = synthetic_token("tier-write")
        cases = {
            "plain": stem,
            "quote": stem + '"tail',
            "backslash": stem + "\\tail",
            "newline": stem + "\ntail",
        }
        seen_argv = []

        def real_runner(argv, *, invocation=None):
            """Runs the argv the BACKEND built, through the one guarded door."""
            argv = tuple(str(a) for a in argv)
            seen_argv.append(argv)
            if argv[0] != "security":
                raise AssertionError("the backend built argv for %r" % (argv[0],))
            stdin_bytes = getattr(invocation, "stdin_bytes", None)
            if stdin_bytes is None:
                return unguarded_security(*argv[1:], check=False)
            return security_with_stdin(argv[1:], stdin_bytes)

        service = "bridge-secrets-write-suite"
        with temporary_keychain() as path:
            backend = keychain.KeychainBackend(
                keychain_path=path,
                runner=real_runner,
                context=base.Context(platform="darwin", interactive=True,
                                     over_ssh=False, display=True),
            )
            for account, value in cases.items():
                with self.subTest(shape=account):
                    ref = refs.parse("keychain://%s/%s" % (service, account))
                    reading = backend.write(ref, values.Secret(value))
                    self.assertTrue(reading.present, reading.note)
                    self.assertEqual(
                        reading.secret.expose(), value.encode("utf-8"),
                        "the quoting rules are a recording of this tool, and this "
                        "is the tool")
                    self.assertEqual(
                        reading.fingerprint,
                        hashlib.sha256(value.encode("utf-8")).hexdigest()[:8],
                        "the fingerprint two machines compare has to be a plain "
                        "sha256 prefix")

        self.assertEqual(len(seen_argv), 2 * len(cases),
                         "one write and one readback per value: %r" % (seen_argv,))
        # And none of it stood in a command line on the real tool either.
        # Everything here is visible in `ps` while the call runs.
        for argv in seen_argv:
            joined = " ".join(argv)
            for value in cases.values():
                self.assertNotIn(value, joined)
                self.assertNotIn(value.encode("utf-8").hex(), joined)


# ---------------------------------------------------------------------------
# The meta case over the two tiers
# ---------------------------------------------------------------------------

class TheWriteTierRunsWhereverTheSuiteRuns(MachineGuard):
    """A skipped tier is honest. A suite that is ALL skip says nothing.

    The macOS tier above skips on Linux. If the argv tier ever shrank, a green
    run on Linux would report the write path as covered while running almost
    nothing against it, and the write path is the one that can disclose a value.
    """

    MINIMUM = 40

    def _argv_tier_classes(self):
        module = sys.modules[__name__]
        return [obj for obj in vars(module).values()
                if isinstance(obj, type)
                and issubclass(obj, WriteCase)
                and obj is not WriteCase]

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

    def test_the_guard_is_what_keeps_this_file_off_the_login_keychain(self):
        # The guard never fires in a green run, so nothing else here would
        # notice if it stopped refusing. The write path is the reason that
        # matters: an unguarded run would ADD items to a real keychain.
        with self.assertRaises(AssertionError):
            subprocess.run(["security", "add-generic-password", "-s", "probe"],
                           capture_output=True)
