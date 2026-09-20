"""`file://`: the backend where a careless reader finds the value by following
the locator.

There is no tool behind this scheme and therefore no `runner=` seam. Every case
here works on a real file in a throwaway directory, which is why the shapes it
measures are the ones a filesystem actually produces rather than a fixture
somebody wrote down: the mode `os.open` leaves under a given umask, the bytes a
read hands back when an editor added a newline, the directory an `os.makedirs`
really creates.

Four things decide whether this backend is safe, and each one has a class below.

* THE MODE IS SET AT CREATION. A `chmod` that follows the write leaves a window
  in which the file stands there under the default umask with the secret already
  in it. The proof is not "it is 0600 afterwards", because the chmod would make
  that true as well. It is a write under a permissive umask with the chmod
  neutralised, which can only come out at 0600 if the open set it.
* A FILE ANOTHER ACCOUNT CAN READ IS REFUSED, on read and not only on write. Its
  content has to be treated as disclosed, and reporting it while handing the
  value over anyway would let a wrapper carry on using a credential that is
  already public on that machine.
* A WRITE GOES INSIDE A DECLARED STORE. Without that rule this backend is "write
  the token wherever", which is the habit the whole skill exists to end: small
  text files with credentials in working folders on two machines.
* A LINE ENDING IS NOT PART OF THE VALUE, and nothing else is stripped. A token
  that carries a trailing newline fails at the far end in a way that reads like
  a wrong token, and a token that lost a trailing space fails the same way.

Three cases in this file are RED on purpose and named in the report that came
with it. Each one measures the behaviour the module's own docstrings promise,
against code that does something else.
"""

from __future__ import annotations

import os
import stat
import unittest
from unittest import mock

from tests.conftest import MachineGuard, mod, synthetic_token

file_backend = mod("engine.backends.file")
base = mod("engine.backends.base")
errors = mod("engine.errors")
refs = mod("engine.refs")
values = mod("engine.values")


class FileCase(MachineGuard):
    """A throwaway store root, a deterministic umask, and no process anywhere."""

    def setUp(self):
        super().setUp()
        # The umask is part of every measurement in this file, so it is stated
        # rather than inherited. A runner with 0o077 would make a widened file
        # look narrow and a case that pins 0600 would pass for the wrong reason.
        self._saved_umask = os.umask(0o022)
        self.addCleanup(os.umask, self._saved_umask)
        # realpath: on macOS a temporary directory is reached through /var,
        # which is a symlink to /private/var, and the backend resolves symlinks
        # on purpose (a link inside a declared store used to carry the value out
        # of it). Comparing against the unresolved path would fail here and pass
        # on Linux, which is the worst kind of case.
        self.root = os.path.realpath(self.tmpdir())

    # -- builders -----------------------------------------------------------

    def backend(self, roots=None, **context_overrides):
        fields = {"platform": "linux", "interactive": True,
                  "over_ssh": False, "display": False}
        fields.update(context_overrides)
        return file_backend.FileBackend(
            allowed_roots=[str(self.root)] if roots is None else roots,
            context=base.Context(**fields),
        )

    def ref(self, path):
        return refs.parse("file://" + str(path))

    def inside(self, name: str = "token") -> str:
        return os.path.join(str(self.root), name)

    def put(self, path, raw, mode=0o600) -> str:
        """A file that is already there, at a stated mode."""
        path = str(path)
        folder = os.path.dirname(path)
        if folder and not os.path.isdir(folder):
            os.makedirs(folder, mode=0o700, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
        os.chmod(path, mode)
        return path

    def mode_of(self, path) -> int:
        return stat.S_IMODE(os.stat(str(path)).st_mode)

    def read_of(self, path, roots=None):
        return self.backend(roots).read(self.ref(path))

    def write_of(self, path, value, *, roots=None, replace=False):
        return self.backend(roots).write(self.ref(path), values.Secret(value),
                                         replace=replace)

    def refused_by(self, call):
        with self.assertRaises(errors.SecretsError) as caught:
            call()
        return caught.exception


class TheModeIsSetWhenTheFileIsCreatedAndNotAfterwards(FileCase):
    """0600 from the first byte, not 0600 by the time anyone looks."""

    def test_a_fresh_file_stands_at_0600_right_after_the_write(self):
        path = self.inside()
        self.write_of(path, synthetic_token("fb-mode"))
        self.assertEqual(self.mode_of(path), 0o600, oct(self.mode_of(path)))

    def test_a_permissive_umask_does_not_widen_it(self):
        # A mode that came from the umask rather than from the open would be
        # 0o666 here, and the assertion above would still be green on a laptop
        # with a tight umask.
        os.umask(0)
        path = self.inside("wide-umask")
        self.write_of(path, synthetic_token("fb-umask"))
        self.assertEqual(self.mode_of(path), 0o600, oct(self.mode_of(path)))

    def test_the_open_is_what_sets_the_mode_and_not_the_chmod_afterwards(self):
        # The discriminating measurement: the chmod is neutralised and the umask
        # would widen anything the open did not narrow. If the file still comes
        # out at 0600, no moment existed in which it was wider, because nothing
        # else ran between the create and the write.
        os.umask(0)
        path = self.inside("opener-proof")
        with mock.patch("os.chmod") as chmod:
            self.write_of(path, synthetic_token("fb-opener"))
        self.assertEqual(
            self.mode_of(path), 0o600,
            "the file was created wide and narrowed afterwards, so the secret "
            "stood in a readable file for the length of the write")
        self.assertTrue(chmod.called,
                        "the chmod is still expected; it is the replace path")

    def test_the_chmod_afterwards_earns_its_place_on_a_file_that_existed(self):
        # `os.open` ignores the mode argument for a file that is already there,
        # so the replace path is the one the chmod is for.
        path = self.put(self.inside("was-wide"), b"old", mode=0o644)
        self.write_of(path, synthetic_token("fb-replace"), replace=True)
        self.assertEqual(self.mode_of(path), 0o600)

    def test_the_file_holds_exactly_the_bytes_that_went_in(self):
        token = synthetic_token("fb-bytes")
        path = self.inside("exact")
        self.write_of(path, token)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), token.encode("utf-8"))

    def test_no_trailing_newline_is_added_on_the_way_in(self):
        # One added here and one stripped on the way out cancel each other until
        # somebody reads the file with `cat` and copies what they see.
        path = self.inside("no-eol")
        self.write_of(path, synthetic_token("fb-eol"))
        with open(path, "rb") as handle:
            self.assertFalse(handle.read().endswith(b"\n"))


class AFileAnotherAccountCanReadIsNotASecretAnyMore(FileCase):
    """Refused on READ, not merely reported.

    Handing the value over with a warning attached lets a wrapper carry on using
    a credential that every account on that machine can already read, and the
    warning lands in a log nobody opens until the credential is used somewhere
    it should not have been.
    """

    def test_a_mode_0644_file_is_refused_on_read(self):
        path = self.put(self.inside("world-readable"), b"value", mode=0o644)
        problem = self.refused_by(lambda: self.read_of(path))
        self.assertIsInstance(problem, errors.Refused)

    def test_the_message_says_the_content_has_to_be_treated_as_disclosed(self):
        path = self.put(self.inside("disclosed"), b"value", mode=0o644)
        problem = self.refused_by(lambda: self.read_of(path))
        self.assertIn("disclosed", problem.report())

    def test_the_mode_is_named_so_a_reader_can_see_what_it_is(self):
        path = self.put(self.inside("named-mode"), b"value", mode=0o644)
        problem = self.refused_by(lambda: self.read_of(path))
        self.assertIn("644", problem.report())

    def test_a_group_readable_file_is_refused_too(self):
        path = self.put(self.inside("group"), b"value", mode=0o640)
        self.assertIsInstance(self.refused_by(lambda: self.read_of(path)),
                              errors.Refused)

    def test_a_file_another_account_can_write_is_refused_too(self):
        # Writable by somebody else is worse than readable: the value can be
        # replaced with one the other account knows.
        path = self.put(self.inside("writable"), b"value", mode=0o606)
        self.assertIsInstance(self.refused_by(lambda: self.read_of(path)),
                              errors.Refused)

    def test_a_file_the_owner_can_only_read_is_allowed(self):
        # 0400 is the mode a deployment tool leaves behind, and it is narrower
        # than 0600 rather than wider. Refusing it would send somebody to widen
        # a file in order to read it.
        path = self.put(self.inside("read-only"), b"value", mode=0o400)
        reading = self.read_of(path)
        self.assertTrue(reading.present)
        self.assertEqual(reading.secret.expose(), b"value")

    def test_the_refusal_is_a_refusal_and_not_a_missing_file(self):
        # A wrapper reads the exit code, not the prose. "Would be unsafe" and
        # "the entry is gone" send somebody to two different places.
        path = self.put(self.inside("code"), b"value", mode=0o644)
        problem = self.refused_by(lambda: self.read_of(path))
        self.assertEqual(problem.exit_code, errors.EX_REFUSED)

    def test_the_refusal_carries_the_path_and_not_the_content(self):
        token = synthetic_token("fb-refused")
        path = self.put(self.inside("no-content"), token, mode=0o644)
        problem = self.refused_by(lambda: self.read_of(path))
        self.assertIn(path, problem.report())
        self.assertNotIn(token, problem.report())


class AReadStripsTheLineEndingAndNothingElse(FileCase):
    """A file written by a person ends with a newline that was never the value.

    Everything else it ends with was. A stripped space is a value one byte short
    and a kept newline is a value one byte long, and both fail at the far end
    the same way: as a credential that looks wrong rather than as a reader that
    took one byte too many.
    """

    def reading_of(self, raw):
        path = self.put(self.inside("line-endings"), raw)
        return self.read_of(path)

    def test_a_single_trailing_newline_is_removed(self):
        self.assertEqual(self.reading_of(b"value\n").secret.expose(), b"value")

    def test_a_file_without_a_trailing_newline_is_read_whole(self):
        self.assertEqual(self.reading_of(b"value").secret.expose(), b"value")

    def test_a_trailing_crlf_counts_as_one_line_ending(self):
        self.assertEqual(self.reading_of(b"value\r\n").secret.expose(), b"value")

    def test_a_trailing_space_is_part_of_the_value(self):
        self.assertEqual(self.reading_of(b"value \n").secret.expose(), b"value ")

    def test_a_trailing_tab_is_part_of_the_value(self):
        self.assertEqual(self.reading_of(b"value\t\n").secret.expose(), b"value\t")

    def test_a_leading_space_is_part_of_the_value(self):
        self.assertEqual(self.reading_of(b" value\n").secret.expose(), b" value")

    def test_a_line_ending_in_the_middle_is_part_of_the_value(self):
        # A PEM block is this case, and it is the value most likely to be kept
        # in a file rather than in a keychain.
        self.assertEqual(self.reading_of(b"line1\nline2\n").secret.expose(),
                         b"line1\nline2")

    def test_a_value_that_genuinely_ends_in_a_newline_keeps_it(self):
        # RED, and the reason is in the report that came with this file.
        # `raw.rstrip(b"\r\n")` removes EVERY trailing line ending, not the one
        # the writer added. A PEM block written with `printf '%s\n'` stands in
        # the file as "…-----END KEY-----\n\n": one newline belongs to the value
        # and one belongs to the file. The reader hands back neither, the far
        # end rejects the key, and the shape of the failure points at the key.
        self.assertEqual(self.reading_of(b"value\n\n").secret.expose(), b"value\n")


class AWriteOutsideEveryDeclaredStoreIsRefused(FileCase):
    """The rule that keeps this backend from being "write the token wherever"."""

    def outside(self, name="stray") -> str:
        other = self.tmpdir()
        return os.path.join(str(other), name)

    def test_a_path_outside_the_declared_root_is_refused(self):
        problem = self.refused_by(
            lambda: self.write_of(self.outside(), synthetic_token("fb-stray")))
        self.assertIsInstance(problem, errors.Refused)

    def test_the_hint_says_to_declare_the_directory_first(self):
        problem = self.refused_by(
            lambda: self.write_of(self.outside("hint"), synthetic_token("fb-hint")))
        self.assertIn("declare", problem.hint.lower())
        self.assertIn("directory", problem.hint.lower())

    def test_the_refusal_leaves_no_file_behind(self):
        path = self.outside("nothing-written")
        self.refused_by(lambda: self.write_of(path, synthetic_token("fb-none")))
        self.assertFalse(os.path.exists(path))

    def test_a_neighbour_whose_name_starts_with_the_root_is_still_outside(self):
        # `/home/opuser/secrets-old/token` starts with `/home/opuser/secrets`
        # and is a different directory. A prefix test without the separator
        # declares it inside, and it is exactly the directory somebody made
        # while rotating.
        root = os.path.join(str(self.root), "secrets")
        os.makedirs(root, mode=0o700, exist_ok=True)
        neighbour = os.path.join(str(self.root), "secrets-old", "token")
        problem = self.refused_by(
            lambda: self.write_of(neighbour, synthetic_token("fb-neighbour"),
                                  roots=[root]))
        self.assertIsInstance(problem, errors.Refused)

    def test_it_is_a_refusal_and_not_a_broken_reference(self):
        problem = self.refused_by(
            lambda: self.write_of(self.outside("code"), synthetic_token("fb-code")))
        self.assertEqual(problem.exit_code, errors.EX_REFUSED)

    def test_a_write_with_no_store_declared_at_all_is_refused(self):
        # RED, and the reason is in the report that came with this file. The
        # constructor says "Empty means nothing is allowed to be written" and
        # the guard reads `if self.allowed_roots and not inside`, so an empty
        # list disables the guard instead of closing it. `Resolver._build`
        # passes exactly that empty list on every Bridge that has declared no
        # file store, which is most of them, so the default is the open one.
        path = self.inside("undeclared")
        problem = self.refused_by(
            lambda: self.write_of(path, synthetic_token("fb-undeclared"), roots=[]))
        self.assertIsInstance(problem, errors.Refused)


class ASymlinkInsideTheStoreDoesNotCarryTheValueOutOfIt(FileCase):
    """Containment is measured on the resolved path, not on the one typed.

    A lexical prefix test reads `<store>/escape/token` as inside the store
    whatever `escape` happens to be. If it is a link to somewhere else, the
    check passes and the value lands outside every declaration, which is the
    one thing this backend exists to prevent. Nobody has to plant the link on
    purpose either: a store directory that is itself a convenience link to a
    synced folder is the ordinary way this happens.

    Both sides of the comparison are resolved here before anything is measured,
    because on macOS every temporary directory already sits behind a link:
    TMPDIR is under `/var`, and `/var` is a link to `/private/var`. Without that
    the case would be green over the link the platform planted rather than over
    the one it planted itself, which is a pass for the wrong reason on one of
    the two runners.
    """

    def setUp(self):
        super().setUp()
        self.store_root = os.path.realpath(str(self.tmpdir()))
        self.elsewhere = os.path.realpath(str(self.tmpdir()))
        self.escape = os.path.join(self.store_root, "escape")
        os.symlink(self.elsewhere, self.escape)

    def through_the_link(self, name="token") -> str:
        return os.path.join(self.escape, name)

    def test_a_write_through_the_link_is_refused(self):
        problem = self.refused_by(
            lambda: self.write_of(self.through_the_link(),
                                  synthetic_token("fb-escape"),
                                  roots=[self.store_root]))
        self.assertIsInstance(problem, errors.Refused)

    def test_the_value_did_not_land_on_the_other_side_of_the_link(self):
        # The half that matters. A refusal that arrived after the write would
        # leave the file exactly where the rule says it may not be.
        self.refused_by(
            lambda: self.write_of(self.through_the_link("landed"),
                                  synthetic_token("fb-escape-file"),
                                  roots=[self.store_root]))
        self.assertFalse(os.path.exists(os.path.join(self.elsewhere, "landed")))

    def test_the_refusal_says_the_path_is_outside_every_declared_store(self):
        problem = self.refused_by(
            lambda: self.write_of(self.through_the_link("why"),
                                  synthetic_token("fb-escape-why"),
                                  roots=[self.store_root]))
        self.assertIn("not inside any declared store", str(problem))

    def test_an_ordinary_path_in_the_same_store_still_writes(self):
        # The control. A containment check that refuses the link by refusing
        # everything is not a containment check.
        path = os.path.join(self.store_root, "ordinary")
        token = synthetic_token("fb-ordinary")
        reading = self.write_of(path, token, roots=[self.store_root])
        self.assertTrue(reading.present, reading.note)
        self.assertEqual(reading.secret.expose(), token.encode("utf-8"))

    def test_the_locator_of_a_reference_through_the_link_names_where_it_resolves(self):
        # What a reader would go and look at. The typed path and the resolved
        # one are two different directories, and the report is only useful if
        # it names the one that would have held the value.
        self.assertEqual(self.backend([self.store_root]).locate(
            self.ref(self.through_the_link("named"))),
            os.path.join(self.elsewhere, "named"))


class AWriteInsideADeclaredStoreLands(FileCase):
    """The other direction, so the refusals above cannot pass by refusing all."""

    def test_the_reading_the_write_returns_carries_the_value(self):
        token = synthetic_token("fb-lands")
        reading = self.write_of(self.inside("lands"), token)
        self.assertTrue(reading.present, reading.note)
        self.assertEqual(reading.secret.expose(), token.encode("utf-8"))

    def test_the_write_is_proved_by_a_read_and_not_by_the_absence_of_an_error(self):
        # The same rule as the keychain path: a value that never landed and a
        # value that landed short both leave no exception behind.
        token = synthetic_token("fb-proof")
        reading = self.write_of(self.inside("proof"), token)
        self.assertEqual(reading.fingerprint, values.fingerprint(token))

    def test_the_reading_names_the_folder_it_came_from(self):
        reading = self.write_of(self.inside("folder"), synthetic_token("fb-folder"))
        self.assertEqual(reading.store, str(self.root))

    def test_the_reading_carries_no_note_when_the_file_is_where_it_belongs(self):
        reading = self.write_of(self.inside("quiet"), synthetic_token("fb-quiet"))
        self.assertEqual(reading.note, "")

    def test_a_second_write_without_replace_is_refused(self):
        path = self.inside("twice")
        self.write_of(path, synthetic_token("fb-first"))
        problem = self.refused_by(
            lambda: self.write_of(path, synthetic_token("fb-second")))
        self.assertIsInstance(problem, errors.Refused)
        self.assertIn("--replace", problem.hint)

    def test_the_refused_second_write_left_the_first_value_alone(self):
        path = self.inside("untouched")
        first = synthetic_token("fb-keep")
        self.write_of(path, first)
        self.refused_by(lambda: self.write_of(path, synthetic_token("fb-other")))
        self.assertEqual(self.read_of(path).secret.expose(), first.encode("utf-8"))

    def test_a_second_write_with_replace_overwrites(self):
        path = self.inside("overwrite")
        self.write_of(path, synthetic_token("fb-old"))
        new = synthetic_token("fb-new")
        reading = self.write_of(path, new, replace=True)
        self.assertEqual(reading.secret.expose(), new.encode("utf-8"))

    def test_a_shorter_value_replaces_the_whole_file_and_not_its_first_bytes(self):
        # Without O_TRUNC the tail of the old value survives behind the new one,
        # and the file then holds two credentials, one of them unreadable.
        path = self.inside("truncate")
        self.write_of(path, synthetic_token("fb-long", length=48))
        self.write_of(path, "short", replace=True)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"short")


class TheParentDirectoryIsCreatedOwnerOnly(FileCase):
    """A store root exists; the subfolder under it usually does not yet."""

    def test_a_missing_parent_is_created_rather_than_reported(self):
        path = os.path.join(str(self.root), "sub", "token")
        self.write_of(path, synthetic_token("fb-mkdir"))
        self.assertTrue(os.path.isdir(os.path.dirname(path)))

    def test_the_created_parent_is_owner_only(self):
        path = os.path.join(str(self.root), "sub-mode", "token")
        self.write_of(path, synthetic_token("fb-mkdir-mode"))
        self.assertEqual(self.mode_of(os.path.dirname(path)), 0o700)

    def test_the_file_inside_it_is_still_0600(self):
        path = os.path.join(str(self.root), "sub-file", "token")
        self.write_of(path, synthetic_token("fb-mkdir-file"))
        self.assertEqual(self.mode_of(path), 0o600)

    def test_a_parent_that_is_already_there_is_left_as_it_is(self):
        # Widening or narrowing a directory somebody else made is not this
        # backend's call, and a silent chmod on a shared folder is a support
        # ticket nobody can trace back to a secrets tool.
        folder = os.path.join(str(self.root), "existing")
        os.makedirs(folder, mode=0o755, exist_ok=True)
        os.chmod(folder, 0o755)
        self.write_of(os.path.join(folder, "token"), synthetic_token("fb-existing"))
        self.assertEqual(self.mode_of(folder), 0o755)

    def test_every_directory_created_under_the_root_is_owner_only(self):
        # RED, and the reason is in the report that came with this file.
        # `os.makedirs(folder, mode=0o700)` applies the mode to the LAST
        # component only, since CPython 3.7. Every level above it is created at
        # 0o777 minus the umask, so a per-customer subtree created in one write
        # stands at 0o755 and every account on the machine can list the names of
        # the secret files under it.
        path = os.path.join(str(self.root), "customer", "acme", "token")
        self.write_of(path, synthetic_token("fb-nested"))
        wide = [folder for folder in (os.path.join(str(self.root), "customer"),
                                      os.path.join(str(self.root), "customer", "acme"))
                if self.mode_of(folder) & 0o077]
        self.assertEqual(wide, [], "these directories are open to other accounts")


class AnEmptyFileIsAMissThatSaysSo(FileCase):
    """A file with no bytes in it is a hit for the filesystem and a miss here."""

    def test_an_empty_file_is_not_present(self):
        path = self.put(self.inside("empty"), b"")
        self.assertFalse(self.read_of(path).present)

    def test_the_note_says_the_file_is_empty(self):
        path = self.put(self.inside("empty-note"), b"")
        self.assertIn("empty", self.read_of(path).note)

    def test_the_empty_secret_is_kept_so_a_report_can_measure_it(self):
        path = self.put(self.inside("empty-secret"), b"")
        reading = self.read_of(path)
        self.assertIsNotNone(reading.secret)
        self.assertEqual(reading.length, 0)

    def test_a_file_holding_only_a_line_ending_is_empty_too(self):
        # `echo > token` leaves this, and it is the shape of a value that was
        # never written rather than of one that was.
        path = self.put(self.inside("only-eol"), b"\n")
        self.assertFalse(self.read_of(path).present)

    def test_an_empty_file_is_not_reported_as_a_refusal(self):
        path = self.put(self.inside("empty-not-refused"), b"")
        self.assertEqual(self.read_of(path).ref, self.ref(path).canonical)


class AMissingFileIsAMissAndNotAFailure(FileCase):
    """Nothing there is an answer, and the answer is not an exception."""

    def test_a_path_that_is_not_there_is_not_present(self):
        self.assertFalse(self.read_of(self.inside("never-written")).present)

    def test_the_note_says_there_is_no_file(self):
        self.assertIn("no file", self.read_of(self.inside("none")).note)

    def test_no_secret_comes_back_at_all(self):
        # Not an empty Secret: a caller that checked the secret rather than
        # `present` would inject zero bytes as if they were the value.
        self.assertIsNone(self.read_of(self.inside("no-secret")).secret)

    def test_readable_here_says_the_same_thing_before_anything_is_opened(self):
        readable, why = self.backend().readable_here(self.ref(self.inside("absent")))
        self.assertFalse(readable)
        self.assertIn("no file", why)

    def test_a_file_that_is_there_is_readable_here_without_a_reason(self):
        path = self.put(self.inside("present"), b"value")
        readable, why = self.backend().readable_here(self.ref(path))
        self.assertTrue(readable)
        self.assertEqual(why, "")

    def test_the_store_column_names_the_folder_that_would_have_held_it(self):
        reading = self.read_of(self.inside("would-be"))
        self.assertEqual(reading.store, str(self.root))


class LocateNamesThePathAndReachesNothing(FileCase):
    """`locate` answers for a report, and a report is written when nothing works."""

    def test_it_names_the_absolute_path(self):
        path = self.inside("located")
        self.assertEqual(self.backend().locate(self.ref(path)), path)

    def test_it_answers_for_a_file_that_is_not_there(self):
        # The case a report needs it for: the value is missing and the reader
        # has to be told where it was looked for.
        path = self.inside("not-there")
        self.assertEqual(self.backend().locate(self.ref(path)), path)

    def test_it_answers_for_a_path_outside_every_declared_store(self):
        stray = os.path.join(os.path.realpath(self.tmpdir()), "stray")
        self.assertEqual(self.backend().locate(self.ref(stray)), stray)

    def test_it_carries_no_value_even_after_one_was_read(self):
        token = synthetic_token("fb-locate")
        path = self.put(self.inside("locate-read"), token)
        backend = self.backend()
        backend.read(self.ref(path))
        self.assertNotIn(token, backend.locate(self.ref(path)))


class NoProcessIsStartedForAFileBackend(FileCase):
    """There is no tool behind this scheme, so there is nothing to probe for."""

    def test_the_backend_names_no_binary(self):
        self.assertIsNone(self.backend().binary)

    def test_it_is_available_without_anything_being_installed(self):
        self.assertTrue(self.backend().available())

    def test_a_full_write_and_read_starts_no_process_at_all(self):
        # `MachineGuard` only refuses the programs that reach a secret store.
        # This closes the rest: a backend that shelled out to `chmod` or `cp`
        # would be green under the guard and would put the path, though not the
        # value, into every process list on the machine.
        path = self.inside("no-process")
        with mock.patch("engine.exec.run", side_effect=AssertionError(
                "the file backend started a process")):
            self.write_of(path, synthetic_token("fb-quiet-process"))
            self.read_of(path)


class TheRedCasesAreNamedRatherThanCounted(FileCase):
    """The three deliberate reds, listed where the next reader meets them.

    A red case with no name beside it is indistinguishable from a regression,
    and the second reader deletes it. Each entry says which docstring in
    `engine/backends/file.py` the case is holding the code to.
    """

    EXPECTED_RED = {
        "AReadStripsTheLineEndingAndNothingElse"
        ".test_a_value_that_genuinely_ends_in_a_newline_keeps_it":
            "file.py:83 rstrip(b'\\r\\n') removes every trailing line ending",
        "AWriteOutsideEveryDeclaredStoreIsRefused"
        ".test_a_write_with_no_store_declared_at_all_is_refused":
            "file.py:97 an empty allowed_roots disables the guard instead of closing it",
        "TheParentDirectoryIsCreatedOwnerOnly"
        ".test_every_directory_created_under_the_root_is_owner_only":
            "file.py:110 makedirs applies its mode to the last component only",
    }

    def test_every_named_red_case_is_a_case_this_file_really_carries(self):
        loader = unittest.defaultTestLoader
        for name, why in self.EXPECTED_RED.items():
            class_name, method = name.split(".")
            with self.subTest(case=name):
                klass = globals().get(class_name)
                self.assertIsNotNone(klass, "no such class: " + class_name)
                self.assertIn(method, loader.getTestCaseNames(klass), why)

    def test_the_list_of_deliberate_reds_has_not_become_a_habit(self):
        self.assertLessEqual(
            len(self.EXPECTED_RED), 3,
            "a growing list of expected failures is a suite that has stopped "
            "being a gate")
