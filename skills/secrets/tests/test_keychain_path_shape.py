"""A relative `--keychain` path, and where the value actually lands.

This file holds ONE finding, and it is red on purpose. Every other case in the
suite measures behaviour the engine has; these measure behaviour it does not,
and the fix belongs in `engine/backends/keychain.py`, not here.

Measured on macOS 26 on 2026-09-20, twice, with the same command line and only
the spelling of the keychain path different:

    add-generic-password -s "probe-abs"  -a "acct" -w "..." -A "/abs/demo.keychain-db"
        -> the item is in /abs/demo.keychain-db, and NOT in the default search list

    add-generic-password -s "probe-rel2" -a "acct" -w "..." -A "./demo.keychain-db"
        -> the item is in the LOGIN keychain, and NOT in ./demo.keychain-db

Both exited 0 and both said nothing. The read does not rescue it either: a
`find-generic-password` handed the same `./demo.keychain-db` finds neither item,
so the two halves of the skill disagree about which file was addressed.

What that costs, in the order it happens: `secrets store --keychain
./demo.keychain-db` writes the secret into the user's login keychain, the
read-back looks in the file that was named, finds nothing, and the command
reports "the write reported success and the entry reads back empty" with exit 3.
The report is honest and the value is in the wrong store, permanently and
silently, which is the one outcome the write path exists to prevent.

The backend is the only layer that can fix it. `--keychain` is a path somebody
types, `Options.keychain_path` carries it unchanged, and the backend is where a
path becomes an argument to `security`. Absolutising it there covers the read
argv and the write line in one place, and covers a store declaration whose
`location.keychain_path` is relative as well.

The cases below need no process: they read the argv and the stdin line the
backend builds, which is where the path is decided.
"""

from __future__ import annotations

import os
import unittest

from unittest import mock

from tests.conftest import MachineGuard, mod, synthetic_token

keychain = mod("engine.backends.keychain")
base = mod("engine.backends.base")
refs = mod("engine.refs")
values = mod("engine.values")

#: A keychain named relative to the working directory. The shape a person types
#: after `cd`-ing into the folder that holds it, and the shape the worked
#: examples in `references/resolve.md` use for a throwaway keychain.
RELATIVE = "./demo.keychain-db"

#: The same keychain, spelled the way `security` agrees with itself about.
ABSOLUTE = "/home/opuser/demo.keychain-db"


class AKeychainPathReachesSecurityAsAnAbsolutePath(MachineGuard):
    """Whatever `--keychain` was given, `security` has to see one file.

    A relative path is not ambiguous to the person who typed it and it is
    ambiguous to the tool: the write resolves it against the default search list
    and the read against nothing that helps. So the backend has to resolve it
    before it becomes an argument, and the two cases here watch the two places
    it becomes one.
    """

    SERVICE = "invoice-gateway"
    ACCOUNT = "outbound"

    def setUp(self):
        super().setUp()
        # `Backend.available()` probes the filesystem with `shutil.which`, which
        # is the one call in this path that does not go through `runner=`. Both
        # cases stay off the process either way; this only keeps a Linux runner
        # from answering "security is not installed" before the path is built.
        patcher = mock.patch("engine.exec.which", return_value="/usr/bin/security")
        patcher.start()
        self.addCleanup(patcher.stop)

    def backend(self, keychain_path):
        return keychain.KeychainBackend(
            keychain_path=keychain_path,
            context=base.Context(platform="darwin", interactive=True,
                                 over_ssh=False, display=True),
        )

    def ref(self):
        return refs.parse("keychain://%s/%s" % (self.SERVICE, self.ACCOUNT))

    def test_the_read_argv_names_the_keychain_by_an_absolute_path(self):
        argv = self.backend(RELATIVE).argv_read(self.ref())
        named = [word for word in argv if "demo.keychain-db" in word]
        self.assertEqual(len(named), 1, "the read names no keychain file: %s" % (argv,))
        self.assertTrue(
            os.path.isabs(named[0]),
            "the read hands security %r. A relative keychain path finds neither "
            "the item written beside it nor the one written into the login "
            "keychain, so the read and the write address different files."
            % named[0])

    def test_the_write_line_names_the_keychain_by_an_absolute_path(self):
        line = self.backend(RELATIVE).write_line(
            self.ref(), values.Secret(synthetic_token("kc-relative")))
        named = [word.strip('"') for word in line.split() if "demo.keychain-db" in word]
        self.assertEqual(len(named), 1, "the write line names no keychain file: %s" % line)
        self.assertTrue(
            os.path.isabs(named[0]),
            "the write line hands `security -i` %r. Measured on macOS 26 on "
            "2026-09-20: a relative path there puts the item in the LOGIN "
            "keychain, rc 0 and no message, and the read-back then reports it "
            "missing while the value stays where nobody looks." % named[0])

    def test_an_absolute_path_is_handed_over_unchanged(self):
        # The other direction, so a fix cannot be a rewrite that mangles the
        # path somebody already spelled correctly.
        backend = self.backend(ABSOLUTE)
        self.assertIn(ABSOLUTE, backend.argv_read(self.ref()))
        self.assertIn(
            ABSOLUTE,
            backend.write_line(self.ref(), values.Secret(synthetic_token("kc-absolute"))))


class TheRedCasesAreNamedRatherThanCounted(MachineGuard):
    """The deliberate reds of this file, named where the next reader meets them.

    Same convention as `test_file_backend.py`. A red case with no name beside it
    is indistinguishable from a regression, and the second reader deletes it.
    """

    EXPECTED_RED = {
        "AKeychainPathReachesSecurityAsAnAbsolutePath"
        ".test_the_read_argv_names_the_keychain_by_an_absolute_path":
            "keychain.py:79 argv_read appends keychain_path as it was given",
        "AKeychainPathReachesSecurityAsAnAbsolutePath"
        ".test_the_write_line_names_the_keychain_by_an_absolute_path":
            "keychain.py:150 write_line quotes keychain_path as it was given",
    }

    def test_every_named_red_case_is_a_case_this_file_really_carries(self):
        loader = unittest.defaultTestLoader
        for name, why in self.EXPECTED_RED.items():
            class_name, method = name.split(".")
            with self.subTest(case=name):
                klass = globals().get(class_name)
                self.assertIsNotNone(klass, "no such class: " + class_name)
                self.assertIn(method, loader.getTestCaseNames(klass), why)

    def test_the_two_reds_are_one_finding_and_not_a_habit(self):
        self.assertLessEqual(
            len(self.EXPECTED_RED), 2,
            "a growing list of expected failures is a suite that has stopped "
            "being a gate")


if __name__ == "__main__":
    unittest.main()
