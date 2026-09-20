"""The meta layer: what has to be true of the SUITE, not of the engine.

Every other file here measures one module. This one measures the measuring.
Five claims, and each of them was cheap to believe and expensive to be wrong
about:

1. NOTHING IN THIS SUITE SITS OUTSIDE THE MACHINE GUARD. The guard is the only
   thing keeping these cases off a real login keychain and a real database, and
   it protects exactly what inherits it. A class that forgot the base class
   looks identical in a green run.

2. THE GUARD ITSELF IS EXERCISED. An instrumented run of this suite fires the
   guard zero times, because every case passes `runner=` and never reaches a
   process. A branch that never executes is a branch nobody has tested, and
   this one is load bearing for all of the others.

3. NO LIVE CREDENTIAL IS WRITTEN DOWN HERE. Not a real one, not a revoked one,
   not in a fixture. The values this suite uses are assembled at runtime from
   `synthetic_token`, so there is no literal to copy in the first place, and
   this file is what keeps that true as the tree grows.

4. NO VERB OF THE COMMAND LINE PRINTS A VALUE. `test_cli.py` measures that
   behaviourally, one verb at a time. This file measures it structurally, out
   of the syntax tree: `expose()` and `expose_text()` are the only doors out of
   the wrapper, and both of them have to stand in the run path, never in an
   argument to `print` or to a write on the output stream. A behavioural case
   covers the verbs that exist today; the syntax tree covers the one somebody
   adds next week.

5. A RUN THAT MEASURED NOTHING IS NOT A GREEN RUN. In this repo a suite in
   which every case skipped once printed a green tally and exited 0. The tally
   was repaired, and the floor below is the other half of that repair: the
   suite says how many cases it expects to carry and names the handful that are
   allowed to skip, so a run that quietly collected a tenth of them fails
   instead of congratulating itself.

This file holds no engine behaviour. When one of these cases goes red the
answer is almost never in `engine/`.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from tests.conftest import SKILL_DIR, MachineGuard, mod

TESTS_DIR = SKILL_DIR / "tests"

cli = mod("engine.cli")

#: Directories that hold no authored text and cost the most to walk.
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache"}

#: The marker that says a line looks like a credential on purpose.
PRAGMA = "pragma: allowlist secret"


def skill_files():
    """Every readable text file of this skill, relative paths, sorted.

    Symlinks are skipped for the reason `engine/discover.py` skips them: the
    discovery symlinks point back into the tree, and following one counts the
    same file twice under two names.
    """
    out = []
    for path in sorted(SKILL_DIR.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if set(path.parts) & SKIP_DIRS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        out.append((path.relative_to(SKILL_DIR).as_posix(), text))
    return out


# ---------------------------------------------------------------------------
# 1. Every case stands under the guard
# ---------------------------------------------------------------------------

class EveryTestClassStandsUnderTheMachineGuard(MachineGuard):
    """The guard protects what inherits it, so that is what is measured.

    Deliberately an inheritance check and not a scan for the shape of a call.
    A scan over source text sees how a call was TYPED; it cannot see an argv
    assembled from a variable, a bare `Popen`, or an `os.system`, and all three
    reach a real keychain exactly as well as the spelling it looked for.
    """

    def test_every_test_class_in_the_suite_stands_under_the_guard(self):
        # Accumulated across files in sorted order, which is also the order a
        # base class is defined before the cases that use it. A class that
        # inherits a guarded base is guarded, however deep the chain.
        guarded = {"MachineGuard"}
        outside = []
        for path in sorted(TESTS_DIR.rglob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            # Module level only. A helper class defined inside a test body is a
            # fixture, not a case, and the runner never collects it.
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                bases = set()
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.add(base.id)
                    elif isinstance(base, ast.Attribute):
                        bases.add(base.attr)
                if bases & guarded:
                    guarded.add(node.name)          # a base class of its own
                else:
                    outside.append(
                        "%s:%s(%s)" % (path.name, node.name, ", ".join(sorted(bases))))
        self.assertEqual(
            outside, [],
            "these test classes do not inherit MachineGuard, so nothing stops "
            "them reaching a real keychain or a real database: " + ", ".join(outside))

    def test_the_suite_is_not_one_file_pretending_to_be_a_suite(self):
        # Without this the case above is also green over a tests directory that
        # holds nothing, which is the shape a broken checkout has.
        files = sorted(p.name for p in TESTS_DIR.rglob("test_*.py"))
        self.assertGreaterEqual(
            len(files), 8,
            "the suite lost test files rather than cases: " + ", ".join(files))


# ---------------------------------------------------------------------------
# 2. The guard itself
# ---------------------------------------------------------------------------

class TheGuardIsExercisedBecauseAGreenRunNeverFiresIt(MachineGuard):
    """The bolt, fired on purpose. Nothing else in this tree ever trips it.

    Every entry below is a READ that discloses nothing, and that is a hard
    requirement rather than good taste: when the mutation battery softens the
    guard, this table is what runs for real on the machine under the suite. It
    has to be inert when that happens.

    The guard matches by BASENAME on the resolved argv, so a full path, an argv
    assembled at runtime and a program hidden behind one layer of shell are all
    in the table. Source text is not what reaches a machine.
    """

    DENIED = (
        ["security", "error", "-25308"],
        ["/usr/bin/security", "error", "-25308"],
        ["keepassxc-cli", "--version"],
        ["az", "--version"],
        ["op", "--version"],
        ["ssh", "-V"],
        ["scp"],
        ["sudo", "-V"],
        ["secret-tool", "--version"],
    )

    HIDDEN = ["/bin/sh", "-c", "security error -25308"]

    def test_the_table_covers_every_program_the_guard_names(self):
        # Otherwise a name added to the deny list arrives with no case behind
        # it, and the list grows into a claim nobody checks.
        from tests import conftest

        covered = {os.path.basename(argv[0]) for argv in self.DENIED}
        covered.add(os.path.basename(self.HIDDEN[2].split()[0]))
        missing = sorted(conftest._DENY - covered)
        self.assertEqual(missing, [],
                         "these denied programs have no case in DENIED: %s" % missing)

    def test_subprocess_run_refuses_every_denied_program(self):
        for argv in self.DENIED:
            with self.subTest(argv=argv):
                with self.assertRaises(AssertionError) as caught:
                    subprocess.run(argv, capture_output=True)
                self.assertIn("tried to exec", str(caught.exception))

    def test_popen_refuses_every_denied_program(self):
        # `subprocess.run` is the shape a source scan looks for. `Popen` is the
        # one it does not, and call, check_output and check_call all arrive here.
        for argv in self.DENIED:
            with self.subTest(argv=argv):
                with self.assertRaises(AssertionError) as caught:
                    subprocess.Popen(argv, stdout=subprocess.PIPE)
                self.assertIn("tried to exec", str(caught.exception))

    def test_os_system_and_os_popen_are_closed_too(self):
        # Neither goes through subprocess, so patching subprocess alone leaves a
        # second and quieter door open.
        for argv in self.DENIED:
            command = " ".join(argv)
            with self.subTest(command=command):
                with self.assertRaises(AssertionError):
                    os.system(command)
                with self.assertRaises(AssertionError):
                    os.popen(command)

    def test_a_denied_program_hidden_inside_a_shell_is_refused_too(self):
        # A deny list that reads only argv[0] is walked past by one layer of
        # shell, and the shim this skill ships is a shell script.
        for starter in (subprocess.run, subprocess.Popen):
            with self.subTest(starter=starter.__name__):
                with self.assertRaises(AssertionError) as caught:
                    starter(self.HIDDEN, stdout=subprocess.PIPE)
                self.assertIn("security", str(caught.exception))
        with self.assertRaises(AssertionError):
            os.system(" ".join(self.HIDDEN[:2]) + " '%s'" % self.HIDDEN[2])

    def test_an_argv_assembled_at_runtime_is_refused_too(self):
        # Nothing on this line spells the program out, and the guard still sees
        # it. That difference is why an inheritance check replaced a word scan.
        program = "".join(["s", "e", "c", "u", "r", "i", "t", "y"])
        with self.assertRaises(AssertionError):
            subprocess.run([program, "error", "-25308"], capture_output=True)

    def test_a_harmless_local_call_still_runs(self):
        # A guard that refuses everything is not a guard, it is a broken suite.
        done = subprocess.run(["/bin/echo", "still local"],
                              capture_output=True, text=True)
        self.assertEqual(done.stdout.strip(), "still local")

    def test_the_guard_is_put_back_when_a_test_ends(self):
        # Otherwise one case's patch leaks into every later case in the process.
        before_run, before_popen = subprocess.run, subprocess.Popen
        before_system, before_os_popen = os.system, os.popen

        class Probe(MachineGuard):
            def runTest(self):
                pass

        case = Probe()
        case.setUp()
        self.assertIsNot(subprocess.run, before_run, "the guard did not arm")
        case.doCleanups()
        self.assertIs(subprocess.run, before_run)
        self.assertIs(subprocess.Popen, before_popen)
        self.assertIs(os.system, before_system)
        self.assertIs(os.popen, before_os_popen)


# ---------------------------------------------------------------------------
# 3. No live credential is written down here
# ---------------------------------------------------------------------------

#: Shapes with a vendor prefix. Low noise, so they run over every line of every
#: file. Each one is assembled from pieces rather than written out, so this
#: table does not itself look like the thing it is looking for.
PREFIXED_SHAPES = (
    ("a github style token",
     re.compile(r"\b(?:gh[pousr]|github" + "_pat)_[A-Za-z0-9_]{20,}")),
    ("an aws access key id",
     re.compile(r"\b(?:AK" + "IA|AS" + "IA)[0-9A-Z]{16}\b")),
    ("a slack token",
     re.compile(r"\bxo" + r"x[abprs]-[A-Za-z0-9-]{10,}")),
    ("a google api key",
     re.compile(r"\bAI" + r"za[0-9A-Za-z_\-]{35}\b")),
    ("an openai style token",
     re.compile(r"\bs" + r"k-[A-Za-z0-9]{32,}")),
    ("a private key header",
     re.compile(r"-----BE" + "GIN [A-Z ]*PRIVATE KEY-----")),
)

#: The shape with no vendor in it: a long run that mixes both cases and digits.
#: It is the one that catches a credential nobody recognises, and it is also the
#: one that fires on an ordinary identifier, so it runs only where a VALUE can
#: stand: inside a string literal in Python, inside quotes or backticks
#: elsewhere. A pasted credential is a value; `AValueThatLooksLikeThis` is a
#: class name, and a check that could not tell them apart would be switched off
#: within a week.
HIGH_ENTROPY = re.compile(
    r"(?<![A-Za-z0-9+/=_.\-])"
    r"(?=[A-Za-z0-9+/_-]*[a-z])(?=[A-Za-z0-9+/_-]*[A-Z])(?=[A-Za-z0-9+/_-]*[0-9])"
    r"[A-Za-z0-9+/_-]{32,}(?![A-Za-z0-9+/=_.\-])"
)

QUOTED_RUN = re.compile(r"""["'`]([^"'`\n]{32,})["'`]""")


def credential_shaped(path: str, text: str):
    """Every line of `text` that looks like a credential and is not marked.

    Returns a list of `"path:line: why"` strings. A line carrying the allowlist
    pragma is skipped, which is the whole point of the pragma: a fixture that
    has to look like a token says so on its own line.
    """
    problems = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if PRAGMA in line:
            continue
        for why, pattern in PREFIXED_SHAPES:
            found = pattern.search(line)
            if found:
                problems.append("%s:%d: %s" % (path, number, why))

    if path.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                line = getattr(node, "lineno", 0)
                source = lines[line - 1] if 0 < line <= len(lines) else ""
                if PRAGMA in source:
                    continue
                if HIGH_ENTROPY.search(node.value):
                    problems.append(
                        "%s:%d: a high entropy run inside a string literal" % (path, line))
    else:
        for number, line in enumerate(lines, 1):
            if PRAGMA in line:
                continue
            for chunk in QUOTED_RUN.findall(line):
                if HIGH_ENTROPY.search(chunk):
                    problems.append(
                        "%s:%d: a high entropy run inside quoted text" % (path, number))
    return problems


class NoCredentialIsWrittenDownAnywhereInThisSkill(MachineGuard):
    """No value in this tree, not even a revoked one.

    The way to keep that true is to have no literal worth copying: every value
    the suite uses comes out of `synthetic_token`, assembled at runtime from a
    prefix. A fixture that genuinely has to carry a token shaped string marks
    its own line with the allowlist pragma, so the exceptions are countable
    rather than assumed.
    """

    def test_this_file_carries_no_live_credential(self):
        path = Path(__file__)
        problems = credential_shaped(path.name, path.read_text(encoding="utf-8"))
        self.assertEqual(problems, [],
                         "this file carries something credential shaped: %s" % problems)

    def test_no_file_of_this_skill_carries_a_live_credential(self):
        problems = []
        for path, text in skill_files():
            problems.extend(credential_shaped(path, text))
        self.assertEqual(
            problems, [],
            "these lines are credential shaped and carry no allowlist pragma. "
            "If the line is a fixture, mark it. If it is a value, it does not "
            "belong in a repository at all: " + "; ".join(problems))

    def test_the_scan_really_reaches_the_whole_skill_and_not_one_directory(self):
        # Otherwise the case above is green over an empty list, which is the
        # answer a mistyped root gives and the answer a clean tree gives.
        seen = {path for path, _ in skill_files()}
        for expected in ("SKILL.md", "engine/cli.py", "engine/backends/keychain.py",
                         "tests/conftest.py", "tests/mutations.py", "run-tests.sh"):
            self.assertIn(expected, seen, "the scan never reached %s" % expected)
        self.assertGreater(len(seen), 20, "the scan reached %d files" % len(seen))

    def test_the_scan_finds_a_credential_that_was_pasted_in(self):
        # The positive control. Both shapes, because they take different routes
        # through the scanner: the prefixed one reads every line, the high
        # entropy one reads only where a value can stand.
        prefixed = 'token = "gh' + 'p_' + "A" * 36 + '"'
        entropy = 'token = "' + ("aB3" * 12) + '"'
        self.assertTrue(credential_shaped("poisoned.py", prefixed),
                        "a prefixed token walked past the scan")
        self.assertTrue(credential_shaped("poisoned.py", entropy),
                        "a high entropy value walked past the scan")

    def test_the_pragma_is_what_silences_it_and_nothing_else(self):
        poisoned = 'token = "gh' + 'p_' + "A" * 36 + '"'
        self.assertEqual(credential_shaped("poisoned.py", poisoned + "  # " + PRAGMA), [])
        self.assertTrue(credential_shaped("poisoned.py", poisoned + "  # harmless, honest"))

    def test_an_identifier_that_mixes_cases_and_digits_is_not_a_credential(self):
        # The false positive that would switch this check off. Class names in
        # this suite are sentences, so they are long, and several carry a digit.
        # The fixture below carries the pragma because it is a credential shaped
        # run standing inside a string literal, which is exactly the place the
        # scan looks. That is the pragma working rather than the pragma hiding
        # something: the case one line down proves the scan still reads it.
        fixture = "class ABinaryValueIsCoveredInBothBase64Alphabets(Guard):\n"  # pragma: allowlist secret
        self.assertEqual(credential_shaped("cases.py", fixture), [])
        self.assertTrue(HIGH_ENTROPY.search(fixture),
                        "the fixture stopped being the shape it is meant to be")


# ---------------------------------------------------------------------------
# 4. The command line has no verb that prints a value
# ---------------------------------------------------------------------------

#: The two doors out of the wrapper. `values.py` names them that way so that one
#: grep lists every place a value leaves it, and this is that grep, done on the
#: syntax tree so that a rename cannot slip past it.
EXPOSERS = ("expose", "expose_text")

#: Where a value is allowed to land in `cli.py`. Both of them are an assignment
#: and nothing else: one builds the child's environment, one is the bytes handed
#: to the child's standard input. Neither is an argument to anything that writes.
ALLOWED_TARGETS = ("environment", "stdin_bytes")


def exposures(tree):
    """Every call of `expose()` or `expose_text()` inside `tree`."""
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in EXPOSERS]


class TheCommandLineHasNoPathFromAValueToTheOutput(MachineGuard):
    """Measured out of the syntax tree, which covers the verb nobody has written.

    `test_cli.py` runs each verb and asserts the value is in neither stream.
    That is the stronger evidence and it covers the three verbs that exist. The
    tree is what covers `store`, `where` and `audit` when somebody adds them:
    the constraint is structural, so it can be checked structurally.
    """

    def setUp(self):
        super().setUp()
        self.source = (SKILL_DIR / "engine" / "cli.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def line(self, node):
        return self.source.splitlines()[node.lineno - 1].strip()

    def test_the_only_exposures_in_the_command_line_stand_in_the_run_path(self):
        enclosing = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in exposures(node):
                enclosing[call.lineno] = node.name
        self.assertTrue(enclosing, "no exposure at all, so this case measures nothing")
        for number, function in sorted(enclosing.items()):
            with self.subTest(line=number):
                self.assertEqual(
                    function, "command_run",
                    "a value is unwrapped in %s(), and `run` is the only verb "
                    "that is allowed to hold one: %s"
                    % (function, self.source.splitlines()[number - 1].strip()))

    def test_every_exposure_is_an_assignment_and_not_an_argument(self):
        # The shape is the safeguard. An exposure that is an ARGUMENT can be an
        # argument to anything, and `print` is only the most obvious anything.
        landed = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            if node.value not in exposures(node):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    landed.append(target.id)
                elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                    landed.append(target.value.id)
        self.assertEqual(sorted(landed), sorted(ALLOWED_TARGETS),
                         "a value was unwrapped somewhere other than the "
                         "environment assembly and the standard input of the "
                         "child: %s" % sorted(landed))
        self.assertEqual(len(landed), len(exposures(self.tree)),
                         "an exposure in cli.py is not the whole right hand side "
                         "of an assignment, so it is being passed somewhere")

    def test_no_exposure_stands_inside_a_print_or_a_write(self):
        offenders = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            prints = isinstance(function, ast.Name) and function.id == "print"
            writes = isinstance(function, ast.Attribute) and function.attr == "write"
            if not (prints or writes):
                continue
            for argument in list(node.args) + [kw.value for kw in node.keywords]:
                if exposures(argument) or (isinstance(argument, ast.Call)
                                           and argument in exposures(node)):
                    offenders.append("%s: %s" % (node.lineno, self.line(node)))
        self.assertEqual(offenders, [],
                         "these lines print or write something that was unwrapped "
                         "on the spot: " + "; ".join(offenders))

    def test_the_check_would_notice_a_verb_that_printed_a_value(self):
        # The positive control, because every assertion above is a negative and
        # a negative is also true of a scanner that finds nothing at all.
        poisoned = ast.parse(
            "def command_show(args, out, err):\n"
            "    print(secret.expose_text(), file=out)\n")
        found = exposures(poisoned)
        self.assertEqual(len(found), 1)
        printing = [node for node in ast.walk(poisoned)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "print"]
        self.assertTrue(exposures(printing[0].args[0]) or printing[0].args[0] in found,
                        "the print rule would not have seen this")

    def test_the_modules_that_report_never_unwrap_a_value(self):
        # `check`, `discover` and `refs` build the report. A report carries a
        # name, a byte count and a fingerprint, and reaching a value from there
        # is the one mistake that would be invisible in every other case here.
        for name in ("check.py", "discover.py", "refs.py", "resolve.py"):
            with self.subTest(module=name):
                tree = ast.parse((SKILL_DIR / "engine" / name).read_text(encoding="utf-8"))
                self.assertEqual(
                    [node.lineno for node in exposures(tree)], [],
                    "%s unwraps a value, and nothing it produces is for a "
                    "program to consume" % name)


# ---------------------------------------------------------------------------
# 5. A run that measured nothing is not a green run
# ---------------------------------------------------------------------------

#: What the suite is expected to carry. Deliberately well under the count on the
#: day it was written, because this number guards against a run that collected a
#: fraction of the suite, not against somebody deleting one case.
CASE_FLOOR = 400

#: The cases that are allowed to skip, and what they wait for. Each entry is
#: `module.Class.method`. A skip scores as neither green nor red, so a suite
#: that grows skips quietly loses coverage with no line anywhere saying so.
#: These four are honest: three ask the host for something the host may not
#: have, and the fourth is the tier that reads a real keychain.
MAY_SKIP = {
    "test_discover.InRepoAsksGitDirectlyAndHasNoSeam"
    ".test_a_temporary_directory_is_not_a_work_tree": "git is not installed",
    "test_discover.InRepoAsksGitDirectlyAndHasNoSeam"
    ".test_a_directory_that_is_not_there_answers_false_rather_than_raising": "git is not installed",
    "test_keepass.TheEntryIsAddressedByTheGroupPathOfTheReference"
    ".test_a_tilde_in_a_declared_path_is_expanded_before_it_is_used": "this account has no home directory",
    "test_keychain.TheRealKeychainTierReadsBackWhatItStored"
    ".test_a_value_stored_through_stdin_comes_back_byte_exact": "macOS plus the security binary",
}


def collected_cases():
    """Every case unittest would collect, as `module.Class.method` strings."""
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(TESTS_DIR), top_level_dir=str(SKILL_DIR))
    names = []

    def walk(item):
        if isinstance(item, unittest.TestSuite):
            for child in item:
                walk(child)
            return
        name = item.id()
        if name.startswith("tests."):
            name = name[len("tests."):]
        names.append(name)

    walk(suite)
    return names


def cases_that_can_skip():
    """Every case that carries a skip, found in the source rather than in a run.

    A run answers for the host it ran on. The source answers for all of them,
    which is the question worth asking: on a Linux runner a different set skips,
    and a table that only matched this laptop would be wrong there and silent
    about it.
    """
    found = {}
    for path in sorted(TESTS_DIR.rglob("test_*.py")):
        module = path.stem
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for klass in tree.body:
            if not isinstance(klass, ast.ClassDef):
                continue
            class_skips = _decorated_with_skip(klass)
            for method in klass.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not method.name.startswith("test"):
                    continue
                if class_skips or _decorated_with_skip(method) or _calls_skip_test(method):
                    found["%s.%s.%s" % (module, klass.name, method.name)] = method.lineno
    return found


def skip_decorator_names():
    """Names bound in `conftest.py` to one of unittest's own skip decorators.

    `@requires_real_keychain` carries no `skip` in its spelling, and a scan that
    looked for the word would have declared the macOS tier unskippable. The
    aliases are read out of the file that defines them instead, so a second one
    arrives already covered.
    """
    names = {"skip", "skipIf", "skipUnless", "skipTest"}
    tree = ast.parse((TESTS_DIR / "conftest.py").read_text(encoding="utf-8"))
    aliases = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        function = node.value.func
        called = function.attr if isinstance(function, ast.Attribute) else getattr(
            function, "id", "")
        if called in names:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    aliases.add(target.id)
    return aliases


SKIP_ALIASES = skip_decorator_names()


def _decorated_with_skip(node) -> bool:
    for decorator in node.decorator_list:
        text = ast.dump(decorator)
        if "skip" in text.lower():
            return True
        name = decorator.id if isinstance(decorator, ast.Name) else getattr(
            decorator, "attr", "")
        if name in SKIP_ALIASES:
            return True
    return False


def _calls_skip_test(node) -> bool:
    for inner in ast.walk(node):
        if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "skipTest"):
            return True
    return False


class ARunThatMeasuredNothingIsNotAGreenRun(MachineGuard):
    """The floor, and the named handful allowed to stand below it.

    In this repo a run in which every case skipped printed a green tally and
    exited 0. `scripts/tests/tally.awk` was repaired to call that red, and this
    class is the other half: the suite states how many cases it carries and
    which ones may skip, so a collection that quietly lost most of the suite is
    a failure rather than a smaller green number.
    """

    def test_the_suite_collects_more_cases_than_its_own_floor(self):
        names = collected_cases()
        self.assertGreater(
            len(names), CASE_FLOOR,
            "the suite collected %d cases and declares a floor of %d. Either "
            "cases were lost or the floor is stale; both are worth a look, and "
            "neither is worth a green run" % (len(names), CASE_FLOOR))

    def test_nothing_failed_to_load(self):
        # Discovery turns an import error into a case called `_FailedTest`, one
        # line away from an ordinary failure. A file that stopped importing
        # takes its whole count with it, and the floor above would not notice a
        # single file going.
        broken = [name for name in collected_cases() if "_FailedTest" in name]
        self.assertEqual(broken, [], "these modules did not import: %s" % broken)

    def test_only_the_named_handful_of_cases_can_skip(self):
        can_skip = cases_that_can_skip()
        unexpected = sorted(set(can_skip) - set(MAY_SKIP))
        self.assertEqual(
            unexpected, [],
            "these cases can skip and are not in MAY_SKIP. A skip is neither "
            "green nor red, so a suite that grows them quietly loses coverage: "
            + ", ".join(unexpected))

    def test_every_case_the_table_names_is_still_there(self):
        # The other direction. A name that no longer resolves means the table is
        # carrying a permission the suite no longer uses, and the next reader
        # trusts it.
        can_skip = cases_that_can_skip()
        stale = sorted(set(MAY_SKIP) - set(can_skip))
        self.assertEqual(stale, [],
                         "MAY_SKIP names cases that no longer skip: " + ", ".join(stale))

    def test_the_handful_really_is_a_handful(self):
        self.assertLessEqual(
            len(MAY_SKIP), 6,
            "the list of cases allowed to skip has stopped being an exception")
        collected = set(collected_cases())
        for name in MAY_SKIP:
            with self.subTest(case=name):
                self.assertIn(name, collected,
                              "MAY_SKIP names a case the runner does not collect")


# ---------------------------------------------------------------------------
# 6. The skill file and the parser say the same thing
# ---------------------------------------------------------------------------

#: The three verbs `SKILL.md` documents as NOT implemented in this slice. Typing
#: one has to be an argparse usage error, and a parser that quietly grew one
#: would leave the file describing a plan that had already shipped.
PLANNED_BUT_ABSENT = ("store", "where", "audit")


def frontmatter(text: str) -> str:
    """The YAML frontmatter block, as text.

    Read as text rather than parsed. This skill's engine is stdlib only, and a
    test that reached for a YAML library would make the suite need something the
    thing it tests does not.
    """
    if not text.startswith("---\n"):
        return ""
    return text[4:].split("\n---", 1)[0]


def argument_rows(text: str):
    """The first cell of every row of the Arguments table, backticks stripped."""
    block = text.split("## Arguments", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        # A markdown table escapes a pipe INSIDE a cell, and the alternation of
        # `--if-missing` is written that way. Splitting without putting it back
        # cuts that row in half and the flag disappears from the check.
        cell = line.replace(r"\|", "\x00").split("|")[1].strip().replace("\x00", "|")
        cell = cell.strip("`")
        if not cell or set(cell) <= set("- "):
            continue
        if cell == "Argument":
            continue
        rows.append(cell)
    return rows


class TheSkillFileAndTheParserDescribeOneCommandLine(MachineGuard):
    """`SKILL.md` is what an agent reads; the parser is what runs.

    A flag documented and never implemented is a call that fails at the worst
    moment, and a flag implemented and never documented is a capability nobody
    finds. The table and the parser are two hand written lists of the same
    thing, so they are compared rather than trusted.
    """

    def setUp(self):
        super().setUp()
        self.path = SKILL_DIR / "SKILL.md"
        self.text = self.path.read_text(encoding="utf-8")
        parser = cli.build_parser()
        self.verbs = {}
        for action in parser._actions:
            if action.dest == "command" and getattr(action, "choices", None):
                self.verbs = dict(action.choices)
        # Two shapes of the same list. `flags` answers "does the parser take
        # this word", `spellings` keeps the aliases of one option together, so
        # that a table documenting `-v` is not read as leaving `--verbose` out.
        self.flags = {}
        self.spellings = {}
        for verb, subparser in self.verbs.items():
            options = set()
            grouped = []
            for action in subparser._actions:
                options |= set(action.option_strings)
                if action.option_strings:
                    grouped.append(tuple(action.option_strings))
            self.flags[verb] = options
            self.spellings[verb] = grouped

    def test_the_skill_file_is_there(self):
        self.assertTrue(self.path.is_file(), "SKILL.md is what makes this a skill")
        self.assertTrue(self.text.startswith("---\n"), "SKILL.md carries no frontmatter")

    def test_the_skill_declares_itself_core(self):
        block = frontmatter(self.text)
        self.assertIn("metadata:", block, "the scope lives under metadata")
        after = block.split("metadata:", 1)[1]
        self.assertRegex(
            after, r"\n\s+scope:\s*core\b",
            "a skill that ships to open-bridge declares metadata.scope core, and "
            "an unscoped skill inherits nothing safe")

    def test_the_parser_carries_exactly_the_verbs_the_file_names(self):
        named = {cell.split()[0] for cell in argument_rows(self.text)
                 if not cell.startswith("-")}
        self.assertEqual(named, set(self.verbs),
                         "the Arguments table names %s and the parser takes %s"
                         % (sorted(named), sorted(self.verbs)))

    def test_every_flag_the_file_documents_is_a_flag_the_parser_takes(self):
        shared = set.intersection(*self.flags.values()) if self.flags else set()
        missing = []
        for cell in argument_rows(self.text):
            words = cell.split()
            verb = words[0] if words[0] in self.verbs else None
            accepted = self.flags[verb] if verb else shared
            for word in words:
                if not word.startswith("-") or word == "--":
                    # A bare `--` is argparse's own end of options marker, and
                    # the two `run` rows write it because a caller has to type
                    # it. It is not an option the parser declares.
                    continue
                if word not in accepted:
                    missing.append("%s (in row %r)" % (word, cell))
        self.assertEqual(
            missing, [],
            "the Arguments table documents flags the parser does not take: "
            + ", ".join(missing))

    def test_every_flag_the_parser_takes_is_documented(self):
        # The direction that matters for a reader who is looking for a
        # capability rather than checking one. `-h` and `--help` are argparse's
        # own and are left out of the table on purpose.
        written = (" ".join(argument_rows(self.text))).split()
        undocumented = []
        for verb, grouped in self.spellings.items():
            for aliases in grouped:
                if "-h" in aliases or "--help" in aliases:
                    continue
                if not any(alias in written for alias in aliases):
                    undocumented.append("%s %s" % (verb, "/".join(aliases)))
        self.assertEqual(undocumented, [],
                         "the parser takes flags the Arguments table never "
                         "mentions: " + ", ".join(undocumented))

    def test_the_verbs_the_file_calls_a_plan_are_not_implemented(self):
        # `SKILL.md` says these three are the next slice. A parser that grew one
        # without the file noticing would ship a verb nobody documented, and in
        # this skill two of the three would touch a store.
        for verb in PLANNED_BUT_ABSENT:
            with self.subTest(verb=verb):
                self.assertNotIn(verb, self.verbs,
                                 "%s is implemented, and SKILL.md still calls it "
                                 "a plan" % verb)

    def test_the_referenced_files_exist(self):
        # A decision tree that points at a file nobody wrote sends a reader
        # looking, which is worse than saying nothing.
        for name in re.findall(r"`(references/[a-z0-9_.\-]+)`", self.text):
            with self.subTest(reference=name):
                self.assertTrue((SKILL_DIR / name).is_file(),
                                "SKILL.md points at %s and it is not there" % name)


if __name__ == "__main__":
    unittest.main()
