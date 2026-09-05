"""Contract for scripts/check-generated-output.py.

THE SCAR, measured 2026-08-24. A stylesheet lived inside a Python triple-quoted
string. It carried the CSS escape for a middle dot, written as a backslash and
`00B7`. Python parses that literal long before a browser parses CSS, and a
backslash followed by two zeros is an OCTAL escape: the value carried a real NUL
byte. The generated page carried it too, and `workload publish` then died inside
`subprocess` with "embedded null byte" -- an error naming neither CSS, nor the
stylesheet, nor the character.

The house rule that would have prevented it already exists and is older than
this guard: generated files carry native characters, never escapes for them.
This script is that rule with teeth, for the one case where breaking it is
silent rather than merely ugly.

WHAT IT DOES NOT DO, on purpose. It does not flag every escape. A NUL used as a
field separator, an ANSI colour sequence written for a terminal, an escape
inside a regular expression -- all of those have the right consumer and are
correct. The check is narrow by design: a control character in a string that
BECOMES markup, a stylesheet or a script. There is no legitimate instance of
that, which is why it can be a hard gate instead of an advisory.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GUARD = REPO / "scripts" / "check-generated-output.py"


def run(*paths) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD), *[str(p) for p in paths]],
        capture_output=True, text=True)


class Fixture:
    """A throwaway tree, so a test never depends on the live repository."""

    def write(self, name: str, body: str) -> Path:
        path = Path(self.tmp.name) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    @property
    def root(self) -> Path:
        return Path(self.tmp.name)


class ItCatchesTheOneThatBitUs(Fixture, unittest.TestCase):

    def test_an_octal_escape_inside_a_stylesheet_is_refused(self):
        # Written exactly as the defect was: the source says \00B7, Python
        # hands the value a NUL, and the page carries it.
        self.write("gen.py", 'CSS = """\n.x::after { content: " \\00B7 "; }\n"""\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("gen.py", done.stdout)
        self.assertIn("U+0000", done.stdout)

    def test_the_report_names_the_line_and_not_only_the_file(self):
        self.write("gen.py", '\n\n\nCSS = """\n.x { content: "\\00B7"; }\n"""\n')
        done = run(self.root)
        self.assertRegex(done.stdout, r"gen\.py:\d+",
                         "a file name alone does not locate a defect that is "
                         "invisible in the source text")

    def test_the_native_character_is_accepted(self):
        # The fix, and the house rule: write the character.
        self.write("gen.py", 'CSS = """\n.x::after { content: " \u00b7 "; }\n"""\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_doubled_backslash_is_accepted(self):
        # The other correct fix: escape the escape, so CSS receives it intact.
        self.write("gen.py", 'CSS = """\n.x::after { content: "\\\\00B7"; }\n"""\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_raw_string_is_accepted(self):
        self.write("gen.py", 'CSS = r"""\n.x::after { content: "\\00B7"; }\n"""\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


class ItRefusesToCryWolf(Fixture, unittest.TestCase):
    """Every one of these is a correct use. A guard that flags them gets
    switched off, and then it guards nothing."""

    def test_an_ansi_colour_sequence_is_not_a_defect(self):
        self.write("gen.py",
                   'WARN = "\\033[33mkaputt\\033[0m"\n'
                   'HTML = "<p>x</p>"\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_a_nul_used_as_a_separator_is_not_a_defect(self):
        self.write("gen.py", 'KEY = "\\x00".join(["a", "b"])\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_a_control_character_outside_markup_is_not_this_guards_business(self):
        self.write("gen.py", 'SEP = "\\x1e"\nUNIT = "\\x1f"\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_a_docstring_describing_the_defect_is_not_the_defect(self):
        # This very test file, and the guard's own docstring, talk about the
        # escape. Prose that is never emitted must stay readable.
        self.write("gen.py",
                   '"""A backslash followed by 00B7 becomes a NUL in a '
                   'non-raw string; write <span> content as the character."""\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout)


class ItSaysWhatItCovered(Fixture, unittest.TestCase):

    def test_a_clean_run_says_how_much_it_actually_read(self):
        # A guard that prints "clean" without a count is indistinguishable from
        # a guard that read nothing, which is how a broken filter hides.
        self.write("a.py", 'HTML = "<p>ok</p>"\n')
        self.write("b.py", 'CSS = "body { color: red; }"\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertRegex(done.stdout, r"\b2\b",
                         "the clean line does not say how many files it read")

    def test_a_file_it_cannot_parse_is_named_and_not_silently_skipped(self):
        self.write("broken.py", "def (:\n")
        done = run(self.root)
        self.assertIn("broken.py", done.stdout + done.stderr,
                      "an unparseable file was skipped without saying so, so "
                      "the count above it is a lie")

    def test_it_walks_a_directory_and_not_only_the_files_it_is_handed(self):
        self.write("deep/nested/gen.py", 'CSS = """<p>{ content: "\\00B7"; }</p>"""\n')
        done = run(self.root)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("gen.py", done.stdout)


class TheGuardHoldsItselfToItsOwnRule(unittest.TestCase):

    def test_the_live_repository_is_clean(self):
        # The point of the whole exercise: not that the one instance was fixed,
        # but that there is no second one.
        done = run(REPO)
        self.assertEqual(done.returncode, 0,
                         "the repository carries a control character in "
                         "generated markup:\n" + done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
