"""discover: the inventory, derived from the tree rather than declared.

Every case here builds its own tree under `tempfile` and scans that. The
repository is never the subject: a suite that measured the real tree would
report a different number every time somebody wrote a reference into a file,
and the number would be the finding rather than the behaviour.

Git is driven through the `runner=` seam for the same reason. `candidate_files`
asks `git ls-files` first and walks when that says nothing, and both halves have
to be measured on purpose rather than on whether the temporary directory
happened to sit inside somebody's work tree.

Nothing in this file holds a value. `discover` reads files that hold LOCATORS,
never files that hold secrets, and the fixtures say so by containing only
references and prose.

The four cases with scars behind them:

* the example classification, because 19 of 38 hits in this repo are shapes
  written in prose, and a scan that reported those as broken would bury the
  real ones under its own noise.
* `keepass://personal/` before an angle bracket, taken verbatim from
  `rules/secret-placement.md`. On its own it is a reference one segment short,
  so without the follower character it becomes a false alarm at the top of
  every scan.
* the symlink, because the three discovery symlinks point back into the tree
  and following them counted every skill three times.
* the size and binary limits, because a scan that reads a checked in archive
  costs minutes and finds nothing.
"""

from __future__ import annotations

import os
import shutil
import unittest

from tests.conftest import FakeRunner, MachineGuard, completed, mod

discover = mod("engine.discover")
refs = mod("engine.refs")

#: One reference, spelled the way a YAML file spells it. Assembled from parts
#: so that no line in this file reads like a credential even by accident.
KEYCHAIN_REF = "keychain://" + "bks-agent-token/opuser"
KEEPASS_REF = "keepass://" + "personal/org/storage-api/api-key"


class DiscoveryCase(MachineGuard):
    """A fixture tree in a temporary directory, and git on a short leash."""

    def tree(self, files):
        """Write `{relative path: text or bytes}` into a fresh directory."""
        root = self.tmpdir()
        for relative, content in files.items():
            full = root / relative
            full.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                full.write_bytes(content)
            else:
                full.write_text(content, encoding="utf-8")
        return root

    def git_is_absent(self):
        """A runner answering `ls-files` the way a directory outside git does."""
        return FakeRunner().add(
            "ls-files", completed(rc=128, stderr="fatal: not a git repository"))

    def git_lists(self, *names):
        """A runner answering `ls-files` with a tracked set, NUL separated."""
        return FakeRunner().add("ls-files", completed(stdout="\0".join(names) + "\0"))

    def scan(self, root, runner, paths=None):
        return discover.find(str(root), paths, runner=runner)

    def raws(self, findings):
        return [finding.raw for finding in findings]

    def places(self, findings):
        return [(finding.path, finding.line) for finding in findings]


class AReferenceInAYamlFileIsFoundWithItsLineNumber(DiscoveryCase):
    """The finding has to say WHERE, or the inventory is a list of strings.

    `check` prints the places a reference is written down so that a rotation
    knows which files move with it. A path that does not resolve from the root,
    or a line number off by the file's leading comment, sends that edit to the
    wrong place.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({
            "identity/accounts/cloudflare.yaml": (
                "# yaml-language-server: $schema=./_schema.yaml\n"
                "---\n"
                "provider: cloudflare\n"
                "env:\n"
                f"  CLOUDFLARE_API_TOKEN: {KEYCHAIN_REF}\n"  # pragma: allowlist secret
            ),
        })
        self.findings = self.scan(self.root, self.git_is_absent())

    def test_the_reference_is_found_exactly_once(self):
        self.assertEqual(self.raws(self.findings), [KEYCHAIN_REF])

    def test_the_path_is_relative_to_the_root(self):
        self.assertEqual(self.findings[0].path, "identity/accounts/cloudflare.yaml")
        self.assertTrue(os.path.exists(os.path.join(str(self.root),
                                                    self.findings[0].path)))

    def test_the_line_number_counts_from_one_and_skips_no_header(self):
        # Five lines in, behind a modeline, a document marker and two keys.
        # A parser that counted from zero, or that dropped the schema comment
        # because it holds a dollar sign, would land on the wrong line.
        self.assertEqual(self.findings[0].line, 5)

    def test_the_finding_carries_the_parsed_reference(self):
        finding = self.findings[0]
        self.assertTrue(finding.ok)
        self.assertEqual(finding.error, "")
        self.assertEqual(finding.ref.scheme, "keychain")
        self.assertEqual(finding.ref.store, "bks-agent-token")

    def test_two_references_on_one_line_are_two_findings_on_that_line(self):
        root = self.tree({
            "notes.md": f"one {KEYCHAIN_REF} and two {KEEPASS_REF}\n",
        })
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(self.places(findings), [("notes.md", 1), ("notes.md", 1)])

    def test_the_scan_asks_for_git_and_for_nothing_else(self):
        # The guard in conftest refuses a real store outright. This says the
        # positive half: the only process the inventory wants is the one that
        # lists tracked files.
        runner = self.git_is_absent()
        self.scan(self.root, runner)
        self.assertTrue(runner.calls)
        for call in runner.calls:
            with self.subTest(argv=call["argv"]):
                self.assertEqual(os.path.basename(call["argv"][0]), "git")


class ADocumentationExampleIsNotABrokenReference(DiscoveryCase):
    """A shape written in prose is a shape, not a secret that went missing.

    Measured on this repo: 19 of 38 hits are examples. Reporting those as
    broken would put more false entries in the report than real ones, and a
    report like that gets read once.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({
            "docs/secrets.md": (
                "# How to write one\n"
                "A Key Vault reference looks like "
                "azure-keyvault://$VAULT/$NAME in a template.\n"
                f"The live one in this Bridge is {KEYCHAIN_REF}.\n"  # pragma: allowlist secret
                "A KeePass entry is keepass://personal/…/entry/password.\n"
            ),
        })
        self.findings = self.scan(self.root, self.git_is_absent())
        self.by_line = {finding.line: finding for finding in self.findings}

    def test_a_dollar_placeholder_makes_it_an_example(self):
        self.assertTrue(self.by_line[2].example)

    def test_an_ellipsis_makes_it_an_example(self):
        self.assertTrue(self.by_line[4].example)

    def test_an_example_carries_no_parsed_reference(self):
        self.assertIsNone(self.by_line[2].ref)
        self.assertFalse(self.by_line[2].ok)

    def test_the_error_says_example_rather_than_naming_a_grammar_problem(self):
        # The difference between "somebody wrote a shape" and "somebody wrote a
        # reference wrong". The second is work; the first is documentation.
        self.assertIn("example", self.by_line[2].error)
        self.assertNotIn("segments", self.by_line[2].error)

    def test_the_live_reference_on_the_next_line_is_still_found(self):
        self.assertTrue(self.by_line[3].ok)
        self.assertEqual(self.by_line[3].raw, KEYCHAIN_REF)

    def test_is_example_reads_the_reference_and_not_the_file(self):
        # Classification is per reference, so one example does not mark the
        # file and one live reference does not clear it.
        self.assertTrue(discover.is_example("azure-keyvault://$VAULT/$NAME"))
        self.assertFalse(discover.is_example(KEYCHAIN_REF))


class AReferenceCutAtAnAngleBracketIsAnExample(DiscoveryCase):
    """The line from `rules/secret-placement.md`, and the only evidence there is.

    The scanner stops at the angle bracket because a reference cannot contain
    one, so the matched text is `keepass://personal/` with no placeholder in it
    at all. Nothing inside the match says it is prose. The character that
    stopped the match is what says so.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({
            "rules/secret-placement.md": (
                "Examples (1Password vault or KeePass group path):\n"
                "keepass://personal/<org>/<service>/hf-token/token\n"
            ),
        })
        self.findings = self.scan(self.root, self.git_is_absent())

    def test_the_matched_text_stops_at_the_bracket(self):
        self.assertEqual(self.raws(self.findings), ["keepass://personal/"])

    def test_it_is_classified_as_an_example(self):
        self.assertTrue(self.findings[0].example)
        self.assertIn("example", self.findings[0].error)

    def test_it_is_not_reported_as_a_reference_two_segments_short(self):
        # What the report would say without the follower rule, and it would say
        # it about a documentation file, at the top of every scan of the repo.
        self.assertNotIn("segments", self.findings[0].error)
        self.assertIsNone(self.findings[0].ref)

    def test_the_same_text_without_the_bracket_really_is_broken(self):
        # The other side of the pair: the follower is doing the work here, not
        # some property of the matched text.
        root = self.tree({"notes.md": "keepass://personal/ on its own\n"})
        findings = self.scan(root, self.git_is_absent())
        self.assertFalse(findings[0].example)
        self.assertIn("segments", findings[0].error)


class ABrokenReferenceIsAFindingWithItsError(DiscoveryCase):
    """A reference that does not parse is the point of the scan, not a skip."""

    def test_too_many_segments_is_reported_with_the_parser_message(self):
        root = self.tree({"infra/remotes/box.yaml": "token: keychain://a/b/c\n"})
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(len(findings), 1)
        self.assertIn("at most 2", findings[0].error)
        self.assertEqual(findings[0].path, "infra/remotes/box.yaml")

    def test_a_broken_reference_is_neither_ok_nor_an_example(self):
        root = self.tree({"box.yaml": "path: file://relative/token\n"})
        findings = self.scan(root, self.git_is_absent())
        self.assertFalse(findings[0].ok)
        self.assertFalse(findings[0].example)
        self.assertIn("absolute path", findings[0].error)

    def test_a_scheme_nobody_declared_is_reported_too(self):
        # The case this module's own docstring names: `keeper://` sat in
        # `identity/accounts/_template.yaml` for months, "invisible to every
        # check because nothing ever looked". A scan that cannot see it leaves
        # it invisible, and an account file that carries it still resolves to
        # nothing at all.
        root = self.tree({"identity/accounts/ghost.yaml": "api: keeper://vault/item\n"})
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(len(findings), 1,
                         "a reference with an undeclared scheme is the one the "
                         "scan exists to surface, and it produced no finding")
        self.assertIn("keeper", findings[0].error)


class ASymlinkBackIntoTheTreeDoesNotDoubleTheFindings(DiscoveryCase):
    """The defect that counted every skill three times.

    `.claude/skills`, `.agents/skills` and `.github/skills` all point at
    `skills/`. Following them turns one reference into three findings in three
    paths, two of which are the same file under another name, and a rotation
    then goes looking for files that are not really there.
    """

    def test_a_tracked_symlink_to_a_scanned_file_adds_no_second_finding(self):
        # git lists a symlink as an entry of its own, so this is the path the
        # defect actually came down.
        root = self.tree({"skills/secrets/SKILL.md": f"reads {KEYCHAIN_REF}\n"})
        link = root / "mirror.md"
        os.symlink(str(root / "skills/secrets/SKILL.md"), str(link))
        findings = self.scan(root, self.git_lists("skills/secrets/SKILL.md", "mirror.md"))
        self.assertEqual(self.places(findings), [("skills/secrets/SKILL.md", 1)])

    def test_the_walk_does_not_descend_into_a_symlinked_directory(self):
        # The real shape: `.claude/skills` is a relative symlink at `../skills`,
        # so a walk that followed links would read every skill a second time
        # under a second path, and a third time through `.agents/skills`.
        root = self.tree({"skills/secrets/SKILL.md": f"reads {KEYCHAIN_REF}\n"})
        (root / ".claude").mkdir()
        os.symlink("../skills", str(root / ".claude" / "skills"))
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(self.places(findings), [("skills/secrets/SKILL.md", 1)])

    def test_the_file_behind_the_symlink_is_still_found_once(self):
        # The guard must not cost the real finding: a scan that skipped both
        # the link and its target would be quiet for the wrong reason.
        root = self.tree({"skills/secrets/SKILL.md": f"reads {KEYCHAIN_REF}\n"})
        os.symlink(str(root / "skills"), str(root / "mirror"))
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(self.raws(findings), [KEYCHAIN_REF])


class AFileTheScannerCannotReadIsSkipped(DiscoveryCase):
    """Binary, oversized and undecodable files cost time and hold no declaration."""

    def test_a_binary_file_with_a_reference_in_it_is_not_reported(self):
        root = self.tree({
            "assets/blob.bin": KEYCHAIN_REF.encode("utf-8") + b"\x00\x00payload",
            "keep.yaml": f"token: {KEEPASS_REF}\n",  # pragma: allowlist secret
        })
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(self.raws(findings), [KEEPASS_REF])

    def test_a_file_that_is_not_utf8_is_not_reported(self):
        root = self.tree({"legacy.txt": KEYCHAIN_REF.encode("utf-8") + b" \xff\xfe\n"})
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(findings, [])

    def test_a_file_one_byte_over_the_limit_is_not_read(self):
        root = self.tree({"huge.yaml": self.padded(discover.MAX_FILE_BYTES + 1)})
        self.assertEqual(self.scan(root, self.git_is_absent()), [])

    def test_a_file_at_exactly_the_limit_is_still_read(self):
        # The boundary in both directions, because a limit tested from one side
        # only is a limit that can move by one and stay green.
        root = self.tree({"large.yaml": self.padded(discover.MAX_FILE_BYTES)})
        self.assertEqual(self.raws(self.scan(root, self.git_is_absent())),
                         [KEYCHAIN_REF])

    def padded(self, size):
        """A YAML file of exactly `size` bytes with one reference on line one."""
        head = f"token: {KEYCHAIN_REF}\n"  # pragma: allowlist secret
        return head + "#" * (size - len(head.encode("utf-8")))

    def test_readable_text_says_none_rather_than_raising_on_a_missing_file(self):
        self.assertIsNone(discover.readable_text(str(self.tmpdir() / "gone.yaml")))


class ExamplesAreDroppedOnDemandAndNeverCountAsReferences(DiscoveryCase):
    """`check` resolves `unique_refs` and prints `group_by_ref`.

    An example reaching either one would send the resolver at a placeholder and
    print a row for a secret nobody has.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree({
            "docs/how.md": (
                "shape: azure-keyvault://$VAULT/$NAME\n"
                f"live: {KEYCHAIN_REF}\n"  # pragma: allowlist secret
            ),
            "infra/channels/mail.yaml": f"token: {KEYCHAIN_REF}\n",  # pragma: allowlist secret
            "identity/accounts/onepassword.yaml": "token: op://Engineering/item/credential\n",
        })
        self.findings = self.scan(self.root, self.git_is_absent())

    def test_group_by_ref_keeps_examples_by_default(self):
        grouped = discover.group_by_ref(self.findings)
        self.assertIn("azure-keyvault://$VAULT/$NAME", grouped)

    def test_group_by_ref_without_examples_drops_them(self):
        grouped = discover.group_by_ref(self.findings, examples=False)
        self.assertNotIn("azure-keyvault://$VAULT/$NAME", grouped)
        for key in grouped:
            with self.subTest(key=key):
                self.assertNotIn("$", key)

    def test_group_by_ref_gathers_every_place_one_reference_is_written(self):
        grouped = discover.group_by_ref(self.findings, examples=False)
        places = sorted(finding.path for finding in grouped[KEYCHAIN_REF])
        self.assertEqual(places, ["docs/how.md", "infra/channels/mail.yaml"])

    def test_group_by_ref_keys_a_live_reference_by_its_canonical_spelling(self):
        grouped = discover.group_by_ref(self.findings, examples=False)
        self.assertIn("1password://Engineering/item/credential", grouped)
        self.assertNotIn("op://Engineering/item/credential", grouped)

    def test_unique_refs_never_returns_an_example(self):
        for ref in discover.unique_refs(self.findings):
            with self.subTest(ref=ref.canonical):
                self.assertFalse(discover.is_example(ref.canonical))
                self.assertIn(ref.scheme, refs.SCHEME_NAMES)

    def test_unique_refs_collapses_one_reference_written_in_two_files(self):
        canonicals = [ref.canonical for ref in discover.unique_refs(self.findings)]
        self.assertEqual(canonicals.count(KEYCHAIN_REF), 1)
        self.assertEqual(len(canonicals), 2)

    def test_a_broken_reference_is_grouped_under_the_text_the_file_wrote(self):
        # It has no canonical form to group by, and dropping it would lose the
        # one finding somebody has to act on.
        root = self.tree({"box.yaml": "token: keychain://a/b/c\n"})
        grouped = discover.group_by_ref(self.scan(root, self.git_is_absent()),
                                        examples=False)
        self.assertEqual(list(grouped), ["keychain://a/b/c"])


class CandidateFilesFallsBackToAWalkWhenGitReturnsNothing(DiscoveryCase):
    """Tracked first, walked otherwise, and the seam is how both get measured."""

    def setUp(self):
        super().setUp()
        self.root = self.tree({
            "identity/accounts/cloudflare.yaml": f"token: {KEYCHAIN_REF}\n",  # pragma: allowlist secret
            "node_modules/pkg/index.js": f"const t = '{KEEPASS_REF}'\n",
            "__pycache__/stale.pyc": "irrelevant\n",
            ".venv/lib/thing.py": "irrelevant\n",
        })

    def test_git_is_asked_first_with_the_root_and_a_nul_separator(self):
        runner = self.git_is_absent()
        discover.candidate_files(str(self.root), runner=runner)
        call = runner.calls[0]
        self.assertEqual(call["argv"][:2], ("git", "-C"))
        self.assertEqual(call["argv"][2], os.path.abspath(str(self.root)))
        self.assertIn("ls-files", call["argv"])
        self.assertIn("-z", call["argv"])

    def test_a_tracked_listing_is_used_as_it_stands(self):
        runner = self.git_lists("a.yaml", "b/c.md")
        self.assertEqual(discover.candidate_files(str(self.root), runner=runner),
                         ["a.yaml", "b/c.md"])

    def test_an_empty_listing_falls_back_to_the_walk(self):
        # An empty repository and a repository with nothing tracked yet both
        # answer with zero bytes and exit 0. Trusting that would report a clean
        # tree over a tree nobody had committed.
        runner = FakeRunner().add("ls-files", completed(rc=0, stdout=""))
        listed = discover.candidate_files(str(self.root), runner=runner)
        self.assertIn("identity/accounts/cloudflare.yaml", listed)

    def test_a_non_zero_exit_falls_back_to_the_walk(self):
        listed = discover.candidate_files(str(self.root), runner=self.git_is_absent())
        self.assertIn("identity/accounts/cloudflare.yaml", listed)

    def test_the_walk_returns_paths_relative_to_the_root(self):
        for name in discover.candidate_files(str(self.root), runner=self.git_is_absent()):
            with self.subTest(name=name):
                self.assertFalse(os.path.isabs(name))
                self.assertTrue(os.path.exists(os.path.join(str(self.root), name)))

    def test_the_walk_skips_the_directories_that_hold_no_declaration(self):
        listed = discover.candidate_files(str(self.root), runner=self.git_is_absent())
        joined = " ".join(listed)
        for skipped in ("node_modules", "__pycache__", ".venv"):
            with self.subTest(skipped=skipped):
                self.assertNotIn(skipped, joined)

    def test_the_walk_skips_the_git_directory_itself(self):
        root = self.tree({".git/config": f"token = {KEYCHAIN_REF}\n"})  # pragma: allowlist secret
        self.assertEqual(self.scan(root, self.git_is_absent()), [])

    def test_the_walk_does_not_skip_a_dot_github_directory(self):
        # A workflow file is a declaration like any other: it is where an
        # `env:` value naming a Key Vault secret lives. The tracked listing
        # includes it, so a tree scanned with git present and the same tree
        # scanned without it disagree about what is in the inventory.
        root = self.tree({
            ".github/workflows/deploy.yml": f"  AZURE_TOKEN: {KEYCHAIN_REF}\n",  # pragma: allowlist secret
        })
        findings = self.scan(root, self.git_is_absent())
        self.assertEqual(self.places(findings), [(".github/workflows/deploy.yml", 1)],
                         "the walk prunes every directory whose name starts with "
                         "'.git', so .github goes out with .git")


class ADirectoryHandedToFindKeepsItsPlaceInTheTree(DiscoveryCase):
    """`secrets refs <path>` takes paths, and a path may be a directory.

    Every other route through `find` reports a path that resolves from the
    root, which is what makes the report actionable. The directory route has to
    agree with it or the same file is named two different ways depending on how
    the scan was started.
    """

    def test_a_directory_in_paths_reports_paths_that_resolve_from_the_root(self):
        root = self.tree({"identity/accounts/cloudflare.yaml": f"t: {KEYCHAIN_REF}\n"})
        findings = self.scan(root, self.git_is_absent(), paths=["identity"])
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            os.path.exists(os.path.join(str(root), findings[0].path)),
            "a reported path has to open from the root the scan was given; "
            f"got {findings[0].path!r}")

    def test_a_file_in_paths_reports_a_path_that_resolves_from_the_root(self):
        root = self.tree({"identity/accounts/cloudflare.yaml": f"t: {KEYCHAIN_REF}\n"})
        findings = self.scan(root, self.git_is_absent(),
                             paths=["identity/accounts/cloudflare.yaml"])
        self.assertEqual(findings[0].path, "identity/accounts/cloudflare.yaml")

    def test_naming_paths_does_not_ask_git_anything(self):
        root = self.tree({"a.yaml": f"t: {KEYCHAIN_REF}\n"})
        runner = self.git_is_absent()
        self.scan(root, runner, paths=["a.yaml"])
        self.assertEqual(runner.calls, [])


class InRepoAsksGitDirectlyAndHasNoSeam(DiscoveryCase):
    """The one call in this module that no runner can stand in for.

    Worth a case of its own: every other process in `discover` goes through
    `exec.run`, so a reader who saw the seam everywhere would assume it here
    too and write a test that measures nothing.
    """

    def test_a_temporary_directory_is_not_a_work_tree(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed, so in_repo has nothing to ask")
        self.assertFalse(discover.in_repo(str(self.tmpdir())))

    def test_a_directory_that_is_not_there_answers_false_rather_than_raising(self):
        # `find` is called on whatever root the caller typed, and a typo must
        # not come back as a traceback from a subprocess two layers down.
        if shutil.which("git") is None:
            self.skipTest("git is not installed, so in_repo has nothing to ask")
        self.assertFalse(discover.in_repo(str(self.tmpdir() / "not-there")))


if __name__ == "__main__":  # pragma: no cover - the runner drives unittest
    unittest.main()
