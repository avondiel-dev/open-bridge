"""refs: the grammar, the canonical spelling, the rejections and the scanner.

Nothing in this file holds a value. A reference is a locator, `refs` never
opens a store, and the whole module can be exercised with strings that name
places rather than secrets. That is the point of separating the grammar from
the backends, and it is why this file needs no fixture with a credential in it.

Four groups of cases, and each group has a reason it exists:

* the shape table, because five other places in the repo carry the same list
  of schemes as a literal and `scripts/check-secret-grammar.py` only compares
  the NAMES. Whether each scheme still parses its documented shape is measured
  here.
* the canonical form, because `check` groups findings by it and `unique_refs`
  deduplicates on it. A canonical form that is not a fixed point means two
  spellings of one secret get resolved twice and reported as two entries.
* the rejections, because the caller is a person who has just typed the URI
  into a YAML file by hand. An error that says "invalid" and stops teaches
  nothing, so every case here reads the message as well as the exception type.
* the scanner, because `discover` sees a file one line at a time and quoting
  styles differ per file type. The follower character is the part with a scar:
  it is what tells `keepass://personal/` inside prose apart from a reference
  that really is two segments short.
"""

from __future__ import annotations

import re
import unittest

from tests.conftest import MachineGuard, mod

refs = mod("engine.refs")
errors = mod("engine.errors")


#: One row per declared shape in `rules/secret-placement.md`, written out
#: rather than generated from `SCHEMES`. A table derived from the thing under
#: test agrees with it by construction and measures nothing; this one disagrees
#: the moment a spec changes, which is the whole job.
#:
#: (uri, scheme, store, path, field)
DOCUMENTED_SHAPES = (
    ("azure-keyvault://prod-vault/storage-key",
     "azure-keyvault", "prod-vault", ("storage-key",), None),
    ("keychain://bks-agent-token",
     "keychain", "bks-agent-token", (), None),
    ("keychain://bks-agent-token/opuser",
     "keychain", "bks-agent-token", ("opuser",), None),
    ("1password://Engineering/cloudflare-token/credential",
     "1password", "Engineering", ("cloudflare-token",), "credential"),
    ("op://Engineering/cloudflare-token/credential",
     "1password", "Engineering", ("cloudflare-token",), "credential"),
    ("keepass://personal/org/customer/storage-api/password",
     "keepass", "personal", ("org", "customer", "storage-api"), "password"),
    ("vault://kv/team/deploy/token",
     "vault", "kv", ("team", "deploy"), "token"),
    ("file:///home/opuser/.config/bridge/token",
     "file", "/home/opuser/.config/bridge/token", (), None),
)

#: The references the round-trip cases run over. Short and long forms of each
#: scheme, because the field rules only differ between them.
ROUND_TRIP = tuple(row[0] for row in DOCUMENTED_SHAPES) + (
    "1password://Engineering/cloudflare-token",
    "keepass://personal/org/storage-api",
    "keepass://personal/org/storage-api#api-key",
    "vault://kv/team/deploy",
    "file:///",
)


def parts(ref):
    """The parts of a reference that carry its MEANING.

    Deliberately not `Ref` equality. `Ref` is a dataclass and `raw` is one of
    its fields, so two references to the same place compare unequal whenever
    the files spelled them differently, which is exactly the case the canonical
    form exists for. `raw` is documented as what the file actually said, so it
    is right that it survives parsing and right that it is left out here.
    """
    return (ref.scheme, ref.store, tuple(ref.path), ref.field)


class EverySchemeParsesItsDocumentedShape(MachineGuard):
    """The table in `rules/secret-placement.md`, one case per row."""

    def test_each_documented_shape_parses_into_the_documented_parts(self):
        for uri, scheme, store, path, field in DOCUMENTED_SHAPES:
            with self.subTest(uri=uri):
                ref = refs.parse(uri)
                self.assertEqual(
                    (ref.scheme, ref.store, tuple(ref.path), ref.field),
                    (scheme, store, path, field))

    def test_every_declared_scheme_has_a_row_in_the_table(self):
        # A scheme added to SCHEMES without a row here would be covered by
        # nothing, and the suite would stay green over a grammar nobody
        # measured. The check-secret-grammar script compares scheme NAMES
        # across the repo; it never parses one.
        covered = {refs.parse(row[0]).scheme for row in DOCUMENTED_SHAPES}
        self.assertEqual(covered, set(refs.SCHEME_NAMES))

    def test_the_raw_spelling_is_kept_as_the_file_wrote_it(self):
        ref = refs.parse("op://Engineering/cloudflare-token/credential")
        self.assertEqual(ref.raw, "op://Engineering/cloudflare-token/credential")

    def test_a_scheme_is_read_case_insensitively(self):
        # `parse` lowercases the scheme, so a shouted reference resolves. The
        # scanner does not, which is recorded in its own case below.
        self.assertEqual(parts(refs.parse("KEYCHAIN://bks-agent-token")),
                         parts(refs.parse("keychain://bks-agent-token")))


class TheCanonicalFormIsAFixedPoint(MachineGuard):
    """`check` groups by the canonical form, so it has to stop changing.

    `unique_refs` and `group_by_ref` both key on it. A canonical form that
    parses back into something else means one secret is resolved twice and
    reported as two rows, each of them half the story.
    """

    def test_parsing_the_canonical_form_gives_the_same_reference_back(self):
        for uri in ROUND_TRIP:
            with self.subTest(uri=uri):
                once = refs.parse(uri)
                twice = refs.parse(once.canonical)
                self.assertEqual(parts(twice), parts(once))

    def test_canonicalising_twice_changes_nothing(self):
        for uri in ROUND_TRIP:
            with self.subTest(uri=uri):
                once = refs.parse(uri).canonical
                self.assertEqual(refs.parse(once).canonical, once)

    def test_the_canonical_form_of_a_short_reference_spells_the_default_field(self):
        self.assertEqual(refs.parse("1password://Engineering/cloudflare-token").canonical,
                         "1password://Engineering/cloudflare-token/password")

    def test_the_canonical_form_is_still_a_reference_the_scanner_would_find(self):
        # A canonical form the scanner cannot see would split the inventory:
        # `refs` would report one spelling and `check` another.
        for uri in ROUND_TRIP:
            canonical = refs.parse(uri).canonical
            with self.subTest(uri=uri):
                self.assertEqual(refs.find_in_text(canonical), [canonical])

    def test_a_percent_encoded_separator_survives_canonicalisation(self):
        # `parse` calls `unquote` on every segment, which is a deliberate
        # decision to accept percent-encoding: it is the only way to write a
        # KeePass group or entry whose own name contains a slash, and the rule
        # defines `<group-path>` as slash separated, so the separator has to be
        # escapable. `canonical` joins the decoded segments back with plain
        # slashes and does not re-quote, so the escape is lost and the next
        # parse reads one segment as two.
        once = refs.parse("keepass://personal/team%2Fsub/storage-api/password")
        self.assertEqual(once.path, ("team/sub", "storage-api"))
        twice = refs.parse(once.canonical)
        self.assertEqual(parts(twice), parts(once),
                         "canonical decoded a segment separator it never re-encoded, "
                         "so one group became two")


class TheOpAliasIsAcceptedAndNeverEmitted(MachineGuard):
    """`op://` is the 1Password CLI's own spelling, so people paste it."""

    def test_op_parses_as_1password(self):
        self.assertEqual(refs.parse("op://Engineering/item/credential").scheme,
                         "1password")

    def test_the_canonical_form_never_says_op(self):
        canonical = refs.parse("op://Engineering/item/credential").canonical
        self.assertTrue(canonical.startswith("1password://"), canonical)
        self.assertNotIn("op://", canonical)

    def test_both_spellings_of_one_item_canonicalise_to_one_string(self):
        # This is what stops `check` resolving the same item twice because two
        # files disagreed about which spelling to use.
        self.assertEqual(refs.parse("op://Engineering/item/credential").canonical,
                         refs.parse("1password://Engineering/item/credential").canonical)

    def test_op_is_an_accepted_prefix_but_not_a_declared_scheme(self):
        self.assertIn("op://", refs.URI_PREFIXES)
        self.assertNotIn("op", refs.SCHEME_NAMES)
        self.assertEqual(refs.ALIASES, {"op": "1password"})


class TheFieldIsTheLastSegmentUnlessAHashSaysOtherwise(MachineGuard):
    """The two ways to name a field, and why there are two.

    The slash form is ambiguous the moment an entry is called "password", and
    entries called "password" are common in a KeePass tree that was grown by
    hand. The hash form is the way out, and it has to leave every segment
    before it to the path or it buys nothing.
    """

    def test_the_last_segment_is_the_field(self):
        ref = refs.parse("keepass://personal/org/storage-api/api-key")
        self.assertEqual(ref.field, "api-key")
        self.assertEqual(ref.path, ("org", "storage-api"))

    def test_a_hash_leaves_every_segment_to_the_path(self):
        ref = refs.parse("keepass://personal/org/storage-api#api-key")
        self.assertEqual(ref.field, "api-key")
        self.assertEqual(ref.path, ("org", "storage-api"))

    def test_a_short_reference_gets_the_default_field(self):
        self.assertEqual(refs.parse("1password://Engineering/item").field, "password")
        self.assertEqual(refs.parse("keepass://personal/entry").field, "password")

    def test_vault_defaults_to_value_and_not_to_password(self):
        # HashiCorp KV calls the usual field `value`. A default of `password`
        # here would resolve to a field that is not there and report the entry
        # as missing, which is the wrong diagnosis entirely.
        #
        # Two segments, because the default only applies at the MINIMUM length:
        # `vault://kv/team/deploy` is three and reads `deploy` as the field.
        self.assertEqual(refs.parse("vault://kv/deploy").field, "value")
        self.assertEqual(refs.parse("vault://kv/team/deploy").field, "deploy")

    def test_an_entry_actually_named_password_round_trips(self):
        # Without the hash form this reference means "entry `org`, field
        # `password`". With it, it means "entry `password`, default field".
        ref = refs.parse("keepass://personal/org/password#password")
        self.assertEqual(ref.path, ("org", "password"))
        self.assertEqual(ref.field, "password")
        again = refs.parse(ref.canonical)
        self.assertEqual(parts(again), parts(ref))
        self.assertEqual(again.path[-1], "password")

    def test_the_slash_form_reads_a_trailing_password_as_the_field(self):
        # The other half of the pair above, so the ambiguity is written down
        # rather than implied: the same word means different things in the two
        # spellings, and that is the reason the hash form exists.
        ref = refs.parse("keepass://personal/org/password")
        self.assertEqual(ref.path, ("org",))
        self.assertEqual(ref.field, "password")

    def test_a_scheme_without_a_field_never_carries_one(self):
        for uri in ("keychain://bks-agent-token/opuser",
                    "azure-keyvault://prod-vault/storage-key",
                    "file:///home/opuser/token"):
            with self.subTest(uri=uri):
                self.assertIsNone(refs.parse(uri).field)

    def test_the_label_hides_a_default_field_and_shows_an_explicit_one(self):
        # The label is a column in a report, so it stays quiet about a field
        # nobody chose and loud about one somebody did.
        self.assertEqual(refs.parse("keepass://personal/storage-api").label(),
                         "storage-api")
        self.assertEqual(refs.parse("keepass://personal/storage-api#api-key").label(),
                         "storage-api#api-key")


class EveryRejectionNamesWhatIsWrong(MachineGuard):
    """The message is the product here, not the exception type.

    Every one of these is read by somebody who has just written the URI into a
    YAML file. A rejection that says "invalid reference" sends them to the
    parser source; a rejection that names the expected shape does not.
    """

    def refuse(self, uri):
        with self.assertRaises(errors.ReferenceError_) as caught:
            refs.parse(uri)
        return caught.exception

    def test_an_unknown_scheme_is_named_in_the_message(self):
        problem = self.refuse("kubernetes://ns/secret/key")
        self.assertIn("unknown scheme", str(problem))
        self.assertIn("kubernetes", str(problem))

    def test_keeper_is_rejected_because_nothing_ever_defined_it(self):
        # `keeper://` sat in `identity/accounts/_template.yaml` for months. No
        # rule named it, no parser implemented it, and every account file that
        # copied the template carried a reference that could never resolve.
        # It has to be a loud rejection rather than a scheme that quietly
        # parses into a backend nobody wrote.
        problem = self.refuse("keeper://vault/item/password")
        self.assertIn("unknown scheme", str(problem))
        self.assertIn("keeper", str(problem))
        self.assertIn("secret-placement", problem.hint)
        self.assertNotIn("keeper", refs.SCHEME_NAMES)
        self.assertNotIn("keeper://", refs.URI_PREFIXES)

    def test_too_few_segments_says_how_many_it_wanted(self):
        problem = self.refuse("azure-keyvault://prod-vault")
        self.assertIn("at least 2", str(problem))
        self.assertIn("got 1", str(problem))
        self.assertEqual(problem.hint, "azure-keyvault://<vault>/<secret>")

    def test_too_many_segments_says_how_many_it_takes(self):
        problem = self.refuse("keychain://service/account/extra")
        self.assertIn("at most 2", str(problem))
        self.assertIn("got 3", str(problem))
        self.assertEqual(problem.hint, "keychain://<service>[/<account>]")

    def test_a_field_on_a_scheme_that_has_none_says_to_drop_it(self):
        for uri in ("keychain://service/account#password",
                    "azure-keyvault://prod-vault/storage-key#password",
                    "file:///home/opuser/token#password"):
            with self.subTest(uri=uri):
                problem = self.refuse(uri)
                self.assertIn("no field", str(problem))
                self.assertEqual(problem.hint, "drop the #field part")

    def test_a_relative_file_path_is_refused_with_the_three_slash_shape(self):
        # `file://token` is the typo that looks right: two slashes read the
        # first segment as a host, so the path is relative and resolution
        # would silently depend on the working directory of whoever ran it.
        problem = self.refuse("file://relative/token")
        self.assertIn("absolute path", str(problem))
        self.assertIn("three slashes", problem.hint)

    def test_an_empty_field_after_the_hash_is_refused(self):
        problem = self.refuse("keepass://personal/storage-api#")
        self.assertIn("field is empty", str(problem))

    def test_an_empty_store_is_refused_by_the_name_the_scheme_uses_for_it(self):
        problem = self.refuse("keepass:// /storage-api")
        self.assertIn("database", str(problem))
        self.assertIn("empty", str(problem))

    def test_a_string_that_is_no_reference_lists_the_schemes_that_exist(self):
        problem = self.refuse("AKIA-looking-thing-that-is-not-a-uri")
        self.assertIn("not a secret reference", str(problem))
        for name in refs.SCHEME_NAMES:
            self.assertIn(name, problem.hint)

    def test_a_rejection_that_has_seen_a_scheme_names_the_reference(self):
        # Once a `<scheme>://` prefix is proven, the string is a locator and
        # naming it is how the reader finds the line to fix.
        for uri in ("kubernetes://ns/secret/key", "azure-keyvault://only-one",
                    "keychain://a/b/c", "keychain://a#f", "file://relative/x",
                    "keepass://personal/entry#"):
            with self.subTest(uri=uri):
                problem = self.refuse(uri)
                self.assertEqual(problem.ref, uri)
                self.assertTrue(problem.hint, "a rejection without a hint teaches nothing")
                self.assertIn(uri, problem.report())

    def test_a_rejection_that_has_seen_no_scheme_describes_rather_than_quotes(self):
        # The likeliest thing in this position is the VALUE, typed where a
        # reference belongs: `--env TOKEN=hunter2`, the `docker run -e` habit.
        # Echoing it would put it on stderr, in the transcript and in whatever
        # log the harness keeps, which is the one thing this skill exists to
        # prevent. A length and a fingerprint identify the mistake without
        # disclosing it.
        for uri in ("plain-text", "hunter2-not-a-reference"):
            with self.subTest(uri=uri):
                problem = self.refuse(uri)
                self.assertNotIn(uri, problem.report())
                self.assertIn(str(len(uri)), problem.ref)
                self.assertIn("sha256", problem.ref)
                self.assertTrue(problem.hint, "a rejection without a hint teaches nothing")

    def test_a_control_character_in_a_segment_is_refused_without_an_echo(self):
        # A percent-encoded newline survives unquoting and would split the
        # command line that goes to `security -i` on stdin, so everything after
        # it becomes a second command with a name the reference author chose.
        problem = self.refuse("keychain://svc%0Aadd-generic-password -s evil/acct")
        self.assertIn("control character", str(problem))
        self.assertNotIn("add-generic-password", problem.report())

    def test_a_rejection_exits_as_a_configuration_problem(self):
        # The exit code is the contract a wrapper script reads. A malformed
        # reference is the caller's file being wrong, never the vault being
        # away, so it must not share a code with the unreachable case.
        problem = self.refuse("kubernetes://ns/secret/key")
        self.assertEqual(problem.exit_code, errors.EX_CONFIG)
        self.assertNotEqual(problem.exit_code, errors.EX_UNAVAILABLE)
        self.assertNotEqual(problem.exit_code, errors.EX_MISSING)


class TheExportedListsHoldExactlyTheDeclaredSchemes(MachineGuard):
    """Four copies of one list, and this is where the skill's own two meet.

    `URI_PREFIXES` is read by the overlay leak check to decide that a value is
    a locator rather than a raw secret, and `ENV_VALUE_PATTERN_SOURCE` is
    repeated character for character in the workload schema. A scheme missing
    from the first is a credential reported as a leak; a scheme missing from
    the second is a declaration refused for being correct.
    """

    def expected(self):
        return set(refs.SCHEME_NAMES) | set(refs.ALIASES)

    def test_uri_prefixes_are_the_declared_schemes_plus_the_alias(self):
        self.assertEqual({prefix[:-len("://")] for prefix in refs.URI_PREFIXES},
                         self.expected())

    def test_uri_prefixes_carry_no_duplicate_and_end_in_the_separator(self):
        self.assertEqual(len(refs.URI_PREFIXES), len(set(refs.URI_PREFIXES)))
        for prefix in refs.URI_PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertTrue(prefix.endswith("://"))

    def test_the_env_pattern_alternation_is_the_same_set(self):
        alternation = re.search(r"\^\(([^)]*)\)://", refs.ENV_VALUE_PATTERN_SOURCE)
        self.assertIsNotNone(alternation, refs.ENV_VALUE_PATTERN_SOURCE)
        self.assertEqual(set(alternation.group(1).split("|")), self.expected())

    def test_the_compiled_env_pattern_accepts_a_locator_of_every_scheme(self):
        pattern = re.compile(refs.ENV_VALUE_PATTERN_SOURCE)
        for uri in ("azure-keyvault://prod-vault/storage-key",
                    "keychain://bks-agent-token",
                    "1password://Engineering/item/credential",
                    "op://Engineering/item/credential",
                    "keepass://personal/org/storage-api/password",
                    "vault://kv/team/deploy/token",
                    "file:///home/opuser/token"):
            with self.subTest(uri=uri):
                self.assertTrue(pattern.match(uri))

    def test_the_compiled_env_pattern_refuses_what_is_not_a_locator(self):
        pattern = re.compile(refs.ENV_VALUE_PATTERN_SOURCE)
        for value in ("keeper://vault/item",          # the ghost scheme
                      "https://example.com/token",    # a URL, not a locator
                      "keychain://",                  # a scheme and nothing else
                      "keychain://a b",               # a value with a space in it
                      " keychain://a",                # leading whitespace
                      "prefix keychain://a",          # a locator inside prose
                      "KEYCHAIN://a"):                # the pattern is lowercase
            with self.subTest(value=value):
                self.assertIsNone(pattern.match(value))

    def test_the_env_pattern_also_accepts_a_locator_with_a_newline_glued_on(self):
        # Measured, not endorsed. The pattern ends in `$`, and Python reads `$`
        # as "end of string, or just before a final newline". The workload
        # schema carries this pattern character for character to validate an
        # `execution.env` value, so a value that picked up a trailing newline
        # passes a gate whose whole job is to say what the value may be. The
        # case is here so that a later `\Z` is a deliberate change with a test
        # that moves, rather than a surprise.
        pattern = re.compile(refs.ENV_VALUE_PATTERN_SOURCE)
        self.assertIsNotNone(pattern.match("keychain://bks-agent-token\n"))

    def test_is_reference_agrees_with_the_prefix_list(self):
        self.assertTrue(refs.is_reference("op://Engineering/item/credential"))
        self.assertTrue(refs.is_reference("keychain://service"))
        self.assertFalse(refs.is_reference("keeper://vault/item"))
        self.assertFalse(refs.is_reference("https://example.com"))
        self.assertFalse(refs.is_reference(None))

    def test_is_reference_says_nothing_about_whether_it_parses(self):
        # The leak check needs "this is a locator" before anything knows
        # whether it is a well formed one. A malformed locator is still not a
        # raw credential, so reporting it as one would be the wrong alarm.
        self.assertTrue(refs.is_reference("keychain://a/b/c"))
        with self.assertRaises(errors.ReferenceError_):
            refs.parse("keychain://a/b/c")


class SeveralReferencesOnOneLineAreAllFound(MachineGuard):
    """The scanner sees a file one line at a time, and lines are messy.

    A YAML value is quoted one way, a shell line another, prose neither, and a
    markdown table wraps everything in backticks. All four shapes appear in
    this repo, so the scanner has to end a reference on the quote rather than
    swallow it.
    """

    def test_quoted_and_unquoted_references_are_found_side_by_side(self):
        line = ('token: "keychain://bks-agent/opuser" and '
                'keepass://personal/org/storage-api/password, plus '
                "op://Engineering/item/credential.")
        self.assertEqual(refs.find_in_text(line), [
            "keychain://bks-agent/opuser",
            "keepass://personal/org/storage-api/password",
            "op://Engineering/item/credential",
        ])

    def test_a_single_quoted_value_ends_at_the_quote(self):
        self.assertEqual(refs.find_in_text("env: 'file:///home/opuser/token'"),
                         ["file:///home/opuser/token"])

    def test_a_backticked_value_ends_at_the_backtick(self):
        # Every shape in `rules/secret-placement.md` is written inside
        # backticks, so a scanner that ate them would report the whole table.
        self.assertEqual(refs.find_in_text("| `keychain://service` | an item |"),
                         ["keychain://service"])

    def test_a_trailing_full_stop_is_not_part_of_the_reference(self):
        found, follower = next(refs.iter_in_text("see keychain://bks-agent/opuser."))
        self.assertEqual(found, "keychain://bks-agent/opuser")
        self.assertEqual(follower, ".")

    def test_a_trailing_colon_is_not_part_of_the_reference(self):
        found, follower = next(refs.iter_in_text("a: vault://kv/team/deploy/token:"))
        self.assertEqual(found, "vault://kv/team/deploy/token")
        self.assertEqual(follower, ":")

    def test_a_markdown_link_does_not_swallow_the_closing_bracket(self):
        line = "[keychain://bks-agent/opuser](notes.md) and (keepass://personal/entry)"
        self.assertEqual(refs.find_in_text(line),
                         ["keychain://bks-agent/opuser", "keepass://personal/entry"])

    def test_the_follower_is_the_character_that_stopped_the_match(self):
        line = ('token: "keychain://bks-agent/opuser", '
                "next keepass://personal/entry/password;")
        self.assertEqual([follower for _, follower in refs.iter_in_text(line)],
                         ['"', ";"])

    def test_a_placeholder_cut_at_an_angle_bracket_reports_the_bracket(self):
        # The line is taken from `rules/secret-placement.md`. Nothing in the
        # matched text says it is prose: `keepass://personal/` on its own is a
        # reference one segment short, and reporting it as broken would put a
        # false entry at the top of every scan of the repo. The bracket that
        # stopped the match is the only evidence there is.
        line = "keepass://personal/<org>/<service>/hf-token/token"
        found, follower = next(refs.iter_in_text(line))
        self.assertEqual(found, "keepass://personal/")
        self.assertEqual(follower, "<")

    def test_a_placeholder_right_after_the_scheme_is_not_matched_at_all(self):
        # `keychain://<service>/<account>` has no character the scanner would
        # accept after the separator, so it never becomes a match. That is the
        # quiet half of the example handling: such a line is invisible rather
        # than classified, and it is worth knowing which of the two happened
        # when a documented shape does not turn up in a scan.
        self.assertEqual(refs.find_in_text("keychain://<service>/<account>"), [])

    def test_a_brace_placeholder_stays_inside_the_match(self):
        # `{` is not in the scanner's stop set, so a brace placeholder is
        # carried into the matched text and has to be recognised there rather
        # than by the follower. `discover.is_example` is what catches it.
        found, follower = next(refs.iter_in_text("keychain://${SERVICE}/account"))
        self.assertEqual(found, "keychain://${SERVICE")
        self.assertEqual(follower, "}")

    def test_an_ellipsis_inside_a_shape_stays_inside_the_match(self):
        found, _ = next(refs.iter_in_text("keepass://personal/…/entry/password"))
        self.assertIn("…", found)

    def test_a_foreign_store_scheme_is_seen_although_nothing_can_read_it(self):
        # `keeper://` sat in identity/accounts/_template.yaml three times,
        # defined in no list and resolvable by nothing. It stayed invisible
        # because the scanner matched only schemes it already knew, which is the
        # one case the inventory exists to surface. The alternation therefore
        # carries a watchlist of foreign stores as well. `parse` still rejects
        # them, and that rejection is what `refs` reports.
        self.assertEqual(refs.find_in_text("api: keeper://vault/item"),
                         ["keeper://vault/item"])
        with self.assertRaises(errors.ReferenceError_):
            refs.parse("keeper://vault/item")

    def test_a_scheme_in_neither_list_is_invisible_and_that_is_the_stated_limit(self):
        # The honest half. A store nobody has heard of is not detected, because
        # the alternative is matching every `x://` in the tree, which is every
        # URL in every document. The watchlist is the compromise, and this case
        # records its edge rather than leaving it to be found later.
        self.assertEqual(refs.find_in_text("api: inventedvault://a/b"), [])

    def test_a_scheme_glued_to_a_preceding_word_is_not_a_reference(self):
        # The leading word boundary. Without it, `https://.../keyvault://x`
        # and similar noise would enter the inventory.
        self.assertEqual(refs.find_in_text("myfile:///home/opuser/token"), [])
        self.assertEqual(refs.find_in_text("a-file:///home/opuser/token"),
                         ["file:///home/opuser/token"])

    def test_a_shouted_reference_is_not_matched_although_parse_would_take_it(self):
        # The one place the two halves of this module disagree. Recorded so
        # that a scan reporting nothing over an upper case reference is a
        # known property rather than an afternoon.
        self.assertEqual(refs.find_in_text("KEYCHAIN://bks-agent"), [])
        self.assertEqual(refs.parse("KEYCHAIN://bks-agent").scheme, "keychain")

    def test_a_line_with_no_reference_yields_nothing(self):
        self.assertEqual(refs.find_in_text("nothing to see, https://example.com/x"), [])
        self.assertEqual(list(refs.iter_in_text("")), [])

    def test_find_in_text_is_iter_in_text_without_the_followers(self):
        text = "keychain://a/b and keepass://personal/entry/password."
        self.assertEqual(refs.find_in_text(text),
                         [raw for raw, _ in refs.iter_in_text(text)])

    def test_every_reference_the_scanner_finds_on_a_clean_line_parses(self):
        # The contract `discover` leans on: a match without a placeholder in it
        # is a reference, so an error on one of these is a real defect in the
        # file rather than in the scanner.
        text = "\n".join(row[0] for row in DOCUMENTED_SHAPES)
        for raw in refs.find_in_text(text):
            with self.subTest(raw=raw):
                refs.parse(raw)


if __name__ == "__main__":  # pragma: no cover - the runner drives unittest
    unittest.main()
