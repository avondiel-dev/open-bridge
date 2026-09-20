"""patterns: what counts as a secret, and how little of it a report may say.

One pattern set replaced three that had drifted apart, so this file measures the
properties the three copies used to disagree about, and the two properties that
decide whether anybody keeps reading the report.

1. THE LIST IS USABLE BY THE THINGS THAT READ IT. `audit` looks a finding up in
   `BY_NAME` to say where the value belongs, and `scripts/check-secret-patterns.py`
   greps the other copies for `marker`. A duplicate name loses a pattern out of
   the lookup without changing a single scan result, and a marker that names
   nothing in its own pattern reports parity with a copy that carries something
   else. Both are quiet, so both get a case.

2. A SHAPE FIRES ON ITSELF AND ON NOTHING NEXT DOOR. Every pattern is driven
   with a synthetic example of its own format, and every example is driven
   against the whole list. A GitHub token that also reads as an OpenAI key makes
   the suggestion wrong, and a wrong suggestion sends somebody to the wrong
   store.

3. THE THREE SHAPES THE OLDER COPIES WALKED PAST. The fine-grained GitHub
   token, the Google key and the Bearer header, one blind spot each, named in
   the module docstring of `patterns.py`. Each case asserts the shape is found
   AND that `copies` now forces it into the scan that used to miss it, because
   finding it here and not there is the state this list was built to end.

4. A NAME IS NOT A VALUE. The assignment heuristic reads `token = ...` lines,
   where the shape proves nothing on its own: measured over this repo it
   produced 106 findings and 5 of them were real. `looks_opaque` is what
   collapsed the other 101, so each reason it rejects something gets a case, and
   each case carries a twin that IS accepted. Without the twin a rejection
   passes for the wrong reason, which is a green case measuring nothing.

5. NO REPORT QUOTES ENOUGH OF A VALUE TO USE IT. `excerpt` is capped at eight
   characters plus an ellipsis. The rule has a scar: a verify pass once decoded
   a credential into a transcript while checking whether the credential was
   really there, so the log written to protect the value was where the value
   ended up.

6. PERSONAL DATA IS REPORTED AND NEVER MOVED. An IBAN is on every invoice and a
   tax id unlocks nothing. Both are worth knowing about where they lie, neither
   may be proposed for a vault, and `--no-pii` has to drop exactly those two and
   keep the credentials standing on the same line.

NO CREDENTIAL IS WRITTEN DOWN HERE. Every example is assembled at runtime from
its format's alphabet, the way `conftest.synthetic_token` does it, so there is
no literal in this file worth copying. The irony is unavoidable and worth
naming: a suite about a scanner is full of strings shaped like the thing the
scanner looks for, the scanner runs over this repo including this file, and the
few lines that still read as a credential carry the allowlist pragma for exactly
the reason the pragma exists.

Nothing here touches a process or a store. `patterns.py` is a pure module, so
the cases are calls and comparisons; `MachineGuard` stands behind them anyway,
because a class in this suite that does not inherit it looks identical in a
green run.
"""

from __future__ import annotations

import unittest

from tests.conftest import MachineGuard, mod, synthetic_token

patterns = mod("engine.patterns")


# ---------------------------------------------------------------------------
# Examples, assembled rather than pasted
# ---------------------------------------------------------------------------

#: The same deterministic construction `conftest.synthetic_token` uses, with the
#: alphabet as a parameter. It is here and not there because a vendor format
#: dictates its own alphabet: an AWS key id is upper case and digits, a Google
#: key also takes `-` and `_`, and a base64 account key takes `+` and `/`. A body
#: drawn from the wrong alphabet produces a string the real regex would never
#: meet, and a pattern proved against it is proved against nothing.
_MIXED = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"  # pragma: allowlist secret
_UPPER_DIGITS = "ABCDEFGHIJKLMNPQRSTUVWXYZ23456789"
_DIGITS = "0123456789"
_BASE64 = _MIXED + "+/"
_URLSAFE = _MIXED + "-_"


def _shaped(prefix: str, length: int, alphabet: str = _MIXED) -> str:
    """A body of `length` characters out of `alphabet`, stable for `prefix`.

    Deterministic, so a failing assertion reproduces with the same string rather
    than with a new one that may not fail.
    """
    offset = sum(ord(character) for character in prefix)
    return "".join(alphabet[(offset + step * 7) % len(alphabet)]
                   for step in range(length))


#: Every vendor prefix is split across two pieces. Not decoration: the suite's
#: own credential scan reads the raw source line, and an unsplit `ghp_` followed
#: by a long body is exactly what it refuses. Splitting keeps this file free of
#: the shape without weakening the fixture, since the value the engine sees is
#: assembled before it gets there.
def _private_key() -> str:
    return "-----" + "BEGIN" + " RSA PRIVATE KEY-----"


def _ssh_public() -> str:
    return "ssh-" + "rsa AAAA" + _shaped("sshkey", 40) + " deploy@buildhost"


def _aws_key() -> str:
    return "AK" + "IA" + _shaped("awskey", 16, _UPPER_DIGITS)


def _aws_temp_key() -> str:
    return "AS" + "IA" + _shaped("awstemp", 16, _UPPER_DIGITS)


def _github_token() -> str:
    return "gh" + "p_" + _shaped("ghclassic", 36)


def _github_fine_grained() -> str:
    return "github" + "_pat_" + _shaped("ghfine", 60, _MIXED + "_")


def _slack_token() -> str:
    return "xo" + "xb-" + _shaped("slack", 12, _DIGITS) + "-" + _shaped("slackbody", 24)


def _openai_key() -> str:
    return "s" + "k-" + _shaped("openai", 40)


def _google_key() -> str:
    # Exactly 35 characters after the prefix. The regex says `{35}`, which is the
    # real format, so a body of 34 or 36 would prove the opposite of the case.
    return "AI" + "za" + _shaped("googlekey", 35, _URLSAFE)


def _jwt() -> str:
    return ("ey" + "J" + _shaped("jwthead", 24) + "."
            + "ey" + "J" + _shaped("jwtbody", 30) + "."
            + _shaped("jwtsig", 28))


def _azure_account_key() -> str:
    return ("DefaultEndpointsProtocol=https;AccountName=invoices;"
            + "Account" + "Key=" + _shaped("azurekey", 40, _BASE64) + "==")


def _bearer_header() -> str:
    return "Authorization: " + "Bearer " + _shaped("bearer", 40)


def _password_assignment() -> str:
    return "password = " + _shaped("handwritten", 20)


#: The Bundesbank's documentation IBAN, which is what a well formed one looks
#: like and belongs to nobody. The pragma is on the line for the engine's own
#: sake: `audit` scans this repo, this literal is what it is looking for, and a
#: scanner that reports its own fixtures teaches its reader to skim.
IBAN_LINE = "pay the invoice to DE89 3704 0044 0532 0130 00"  # pragma: allowlist secret

#: Eleven digits in ascending order, so the number is plainly made up: a real
#: German tax id carries a check digit this one fails.
TAX_ID_LINE = "Steuer-ID: 12345678901"  # pragma: allowlist secret


#: One synthetic line per pattern, keyed by the pattern's own name. A case below
#: holds this table to the list, so a pattern that arrives without an example is
#: a red case rather than a loop that quietly measures one shape less.
EXAMPLES = {
    "private-key": _private_key(),
    "ssh-public-with-key": _ssh_public(),
    "aws-access-key": _aws_key(),
    "aws-temp-key": _aws_temp_key(),
    "github-token": _github_token(),
    "github-fine-grained": _github_fine_grained(),
    "slack-token": _slack_token(),
    "openai-style-key": _openai_key(),
    "google-api-key": _google_key(),
    "jwt": _jwt(),
    "azure-account-key": _azure_account_key(),
    "bearer-token": _bearer_header(),
    "password-assignment": _password_assignment(),
    "iban": IBAN_LINE,
    "german-tax-id": TAX_ID_LINE,
}

#: Lines that carry no secret and are the shapes a scanner most likes to trip
#: over. A false positive costs the same as a miss in the end: it is how a
#: reader learns to skim the report.
INNOCENT_LINES = (
    "from engine import patterns as patterns_mod",
    "# the value belongs in the keychain, not in this file",
    "reference: keychain://invoice-gateway/outbound",
    "config_path = /home/opuser/projects/invoices/settings.yaml",
    "class AReferenceIsALocationAndNeverAValue(MachineGuard):",
    "token = request.headers",
    "Bearer authentication is described in references/resolve.md",
)

#: The two copies `scripts/check-secret-patterns.py` compares against. Written
#: down here rather than read out of that script: the skill has to keep working
#: when its directory is copied out of the repo on its own, so a case in it may
#: not reach up into the repo for the list it checks. A third name appearing in
#: `copies` is a promise made to a file nothing compares.
KNOWN_COPIES = ("overlay", "promote")

#: The patterns that live in this skill and nowhere else. The assignment
#: heuristic, because the overlay scan deliberately runs no key-and-value guess
#: over code, where it is wrong far more often than right. The personal-data
#: pair, because a promote scan is not where personal data is decided.
SKILL_ONLY = ("german-tax-id", "iban", "password-assignment")

#: The one pattern name that is an acronym instead of words. JWT is the name of
#: the format itself, so a reader who meets it in a report already has the whole
#: term. Every other pattern either carries a note or is a compound of words.
SELF_EXPLAINING_ACRONYMS = ("jwt",)


class PatternCase(MachineGuard):
    """Shared lookups. The guard comes with it, which is why it is a base."""

    def names(self, line: str, *, include_pii: bool = True):
        """The pattern names that fire on `line`, in the order they fire."""
        return [pattern.name for pattern, _ in
                patterns.scan_line(line, include_pii=include_pii)]

    def excerpts(self, line: str):
        return [text for _, text in patterns.scan_line(line)]

    def pattern(self, name: str):
        found = patterns.BY_NAME.get(name)
        self.assertIsNotNone(found, "the list no longer carries %r" % name)
        return found


# ---------------------------------------------------------------------------
# 1. The list is usable by the things that read it
# ---------------------------------------------------------------------------

class EveryPatternCarriesWhatItsReadersLookUp(PatternCase):
    """Four fields, and each of them is read by something outside this module.

    `name` is the key `audit` resolves a finding through, `marker` is the string
    the parity check greps the other copies for, `kind` decides which half of the
    report a finding lands in, and a note or a speaking name is what the person
    reading the finding gets instead of "suspicious string".
    """

    def test_every_pattern_has_a_name_and_no_two_share_one(self):
        # A duplicate name is invisible in every scan and empties one pattern out
        # of BY_NAME, so `audit` stops proposing a store for it and says nothing
        # about why.
        names = [pattern.name for pattern in patterns.ALL]
        self.assertTrue(all(names), "a pattern has an empty name: %s" % names)
        self.assertEqual(
            sorted(names), sorted(set(names)),
            "two patterns share a name, so BY_NAME carries fewer entries than "
            "the list and audit loses the suggestion for one of them")
        self.assertEqual(
            len(patterns.BY_NAME), len(patterns.ALL),
            "BY_NAME holds %d of %d patterns"
            % (len(patterns.BY_NAME), len(patterns.ALL)))

    def test_every_pattern_names_a_kind_the_report_can_route(self):
        # `Report.credentials` and `Report.pii` filter on this string. A third
        # spelling is not an error anywhere: the finding simply appears in
        # neither list, and a scan that found something reports nothing.
        for pattern in patterns.ALL:
            with self.subTest(pattern=pattern.name):
                self.assertIn(
                    pattern.kind, ("credential", "pii"),
                    "%s carries kind %r, which no half of the report selects"
                    % (pattern.name, pattern.kind))

    def test_each_group_holds_only_its_own_kind(self):
        # The wrong tuple is worse than the wrong kind: a personal-data pattern
        # among the credentials gets proposed for a vault, and a credential among
        # the PII never gets proposed at all.
        for pattern in patterns.CREDENTIALS:
            with self.subTest(credential=pattern.name):
                self.assertEqual(pattern.kind, "credential")
        for pattern in patterns.PII:
            with self.subTest(pii=pattern.name):
                self.assertEqual(pattern.kind, "pii")
        self.assertEqual(
            len(patterns.ALL), len(patterns.CREDENTIALS) + len(patterns.PII),
            "ALL is no longer the two groups, so a group exists that nothing "
            "scans and no case here covers")

    def test_a_marker_that_is_compared_against_a_copy_is_recoverable_from_it(self):
        # The parity check greps another file for this string. If the string
        # names nothing in the pattern that declares it, the check can report
        # that a copy carries a shape while the copy carries something else, and
        # a green parity run is the whole point of having one.
        for pattern in patterns.ALL:
            if not pattern.copies:
                continue            # nothing greps for it, see the case below
            with self.subTest(pattern=pattern.name):
                self.assertTrue(
                    self.recoverable(pattern),
                    "%s declares the marker %r, which appears neither in its "
                    "own expression nor in an alias nor in the text its own "
                    "example matches"
                    % (pattern.name, pattern.marker))

    def recoverable(self, pattern) -> bool:
        """Whether the marker names something this pattern really carries.

        Two ways, and both are honest evidence. Either the marker or an alias
        stands in the expression itself, which is how `AKIA` and `gh[pousr]_`
        are carried, or the marker stands in the text the expression matches,
        which is how `ssh-rsa` and `ghp_` are carried without appearing
        literally in a character class.
        """
        spellings = (pattern.marker, *pattern.aliases)
        if any(spelling in pattern.regex.pattern for spelling in spellings):
            return True
        match = pattern.regex.search(EXAMPLES[pattern.name])
        return bool(match) and pattern.marker in match.group(0)

    def test_the_patterns_exempt_from_that_are_only_the_skill_only_ones(self):
        # The exemption above is `not pattern.copies`. This is what stops it
        # growing: a pattern that drops its copies to silence the case would
        # also have to appear here.
        exempt = sorted(p.name for p in patterns.ALL if not p.copies)
        self.assertEqual(
            exempt, sorted(SKILL_ONLY),
            "the marker check skips %s, and only the skill-only patterns are "
            "meant to be skipped" % exempt)

    def test_every_marker_is_unique_because_the_parity_check_greps_for_it(self):
        markers = list(patterns.MARKERS)
        self.assertEqual(
            sorted(markers), sorted(set(markers)),
            "two patterns share a marker, so one gap in another copy reads as "
            "covered by the other pattern: %s" % markers)
        self.assertEqual(
            markers, [pattern.marker for pattern in patterns.ALL],
            "MARKERS has drifted away from ALL, and it is what the parity "
            "check iterates")

    def test_every_pattern_explains_itself_by_note_or_by_name(self):
        # The finding a person reads says the pattern's name and, in verbose
        # mode, its note. "suspicious string" is what this avoids.
        for pattern in patterns.ALL:
            with self.subTest(pattern=pattern.name):
                self.assertTrue(
                    pattern.note
                    or "-" in pattern.name
                    or pattern.name in SELF_EXPLAINING_ACRONYMS,
                    "%s is neither a compound name nor annotated, so a reader "
                    "meeting it in a report learns nothing from it"
                    % pattern.name)


# ---------------------------------------------------------------------------
# 2. A shape fires on itself and on nothing next door
# ---------------------------------------------------------------------------

class EachShapeFiresOnItsOwnExampleAndOnNoOther(PatternCase):
    """Both halves, because each one alone is comfortable and wrong.

    A pattern that fires on its own example and on three neighbours produces a
    finding that names the wrong vendor, and `audit` then proposes the wrong
    store for it. A pattern that fires on nothing is a line of the list that
    looks like coverage.
    """

    def test_the_example_table_covers_every_pattern_in_the_list(self):
        # Otherwise the loops below shrink silently when a pattern is added, and
        # the new one is the only one nobody drove.
        self.assertEqual(
            sorted(EXAMPLES), sorted(pattern.name for pattern in patterns.ALL),
            "the example table and the pattern list disagree, so some pattern "
            "is measured by nothing here")

    def test_every_pattern_fires_on_an_example_of_its_own_shape(self):
        for name in sorted(EXAMPLES):
            with self.subTest(pattern=name):
                self.assertIn(
                    name, self.names(EXAMPLES[name]),
                    "%s did not fire on a synthetic line of its own format"
                    % name)

    def test_no_example_fires_a_neighbouring_pattern(self):
        for name in sorted(EXAMPLES):
            with self.subTest(pattern=name):
                self.assertEqual(
                    self.names(EXAMPLES[name]), [name],
                    "a line carrying one %s also fired %s, so a finding can "
                    "name the wrong vendor and audit can propose the wrong "
                    "store" % (name, self.names(EXAMPLES[name])))

    def test_a_github_token_is_not_an_openai_key(self):
        # The pair the whole matrix above exists for, spelled out, because this
        # is the confusion a reader of the report would have to catch.
        self.assertEqual(self.names(_github_token()), ["github-token"])
        self.assertEqual(self.names(_openai_key()), ["openai-style-key"])
        self.assertIsNone(
            self.pattern("openai-style-key").regex.search(_github_token()),
            "the OpenAI expression matches a GitHub token")
        self.assertIsNone(
            self.pattern("github-token").regex.search(_openai_key()),
            "the GitHub expression matches an OpenAI key")

    def test_an_ordinary_line_fires_nothing(self):
        for line in INNOCENT_LINES:
            with self.subTest(line=line):
                self.assertEqual(
                    self.names(line), [],
                    "an ordinary line was reported, and a report with noise in "
                    "it gets skimmed, which is how the real hit gets skimmed too")

    def test_the_whole_line_is_read_including_a_comment(self):
        # The one live credential that reached a tracked file in this repo sat
        # in a comment, put there by the commit that added the detector for it.
        commented = "# left here by mistake: " + _aws_key()
        self.assertEqual(self.names(commented), ["aws-access-key"])


# ---------------------------------------------------------------------------
# 3. The three shapes the older copies each walked past
# ---------------------------------------------------------------------------

class TheThreeShapesTheOlderCopiesWalkedPast(PatternCase):
    """One blind spot per copy, and the fix is not only that they are found.

    The promote scan had no `github_pat_`, the overlay scan had no `Bearer`, and
    neither of the two had `AIza`, which was known only to a rule that never left
    one instance. Finding them here and not in the copies is the state this list
    was made to end, so each case also asserts that `copies` now forces the
    pattern into the scan that used to miss it.
    """

    def test_the_fine_grained_github_token_is_detected(self):
        self.assertEqual(self.names(_github_fine_grained()),
                         ["github-fine-grained"])
        self.assertIn(
            "promote", self.pattern("github-fine-grained").copies,
            "the promote scan is the copy that did not know this format, so it "
            "is the copy the parity check has to hold to it")

    def test_the_older_github_prefix_does_not_cover_the_fine_grained_one(self):
        # Why there are two GitHub patterns rather than one. Without this the
        # second one reads as a duplicate and the next reader deletes it.
        self.assertIsNone(
            self.pattern("github-token").regex.search(_github_fine_grained()),
            "the classic prefix pattern matches the fine-grained format, which "
            "would make the second pattern redundant")

    def test_the_google_api_key_is_detected(self):
        self.assertEqual(self.names(_google_key()), ["google-api-key"])
        for copy in KNOWN_COPIES:
            with self.subTest(copy=copy):
                self.assertIn(
                    copy, self.pattern("google-api-key").copies,
                    "both CORE scans were blind to AIza, so both have to carry "
                    "it now")

    def test_the_bearer_header_is_detected(self):
        self.assertEqual(self.names(_bearer_header()), ["bearer-token"])
        self.assertIn(
            "overlay", self.pattern("bearer-token").copies,
            "the overlay scan is the copy that did not know the Bearer header")

    def test_a_bearer_header_with_a_short_value_is_not_reported(self):
        # The header word on its own is prose, and there is a lot of prose about
        # bearer tokens in this tree. Twenty characters is where the expression
        # draws the line, so the line is measured rather than assumed.
        self.assertEqual(self.names("Authorization: " + "Bearer " + "abc123"), [])


# ---------------------------------------------------------------------------
# 4. A name is not a value
# ---------------------------------------------------------------------------

class LooksOpaqueSeparatesAValueFromTheCodeAroundIt(PatternCase):
    """The heuristic that made the assignment pattern usable.

    Measured over this repo, the assignment pattern without this second question
    produced 106 findings and 5 of them were real. The other 101 were calls,
    interpolations, dotted paths and stand-in words: every one of them a line
    where the NAME says `token` and the VALUE says something else.

    Each case here carries a twin that is accepted. A rejection on its own goes
    green for whatever reason happens to fire first, which for most of these
    strings is the length rule rather than the rule the case is named after.
    """

    def test_a_call_is_not_a_value(self):
        # Mixed case and a digit on purpose. `get_deploy_token()` is rejected
        # twice over, by the parentheses and by being all one character class,
        # so it would stay red with the parentheses rule deleted and the case
        # would be measuring the other rule under this name.
        self.assertFalse(patterns.looks_opaque("getDeployToken3()"))
        self.assertTrue(patterns.looks_opaque("getDeployToken3x"),
                        "the same string without the parentheses is a value, so "
                        "the parentheses are what the case measures")

    def test_an_interpolation_is_not_a_value(self):
        self.assertFalse(patterns.looks_opaque("$DEPLOYMENT_TOKEN_A1"))
        self.assertTrue(patterns.looks_opaque("DEPLOYMENT_TOKEN_A1"))

    def test_a_template_placeholder_is_not_a_value(self):
        self.assertFalse(patterns.looks_opaque("{{ deployment_secret_A1 }}"))
        self.assertTrue(patterns.looks_opaque("deployment_secret_A1"))

    def test_a_dotted_path_is_not_a_value(self):
        # `token = request.headers` is the shape that produced the largest share
        # of those 101, and it is NOT the fixture here: being all lower case it
        # is rejected by the character-class rule as well, so it stays rejected
        # with the dotted-path rule deleted. The mixed-case path below passes
        # every other rule, which makes the dot the only thing under measurement.
        self.assertFalse(patterns.looks_opaque("self.headers.Authorization"))
        self.assertTrue(patterns.looks_opaque("selfheadersAuthorization"))
        self.assertFalse(patterns.looks_opaque("request.headers"),
                         "the shape the scar is named after")

    def test_a_stand_in_word_is_not_a_value(self):
        body = _shaped("standin", 12)
        for word in ("example", "redacted", "changeme", "your-token"):
            with self.subTest(word=word):
                self.assertFalse(
                    patterns.looks_opaque(word + body),
                    "%r is what a person writes where a value goes" % word)
                self.assertTrue(
                    patterns.looks_opaque(_shaped(word, 9) + body),
                    "the same length and the same character classes without the "
                    "stand-in word is a value, so the word is what was measured")

    def test_a_value_under_twelve_characters_is_not_a_value(self):
        self.assertFalse(patterns.looks_opaque("aB3dE6gH1"))
        self.assertTrue(patterns.looks_opaque("aB3dE6gH1jK4m"),
                        "the same alphabet at twelve characters is a value")

    def test_a_value_of_one_character_class_is_not_a_value(self):
        for uniform in ("abcdefghijklmnop", "ABCDEFGHIJKLMNOP", "348715930264"):
            with self.subTest(value=uniform):
                self.assertFalse(patterns.looks_opaque(uniform))
        self.assertTrue(patterns.looks_opaque("abcdefghijklmn4p"),
                        "one digit in the same string is the whole difference")

    def test_a_realistic_opaque_token_is_accepted(self):
        # The direction that matters most: a heuristic that rejects everything
        # is not a filter, it is a scanner that has been switched off.
        self.assertTrue(patterns.looks_opaque(synthetic_token("opaque")))

    def test_the_assignment_pattern_only_fires_once_the_value_is_opaque(self):
        # The two halves joined up: the confirm hook is what carries the
        # heuristic into the scan, and without it the scan is the 106 findings.
        self.assertEqual(self.names(_password_assignment()),
                         ["password-assignment"])
        for line in ("password = get_deploy_token()",
                     "api_key = $DEPLOYMENT_TOKEN_A1",
                     "client_secret = request.headers",
                     "token = changeme-before-first-run"):
            with self.subTest(line=line):
                self.assertEqual(
                    self.names(line), [],
                    "the assignment pattern reported a line whose value is not "
                    "a value")

    def test_the_hand_written_spellings_are_all_reached(self):
        # The German spellings are in the expression because this tree is
        # written in two languages, and a pattern nobody drives is a claim.
        body = _shaped("spelling", 20)
        for key in ("password", "passwort", "kennwort", "api_key",
                    "api-key", "client_secret", "token"):
            with self.subTest(key=key):
                self.assertEqual(self.names(key + " = " + body),
                                 ["password-assignment"])


# ---------------------------------------------------------------------------
# 5. A line that declares itself a fixture
# ---------------------------------------------------------------------------

class ADeliberateFixtureSaysSoOnItsOwnLine(PatternCase):
    """The pragma, and nothing but the pragma, silences a line.

    A synthetic fixture carries it and a real secret never does, which is the
    whole contract. It is spelled the way `detect-secrets` spells it so that one
    convention covers both tools, and a second spelling here would mean a line
    marked for one scanner and loud in the other.
    """

    def test_the_pragma_is_spelled_the_way_detect_secrets_spells_it(self):
        self.assertEqual(patterns.PRAGMA, "pragma: allowlist secret")

    def test_a_line_carrying_the_pragma_reports_nothing(self):
        line = _aws_key() + "  # " + patterns.PRAGMA
        self.assertEqual(self.names(line), [])

    def test_the_same_line_without_the_pragma_reports(self):
        # The twin, so the case above cannot pass because the fixture stopped
        # being credential shaped.
        self.assertEqual(self.names(_aws_key()), ["aws-access-key"])

    def test_the_pragma_counts_wherever_it_stands_on_the_line(self):
        for line in (patterns.PRAGMA + ": " + _aws_key(),
                     _aws_key() + "  # " + patterns.PRAGMA,
                     "<!-- " + patterns.PRAGMA + " --> " + _aws_key()):
            with self.subTest(line=line):
                self.assertTrue(patterns.exempt(line))
                self.assertEqual(self.names(line), [])

    def test_an_ordinary_comment_silences_nothing(self):
        # Otherwise "it is fine, honestly" in a comment would be enough, and the
        # exceptions stop being countable.
        line = _aws_key() + "  # this one is revoked, honestly"
        self.assertFalse(patterns.exempt(line))
        self.assertEqual(self.names(line), ["aws-access-key"])

    def test_the_pragma_silences_personal_data_too(self):
        # The fixtures in this file are the reason: an IBAN written down as an
        # example is still what the PII pattern looks for.
        self.assertEqual(self.names(IBAN_LINE + "  # " + patterns.PRAGMA), [])


# ---------------------------------------------------------------------------
# 6. Personal data is reported and never moved
# ---------------------------------------------------------------------------

class PersonalDataIsReportedAndNeverProposedForAVault(PatternCase):
    """An IBAN is on every invoice and a tax id unlocks nothing.

    Both are worth knowing about where they lie in a repo that ships, and
    neither may be proposed for a store: locking an IBAN away makes it useless
    for its own purpose and buys no security. `audit` reads `suggests` to decide
    what to propose, so an empty `suggests` is what enforces that.
    """

    def test_a_well_formed_iban_is_found(self):
        self.assertEqual(self.names(IBAN_LINE), ["iban"])

    def test_a_german_tax_id_line_is_found(self):
        self.assertEqual(self.names(TAX_ID_LINE), ["german-tax-id"])

    def test_the_tax_id_pattern_needs_the_word_and_not_only_eleven_digits(self):
        # Eleven digits on their own are an order number as often as a tax id,
        # and a pattern that reported both would be off within a week.
        self.assertEqual(self.names("order number 12345678901"), [])

    def test_neither_personal_data_pattern_proposes_a_store(self):
        for pattern in patterns.PII:
            with self.subTest(pattern=pattern.name):
                self.assertEqual(
                    pattern.suggests, "",
                    "%s proposes %r. Personal data is reported where it lies "
                    "and never moved into a vault"
                    % (pattern.name, pattern.suggests))

    def test_every_personal_data_pattern_carries_the_pii_kind(self):
        # `Report.pii` selects on it, and `audit._suggest` skips on it. A PII
        # pattern marked as a credential would be proposed for a store by the
        # same code path that proposes one for a GitHub token.
        for pattern in patterns.PII:
            with self.subTest(pattern=pattern.name):
                self.assertEqual(pattern.kind, "pii")

    def test_dropping_personal_data_keeps_the_credential_on_the_same_line(self):
        # One line carrying all three, so the toggle is measured where it is
        # hardest: a filter that dropped the line rather than the two patterns
        # would look identical on a line that carries only an IBAN.
        line = _aws_key() + "  " + IBAN_LINE + "  " + TAX_ID_LINE
        self.assertEqual(self.names(line),
                         ["aws-access-key", "iban", "german-tax-id"])
        self.assertEqual(self.names(line, include_pii=False),
                         ["aws-access-key"])

    def test_dropping_personal_data_is_the_only_thing_the_flag_does(self):
        for name in sorted(EXAMPLES):
            pattern = self.pattern(name)
            if pattern.kind == "pii":
                continue
            with self.subTest(pattern=name):
                self.assertEqual(
                    self.names(EXAMPLES[name], include_pii=False), [name],
                    "--no-pii changed what a credential pattern reports")


# ---------------------------------------------------------------------------
# 7. No report quotes enough of a value to use it
# ---------------------------------------------------------------------------

class NoExcerptCarriesEnoughOfAValueToUseIt(PatternCase):
    """Eight characters, and the rule has a scar.

    A verify pass once decoded a base64 credential into a transcript while
    checking whether the credential was really there, so the log that existed to
    protect the value is where the value ended up. A finding is a location; the
    excerpt is there to recognise the hit in the file and for nothing else.
    """

    #: The cap `excerpt` declares. Written down so the cases below fail with a
    #: number rather than with a length nobody can compare against anything.
    CAP = 8

    def test_a_match_shorter_than_the_cap_comes_back_whole(self):
        self.assertEqual(patterns.excerpt("AK" + "IA12"), "AK" + "IA12")

    def test_a_match_of_exactly_the_cap_is_not_cut(self):
        # The boundary, because `<=` and `<` differ by exactly this case and a
        # trailing ellipsis on a complete value is a lie about what was found.
        eight = _shaped("boundary", self.CAP)
        self.assertEqual(patterns.excerpt(eight), eight)

    def test_a_long_match_is_cut_to_the_cap_and_an_ellipsis(self):
        long_value = _shaped("verylong", 64)
        cut = patterns.excerpt(long_value)
        self.assertEqual(len(cut), self.CAP + 1,
                         "an excerpt of %d characters: %r" % (len(cut), cut))
        self.assertTrue(cut.endswith("…"))
        self.assertEqual(cut[:self.CAP], long_value[:self.CAP])

    def test_the_tail_of_a_long_match_is_nowhere_in_the_excerpt(self):
        long_value = _shaped("tailcheck", 64)
        cut = patterns.excerpt(long_value)
        self.assertNotIn(long_value[self.CAP:], cut)
        self.assertNotIn(long_value, cut)

    def test_no_excerpt_a_scan_produces_is_longer_than_the_cap(self):
        # Over the whole table, because the cap is applied in `scan_line` and a
        # pattern added later reaches the report through the same call.
        for name in sorted(EXAMPLES):
            for text in self.excerpts(EXAMPLES[name]):
                with self.subTest(pattern=name, excerpt=text):
                    self.assertLessEqual(
                        len(text), self.CAP + 1,
                        "%s put %d characters of a value into a finding"
                        % (name, len(text)))

    def test_a_scan_of_a_long_credential_keeps_the_value_out_of_the_finding(self):
        # The end to end version of the scar: the value goes in, the finding
        # comes out, and the value is not in it.
        token = _github_token()
        found = patterns.scan_line(token)
        self.assertEqual([pattern.name for pattern, _ in found], ["github-token"])
        for _, text in found:
            self.assertNotIn(token, text)
            self.assertNotIn(token[self.CAP:], text)


# ---------------------------------------------------------------------------
# 8. copies: which other scanners have to carry the pattern
# ---------------------------------------------------------------------------

class CopiesSaysWhichOtherScannersHaveToCarryThePattern(PatternCase):
    """The field the parity check routes by, held to the two copies that exist.

    `copies` is a promise: the pattern has to appear in each file named there,
    and `scripts/check-secret-patterns.py` fails the repo when it does not. A
    name nobody compares is a promise made to nothing, and an empty tuple on a
    pattern that belongs in a copy is a blind spot that reports as green.
    """

    def test_the_skill_only_patterns_are_the_assignment_heuristic_and_the_pii_pair(self):
        self.assertEqual(
            sorted(p.name for p in patterns.ALL if not p.copies),
            sorted(SKILL_ONLY),
            "the set of patterns that live only in this skill has changed. "
            "The assignment heuristic stays here because the overlay scan runs "
            "no key-and-value guess over code, and personal data stays here "
            "because a promote scan is not where it is decided")

    def test_every_other_pattern_names_at_least_one_copy(self):
        for pattern in patterns.ALL:
            if pattern.name in SKILL_ONLY:
                continue
            with self.subTest(pattern=pattern.name):
                self.assertTrue(
                    pattern.copies,
                    "%s is carried by this skill alone, so the other scanners "
                    "walk past the shape and nothing says so" % pattern.name)

    def test_a_copy_name_is_one_of_the_two_that_are_really_compared(self):
        for pattern in patterns.ALL:
            for copy in pattern.copies:
                with self.subTest(pattern=pattern.name, copy=copy):
                    self.assertIn(
                        copy, KNOWN_COPIES,
                        "%s promises to appear in %r, which is not a file the "
                        "parity check reads" % (pattern.name, copy))

    def test_no_pattern_names_the_same_copy_twice(self):
        for pattern in patterns.ALL:
            with self.subTest(pattern=pattern.name):
                self.assertEqual(
                    sorted(pattern.copies), sorted(set(pattern.copies)),
                    "%s names a copy twice, which reads as two obligations and "
                    "is one" % pattern.name)

    def test_the_personal_data_patterns_reach_no_copy_at_all(self):
        # Said directly rather than only through the set above: a promote scan
        # that carried the IBAN pattern would refuse a promote over an invoice
        # number, and the next person would switch the scan off.
        for pattern in patterns.PII:
            with self.subTest(pattern=pattern.name):
                self.assertEqual(pattern.copies, ())


if __name__ == "__main__":
    unittest.main()
