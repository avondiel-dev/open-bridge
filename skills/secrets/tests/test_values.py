"""values: the wrapper that will not print itself, and the redactor.

Two properties are measured here, and nothing else in this tree guards either.

The first is that a value cannot land in a log line by accident. Every way
Python turns an object into text goes through `__str__` or `__format__`, so a
wrapper that guards only one of them is guarded nowhere: an f-string reaches
`__format__` and never touches `__str__`. The cases below use all three
spellings a caller reaches for, plus the one spelling that is allowed to work,
`!r`, because a report has to be able to name the value it is talking about.

The second is that a value which has already left the process is recognised on
the way back in. A token handed to a child comes back wearing whatever encoding
the tool in the middle applied: base64 from a shell pipeline, hex from a dump,
percent escapes from a URL, JSON escapes from an API error body. A redactor that
only knows the raw spelling prints the value it was built to hide.

The trailing newline case is a measured leak rather than an invented one.
`printenv TOKEN | base64` encodes the value WITH the newline the shell added,
and that encoding shares only a prefix with the encoding of the value alone, so
one character of the real base64 survived the scrub. That is why the assertion
there is equality against the placeholder and not `assertNotIn`: the residue was
never the whole string, and `assertNotIn` on the full encoding would have passed
while the leak was live.

No fixture here holds a credential. Every value is assembled at runtime, either
by `synthetic_token()` from the conftest or by the two helpers below, so there
is no literal in this file for anybody to copy.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from urllib.parse import quote

from tests.conftest import MachineGuard, mod, synthetic_token

values = mod("engine.values")


def awkward_password() -> str:
    """A password carrying the characters that change shape on the way out.

    A slash and a plus are percent escaped, a double quote and a backslash are
    JSON escaped, so ONE value exercises both encodings rather than two values
    exercising one each. That matters because the two encodings overlap: a
    value that only needed percent escaping would leave the JSON variant
    untested and the case would still read as if it covered both.
    """
    return "pw" + "/" + "a+b" + '"' + "c" + "\\" + "d" + "-1234"


def binary_key() -> bytes:
    """Bytes that are not text, and whose two base64 alphabets differ.

    The standard alphabet ends in `+` and `/`, the url safe one in `-` and `_`,
    and those last two table entries are the only difference between them. A
    value whose encoding never reaches them cannot tell a redactor that knows
    one alphabet from a redactor that knows both, so the bytes here are chosen
    to reach them. They are also not valid UTF-8, which is the second half of
    the point: a key file is bytes, the text variants cannot be built for it,
    and the encodings are all the redactor has to work with.
    """
    return bytes((0xFB, 0xFF, 0xFE, 0xFA, 0xFF, 0xFB, 0x3E, 0x3F))


# ---------------------------------------------------------------------------
# Secret
# ---------------------------------------------------------------------------

class ASecretRefusesToRenderAsText(MachineGuard):
    """The value must not reach a log line because somebody interpolated it."""

    def setUp(self):
        super().setUp()
        self.token = synthetic_token("ghp")
        self.secret = values.Secret(self.token, origin="keychain://github/token")

    def test_str_raises_rather_than_returning_the_value(self):
        with self.assertRaises(TypeError):
            str(self.secret)

    def test_an_f_string_raises_the_same_way(self):
        # An f-string goes to __format__ and never touches __str__, so a
        # wrapper that guarded only __str__ would print the value here, in the
        # single most common way a message gets built.
        with self.assertRaises(TypeError):
            f"{self.secret}"

    def test_percent_formatting_raises_too(self):
        with self.assertRaises(TypeError):
            "%s" % self.secret

    def test_joining_it_into_a_line_raises_as_well(self):
        with self.assertRaises(TypeError):
            " ".join(["Authorization: Bearer", self.secret])

    def test_the_refusal_says_where_to_go_instead(self):
        # A TypeError with no route is a puzzle. The message names `expose()`,
        # which is also the term `grep -rn expose(` finds, so the reader lands
        # on the review surface rather than inventing a way around it.
        with self.assertRaises(TypeError) as caught:
            str(self.secret)
        self.assertIn("expose()", str(caught.exception))

    def test_the_repr_describes_and_does_not_disclose(self):
        shown = repr(self.secret)
        self.assertNotIn(self.token, shown)
        self.assertIn(str(len(self.token)), shown)
        self.assertIn(self.secret.fingerprint, shown)
        self.assertIn("keychain://github/token", shown)

    def test_the_repr_conversion_in_an_f_string_still_works(self):
        # The one spelling that has to keep working: a report names the value
        # it is talking about, and `!r` is how it does that.
        self.assertEqual(f"{self.secret!r}", repr(self.secret))

    def test_describe_carries_the_same_two_facts_and_no_third(self):
        described = self.secret.describe()
        self.assertNotIn(self.token, described)
        self.assertIn(str(len(self.token)), described)
        self.assertIn(self.secret.fingerprint, described)


class AValueThatIsNeitherTextNorBytesIsRefused(MachineGuard):
    """`bytes(5)` is five zero bytes, not the text "5".

    So an integer handed to the wrapper becomes a block of NUL bytes that is
    not empty, carries a fingerprint, and reports as a healthy read all the way
    up through `check`. `password: 12345678` in a YAML file parses as an int,
    and 12345678 is also how many zero bytes that value would become.

    No shipped backend can hand it one today: both decode from the output of a
    process, so both arrive with `str` or `bytes`. The wrapper is still the one
    place a value lives, and a silent conversion there is not visible anywhere
    downstream, which is the whole argument for refusing it at the door.
    """

    def test_an_integer_does_not_become_that_many_zero_bytes(self):
        with self.assertRaises(TypeError):
            values.Secret(5)

    def test_a_boolean_does_not_become_one_zero_byte(self):
        with self.assertRaises(TypeError):
            values.Secret(True)


class TheFingerprintIsTheFirstEightHexCharactersOfSha256(MachineGuard):
    """How two machines compare a secret without either learning the other's copy."""

    def test_it_matches_hashlib(self):
        token = synthetic_token("fp")
        self.assertEqual(
            values.Secret(token).fingerprint,
            hashlib.sha256(token.encode("utf-8")).hexdigest()[:8],
        )

    def test_it_is_eight_hex_characters_and_not_the_whole_digest(self):
        # Long enough to tell two live tokens apart in a report, short enough
        # that somebody holding the report and not the vault has no handle.
        shown = values.Secret(synthetic_token("fp")).fingerprint
        self.assertEqual(len(shown), 8)
        self.assertTrue(all(char in "0123456789abcdef" for char in shown), shown)

    def test_two_values_that_differ_by_one_character_do_not_share_one(self):
        token = synthetic_token("fp")
        self.assertNotEqual(
            values.Secret(token).fingerprint,
            values.Secret(token[:-1] + "x").fingerprint,
        )

    def test_text_and_its_utf8_bytes_fingerprint_alike(self):
        # One machine reads the value as text and another as bytes. If the two
        # fingerprints differed, a report comparing them would call a matching
        # pair a rotation.
        token = synthetic_token("same")
        self.assertEqual(
            values.Secret(token).fingerprint,
            values.Secret(token.encode("utf-8")).fingerprint,
        )

    def test_the_module_level_helper_agrees_with_the_wrapper(self):
        raw = binary_key()
        self.assertEqual(values.fingerprint(raw), values.Secret(raw).fingerprint)


class TwoSecretsAreEqualWhenTheirBytesAre(MachineGuard):
    """Equality is by value, and by a constant time compare.

    Timing is deliberately not asserted. A wall clock measurement on a shared
    runner is noise, and a case that goes red when the machine is busy teaches
    people to rerun it rather than to read it. What is asserted is the half a
    test can see: the answer has the same shape whether the difference sits in
    the first byte or the last, a shorter value sharing the whole prefix is
    still a miss, and a bare bytes object is NOT equal to a wrapped one, so
    nobody can quietly replace this with a raw byte compare and keep the suite
    green.
    """

    def setUp(self):
        super().setUp()
        self.token = synthetic_token("eq")
        self.secret = values.Secret(self.token)

    def test_equal_values_compare_equal(self):
        self.assertEqual(self.secret, values.Secret(self.token))

    def test_the_same_value_from_two_stores_compares_equal(self):
        # Origin is metadata about where it came from, not part of the value.
        # A copy in the keychain and a copy in the database are the same secret
        # or they are a rotation that somebody left half finished.
        self.assertEqual(
            values.Secret(self.token, origin="keychain://a/b"),
            values.Secret(self.token, origin="keepass://work/a/b/password"),
        )

    def test_a_difference_in_the_last_byte_is_a_miss(self):
        self.assertNotEqual(self.secret, values.Secret(self.token[:-1] + "x"))

    def test_a_difference_in_the_first_byte_is_a_miss_in_the_same_way(self):
        self.assertNotEqual(self.secret, values.Secret("x" + self.token[1:]))

    def test_a_shorter_value_sharing_the_whole_prefix_is_a_miss(self):
        self.assertNotEqual(self.secret, values.Secret(self.token[:-1]))

    def test_the_raw_bytes_are_not_equal_to_the_wrapper(self):
        self.assertNotEqual(self.secret, self.token.encode("utf-8"))
        self.assertNotEqual(self.secret, self.token)

    def test_equal_secrets_collapse_to_one_entry_in_a_set(self):
        self.assertEqual(len({values.Secret(self.token), values.Secret(self.token)}), 1)


class AnEmptyValueIsAMissAndAShortOneIsNot(MachineGuard):
    """`security find-generic-password` exits 0 for an item holding zero bytes.

    So emptiness is the thing a caller has to be able to see, and it is not the
    same question as shortness: a one byte value is a bad password, not an
    absent one, and a caller that conflates the two rotates a secret that was
    never gone.
    """

    def test_zero_bytes_is_empty(self):
        self.assertTrue(values.Secret(b"").is_empty())

    def test_one_byte_is_not_empty(self):
        self.assertFalse(values.Secret("a").is_empty())

    def test_truthiness_follows_the_same_line(self):
        self.assertFalse(bool(values.Secret(b"")))
        self.assertTrue(bool(values.Secret("a")))

    def test_length_is_counted_in_bytes_and_not_in_characters(self):
        # The length column in a report is a measurement of what the store
        # holds. A value with an umlaut in it is two bytes per umlaut, and a
        # column that counted characters would disagree with the store.
        umlaut = "a" + "ä" + "b"
        self.assertEqual(len(values.Secret(umlaut)), 4)


class AReadingThatFoundNothingCarriesNoLengthAndNoFingerprint(MachineGuard):
    """A Reading is the metadata of a read that may not have happened.

    It is kept separate from Secret so a report can carry `present=False`
    without carrying an empty Secret that a careless caller would inject as if
    it were real.
    """

    def test_a_miss_has_no_length(self):
        reading = values.Reading(ref="keychain://github/token", present=False)
        self.assertEqual(reading.length, 0)

    def test_a_miss_has_no_fingerprint(self):
        reading = values.Reading(ref="keychain://github/token", present=False)
        self.assertEqual(reading.fingerprint, "")

    def test_a_hit_carries_both_from_the_secret(self):
        token = synthetic_token("rd")
        secret = values.Secret(token)
        reading = values.Reading(ref="keychain://github/token", present=True, secret=secret)
        self.assertEqual(reading.length, len(token))
        self.assertEqual(reading.fingerprint, secret.fingerprint)

    def test_an_empty_entry_is_absent_and_still_measurable(self):
        # The keychain case: the item exists and holds no bytes. The Reading
        # says absent, and the fingerprint of the empty value is still there,
        # so a report can show that an entry WAS found and was empty rather
        # than showing the same blank row a missing entry produces.
        reading = values.Reading(ref="keychain://github/token", present=False,
                                 secret=values.Secret(b""),
                                 note="the item exists and holds no bytes")
        self.assertFalse(reading.present)
        self.assertEqual(reading.length, 0)
        self.assertEqual(reading.fingerprint, values.fingerprint(b""))


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------

class TheRedactorRemovesTheValueInEveryShapeItLeavesIn(MachineGuard):
    """Each of these is a way a value reached the agent past a raw-spelling scrub."""

    def setUp(self):
        super().setUp()
        self.password = awkward_password()
        self.redactor = values.Redactor()
        self.redactor.register("DB_PASSWORD", values.Secret(self.password))
        self.hole = "[redacted:DB_PASSWORD]"

    def test_the_raw_value_is_gone(self):
        self.assertEqual(self.redactor.scrub("password is " + self.password),
                         "password is " + self.hole)

    def test_percent_encoding_is_gone(self):
        # The shape a value wears inside a connection string that some client
        # built and then printed in its own error message.
        encoded = quote(self.password, safe="")
        self.assertNotEqual(encoded, self.password, "this case would prove nothing otherwise")
        self.assertEqual(self.redactor.scrub("url=" + encoded), "url=" + self.hole)

    def test_json_escaping_is_gone(self):
        # An API that was handed the token and echoed it back inside an error
        # body escapes the quote and the backslash, and nothing else changes.
        escaped = json.dumps(self.password)[1:-1]
        self.assertNotEqual(escaped, self.password, "this case would prove nothing otherwise")
        body = '{"detail":"bad credentials for ' + escaped + '"}'
        self.assertNotIn(self.password, self.redactor.scrub(body))
        self.assertIn(self.hole, self.redactor.scrub(body))

    def test_the_hex_form_is_gone_in_lower_case(self):
        hexed = binascii.hexlify(self.password.encode("utf-8")).decode("ascii")
        self.assertEqual(self.redactor.scrub("dump " + hexed), "dump " + self.hole)

    def test_the_hex_form_is_gone_in_upper_case(self):
        hexed = binascii.hexlify(self.password.encode("utf-8")).decode("ascii").upper()
        self.assertEqual(self.redactor.scrub("dump " + hexed), "dump " + self.hole)

    def test_padded_base64_is_gone(self):
        encoded = base64.b64encode(self.password.encode("utf-8")).decode("ascii")
        self.assertEqual(self.redactor.scrub("blob=" + encoded), "blob=" + self.hole)

    def test_unpadded_base64_is_gone(self):
        # Half the encoders in the world drop the padding. The unpadded form is
        # a prefix of the padded one, so a scrub that only knew the padded form
        # would leave the whole value standing rather than part of it.
        encoded = base64.b64encode(self.password.encode("utf-8")).decode("ascii").rstrip("=")
        self.assertEqual(self.redactor.scrub("blob=" + encoded), "blob=" + self.hole)


class ABinaryValueIsCoveredInBothBase64Alphabets(MachineGuard):
    """A key file is bytes, so the encodings are all the redactor has.

    The two base64 alphabets differ only in their last two table entries, so a
    value whose encoding never reaches those two cannot tell a redactor that
    knows one alphabet from one that knows both.
    """

    def setUp(self):
        super().setUp()
        self.raw = binary_key()
        self.redactor = values.Redactor()
        self.redactor.register("SIGNING_KEY", values.Secret(self.raw))
        self.hole = "[redacted:SIGNING_KEY]"

    def test_the_two_encodings_really_do_differ(self):
        # Without this the two cases below could both be passing against the
        # same string, and the second would be measuring nothing.
        self.assertNotEqual(base64.b64encode(self.raw), base64.urlsafe_b64encode(self.raw))

    def test_the_standard_alphabet_is_removed(self):
        encoded = base64.b64encode(self.raw).decode("ascii")
        self.assertEqual(self.redactor.scrub("key=" + encoded), "key=" + self.hole)

    def test_the_url_safe_alphabet_is_removed(self):
        encoded = base64.urlsafe_b64encode(self.raw).decode("ascii")
        self.assertEqual(self.redactor.scrub("key=" + encoded), "key=" + self.hole)

    def test_the_hex_form_is_removed_in_both_cases(self):
        lower = binascii.hexlify(self.raw).decode("ascii")
        self.assertEqual(self.redactor.scrub(lower), self.hole)
        self.assertEqual(self.redactor.scrub(lower.upper()), self.hole)

    def test_a_value_that_is_not_text_is_still_registered(self):
        # The text variants cannot be built for these bytes. A register that
        # gave up on the UnicodeDecodeError would have skipped the value
        # entirely and reported nothing at all.
        self.assertEqual(self.redactor.names, ("SIGNING_KEY",))
        self.assertEqual(self.redactor.skipped, [])


class Base64OfTheValuePlusTheNewlineTheShellAddedIsRemovedWhole(MachineGuard):
    """The measured leak this family of variants exists for.

    `printenv TOKEN | base64` encodes the value WITH the trailing newline, and
    that encoding shares only a prefix with the encoding of the value alone. A
    redactor registering the value alone therefore replaced the shared prefix
    and printed the rest: one character of the real base64 survived when this
    was measured. Equality against the placeholder is the assertion, because
    the residue was never the whole string and `assertNotIn` on the full
    encoding would have been green throughout.
    """

    def setUp(self):
        super().setUp()
        self.token = synthetic_token("ghp")
        self.redactor = values.Redactor()
        self.redactor.register("GITHUB_TOKEN", values.Secret(self.token))
        self.hole = "[redacted:GITHUB_TOKEN]"

    def test_nothing_of_the_line_feed_encoding_survives(self):
        encoded = base64.b64encode(self.token.encode("utf-8") + b"\n").decode("ascii")
        self.assertEqual(self.redactor.scrub(encoded), self.hole)

    def test_the_carriage_return_form_goes_too(self):
        # The same pipeline on a file that came off Windows, or through a tool
        # that writes CRLF.
        encoded = base64.b64encode(self.token.encode("utf-8") + b"\r\n").decode("ascii")
        self.assertEqual(self.redactor.scrub(encoded), self.hole)

    def test_the_encoding_of_the_bare_value_still_goes(self):
        encoded = base64.b64encode(self.token.encode("utf-8")).decode("ascii")
        self.assertEqual(self.redactor.scrub(encoded), self.hole)

    def test_the_value_with_its_newline_written_out_plainly_goes(self):
        self.assertEqual(self.redactor.scrub(self.token + "\n"), self.hole + "\n")


class ThePlaceholderNamesTheVariableThatHeldTheValue(MachineGuard):
    """Output with a hole in it is only readable when the hole says which secret it was.

    A run that passes three references and then sees one of them echoed needs
    to know WHICH one, because that is the one to rotate.
    """

    def setUp(self):
        super().setUp()
        self.token = synthetic_token("api")
        self.redactor = values.Redactor()
        self.redactor.register("API_TOKEN", values.Secret(self.token))

    def test_the_name_lands_in_the_output(self):
        self.assertIn("API_TOKEN", self.redactor.scrub("sent " + self.token))

    def test_the_value_does_not(self):
        self.assertNotIn(self.token, self.redactor.scrub("sent " + self.token))

    def test_two_registered_values_keep_their_own_names(self):
        other = synthetic_token("smtp")
        self.redactor.register("SMTP_PASSWORD", values.Secret(other))
        cleaned = self.redactor.scrub("api " + self.token + " smtp " + other)
        self.assertEqual(cleaned, "api [redacted:API_TOKEN] smtp [redacted:SMTP_PASSWORD]")

    def test_the_names_are_reported_in_registration_order(self):
        self.redactor.register("SMTP_PASSWORD", values.Secret(synthetic_token("smtp")))
        self.assertEqual(self.redactor.names, ("API_TOKEN", "SMTP_PASSWORD"))


class TheLongestRegisteredValueWinsWhateverOrderTheyCameIn(MachineGuard):
    """Two secrets where one contains the other, registered shorter first.

    Measured on this tree: with API_KEY registered before API_SECRET, scrubbing
    a line holding API_SECRET replaces the stretch of it that is also API_KEY
    and prints the remaining nine characters of API_SECRET. Variants are sorted
    by length WITHIN one `register` call and appended across calls, so the
    order the caller passed the two references decides which value survives.

    The second half is what makes this a leak rather than an untidy
    placeholder: after that substitution the text matches no registered pattern
    any more, so `holds` calls the output clean and `cli._emit` prints it. The
    belt and the braces both go green over a value that is right there in the
    line.

    `secrets run --env API_KEY=... --env API_SECRET=...` is the ordinary way to
    meet this: two references on one command line, in the order somebody typed
    them.
    """

    def setUp(self):
        super().setUp()
        self.key = "ab" + "c123"                    # pragma: allowlist secret
        self.longer = self.key + "def456ghi"        # pragma: allowlist secret
        self.redactor = values.Redactor()
        self.redactor.register("API_KEY", values.Secret(self.key))
        self.redactor.register("API_SECRET", values.Secret(self.longer))

    def test_the_longer_value_is_removed_whole(self):
        cleaned = self.redactor.scrub("secret=" + self.longer)
        self.assertNotIn(self.longer[len(self.key):], cleaned)

    def test_the_second_pair_of_eyes_does_not_go_quiet_over_the_remains(self):
        # True when the scrub is fixed, and true when it is not fixed but
        # `holds` still reports the residue. It fails only in the state that
        # actually prints a secret.
        cleaned = self.redactor.scrub("secret=" + self.longer)
        residue = self.longer[len(self.key):]
        self.assertFalse(
            residue in cleaned and not self.redactor.holds(cleaned),
            "part of API_SECRET survived the scrub AND holds() called the result "
            "clean, so cli._emit would print it: " + repr(cleaned))

    def test_the_other_registration_order_is_already_correct(self):
        # The same two values, longest first, come out whole. The defect is the
        # ORDER and not the pair, which is what makes the repair a sort over
        # all registered patterns rather than another variant.
        redactor = values.Redactor()
        redactor.register("API_SECRET", values.Secret(self.longer))
        redactor.register("API_KEY", values.Secret(self.key))
        self.assertEqual(redactor.scrub("secret=" + self.longer),
                         "secret=[redacted:API_SECRET]")


class AValueTooShortToRedactIsReportedRatherThanCovered(MachineGuard):
    """A two character replacement would black out ordinary words.

    So a value under MIN_REDACTABLE is left alone and its NAME is reported
    instead. `skipped` is the only signal there is: `holds` answers from the
    registered patterns, and a value that was never registered cannot be found
    by it, so a caller reading `holds` alone and ignoring `skipped` prints a
    short value and believes it did not.
    """

    def setUp(self):
        super().setUp()
        self.short = "ab" + "cde"
        self.assertLess(len(self.short), values.MIN_REDACTABLE)
        self.redactor = values.Redactor()
        self.redactor.register("PIN", values.Secret(self.short))

    def test_it_lands_in_skipped(self):
        self.assertEqual(self.redactor.skipped, ["PIN"])

    def test_it_is_not_among_the_names(self):
        self.assertEqual(self.redactor.names, ())

    def test_the_text_is_left_exactly_as_it_came(self):
        text = "the pin is " + self.short + " and the rest is ordinary prose"
        self.assertEqual(self.redactor.scrub(text), text)

    def test_holds_cannot_see_what_was_never_registered(self):
        # Recorded rather than wished away: this is precisely why `skipped` has
        # to be printed by the caller. `holds` is silent here and the value is
        # right there in the line.
        self.assertFalse(self.redactor.holds("the pin is " + self.short))

    def test_a_value_at_the_threshold_is_redacted(self):
        # The boundary, from the other side. MIN_REDACTABLE itself is long
        # enough, and a comparison that drifted by one would silently stop
        # covering the shortest values it is supposed to cover.
        threshold = "zq" + "7k4m"
        self.assertEqual(len(threshold), values.MIN_REDACTABLE)
        redactor = values.Redactor()
        redactor.register("OTP", values.Secret(threshold))
        self.assertEqual(redactor.skipped, [])
        self.assertEqual(redactor.scrub("otp " + threshold), "otp [redacted:OTP]")


class ScrubbingIsIdempotentAndLeavesCleanTextAlone(MachineGuard):
    """`cli._emit` scrubs and then asks `holds` about the result.

    A scrub whose second pass differed from its first would make that check a
    different question from the one the caller thinks it asked, and a scrub
    that touched clean text would corrupt the child's output for every run in
    which nothing leaked, which is nearly all of them.
    """

    def setUp(self):
        super().setUp()
        self.token = synthetic_token("idem")
        self.redactor = values.Redactor()
        self.redactor.register("TOKEN", values.Secret(self.token))

    def test_a_second_pass_changes_nothing(self):
        once = self.redactor.scrub("bearer " + self.token + " ok")
        self.assertEqual(self.redactor.scrub(once), once)

    def test_text_without_a_registered_value_comes_back_unchanged(self):
        text = "GET /health 200 in 4ms, nothing to hide here\n"
        self.assertEqual(self.redactor.scrub(text), text)

    def test_empty_text_comes_back_unchanged(self):
        self.assertEqual(self.redactor.scrub(""), "")

    def test_a_redactor_with_nothing_registered_is_a_pass_through(self):
        self.assertEqual(values.Redactor().scrub("anything at all"), "anything at all")


class HoldsIsTheSecondPairOfEyesBeforeAnythingIsPrinted(MachineGuard):
    """`run` calls it on its own output and refuses to print what it could not clean.

    That refusal is worth something only if `holds` answers about the text it
    was handed, so both directions are measured: it says yes to a survivor and
    it goes quiet once the text is actually clean.
    """

    def setUp(self):
        super().setUp()
        self.token = synthetic_token("hold")
        self.redactor = values.Redactor()
        self.redactor.register("TOKEN", values.Secret(self.token))

    def test_it_reports_a_survivor(self):
        self.assertTrue(self.redactor.holds("Authorization: Bearer " + self.token))

    def test_it_is_quiet_once_the_text_is_clean(self):
        dirty = "Authorization: Bearer " + self.token
        self.assertFalse(self.redactor.holds(self.redactor.scrub(dirty)))

    def test_it_finds_an_encoded_survivor_too(self):
        encoded = base64.b64encode(self.token.encode("utf-8")).decode("ascii")
        self.assertTrue(self.redactor.holds("blob=" + encoded))

    def test_text_that_never_held_a_value_reports_nothing(self):
        self.assertFalse(self.redactor.holds("GET /health 200 in 4ms"))

    def test_empty_text_holds_nothing(self):
        self.assertFalse(self.redactor.holds(""))
