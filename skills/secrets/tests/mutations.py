"""The mutation battery: proof that this suite has teeth.

Every entry names one literal inside one source, the softened version of it, and
the ONE test that has to turn red when the softening is applied. A suite that
stays green under any of these is not a suite. It reports a proof nobody ran,
which is worse than reporting none, and in a skill whose whole job is to keep a
value out of a transcript the difference is not academic.

Each needle guards a behaviour that already cost something. The scars are the
ones written down in the engine docstrings and in `SKILL.md`, not invented here:
a value in argv is readable through `ps` by every process of the same user and
that is how tokens ended up in the process list of two machines in this fleet;
`security find-generic-password` exits 0 for an item holding zero bytes and the
emptiness travelled three layers before anything failed over it; the same
keychain item reads from a desktop session and is refused over ssh, and the
daemon that could not tell those apart rotated a credential that was sitting
right there; `printenv TOKEN | base64` encodes the value together with the
newline the shell added, and one character of the real base64 survived the
scrub when that was measured.

Three needles do not name an engine source.

* Two name `tests/conftest.py`. The machine guard is code too, it is the only
  thing keeping this suite off a live keychain and a live database, and in a
  green run it never fires, so nothing but a needle would ever notice that it
  had stopped refusing.
* One names `engine/backends/keychain.py` but adds a line rather than removing
  one. The property it guards is a NEGATIVE ("no value was ever in an argv"),
  and a negative cannot be softened by deletion. The only way to find out
  whether anything is watching is to put a value where it must not be.

Two more needles add a line for that same reason, one on each of the paths in
this slice that carry a value INTO a store: the keychain write and the Key Vault
write. `argv_carried()` returning False is also what a suite that never ran
anything at all would report, and on a write path that is the difference between
a value on stdin and a value in `ps`.

A third addition is not about argv. The Key Vault metadata needle SPLITS one
call into two rather than deleting anything, because the property is "in the
same call" and a second `set` is what the engine is there to avoid, not the
absence of a flag.

Several needles share one anchor and differ only in what they put there. That is
deliberate and it is not duplication: `_escape` has three ways to be wrong and
each one arrives at the far end as a different length of value, so each gets its
own entry with its own named case. A single needle over that line would be
satisfied by a suite that noticed any one of the three. The same holds for
`looks_opaque`, whose one anchor line rejects a call and an interpolation for two
different reasons, and for the exit code of `audit`, which can be wrong by
answering zero over a loose credential and wrong again by answering non zero over
an invoice.

The pattern needles narrow an expression rather than deleting a line. A pattern
set is a LIST: a deleted entry drops out of `ALL` and out of `BY_NAME`, the
example table in `test_patterns.py` no longer matches the list, and half the file
goes red for a reason that says nothing about the shape. A quantifier narrowed
past the real format is also what a copy walking past a shape really looks like:
the pattern is still there, still in every parity check, and it no longer matches
the thing it is named after.

One needle in the audit walk ADDS a decode where a skip belongs, for the reason
the argv ones add a call: "a file that cannot be read is not read" is a negative,
and a negative is not softened by deletion. Removing the branch instead would
hand `None` to `splitlines` and the case would go red over an AttributeError,
which is a red that measures nothing.

A needle may only name a test that RUNS AND PASSES in the scratch copy. A test
that is red before the mutation is applied scores red afterwards for a reason
that has nothing to do with the mutation, which is the same lie as a skip with
the sign flipped. The deliberate reds of this slice are named in
`test_file_backend.TheRedCasesAreNamedRatherThanCounted`, and none of them is
named here.

A needle may only name a test that RUNS in the scratch copy, because a skip
scores as a pass. Four cases in this suite can skip: the real keychain tier
(macOS plus the `security` binary), two cases that ask git a question, and one
that expands a tilde. None of them is named here, and `test_acceptance.py`
holds that list as a table so it cannot grow quietly.

`run-tests.sh --mutate` copies the skill into a scratch directory, applies one
mutation at a time, runs the named test there and asserts that it fails. The
working tree is never touched.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mutation:
    """One softening, and the single test that has to notice it."""

    name: str
    file: str
    search: str
    replace: str
    test: str
    scar: str


KEYCHAIN = "engine/backends/keychain.py"
KEEPASS = "engine/backends/keepass.py"
VALUES = "engine/values.py"
CLI = "engine/cli.py"
RESOLVE = "engine/resolve.py"
DISCOVER = "engine/discover.py"
CHECK = "engine/check.py"
CONFTEST = "tests/conftest.py"
FILE_BACKEND = "engine/backends/file.py"
AZURE = "engine/backends/azure_keyvault.py"
ONEPASSWORD = "engine/backends/onepassword.py"
STORES = "engine/stores.py"
PATTERNS = "engine/patterns.py"
AUDIT = "engine/audit.py"

#: The line `_escape` really is, kept in one place because three needles soften
#: it three different ways and a copy that drifted would silently stop applying.
#: A raw string, so the backslashes here are the backslashes in the source.
ESCAPE_LINE = r"""    return text.replace("\\", "\\\\").replace('"', '\\"')"""

#: The one line of `looks_opaque` that rejects a value for being code. Two
#: needles soften it, one character class each, and a raw string again because
#: the backslash at the end of that class is a backslash in the source.
OPAQUE_CODE_LINE = r"""    if any(ch in value for ch in "()$<>{}%,; \\"):"""


MUTATIONS = (
    # -- an empty entry is a miss, not a hit --------------------------------
    Mutation(
        name="an-empty-keychain-item-becomes-a-hit",
        file=KEYCHAIN,
        search="        if secret.is_empty():",
        replace="        if False:",
        test="tests.test_keychain.AnEntryWithZeroBytesIsAMissThatSaysSo"
             ".test_an_empty_entry_is_not_present",
        scar="`security find-generic-password` exits 0 for an item holding zero "
             "bytes. Every caller that tested existence instead of length "
             "carried that emptiness one layer further before failing, where it "
             "looked like a permission problem rather than an empty entry",
    ),
    Mutation(
        name="an-empty-keepass-attribute-becomes-a-hit",
        file=KEEPASS,
        search="        if secret.is_empty():",
        replace="        if False:",
        test="tests.test_keepass.AnEmptyAttributeIsAMissNotAHit"
             ".test_the_reading_says_the_value_is_not_present",
        scar="the same rule one store over. `keepassxc-cli show --attributes` "
             "exits 0 and prints one empty line for an attribute that exists and "
             "holds nothing, so existence is not a measurement of the value",
    ),
    Mutation(
        name="an-empty-entry-is-reported-as-missing-rather-than-empty",
        file=CHECK,
        search="    elif reading.secret is not None and reading.secret.is_empty():",
        replace="    elif False:",
        test="tests.test_check.AnEmptyKeychainItemIsAMissNotAHit"
             ".test_the_report_says_empty_rather_than_ok",
        scar="the report has to separate an entry that is gone from an entry "
             "that is there and holds nothing. They call for different work: "
             "the first is a rotation nobody finished, the second is a write "
             "that landed empty",
    ),
    Mutation(
        name="an-empty-entry-stops-counting-as-a-failed-row",
        file=CHECK,
        search="FAILING = (EMPTY, MISSING, BAD_REFERENCE, ERROR)",
        replace="FAILING = (MISSING, BAD_REFERENCE, ERROR)",
        test="tests.test_check.AnEmptyKeychainItemIsAMissNotAHit"
             ".test_an_empty_entry_counts_as_failed",
        scar="a check that tested existence reported green while the caller got "
             "an empty string. A row is green only when bytes came back, and a "
             "verdict list that drops EMPTY puts that green back",
    ),

    # -- a session problem is not a rotation problem ------------------------
    Mutation(
        name="the-interaction-refusal-is-swallowed-by-the-not-found-branch",
        file=KEYCHAIN,
        search="        if done.rc == RC_ITEM_NOT_FOUND:",
        replace="        if done.rc != 0:",
        test="tests.test_keychain.TheSshRefusalIsNeverReportedAsAMiss"
             ".test_the_refusal_raises_not_readable_here",
        scar="the ssh case exactly: the entry is present, the password is right, "
             "and the read fails because the session has no unlocked login "
             "keychain. Reported as absence it makes a daemon rotate a secret "
             "that was never gone",
    ),
    Mutation(
        name="the-interaction-message-is-no-longer-recognised",
        file=KEYCHAIN,
        search='INTERACTION_REFUSED = "User interaction is not allowed"',
        replace='INTERACTION_REFUSED = "\\x00 a string this tool never prints \\x00"',
        test="tests.test_keychain.TheSshRefusalIsNeverReportedAsAMiss"
             ".test_it_is_unavailability_and_not_absence",
        scar="the wording is the whole evidence. The exit status of that refusal "
             "is the low eight bits of errSecInteractionNotAllowed, which no "
             "manual page prints next to a name, so the branch reads the message "
             "and a message nobody matches is a branch nobody takes",
    ),
    Mutation(
        name="not-readable-here-collapses-into-missing",
        file=CHECK,
        search="    if isinstance(problem, NotReadableHere):\n        return UNREADABLE",
        replace="    if isinstance(problem, NotReadableHere):\n        return MISSING",
        test="tests.test_check.ASessionProblemIsNotARotationProblem"
             ".test_a_refusal_raised_by_the_tool_itself_is_not_reported_as_missing",
        scar="a report that says ok on a laptop and missing on the same laptop "
             "over ssh is not measuring the vault, it is measuring the session. "
             "Both were one silent empty string before this skill existed",
    ),
    Mutation(
        name="a-session-that-cannot-read-is-reported-as-an-absent-entry",
        file=CHECK,
        search="            row.status = UNREADABLE if resolver.backend(parsed.scheme).available() else NO_BACKEND",
        replace="            row.status = MISSING",
        test="tests.test_check.ASessionProblemIsNotARotationProblem"
             ".test_an_ssh_session_is_reported_as_not_readable_here",
        scar="the other route to the same wrong answer. Here the session is "
             "known to be unable to read before anything runs, so the report "
             "invents an absence it never measured",
    ),

    # -- the measured macOS parse -------------------------------------------
    Mutation(
        name="the-hex-marker-stops-being-read",
        file=KEYCHAIN,
        search="    hex_match = _HEX.match(rest)\n    if hex_match:",
        replace="    hex_match = _HEX.match(rest)\n    if False:",
        test="tests.test_keychain.TheHexMarkerIsWhyTheGFlagIsUsed"
             ".test_the_same_ten_characters_marked_with_0x_are_five_bytes",
        scar="measured on macOS 26: a value holding a newline, an umlaut or a "
             "backslash comes back hex encoded, and a token that happens to look "
             "like hex is spelled the same way. Ten characters of output, two "
             "different values, and the 0x marker is the only thing that tells "
             "them apart",
    ),
    Mutation(
        name="the-flag-that-marks-the-hex-form-is-dropped",
        file=KEYCHAIN,
        search='        argv.append("-g")',
        replace='        argv.append("-w")',
        test="tests.test_keychain.TheArgvIsWhatTheMeasuredToolTakes"
             ".test_the_g_flag_is_there_and_the_w_flag_is_not",
        scar="`-w` prints the value with no marker at all, so the ambiguity "
             "above becomes unreadable rather than merely awkward. Every caller "
             "in this fleet that used `-w` and then asked whether the output was "
             "hex was guessing, and the guess only stayed invisible because the "
             "tokens involved were ASCII",
    ),

    # -- a value never travels in argv --------------------------------------
    Mutation(
        name="the-keychain-read-hands-the-value-back-in-an-argv",
        file=KEYCHAIN,
        search="        secret = Secret(raw, origin=ref.canonical)\n"
               "        if secret.is_empty():",
        replace="        secret = Secret(raw, origin=ref.canonical)\n"
                '        exec_mod.run(self.argv_read(ref) + ["-w", secret.expose_text()],\n'
                "                     runner=self.runner)\n"
                "        if secret.is_empty():",
        test="tests.test_keychain.NoValueEverTravelsInArgv"
             ".test_the_value_that_came_back_was_never_in_an_argv",
        scar="argv is world readable through `ps` for every process of the same "
             "user, which is how tokens ended up in the process list of two "
             "machines in this fleet before anyone looked. This needle adds a "
             "line instead of removing one, because a negative property cannot "
             "be softened by deletion: the only way to learn whether anything "
             "watches is to put a value where it must not be",
    ),
    Mutation(
        name="the-master-password-travels-in-argv-instead-of-on-stdin",
        file=KEEPASS,
        search='        stdin_bytes = None if self.password is None else self.password.expose() + b"\\n"\n'
               "        done = exec_mod.run(self.argv_read(ref), stdin_bytes=stdin_bytes, runner=self.runner)",
        replace="        stdin_bytes = None\n"
                "        argv = self.argv_read(ref) + ([] if self.password is None\n"
                '                                      else ["--password", self.password.expose_text()])\n'
                "        done = exec_mod.run(argv, stdin_bytes=stdin_bytes, runner=self.runner)",
        test="tests.test_keepass.TheMasterPasswordTravelsOnStdinAndNeverInArgv"
             ".test_no_recorded_call_carries_the_password_in_argv",
        scar="a master password in argv is worse than a token there: it "
             "discloses every entry in the database at once, and it does so "
             "whether or not the call succeeds. `run` takes `stdin_bytes` for "
             "exactly this reason",
    ),
    Mutation(
        name="the-password-on-stdin-loses-its-newline",
        file=KEEPASS,
        search='self.password.expose() + b"\\n"',
        replace="self.password.expose()",
        test="tests.test_keepass.TheMasterPasswordTravelsOnStdinAndNeverInArgv"
             ".test_the_password_ends_in_a_newline_so_the_tool_reads_a_whole_line",
        scar="without the newline the tool waits for the rest of the line and "
             "the read hangs until the deadline, which reads like a broken "
             "database rather than like a missing byte",
    ),

    # -- redaction -----------------------------------------------------------
    Mutation(
        name="only-one-base64-alphabet-is-covered",
        file=VALUES,
        search="            for encoder in (base64.b64encode, base64.urlsafe_b64encode):",
        replace="            for encoder in (base64.b64encode,):",
        test="tests.test_values.ABinaryValueIsCoveredInBothBase64Alphabets"
             ".test_the_url_safe_alphabet_is_removed",
        scar="a key file is bytes, so the encodings are all the redactor has. "
             "The two alphabets differ only in their last two table entries, so "
             "a value whose encoding never reaches those two cannot tell a "
             "redactor that knows one alphabet from one that knows both",
    ),
    Mutation(
        name="the-newline-the-shell-added-is-not-registered",
        file=VALUES,
        search='        for payload in (raw, raw + b"\\n", raw + b"\\r\\n"):',
        replace="        for payload in (raw,):",
        test="tests.test_values.Base64OfTheValuePlusTheNewlineTheShellAddedIsRemovedWhole"
             ".test_nothing_of_the_line_feed_encoding_survives",
        scar="`printenv TOKEN | base64` encodes the value WITH the newline the "
             "shell added, and that encoding shares only a prefix with the "
             "encoding of the value alone. Measured: one character of the real "
             "base64 survived the scrub",
    ),
    Mutation(
        name="the-hex-form-is-covered-in-lower-case-only",
        file=VALUES,
        search="        out.add(hexed.upper())",
        replace="        out.add(hexed.lower())",
        test="tests.test_values.TheRedactorRemovesTheValueInEveryShapeItLeavesIn"
             ".test_the_hex_form_is_gone_in_upper_case",
        scar="a value that was posted to an API and echoed back inside an error "
             "message is not spelled the way it was stored, and which case the "
             "hex arrives in is a property of the tool that printed it",
    ),
    Mutation(
        name="a-value-too-short-to-redact-is-covered-silently-instead-of-reported",
        file=VALUES,
        search="        if len(secret) < self.min_length:",
        replace="        if False:",
        test="tests.test_values.AValueTooShortToRedactIsReportedRatherThanCovered"
             ".test_it_lands_in_skipped",
        scar="a short value produces a replacement that fires on ordinary words "
             "and hides the very output the caller needs to read. The run "
             "reports which names were skipped rather than pretending they were "
             "covered, and a silent skip is the same lie in the other direction",
    ),
    Mutation(
        name="the-second-pair-of-eyes-goes-blind",
        file=VALUES,
        search="        return any(pattern.search(text) for pattern, _ in self._patterns)",
        replace="        return False",
        test="tests.test_values.HoldsIsTheSecondPairOfEyesBeforeAnythingIsPrinted"
             ".test_it_reports_a_survivor",
        scar="scrubbing is pattern replacement and patterns can miss. `holds` is "
             "what `run` asks about its own output before printing it, so a "
             "`holds` that answers no to everything turns the refusal below into "
             "a branch nobody takes",
    ),
    Mutation(
        name="a-stream-that-still-holds-a-value-is-printed-anyway",
        file=CLI,
        search="    if redactor.holds(cleaned):",
        replace="    if False:",
        test="tests.test_cli.AStreamThatStillHoldsAValueIsNotPrinted"
             ".test_the_standard_output_of_the_child_is_dropped_entirely",
        scar="an agent reads this output. Anything printed here is in the "
             "model's context for the rest of the session, in the transcript and "
             "in whatever log the harness keeps, and none of those three can be "
             "unprinted. When the cleaned text still holds a registered value, "
             "printing it is the one thing that must not happen",
    ),
    Mutation(
        name="a-secret-renders-as-text-again",
        file=VALUES,
        search="    def __str__(self) -> str:\n        raise TypeError(",
        replace="    def __str__(self) -> str:\n"
                "        return self.expose_text()\n"
                "        raise TypeError(",
        test="tests.test_values.ASecretRefusesToRenderAsText"
             ".test_str_raises_rather_than_returning_the_value",
        scar="the wrapper exists so that printing a value takes an explicit act, "
             "and `expose()` is the verb chosen so that one grep lists every "
             "place a value leaves it. A `__str__` that answers turns every "
             "f-string and every log line in reach into such a place, and none "
             "of them would show up in that grep",
    ),

    # -- the resolver --------------------------------------------------------
    Mutation(
        name="a-value-is-fetched-once-per-use-again",
        file=RESOLVE,
        search="        if key in self._readings:",
        replace="        if False:",
        test="tests.test_resolve.AReadingIsFetchedOnceAndThenRemembered"
             ".test_two_reads_of_one_reference_issue_one_call",
        scar="not an optimisation. Every read of a keychain item is another "
             "chance for the session to refuse it, so a command that resolves "
             "the same reference three times has three chances to fail halfway "
             "through its own work, and the second failure looks nothing like "
             "the first",
    ),
    Mutation(
        name="a-reference-needed-to-resolve-itself-recurses",
        file=RESOLVE,
        search="        if key in self._resolving:",
        replace="        if False:",
        test="tests.test_resolve.AReferenceThatIsNeededToResolveItselfIsRefusedRatherThanRecursed"
             ".test_it_raises_refused_rather_than_running_out_of_stack",
        scar="a store whose credential lives in that same store cannot be "
             "opened. Without the guard that is a RecursionError, which is not a "
             "sentence anybody can act on, and it arrives with a traceback "
             "naming every store on the way down",
    ),
    Mutation(
        name="a-keepass-master-password-may-live-in-keepass",
        file=RESOLVE,
        search='        if ref.scheme == "keepass":',
        replace="        if False:",
        test="tests.test_resolve.AMasterPasswordInsideTheDatabaseItOpensIsRefused"
             ".test_the_message_says_a_keepass_database_may_not_hold_it",
        scar="the bootstrap is one link deep on purpose. A database whose "
             "password lives in another database is a loop waiting to happen, "
             "and the refusal has to name the shape rather than wait for the "
             "stack to run out. The needle names the case that reads the "
             "MESSAGE, because the type alone does not tell the two refusals "
             "apart: without the scheme check the self reference guard catches "
             "the same declaration one hop later and raises Refused as well, "
             "with the same exit code, the same reference and nothing having "
             "run, so four of that class's six cases stay green over it",
    ),

    # -- the inventory -------------------------------------------------------
    Mutation(
        name="a-documentation-placeholder-is-read-as-a-live-reference",
        file=DISCOVER,
        search='    if is_example(raw) or follower in ("<", "{"):',
        replace='    if follower in ("<", "{"):',
        test="tests.test_discover.ADocumentationExampleIsNotABrokenReference"
             ".test_a_dollar_placeholder_makes_it_an_example",
        scar="measured on this repo: 19 of 38 hits are examples in prose. "
             "Reporting those as broken puts more false entries in the report "
             "than real ones, and a report like that gets read once",
    ),
    Mutation(
        name="a-reference-cut-at-an-angle-bracket-is-read-as-broken",
        file=DISCOVER,
        search='    if is_example(raw) or follower in ("<", "{"):',
        replace="    if is_example(raw):",
        test="tests.test_discover.AReferenceCutAtAnAngleBracketIsAnExample"
             ".test_it_is_classified_as_an_example",
        scar="the scanner stops at the angle bracket because a reference cannot "
             "contain one, so the matched text carries no placeholder at all and "
             "nothing inside it says it is prose. The character that stopped the "
             "match is the only evidence there is, and without it the top of "
             "every scan of this repo is a rules file",
    ),
    Mutation(
        name="the-discovery-symlinks-are-followed",
        file=DISCOVER,
        search="        if os.path.islink(full):",
        replace="        if False:",
        test="tests.test_discover.ASymlinkBackIntoTheTreeDoesNotDoubleTheFindings"
             ".test_a_tracked_symlink_to_a_scanned_file_adds_no_second_finding",
        scar="`.claude/skills` and its two siblings point back into the tree. "
             "Following them counted every skill three times, measured on this "
             "repo before the check existed",
    ),

    # -- the exit codes a wrapper reads --------------------------------------
    Mutation(
        name="a-bad-reference-exits-as-a-missing-entry",
        file=CLI,
        search="    if any(row.status in (check_mod.BAD_REFERENCE, check_mod.ERROR) for row in rows):",
        replace="    if False:",
        test="tests.test_cli.TheExitCodeOfCheckIsWhatAWrapperReads"
             ".test_a_reference_that_does_not_parse_exits_seventy_eight",
        scar="a wrapper that resolves its secret at startup has to tell a "
             "machine problem from a rotation nobody finished. A URI somebody "
             "typed wrong is neither, and reporting it as a missing entry sends "
             "the reader to the vault instead of to the file",
    ),
    Mutation(
        name="a-run-starts-its-child-without-the-secret-it-asked-for",
        file=CLI,
        search='    if missing and args.if_missing == "error":',
        replace="    if False:",
        test="tests.test_cli.TheThreeAnswersToAReferenceThatResolvesToNothing"
             ".test_error_exits_three",
        scar="every caller in this fleet that could not tell the two failures "
             "apart treated both as no secret and started without one, which is "
             "the run that looks successful and writes nothing anybody wanted",
    ),

    # -- the guard itself ----------------------------------------------------
    Mutation(
        name="the-machine-guard-stops-refusing",
        file=CONFTEST,
        search='_DENY = {"security", "keepassxc-cli", "az", "op", "ssh", "scp", "sudo", "secret-tool"}',
        replace='_DENY = {"a-program-nobody-has"}',
        test="tests.test_acceptance.TheGuardIsExercisedBecauseAGreenRunNeverFiresIt"
             ".test_subprocess_run_refuses_every_denied_program",
        scar="whoever runs this suite has a real login keychain and a real "
             "database sitting right there, so a backend that reached around the "
             "`runner=` seam would read a LIVE token and the case would go green "
             "on the strength of it. In a green run the guard never fires, so "
             "nothing but a needle would notice that it had stopped refusing",
    ),
    Mutation(
        name="the-guard-does-not-look-inside-sh-minus-c",
        file=CONFTEST,
        search='    if head in _SHELLS and "-c" in parts:',
        replace="    if False:",
        test="tests.test_acceptance.TheGuardIsExercisedBecauseAGreenRunNeverFiresIt"
             ".test_a_denied_program_hidden_inside_a_shell_is_refused_too",
        scar="a denylist that only reads argv[0] is walked past by one layer of "
             "shell, and the shim this skill ships is a shell script, so that "
             "layer is not hypothetical here",
    ),

    # -- the keychain write line, character by character ---------------------
    #
    # Three ways for `_escape` to be wrong, three lengths of value at the far
    # end, one anchor. Measured on 2026-09-04 against `security -i`.
    Mutation(
        name="the-backslash-in-the-write-line-stops-being-doubled",
        file=KEYCHAIN,
        search=ESCAPE_LINE,
        replace=r"""    return text.replace('"', '\\"')""",
        test="tests.test_write_keychain.TheQuotingIsExactlyOneBackslashPerCharacter"
             ".test_a_backslash_gets_one_backslash_and_not_three",
        scar="`security -i` reads the line the way a shell reads one, so a lone "
             "backslash inside the quotes escapes whatever follows it instead of "
             "being stored. The value arrives short by one character per "
             "backslash, the entry exists, every existence check is green, and "
             "the far end rejects a credential that looks right",
    ),
    Mutation(
        name="the-double-quote-in-the-write-line-stops-being-escaped",
        file=KEYCHAIN,
        search=ESCAPE_LINE,
        replace=r"""    return text.replace("\\", "\\\\")""",
        test="tests.test_write_keychain.TheQuotingIsExactlyOneBackslashPerCharacter"
             ".test_a_double_quote_gets_one_backslash_and_not_two",
        scar="the other half, and the louder one: an unescaped quote closes the "
             "operand early, so the rest of the value becomes further operands "
             "of `add-generic-password`. Measured, the command either stores a "
             "truncated value or exits 2, and which of the two happens depends "
             "on what the value contains",
    ),
    Mutation(
        name="the-two-escapes-of-the-write-line-run-in-the-wrong-order",
        file=KEYCHAIN,
        search=ESCAPE_LINE,
        replace=r"""    return text.replace('"', '\\"').replace("\\", "\\\\")""",
        test="tests.test_write_keychain.TheQuotingIsExactlyOneBackslashPerCharacter"
             ".test_a_backslash_in_front_of_a_quote_keeps_both_escapes_apart",
        scar="both replacements are present and the value still arrives wrong. "
             "Escaping the quote first puts a backslash in front of it, and the "
             "second replacement then doubles the backslash it just added, so a "
             "value holding a backslash next to a quote arrives LONG. The needle "
             "exists because the two entries above both stay red over an order "
             "that is correct, and neither says anything about this one",
    ),
    Mutation(
        name="the-hex-branch-of-the-write-is-never-taken",
        file=KEYCHAIN,
        search="        if _needs_hex(raw):",
        replace="        if False:",
        test="tests.test_write_keychain.AControlCharacterGoesAsHexAndStaysOutOfArgv"
             ".test_a_newline_value_uses_the_x_flag_and_not_the_w_flag",
        scar="the quoted form cannot carry a newline at all: `security -i` reads "
             "whole command LINES from stdin, so a value with a newline in it "
             "ends the command halfway through and the second half is read as "
             "the next command. A PEM key and a service account JSON are both "
             "this case, and both are values somebody will hand to `store`",
    ),
    Mutation(
        name="a-control-character-is-no-longer-recognised-as-one",
        file=KEYCHAIN,
        search="    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)",
        replace="    return False",
        test="tests.test_write_keychain.AControlCharacterGoesAsHexAndStaysOutOfArgv"
             ".test_a_tab_is_a_control_character_too",
        scar="the predicate under the branch above, and it fails differently: "
             "the branch is still there, it simply answers no. A tab and a "
             "carriage return are the two that get forgotten, because the "
             "newline is the one everybody thinks of. The needle names the tab "
             "for that reason, and the non-utf8 case stays green over it, which "
             "is how the two halves of `_needs_hex` are told apart",
    ),
    Mutation(
        name="the-accessor-flag-is-dropped-from-the-write-line",
        file=KEYCHAIN,
        search='        parts.append("-A")',
        replace="        parts.extend([])",
        test="tests.test_write_keychain.TheAccessorFlagIsOnEveryWrite"
             ".test_a_plain_write_carries_the_accessor_flag",
        scar="without `-A` the item is written with no accessor at all, and the "
             "read that follows blocks on a dialog nobody can answer. In a "
             "launchd context that is ten seconds and then nothing, reported as "
             "a missing secret, which is the one answer that sends somebody to "
             "rotate a credential that was never gone",
    ),
    Mutation(
        name="the-keychain-write-hands-the-value-over-in-an-argv",
        file=KEYCHAIN,
        search='        line = self.write_line(ref, secret, replace=replace) + "\\n"',
        replace='        line = self.write_line(ref, secret, replace=replace) + "\\n"\n'
                '        exec_mod.run(["security", "add-generic-password", "-s", ref.store,\n'
                '                      "-w", secret.expose_text()], runner=self.runner)',
        test="tests.test_write_keychain.NoValueEverTravelsInArgvOnTheWritePath"
             ".test_a_plain_value_is_never_in_argv",
        scar="the whole reason `security -i` is used instead of the obvious "
             "`add-generic-password -w`. This needle adds the obvious call "
             "rather than removing anything, because the property is a NEGATIVE "
             "and a negative cannot be softened by deletion: with the line gone "
             "the case is green, and it is equally green for a backend that was "
             "never called at all",
    ),

    # -- a write is believed only after it has been read back ---------------
    Mutation(
        name="the-read-back-no-longer-compares-what-came-back",
        file=RESOLVE,
        search="        if reading.secret != secret:",
        replace="        if False:",
        test="tests.test_store_cli.AWriteIsNotBelievedUntilItHasBeenReadBack"
             ".test_a_value_that_reads_back_different_is_a_failure",
        scar="the read-back is not ceremony. A value that lost two characters to "
             "a quoting rule reads back with present=True and a plausible "
             "length, and the only thing that tells it from a correct write is "
             "the comparison. Without it the verb reports success over an entry "
             "holding something else, and the failure surfaces at the far end as "
             "a rejected credential",
    ),
    Mutation(
        name="an-entry-that-reads-back-empty-is-reported-as-a-write-that-landed",
        file=RESOLVE,
        search="        self._readings.pop(parsed.canonical, None)\n"
               "        if not reading.present or reading.secret is None:",
        replace="        self._readings.pop(parsed.canonical, None)\n"
                "        if False:",
        test="tests.test_store_cli.AWriteIsNotBelievedUntilItHasBeenReadBack"
             ".test_an_entry_that_reads_back_empty_is_a_failure_too",
        scar="every tool in this chain exits 0 for an entry that holds nothing, "
             "which is how an empty value once travelled three layers. The two "
             "failures need different words and different exit codes: an entry "
             "holding the wrong bytes is 70, an entry holding none is 3, and a "
             "wrapper reads the code rather than the prose",
    ),
    Mutation(
        name="the-read-back-is-answered-from-the-cache-instead-of-the-store",
        file=RESOLVE,
        search="        self._readings.pop(parsed.canonical, None)",
        replace="        pass",
        test="tests.test_resolve.AWriteEmptiesTheReadingTheSameRunWasHolding"
             ".test_a_later_read_after_a_mismatched_write_asks_the_store_again",
        scar="one resolver serves a whole command, and the reference being "
             "written has usually been read by it already. On the failure paths "
             "the stale reading is the damage: the refusal says in as many "
             "words that nothing was rolled back and the entry is worth looking "
             "at, and a cached read then reports it exactly as it stood before "
             "the write. The success path is green either way, because a write "
             "that lands installs its own read-back on the way out, which is "
             "why this line went unguarded until a needle asked",
    ),

    # -- the policy is read at the moment of the write ----------------------
    Mutation(
        name="a-store-accepts-a-kind-it-does-not-declare",
        file=CLI,
        search="    if kind not in declared:",
        replace="    if False:",
        test="tests.test_store_cli"
             ".AKindTheTargetStoreDoesNotHoldIsRefusedAndTheMessageSaysWhereItBelongs"
             ".test_the_exit_code_is_the_refusal_code",
        scar="a policy nothing reads at the moment of the write is "
             "documentation. The loose token file gets written anyway, next to "
             "a file that says it should not be, and that is how credentials "
             "ended up in working folders on two machines in this fleet",
    ),
    Mutation(
        name="what-identifies-rather-than-authenticates-is-accepted-into-a-store",
        file=CLI,
        search="    if kind in stores_mod.NOT_A_KIND:",
        replace="    if False:",
        test="tests.test_store_cli.WhatIdentifiesRatherThanAuthenticatesIsNotStored"
             ".test_the_reason_is_printed",
        scar="an IBAN is on every invoice the user writes, so moving it into a "
             "vault makes it useless for the thing it is for and buys nothing, "
             "because knowing it grants nothing. The needle names the case that "
             "reads the REASON, because the exit code alone cannot tell the two "
             "refusals apart: without this branch the word falls through to the "
             "unknown-kind refusal one line down, with the same code and nothing "
             "written, so four of that class's five cases stay green over it",
    ),
    Mutation(
        name="a-pipe-is-no-longer-the-default-source-of-a-value",
        file=CLI,
        search='        source = "stdin" if not sys_mod.stdin.isatty() else "prompt"',
        replace='        source = "prompt"',
        test="tests.test_store_cli.AValuePipedInIsWrittenWithoutEverStandingInArgv"
             ".test_a_pipe_is_the_default_source_when_stdin_is_not_a_terminal",
        scar="a prompt in a pipeline is a process waiting on a terminal that is "
             "not there. It does not fail, it hangs, and in a provisioning "
             "script that is a job nobody notices until the timeout",
    ),
    Mutation(
        name="the-newline-the-pipe-added-is-stored-as-part-of-the-value",
        file=CLI,
        search="        if raw.endswith(b\"\\r\\n\"):\n"
               "            raw = raw[:-2]\n"
               "        elif raw.endswith(b\"\\n\") or raw.endswith(b\"\\r\"):\n"
               "            raw = raw[:-1]\n"
               "        return Secret(raw)",
        replace="        return Secret(raw)",
        test="tests.test_store_cli.AValuePipedInIsWrittenWithoutEverStandingInArgv"
             ".test_a_trailing_newline_from_the_pipe_is_not_part_of_the_value",
        scar="`echo $TOKEN | secrets store ...` sends the value and the newline "
             "the shell added. A token with a trailing newline fails an "
             "Authorization header while looking right in every report, because "
             "the byte does not render",
    ),
    Mutation(
        name="an-empty-pipe-is-written-into-the-store-as-a-secret",
        file=CLI,
        search="    if secret.is_empty():",
        replace="    if False:",
        test="tests.test_store_cli.AnEmptyValueIsAUsageErrorAndNothingIsWritten"
             ".test_the_exit_code_is_the_usage_code",
        scar="a pipe that produced nothing is the ordinary shape of a command "
             "that failed upstream, and writing its result overwrites a working "
             "credential with zero bytes. The store then holds an entry that "
             "exists, so the next `check` is green and the next use is not",
    ),

    # -- the file backend, where the locator IS the value -------------------
    Mutation(
        name="the-mode-of-a-secret-file-comes-from-the-umask",
        file=FILE_BACKEND,
        search="            return os.open(name, flags | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)",
        replace="            return os.open(name, flags | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o666)",
        test="tests.test_file_backend.TheModeIsSetWhenTheFileIsCreatedAndNotAfterwards"
             ".test_the_open_is_what_sets_the_mode_and_not_the_chmod_afterwards",
        scar="the mode belongs to the open. A file created wide and narrowed by "
             "the chmod two lines later stands readable, with the secret already "
             "in it, for the length of the write. The needle names the case that "
             "neutralises the chmod, because every other case in that class is "
             "green over this mutation: the chmod repairs the mode before "
             "anybody looks",
    ),
    Mutation(
        name="a-file-every-account-can-read-is-handed-over-anyway",
        file=FILE_BACKEND,
        search="        if mode not in ALLOWED_MODES:",
        replace="        if False:",
        test="tests.test_file_backend.AFileAnotherAccountCanReadIsNotASecretAnyMore"
             ".test_a_mode_0644_file_is_refused_on_read",
        scar="refused on READ and not merely reported, because a value every "
             "account on the machine can already read has to be treated as "
             "disclosed. Handing it over with a warning attached lets a wrapper "
             "carry on using it, and the warning lands in a log nobody opens "
             "until the credential turns up somewhere it should not have been",
    ),
    Mutation(
        name="a-group-readable-mode-is-added-to-the-allowed-list",
        file=FILE_BACKEND,
        search="ALLOWED_MODES = (0o600, 0o400)",
        replace="ALLOWED_MODES = (0o600, 0o400, 0o640, 0o644)",
        test="tests.test_file_backend.AFileAnotherAccountCanReadIsNotASecretAnyMore"
             ".test_a_group_readable_file_is_refused_too",
        scar="the list is the policy, and 0o640 is the mode somebody reaches for "
             "when a second service account needs the file. It is also the mode "
             "that makes the value readable by every member of that group, which "
             "on a shared machine is not a list anybody audits",
    ),
    Mutation(
        name="a-write-outside-every-declared-store-goes-through",
        file=FILE_BACKEND,
        search="        if not self.inside_a_store(ref):",
        replace="        if False:",
        test="tests.test_file_backend.AWriteOutsideEveryDeclaredStoreIsRefused"
             ".test_a_path_outside_the_declared_root_is_refused",
        scar="without this rule the backend is `write the token wherever`, which "
             "is the habit the whole skill exists to end: small text files with "
             "credentials in working folders and temp directories, on two "
             "machines, found by a scan rather than by anybody noticing",
    ),
    Mutation(
        name="a-neighbour-directory-is-read-as-being-inside-the-store",
        file=FILE_BACKEND,
        search='        return any(path == root or path.startswith(root.rstrip("/") + "/")',
        replace='        return any(path == root or path.startswith(root.rstrip("/"))',
        test="tests.test_file_backend.AWriteOutsideEveryDeclaredStoreIsRefused"
             ".test_a_neighbour_whose_name_starts_with_the_root_is_still_outside",
        scar="a prefix test without the separator declares `/home/opuser/"
             "secrets-old/token` to be inside `/home/opuser/secrets`, and "
             "`secrets-old` is exactly the directory somebody made while "
             "rotating. The containment check then sanctions the one place a "
             "stale copy was always going to land",
    ),
    Mutation(
        name="a-symlink-carries-the-value-out-of-the-declared-store",
        file=FILE_BACKEND,
        search="        return os.path.realpath(os.path.expanduser(ref.store))",
        replace="        return os.path.abspath(os.path.expanduser(ref.store))",
        test="tests.test_file_backend.ASymlinkInsideTheStoreDoesNotCarryTheValueOutOfIt"
             ".test_a_write_through_the_link_is_refused",
        scar="containment is measured on the resolved path or it is not measured "
             "at all: `<store>/escape/token` passes a lexical prefix test "
             "whatever `escape` turns out to be, and the value then lands "
             "outside every declaration while the guard reports it as inside. "
             "Nobody has to plant the link on purpose, a store directory that is "
             "itself a convenience link to a synced folder is the ordinary way",
    ),
    Mutation(
        name="the-parent-directory-of-a-secret-file-is-created-world-listable",
        file=FILE_BACKEND,
        search="        os.mkdir(path, 0o700)",
        replace="        os.mkdir(path, 0o755)",
        test="tests.test_file_backend.TheParentDirectoryIsCreatedOwnerOnly"
             ".test_the_created_parent_is_owner_only",
        scar="the mode of the file is not the whole story: a directory every "
             "account can list gives away the NAMES of the secret files under "
             "it, which on a per-customer subtree is a customer list. The "
             "content stays at 0600 throughout, so nothing else in this suite "
             "would notice",
    ),

    # -- Key Vault: the value goes in a file, the metadata in the same call --
    Mutation(
        name="the-key-vault-write-puts-the-value-on-the-command-line",
        file=AZURE,
        search='        argv = ["az", "keyvault", "secret", "set", *self._common(ref), "--file", path]',
        replace='        argv = ["az", "keyvault", "secret", "set", *self._common(ref), "--value", path]',
        test="tests.test_azure_keyvault.NoValueEverTravelsInArgvOnTheWayIntoTheVault"
             ".test_the_value_flag_is_never_used",
        scar="`az keyvault secret set --value <token>` is the single most common "
             "way a credential leaves a shell in this fleet: it stands in `ps` "
             "for every process of the same user for as long as the call runs, "
             "and it lands in the shell history of whoever typed it. `--file` is "
             "the whole reason this backend exists rather than a two line "
             "wrapper",
    ),
    Mutation(
        name="the-key-vault-write-also-sends-the-value-in-an-argv",
        file=AZURE,
        search="            done = exec_mod.run(self.argv_write(ref, path, merged), runner=self.runner,\n"
               "                                timeout_sec=120)",
        replace='            exec_mod.run(["az", "keyvault", "secret", "set", *self._common(ref),\n'
                '                          "--value", secret.expose_text()], runner=self.runner,\n'
                "                         timeout_sec=120)\n"
                "            done = exec_mod.run(self.argv_write(ref, path, merged), runner=self.runner,\n"
                "                                timeout_sec=120)",
        test="tests.test_azure_keyvault.NoValueEverTravelsInArgvOnTheWayIntoTheVault"
             ".test_no_recorded_call_carries_the_value_in_argv",
        scar="the negative property on the Key Vault path, and it is added "
             "rather than removed for the same reason as the keychain one: the "
             "flag needle above only says that ONE argv is clean, and a second "
             "call beside it discloses the value just as completely. `ps` does "
             "not care which call it was",
    ),
    Mutation(
        name="the-key-vault-metadata-travels-in-a-second-call",
        file=AZURE,
        search="            done = exec_mod.run(self.argv_write(ref, path, merged), runner=self.runner,\n"
               "                                timeout_sec=120)",
        replace="            done = exec_mod.run(self.argv_write(ref, path, {}), runner=self.runner,\n"
                "                                timeout_sec=120)\n"
                '            exec_mod.run(["az", "keyvault", "secret", "set", *self._common(ref),\n'
                '                          "--tags",\n'
                '                          *[f"{key}={value}" for key, value in sorted(merged.items())],\n'
                '                          "-o", "none"], runner=self.runner, timeout_sec=120)',
        test="tests.test_azure_keyvault.TheMetadataTravelsInTheSameCallAsTheValue"
             ".test_the_tags_are_set_in_the_call_that_writes",
        scar="`az keyvault secret set` appends a NEW VERSION, and the metadata of "
             "the previous one does not come along. A second call that repairs "
             "it is the one people forget, and a failure between the two leaves "
             "the version there for good: an entry with no owner, no purpose and "
             "no date, in a vault holding forty of them",
    ),
    Mutation(
        name="the-subscription-of-the-vault-is-left-to-the-default",
        file=AZURE,
        search="        if self.subscription:",
        replace="        if False:",
        test="tests.test_azure_keyvault.TheReadArgvIsWhatTheMeasuredCommandTakes"
             ".test_the_subscription_is_named_when_the_store_declares_one",
        scar="the default subscription of a machine is not the tenant of the "
             "vault, and `az` answers for the wrong one without a word. What "
             "comes back is `SecretNotFound`, which this backend reports as a "
             "miss, so the reader is sent to the vault that does hold the "
             "secret to look for the secret that is in it",
    ),
    Mutation(
        name="the-file-the-value-travels-in-is-widened-after-it-is-created",
        file=AZURE,
        search="                return os.open(name, flags | os.O_CREAT | os.O_TRUNC, 0o600)",
        replace="                handle = os.open(name, flags | os.O_CREAT | os.O_TRUNC, 0o600)\n"
                "                os.fchmod(handle, 0o644)\n"
                "                return handle",
        test="tests.test_azure_keyvault.TheFileTheValueTravelsThroughIsPrivateAndTemporary"
             ".test_the_file_is_created_with_mode_0600",
        scar="a file is the safe channel only while it is unreadable. The "
             "mutation widens it instead of changing the creation mode, because "
             "a creation mode is filtered by the umask and a needle whose bite "
             "depends on the umask of whoever runs the suite proves nothing on "
             "the machine where it matters",
    ),
    Mutation(
        name="the-file-the-value-travelled-in-is-left-on-disk",
        file=AZURE,
        search="        finally:\n            try:\n                os.remove(path)",
        replace="        finally:\n            try:\n                pass",
        test="tests.test_azure_keyvault.TheFileTheValueTravelsThroughIsPrivateAndTemporary"
             ".test_the_file_is_gone_when_the_write_returns",
        scar="the removal sits in a `finally` so that a tool which failed does "
             "not leave a token in a temporary directory. On a Mac that does not "
             "reboot nothing cleans that directory up, and the file outlives "
             "every rotation of the value it holds",
    ),

    # -- KeePass: two lines on stdin, in one order, and never under a lock --
    Mutation(
        name="the-two-lines-of-the-keepass-write-are-swapped",
        file=KEEPASS,
        search='        return master + b"\\n" + secret.expose() + b"\\n"',
        replace='        return secret.expose() + b"\\n" + master + b"\\n"',
        test="tests.test_keepass_write.TheMasterPasswordAndTheValueBothTravelOnStdinInThatOrder"
             ".test_the_master_password_is_the_first_line",
        scar="`--password-prompt` asks twice: first for the password that opens "
             "the database, then for the password of the entry. Swapped, the "
             "tool tries to open the database with the VALUE as its master "
             "password. It fails, the failure reads exactly like a wrong master "
             "password, and the value has been offered at an unlock prompt on "
             "the way. Nothing in the output says which of the two happened",
    ),
    Mutation(
        name="the-second-line-of-the-keepass-write-loses-its-newline",
        file=KEEPASS,
        search='        return master + b"\\n" + secret.expose() + b"\\n"',
        replace='        return master + b"\\n" + secret.expose()',
        test="tests.test_keepass_write.TheMasterPasswordAndTheValueBothTravelOnStdinInThatOrder"
             ".test_each_line_ends_in_a_newline_so_the_tool_reads_a_whole_line",
        scar="the same missing byte as on the read path, one line further down. "
             "Without it the tool waits for the rest of the line and the write "
             "hangs until the deadline, which reads like a broken database "
             "rather than like a newline nobody sent",
    ),
    Mutation(
        name="a-keepass-write-goes-ahead-while-the-database-is-open-elsewhere",
        file=KEEPASS,
        search="        if self.locked(ref):",
        replace="        if False:",
        test="tests.test_keepass_write.ALockFileRefusesTheWriteAlthoughAReadWouldStillWork"
             ".test_the_write_is_refused",
        scar="KDBX has no journal: a save rewrites the whole encrypted file. Two "
             "writers are a real conflict and not a transaction, and the merge "
             "KeePassXC offers happens in the GUI, on reload, with a person "
             "present. A wrapper that writes under a lock is how one of the two "
             "versions quietly wins",
    ),
    Mutation(
        name="a-keepass-replace-adds-a-second-entry-instead-of-editing-the-first",
        file=KEEPASS,
        search='        verb = "edit" if replace else "add"',
        replace='        verb = "add"',
        test="tests.test_keepass_write.TheReplaceIsAVerbAndNotAFlag"
             ".test_a_write_with_replace_uses_the_edit_verb",
        scar="replace is a VERB here and not a flag, unlike every other backend "
             "in this skill. `add` against a name that exists does not overwrite "
             "it, so a rotation leaves two entries of the same name and the read "
             "that follows picks one of them",
    ),
    Mutation(
        name="a-keepass-write-is-allowed-to-address-a-field-it-cannot-write",
        file=KEEPASS,
        search='        if ref.field and ref.field.lower() not in ("password", "") :',
        replace="        if False:",
        test="tests.test_keepass_write.OnlyThePasswordFieldIsWritten"
             ".test_a_reference_naming_another_field_is_refused",
        scar="`keepassxc-cli add --password-prompt` writes the password field "
             "and nothing else, whatever the reference names. A write addressed "
             "at `/notes` or a custom attribute therefore lands in the password "
             "field instead, silently, and the read that proves it asks for the "
             "field the reference named and finds the old value there",
    ),

    # -- 1Password: the refusal IS the feature ------------------------------
    Mutation(
        name="the-one-password-write-stops-being-refused",
        file=ONEPASSWORD,
        search="    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:\n"
               "        raise Refused(",
        replace="    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:\n"
                "        return Reading(ref=ref.canonical, present=True, secret=secret,\n"
                "                       store=ref.store)\n"
                "        raise Refused(",
        test="tests.test_onepassword.WritingIsRefusedBecauseTheCliTakesTheValueInArgv"
             ".test_a_write_is_refused",
        scar="the refusal is the feature and not a gap. `op item create` and `op "
             "item edit` take the value as `field=value` in argv, and the "
             "template form reads it from a file, which is the thing this skill "
             "exists to stop creating. A backend that implements the write "
             "either discloses the value or writes the file; saying what to do "
             "instead is the only third answer",
    ),

    # -- the store declarations, and what they route ------------------------
    Mutation(
        name="the-lone-star-address-stops-answering",
        file=STORES,
        search='    if pattern == "*":\n        return True',
        replace='    if pattern == "*":\n        return False',
        test="tests.test_stores.AnAddressMatchesExactlyOrByPrefixOrByStar"
             ".test_the_lone_star_answers_anything_of_its_own_scheme",
        scar="`addresses: [\"*\"]` is how the login keychain declares itself, and "
             "a store that answers nothing contributes no options to its "
             "backend. The keychain file, the database path and the unlock "
             "reference all quietly go missing, and the failure surfaces three "
             "layers down as a tool that cannot find an entry",
    ),
    Mutation(
        name="a-prefix-address-matches-only-its-own-stem",
        file=STORES,
        search='    if pattern.endswith("*"):\n        return value.startswith(pattern[:-1])',
        replace='    if pattern.endswith("*"):\n        return value == pattern[:-1]',
        test="tests.test_stores.AnAddressMatchesExactlyOrByPrefixOrByStar"
             ".test_a_trailing_star_answers_everything_under_it",
        scar="`cf-*` is the shape in use here, and it exists so that one "
             "declaration covers every Cloudflare token without listing them. A "
             "prefix that matches only the stem routes every real reference to "
             "no store at all",
    ),
    Mutation(
        name="a-prefix-address-matches-anywhere-in-the-name",
        file=STORES,
        search='    if pattern.endswith("*"):\n        return value.startswith(pattern[:-1])',
        replace='    if pattern.endswith("*"):\n        return pattern[:-1] in value',
        test="tests.test_stores.AnAddressMatchesExactlyOrByPrefixOrByStar"
             ".test_a_trailing_star_does_not_match_in_the_middle",
        scar="the same line, the other way round, and this one is silent rather "
             "than loud: `cf-*` would then answer `keychain://my-cf-token/...` as "
             "well, so a reference belonging to one store is resolved with "
             "another store's keychain file and unlock reference. The needle "
             "above stays red over a match that is too WIDE, and says nothing "
             "about it",
    ),
    Mutation(
        name="an-exact-address-starts-matching-by-prefix",
        file=STORES,
        search="    return pattern == value",
        replace="    return value.startswith(pattern)",
        test="tests.test_stores.AnAddressMatchesExactlyOrByPrefixOrByStar"
             ".test_an_exact_address_is_not_a_prefix_by_accident",
        scar="an address without a star is a name and not a stem. `github` "
             "silently swallowing `github-actions` puts a personal token and a "
             "CI credential in one store, which is precisely the distinction the "
             "`holds:` policy of that store exists to make",
    ),
    Mutation(
        name="a-store-answers-a-reference-of-another-scheme",
        file=STORES,
        search="        if ref.scheme != self.backend:\n            return False",
        replace="        if False:\n            return False",
        test="tests.test_stores.AReferenceOfAnotherSchemeIsNotAnsweredHere"
             ".test_a_catch_all_keychain_store_does_not_answer_a_keepass_reference",
        scar="the scheme is checked before the address, and a catch-all keychain "
             "store would otherwise answer every reference in the tree because "
             "`*` matches every address. The keepass reference is then resolved "
             "with the keychain store's options, and the database path it needed "
             "is not among them",
    ),
    Mutation(
        name="a-store-whose-password-lives-inside-itself-is-no-longer-reported",
        file=STORES,
        search="            if parsed is not None and parsed.scheme == store.backend and store.answers(parsed):",
        replace="            if False:",
        test="tests.test_stores.CheckDeclarationsNamesWhatAReaderHasToFix"
             ".test_a_store_whose_own_password_lives_inside_itself_is_reported",
        scar="the loop: opening the store requires the credential that is inside "
             "it. Nothing about the file says so, and without this check the "
             "failure arrives later, as an unlock asking for a secret that is "
             "behind the unlock, with a message naming whatever gave way first",
    ),
    Mutation(
        name="the-line-that-names-an-owner-loses-its-place-at-the-front",
        file=STORES,
        search="    matches.sort(key=lambda placement: (0 if placement.owner else 1, placement.store.name))",
        replace="    matches.sort(key=lambda placement: placement.store.name)",
        test="tests.test_stores.PlacementsForNamesEveryPlaceAKindMayGo"
             ".test_a_line_that_names_an_owner_sorts_before_a_generic_one",
        scar="`where` answers a question that had no answer at all, and the "
             "order of the answer is half of it: the first line is the one a "
             "reader pastes. A generic store at the top sends a customer "
             "credential into the catch-all store while the line naming that "
             "customer sits underneath it, unread",
    ),
    Mutation(
        name="the-owner-filter-stops-dropping-another-owners-line",
        file=STORES,
        search="            if owner and placement.owner and placement.owner != owner:",
        replace="            if False:",
        test="tests.test_stores.PlacementsForNamesEveryPlaceAKindMayGo"
             ".test_asking_for_one_owner_drops_the_line_of_another",
        scar="asking where a credential for one customer belongs and being shown "
             "another customer's subtree is worse than being shown nothing: the "
             "shape is right, the path is plausible, and a customer credential "
             "in the wrong customer's tree is the one placement error that "
             "cannot be undone by moving the file",
    ),
    Mutation(
        name="a-store-declares-a-session-it-cannot-be-reached-from-and-is-believed",
        file=STORES,
        search='        if not contexts or "any" in contexts:\n            return True, ""',
        replace='        if True:\n            return True, ""',
        test="tests.test_stores.AStoreSaysWhetherThisSessionCanReachIt"
             ".test_the_same_store_refuses_a_desktop_session",
        scar="`reachable_from:` is what lets a report say `not readable from "
             "here` instead of `missing`, before anything runs. The two answers "
             "send a reader to two different places, and a daemon that could not "
             "tell them apart rotated a credential that was sitting right there",
    ),

    # -- the three shapes the older copies each walked past ------------------
    #
    # Narrowed rather than deleted. A deleted entry leaves `ALL` and `BY_NAME`
    # one pattern shorter, the example table stops matching the list, and the
    # file goes red in a dozen places for a reason that says nothing about the
    # shape under measurement.
    Mutation(
        name="the-fine-grained-github-token-is-narrowed-past-its-own-format",
        file=PATTERNS,
        search=r're.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")',
        replace=r're.compile(r"\bgithub_pat_[A-Za-z0-9_]{500,}\b")',
        test="tests.test_patterns.TheThreeShapesTheOlderCopiesWalkedPast"
             ".test_the_fine_grained_github_token_is_detected",
        scar="the promote scan knew `ghp_` and nothing else, and the two GitHub "
             "formats share no prefix: the classic expression matches "
             "`github_pat_` at no position at all. A fine-grained token in a "
             "tracked file therefore walked through a scan that reported itself "
             "clean",
    ),
    Mutation(
        name="the-google-key-is-narrowed-past-its-own-length",
        file=PATTERNS,
        search=r're.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")',
        replace=r're.compile(r"\bAIza[0-9A-Za-z_-]{45}\b")',
        test="tests.test_patterns.TheThreeShapesTheOlderCopiesWalkedPast"
             ".test_the_google_api_key_is_detected",
        scar="neither CORE scan knew `AIza`. It was carried by a rule that lived "
             "on one instance and never reached CORE, so the shape was found on "
             "the machine holding that rule and nowhere else. The length IS the "
             "expression here: the prefix on its own stands in half the lines of "
             "a client library",
    ),
    Mutation(
        name="the-bearer-header-is-narrowed-past-every-real-token",
        file=PATTERNS,
        search=r're.compile(r"\bBearer [-A-Za-z0-9._~+/=]{20,}")',
        replace=r're.compile(r"\bBearer [-A-Za-z0-9._~+/=]{200,}")',
        test="tests.test_patterns.TheThreeShapesTheOlderCopiesWalkedPast"
             ".test_the_bearer_header_is_detected",
        scar="the overlay scan had no Bearer at all, and a header pasted out of "
             "a curl call that worked is how a live token reaches a tracked "
             "file. The twenty characters are what keeps the prose about bearer "
             "tokens in this tree out of the report",
    ),

    # -- a name is not a value -----------------------------------------------
    Mutation(
        name="the-assignment-pattern-stops-asking-about-its-own-value",
        file=PATTERNS,
        search='            confirm=lambda match: looks_opaque(match.groupdict().get("value", "")),',
        replace="            confirm=None,",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_the_assignment_pattern_only_fires_once_the_value_is_opaque",
        scar="measured over this repo: the assignment pattern without the second "
             "question produced 106 findings and 5 of them were real. A report "
             "where 101 of 106 lines are calls and placeholders is read once, "
             "and the five real ones are read with the same eye as the 101",
    ),
    Mutation(
        name="the-scan-stops-asking-the-hook-the-pattern-declares",
        file=PATTERNS,
        search="        if match and (pattern.confirm is None or pattern.confirm(match)):",
        replace="        if match:",
        test="tests.test_audit_cli.AValueTypedByHandIsMeasuredBeforeItIsBelieved"
             ".test_a_value_that_is_a_call_rather_than_a_literal_is_not",
        scar="the same 106 findings from the other end. The hook sits on the "
             "pattern and `scan_line` is what asks it, so a list that declares a "
             "confirm and a scan that never calls one is correct in the "
             "declaration and unfiltered in the report",
    ),

    # -- looks_opaque, one rejection at a time -------------------------------
    #
    # Six reasons, six needles. Each case in the suite carries a twin that IS
    # accepted, because a rejection on its own goes green for whichever rule
    # fires first, which for most of these strings is the length.
    Mutation(
        name="a-call-on-the-right-hand-side-is-read-as-a-value",
        file=PATTERNS,
        search=OPAQUE_CODE_LINE,
        replace=r"""    if any(ch in value for ch in "$<>{}%,; \\"):""",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_a_call_is_not_a_value",
        scar="`token = get_deploy_token()` is the commonest line of those 101: "
             "the NAME says token and the value is a call. The parentheses are "
             "the only evidence the line carries, and a heuristic reading the "
             "name instead is the scanner that cried 106 times",
    ),
    Mutation(
        name="an-interpolation-is-read-as-a-value",
        file=PATTERNS,
        search=OPAQUE_CODE_LINE,
        replace=r"""    if any(ch in value for ch in "()<>{}%,; \\"):""",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_an_interpolation_is_not_a_value",
        scar="`password: ${VAULT_PASSWORD}` is a REFERENCE to a secret, which is "
             "the thing this skill exists to produce. Reporting it tells the "
             "reader who did it right that they did it wrong, and that line "
             "stands in every deployment file somebody has already cleaned up",
    ),
    Mutation(
        name="a-dotted-path-is-read-as-a-value",
        file=PATTERNS,
        search='    if "." in value and not any(ch.isdigit() for ch in value):',
        replace="    if False:",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_a_dotted_path_is_not_a_value",
        scar="`token = request.headers` and `secret = self.config.token`: an "
             "attribute path is code, and it is mixed case with no digit in it, "
             "which is exactly the shape the character-class rule accepts. "
             "Without the dot the scan reports the line that READS a credential "
             "as the line that holds one",
    ),
    Mutation(
        name="a-stand-in-word-is-read-as-a-value",
        file=PATTERNS,
        search="    if any(word in lowered for word in PLACEHOLDER_WORDS):",
        replace="    if False:",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_a_stand_in_word_is_not_a_value",
        scar="`changeme`, `your-token-here`, `example`: what a person writes "
             "where a value goes, in every template and every README in this "
             "tree. A scanner that reports its own documentation teaches its "
             "reader to skim, and the next line skimmed is a real one",
    ),
    Mutation(
        name="the-shortest-value-the-heuristic-accepts-drops-to-eight",
        file=PATTERNS,
        search="    if len(value) < 12:",
        replace="    if len(value) < 8:",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_a_value_under_twelve_characters_is_not_a_value",
        scar="under twelve characters the alphabet runs out: a port number, a "
             "colour, a word with a digit in it. Nothing that short "
             "authenticates anything, and a rule that accepts it fills the "
             "report with ordinary words while the real hits sit underneath "
             "them",
    ),
    Mutation(
        name="one-character-class-is-enough-to-count-as-opaque",
        file=PATTERNS,
        search="    return classes >= 2",
        replace="    return classes >= 1",
        test="tests.test_patterns.LooksOpaqueSeparatesAValueFromTheCodeAroundIt"
             ".test_a_value_of_one_character_class_is_not_a_value",
        scar="one class is a word, a run of digits or a hex digest: "
             "`abcdefghijklmnop` is prose and `348715930264` is an order number. "
             "Two classes is the cheapest thing that separates an opaque value "
             "from the language around it, and most of the distance between 5 "
             "findings and 106",
    ),

    # -- the excerpt: a finding is a location, never a value -----------------
    Mutation(
        name="the-excerpt-cap-is-widened-to-a-whole-token",
        file=PATTERNS,
        search="def excerpt(match_text: str, width: int = 8) -> str:",
        replace="def excerpt(match_text: str, width: int = 64) -> str:",
        test="tests.test_patterns.NoExcerptCarriesEnoughOfAValueToUseIt"
             ".test_a_long_match_is_cut_to_the_cap_and_an_ellipsis",
        scar="a report that quotes the match writes the secret into the log that "
             "exists to protect it. Measured here: a verify pass once decoded a "
             "base64 credential into the transcript while checking whether the "
             "credential was really there. Eight characters recognise the hit on "
             "the line and authenticate nothing",
    ),
    Mutation(
        name="the-cut-stops-happening-and-the-whole-match-reaches-the-report",
        file=PATTERNS,
        search='    return match_text[:width] + "…"',
        replace="    return match_text",
        test="tests.test_audit.TheReportNamesThePlaceAndNeverTheValue"
             ".test_the_rendered_report_does_not_carry_the_value",
        scar="the same rule at the far end. Every finding goes through this one "
             "function, so a cut that stops happening puts the value into a "
             "report that gets pasted into an issue, and an issue is a place "
             "nothing can be unprinted from",
    ),

    # -- a line that declares itself a fixture -------------------------------
    Mutation(
        name="the-allowlist-pragma-stops-being-recognised",
        file=PATTERNS,
        search="    return PRAGMA in line",
        replace="    return False",
        test="tests.test_patterns.ADeliberateFixtureSaysSoOnItsOwnLine"
             ".test_a_line_carrying_the_pragma_reports_nothing",
        scar="a suite about a scanner is full of strings shaped like the thing it "
             "looks for, and so is a template and so is a README. Without the "
             "pragma the report is mostly its own fixtures, and a report of its "
             "own fixtures is read once",
    ),
    Mutation(
        name="every-line-reads-as-a-deliberate-fixture",
        file=PATTERNS,
        search="    return PRAGMA in line",
        replace="    return True",
        test="tests.test_patterns.ADeliberateFixtureSaysSoOnItsOwnLine"
             ".test_the_same_line_without_the_pragma_reports",
        scar="the same line the other way round, and this one is silent: every "
             "line is exempt, the scan finds nothing, the run is green, and a "
             "scanner switched off looks exactly like a clean tree. The needle "
             "above stays red over a pragma nobody reads and says nothing at all "
             "about a pragma everybody gets",
    ),
    Mutation(
        name="the-scan-never-asks-whether-the-line-declared-itself",
        file=PATTERNS,
        search="    if exempt(line):\n        return []",
        replace="    if False:\n        return []",
        test="tests.test_audit_cli.ALineThatDeclaresItselfAFixtureIsNotAFinding"
             ".test_the_marked_line_is_walked_past",
        scar="the predicate above is intact and nothing calls it. The contract is "
             "that a deliberate fixture says so on its own line and a real secret "
             "never does, so the marker has to be read where the line is read. "
             "This needle names the end a person meets: the exit code of a run "
             "over a tree of fixtures",
    ),

    # -- personal data is reported, never moved, and can be switched off -----
    Mutation(
        name="the-personal-data-switch-stops-reaching-the-patterns",
        file=PATTERNS,
        search='        if pattern.kind == "pii" and not include_pii:\n            continue',
        replace="        if False:\n            continue",
        test="tests.test_patterns.PersonalDataIsReportedAndNeverProposedForAVault"
             ".test_dropping_personal_data_keeps_the_credential_on_the_same_line",
        scar="`--no-pii` is for the reader hunting credentials, and it has to drop "
             "the two personal-data patterns and nothing else. The case it is "
             "measured by puts all three on ONE line, because a filter that "
             "dropped the line instead would take the credential with it and look "
             "identical on a line carrying only an IBAN",
    ),
    Mutation(
        name="the-no-pii-flag-is-parsed-and-never-passed-on",
        file=CLI,
        search="                           include_pii=not args.no_pii)",
        replace="                           include_pii=True)",
        test="tests.test_audit_cli.NoPiiNarrowsTheReportToCredentialsOnly"
             ".test_the_findings_are_gone_from_the_json_and_not_merely_uncounted",
        scar="an option the parser accepts and the engine never receives is an "
             "option that does nothing. The needle names the JSON case because it "
             "reads the findings themselves rather than the count line, which is "
             "where a wrapper reads them and where hiding a hit and dropping one "
             "look different",
    ),

    # -- a hit inside a declared file store is the store working -------------
    Mutation(
        name="a-value-inside-a-declared-store-is-reported-like-any-other",
        file=AUDIT,
        search="            inside = _inside(full, roots)",
        replace="            inside = False",
        test="tests.test_audit.AValueInsideADeclaredFileStoreIsTheStoreWorking"
             ".test_the_hit_inside_the_declared_directory_is_marked_expected",
        scar="a `file` store is a directory of values by declaration. Reporting "
             "its contents makes every scan on a machine that has one arrive with "
             "eleven expected findings, and a reader who skims eleven skims the "
             "twelfth",
    ),
    Mutation(
        name="a-neighbour-directory-is-read-as-being-inside-the-declared-store",
        file=AUDIT,
        search='    return any(real == base or real.startswith(base.rstrip("/") + "/") for base in roots)',
        replace='    return any(real == base or real.startswith(base.rstrip("/")) for base in roots)',
        test="tests.test_audit.AValueInsideADeclaredFileStoreIsTheStoreWorking"
             ".test_a_neighbour_whose_name_starts_with_the_store_is_still_outside",
        scar="the prefix bug the file backend carries a needle for, here on the "
             "reporting side: `vault-old` is the directory somebody makes while "
             "rotating, and without the separator it counts as part of `vault`. "
             "The stale copy then lies in the one place the scan calls expected "
             "and never prints",
    ),
    Mutation(
        name="every-store-with-a-path-declares-a-directory-full-of-values",
        file=AUDIT,
        search='        if store.backend != "file":\n            continue',
        replace="        if False:\n            continue",
        test="tests.test_audit.AValueInsideADeclaredFileStoreIsTheStoreWorking"
             ".test_a_store_on_another_backend_declares_none_even_when_it_names_a_path",
        scar="a keychain store declares the keychain FILE it reads and a KeePass "
             "store declares its database. Taking a path out of every location "
             "exempts the directory those files sit in, which is where the other "
             "keychains and the other databases sit too",
    ),

    # -- where the value belongs comes out of the declarations ---------------
    Mutation(
        name="the-suggestion-stops-asking-the-placement-policy",
        file=AUDIT,
        search="                cache[kind] = stores_mod.placements_for(stores, kind)",
        replace="                cache[kind] = []",
        test="tests.test_audit.ASuggestionComesFromThePlacementPolicyAndNotFromTheScanner"
             ".test_the_finding_names_the_store_that_declares_this_kind",
        scar="the answer comes out of the declarations, or it is decided per "
             "session by whoever is holding the token, which is the habit that put "
             "credentials in working folders on two machines. A finding that names "
             "no store is `suspicious string` with more words around it",
    ),
    Mutation(
        name="every-finding-is-routed-as-the-same-kind-of-secret",
        file=AUDIT,
        search='        kind = pattern.suggests if pattern else ""',
        replace='        kind = "personal-token"',
        test="tests.test_audit.ASuggestionComesFromThePlacementPolicyAndNotFromTheScanner"
             ".test_a_pattern_that_declares_no_kind_gets_no_suggestion",
        scar="the kind is per pattern, and `password-assignment` declares none on "
             "purpose: it says a value is here, never what the value is for. A "
             "kind invented for it sends a database password to the store that "
             "holds personal tokens, and the proposal is the line a person pastes",
    ),
    Mutation(
        name="a-value-already-inside-its-store-is-proposed-a-store",
        file=AUDIT,
        search='        if finding.kind != "credential" or finding.expected:',
        replace='        if finding.kind != "credential":',
        test="tests.test_audit.AValueInsideADeclaredFileStoreIsTheStoreWorking"
             ".test_nothing_is_suggested_for_a_value_that_is_already_where_it_belongs",
        scar="a value the declaration already put where it belongs needs no home. "
             "Proposing one tells the reader to move a file the store declares, "
             "and a reader who follows that advice once stops following the report",
    ),

    # -- what the walk skips, and what it counts -----------------------------
    Mutation(
        name="the-audit-walk-follows-a-symlink",
        file=AUDIT,
        search="            if os.path.islink(full) or os.path.isdir(full):",
        replace="            if os.path.isdir(full):",
        test="tests.test_audit.ASymlinkIsNotFollowed"
             ".test_the_value_behind_the_link_is_not_reported",
        scar="this repo carries three committed symlinks that point back into "
             "itself, and following them counted every skill three times when "
             "`discover` learned the same lesson. The worse half is a link that "
             "leaves the tree: a scan of a repository then reads a home directory "
             "and prints what it finds there",
    ),
    Mutation(
        name="a-file-that-could-not-be-read-is-counted-as-read",
        file=AUDIT,
        search="                report.skipped_binary += 1",
        replace="                report.files_read += 1",
        test="tests.test_audit.WhatCannotBeReadIsCountedRatherThanPassedOver"
             ".test_both_kinds_of_skip_reach_the_counter",
        scar="a skip that leaves no trace reads exactly like a file that was "
             "clean. The count line is the only thing telling a reader the scan "
             "looked at fewer files than the tree holds, and a value inside a "
             "skipped file is a value nobody has looked at",
    ),
    Mutation(
        name="the-walk-decodes-what-it-was-supposed-to-skip",
        file=AUDIT,
        search="            text = discover.readable_text(full)",
        replace="            text = discover.readable_text(full)\n"
                "            if text is None:\n"
                '                with open(full, encoding="utf-8", errors="replace") as handle:\n'
                "                    text = handle.read()",
        test="tests.test_audit.WhatCannotBeReadIsCountedRatherThanPassedOver"
             ".test_the_value_in_the_binary_file_is_not_reported",
        scar="a PNG is not text and a two megabyte log is not worth a regular "
             "expression per line. The needle ADDS the decode rather than removing "
             "the branch, because deleting the branch hands None to `splitlines` "
             "and the case goes red over an AttributeError, which measures nothing "
             "about what a scan reports out of a compressed image",
    ),

    # -- the exit code a hook and a CI job read ------------------------------
    Mutation(
        name="a-loose-credential-exits-zero",
        file=CLI,
        search="    return EX_MISSING if report.credentials else EX_OK",
        replace="    return EX_OK",
        test="tests.test_audit_cli.APlantedCredentialIsFoundAndSaysWhereItStands"
             ".test_it_exits_the_code_that_means_a_value_is_lying_in_a_file",
        scar="a wrapper reads the code and not the prose. `audit` in a hook or a "
             "CI job that exits 0 over a token lying in a file is a gate that is "
             "switched on and passing, which is worse than no gate at all because "
             "somebody trusts it",
    ),
    Mutation(
        name="an-invoice-in-the-tree-fails-the-run",
        file=CLI,
        search="    return EX_MISSING if report.credentials else EX_OK",
        replace="    return EX_MISSING if report.findings else EX_OK",
        test="tests.test_audit_cli.PersonalDataIsReportedAndNeverProposedForAVault"
             ".test_a_repository_holding_an_invoice_is_not_broken",
        scar="personal data does not change the verdict. An IBAN is on every "
             "invoice its owner writes, so a gate counting findings rather than "
             "credentials fails over a document doing its job, and a gate that "
             "fails over invoices is switched off within a week",
    ),
    Mutation(
        name="a-hit-inside-a-declared-store-counts-towards-the-verdict",
        file=AUDIT,
        search='        return [f for f in self.findings if f.kind == "credential" and not f.expected]',
        replace='        return [f for f in self.findings if f.kind == "credential"]',
        test="tests.test_audit.AValueInsideADeclaredFileStoreIsTheStoreWorking"
             ".test_it_is_kept_out_of_the_credentials_to_deal_with",
        scar="the same property from the report's side: `credentials` is the list "
             "the count line prints and the exit code is taken from. A machine "
             "whose secrets live in a `file` store would fail every run on the "
             "strength of its own store, and red every time is green",
    ),

    # -- the optional second opinion stays optional --------------------------
    Mutation(
        name="the-second-opinion-runs-without-being-asked",
        file=CLI,
        search="    if args.with_gitleaks:",
        replace="    if True:",
        test="tests.test_audit_cli.GitleaksIsASecondOpinionAndNeverTheVerdict"
             ".test_without_the_flag_no_second_process_is_started",
        scar="the second opinion is opt in because it is a second process over the "
             "whole tree. A verb reaching for it by itself shells out on every "
             "run, on every machine, installed or not, and adds a report the "
             "caller did not ask for",
    ),
    Mutation(
        name="the-missing-binary-is-no-longer-noticed-before-the-call",
        file=AUDIT,
        search="    if not gitleaks_available(runner=runner):",
        replace="    if False:",
        test="tests.test_audit.TheSecondOpinionIsOptionalAndSaysWhenItDidNotRun"
             ".test_nothing_runs_when_the_binary_is_absent",
        scar="a machine without the tool has to be TOLD, rather than shown a zero "
             "that reads like a clean tree. Calling it anyway turns a missing "
             "optional tool into a failure in the middle of a report that "
             "otherwise works",
    ),
)
