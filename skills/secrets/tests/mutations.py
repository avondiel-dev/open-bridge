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
)
