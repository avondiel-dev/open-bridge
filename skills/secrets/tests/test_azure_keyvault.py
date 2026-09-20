"""azure-keyvault: the argv it builds, the metadata it carries, the file it uses.

Every case here is driven through the `runner=` seam. No machine in this fleet
runs this suite with `az` signed in to the tenant that owns the vault, and none
of these cases wants one: a suite that reached a real Key Vault would write a
version into somebody's audit log to prove that a flag was spelled correctly.

Four properties, and most of this file is one of them in a different shape.

* THE SUBSCRIPTION IS NAMED WHENEVER THE STORE DECLARES ONE. The default
  subscription of a machine is not always the tenant of the vault, and `az`
  answers for the wrong one without a word. The read then reports "no secret of
  that name" for a secret that is sitting there, one tenant over.
* THE VALUE GOES IN THROUGH A FILE, NEVER THROUGH `--value`. Everything in argv
  is readable through `ps` by every process of the same user, which is how
  tokens ended up in the process list of two machines in this fleet before
  anyone looked. The file exists for the length of one call, at mode 0600, and
  it goes away whatever the tool does.
* THE METADATA TRAVELS IN THE SAME CALL AS THE VALUE. `az keyvault secret set`
  with `--value` alone creates a new version whose content type is null and
  which carries no tags at all. The portal then shows an entry nobody can place,
  and the second call that would have fixed it is the one people forget.
* A FAILED READ IS EITHER A MISS OR A FAULT, AND NEVER BOTH. A missing secret is
  a fact about the vault that a caller may act on. A Forbidden is a fact about
  the signed-in identity, and a rotation watcher that reads it as a miss deletes
  and recreates a secret that was never gone.
"""

from __future__ import annotations

import stat
from pathlib import Path

from tests.conftest import FakeRunner, MachineGuard, completed, mod, synthetic_token

azure = mod("engine.backends.azure_keyvault")
base = mod("engine.backends.base")
errors = mod("engine.errors")
refs = mod("engine.refs")
values = mod("engine.values")

#: Distinguishes "the case said nothing about this" from "the case said empty".
#: An empty content type is a real configuration and has to be expressible, so a
#: plain default would swallow the case that asserts the flag is then absent.
UNSET = object()

#: The reference most cases read. Two segments, which is all this scheme takes:
#: the vault and the secret. There is no group and no field.
TOKEN_REF = "azure-keyvault://bridge-kv/storecove-api-token"

#: A subscription as `az` wants it: the id, not the display name. Lower case and
#: synthetic, and it appears in an argv on purpose, which is safe because a
#: subscription id is an address and not a credential.
SUBSCRIPTION = "b7c1d2e0-aaaa-4bcd-9f00-1a2b3c4d5e6f"


class AzureCase(MachineGuard):
    """A backend wired to a fake process, never to a tenant."""

    VAULT = "bridge-kv"
    SECRET = "storecove-api-token"

    class RunnerThatReadsTheFileTheValueTravelsIn(FakeRunner):
        """Looks at the temporary file WHILE the call is in flight.

        The file lives between the write and the `finally` that removes it, so a
        case looking afterwards could only ever find it gone. Mode and content
        are taken here, inside the call, which is the one moment the tool itself
        would have seen them too.

        Defined inside the case class rather than beside it because every class
        at module level in this suite has to stand under `MachineGuard`, and a
        runner is scaffolding rather than a case.
        """

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.seen: list = []

        def __call__(self, argv, *, invocation=None):
            argv = [str(a) for a in (argv or ())]
            if "--file" in argv:
                path = Path(argv[argv.index("--file") + 1])
                self.seen.append({
                    "path": path,
                    "mode": stat.S_IMODE(path.stat().st_mode),
                    "directory": path.parent,
                    "directory_mode": stat.S_IMODE(path.parent.stat().st_mode),
                    "content": path.read_bytes(),
                })
            return super().__call__(argv, invocation=invocation)

    def setUp(self):
        super().setUp()
        self.value = synthetic_token("storecove")  # pragma: allowlist secret

    # -- builders -----------------------------------------------------------

    def ref(self, uri: str = TOKEN_REF):
        return refs.parse(uri)

    def session(self):
        """A fixed session rather than a detected one.

        This backend does not read the context, but `Context.detect()` asks
        whether stdin is a terminal, and a case whose result depends on how the
        suite was started behaves differently in CI than on a laptop.
        """
        return base.Context(platform="linux", interactive=False, over_ssh=False,
                            display=False)

    def secret(self, text=None):
        return values.Secret(self.value if text is None else text, origin=TOKEN_REF)

    def backend(self, runner=None, *, subscription=None, tags=None, vault_url=None,
                content_type=UNSET):
        options = {} if content_type is UNSET else {"content_type": content_type}
        return azure.AzureKeyVaultBackend(
            subscription=subscription, vault_url=vault_url, tags=tags,
            runner=runner, context=self.session(),
            # `az` is not installed on the runner this suite has to stay green
            # on, and the PATH probe is the one step of a read that does not go
            # through the runner seam. Without this every case below would fail
            # on the probe rather than on the behaviour it is named after, and
            # the file would be an Azure tier wearing a disguise.
            assume_available=True,
            **options)

    # -- one read -----------------------------------------------------------

    def runner(self, *, rc=0, stdout="", stderr="") -> FakeRunner:
        fake = FakeRunner()
        fake.add("secret show", completed(rc=rc, stdout=stdout, stderr=stderr))
        return fake

    def reading(self, *, rc=0, stdout="", stderr="", uri=TOKEN_REF, subscription=None):
        fake = self.runner(rc=rc, stdout=stdout, stderr=stderr)
        backend = self.backend(fake, subscription=subscription)
        return backend.read(self.ref(uri)), fake

    def raised(self, exception_type, **kwargs):
        with self.assertRaises(exception_type) as caught:
            self.reading(**kwargs)
        return caught.exception

    # -- one write ----------------------------------------------------------

    def writing(self, value=None, *, tags=None, declared_tags=None, subscription=None,
                content_type=UNSET, replace=False, set_rc=0, set_stderr="",
                runner=None, read_back=None):
        """One write through the whole backend, plus the runner that saw it.

        A caller that wants the write to fail in its own way adds its route to
        `runner` first: routes are matched in the order they were added, so the
        two added here are the fallback rather than an override.
        """
        value = self.value if value is None else value
        fake = self.RunnerThatReadsTheFileTheValueTravelsIn() if runner is None else runner
        fake.add("secret set", completed(rc=set_rc, stderr=set_stderr))
        fake.add("secret show",
                 completed(stdout=(value if read_back is None else read_back) + "\n"))
        backend = self.backend(fake, subscription=subscription, tags=declared_tags,
                               content_type=content_type)
        reading = backend.write(self.ref(), self.secret(value), replace=replace, tags=tags)
        return reading, fake

    # -- reading the recording ----------------------------------------------

    @staticmethod
    def set_argv(fake: FakeRunner) -> tuple:
        return fake.calls[fake.index_of("secret set")]["argv"]

    @staticmethod
    def without_the_temporary_path(argv) -> list:
        """The argv with the operand after `--file` blanked out.

        The path is a fresh temporary directory per call, so two writes never
        agree on it, and a case comparing whole argvs would be comparing
        `mkdtemp` rather than the backend.
        """
        argv = [str(a) for a in argv]
        if "--file" in argv:
            argv[argv.index("--file") + 1] = "<the temporary file>"
        return argv

    @staticmethod
    def show_calls(fake: FakeRunner) -> list:
        return [call for call in fake.calls if "secret show" in call["joined"]]


class TheReadArgvIsWhatTheMeasuredCommandTakes(AzureCase):
    """`az keyvault secret show --vault-name V --name S --query value -o tsv`.

    Pinned as a whole list rather than by substring. A backend that grew an
    extra flag, or lost the projection that makes the output the value alone,
    would still contain every substring a looser case looks for.
    """

    def test_the_vault_and_the_secret_are_both_named(self):
        argv = self.backend().argv_read(self.ref())
        self.assertEqual(argv, ["az", "keyvault", "secret", "show",
                                "--vault-name", self.VAULT, "--name", self.SECRET,
                                "--query", "value", "-o", "tsv"])

    def test_the_projection_asks_for_the_value_alone(self):
        # Without `--query value` the command prints the whole entry as JSON,
        # value included, and every caller then parses a document to get at one
        # field. The projection is also what keeps the value out of a JSON blob
        # that something downstream might log whole.
        argv = self.backend().argv_read(self.ref())
        self.assertEqual(argv[argv.index("--query") + 1], "value")

    def test_the_output_is_tsv_and_not_json(self):
        argv = self.backend().argv_read(self.ref())
        self.assertEqual(argv[argv.index("-o") + 1], "tsv")

    def test_the_subscription_is_named_when_the_store_declares_one(self):
        # The scar. The default subscription of a machine is not always the
        # tenant that owns the vault, and `az` answers for the wrong one without
        # a word: the read comes back as "no secret of that name" for a secret
        # that is sitting there, one tenant over. Naming it costs nothing and
        # removes the whole class of failure.
        argv = self.backend(subscription=SUBSCRIPTION).argv_read(self.ref())
        self.assertIn("--subscription", argv)
        self.assertEqual(argv[argv.index("--subscription") + 1], SUBSCRIPTION)

    def test_without_a_declared_subscription_the_flag_is_absent_entirely(self):
        # Not the flag with an empty value: `az` reads the next word as the
        # subscription, so an empty one addresses whatever followed it.
        argv = self.backend().argv_read(self.ref())
        self.assertNotIn("--subscription", argv)

    def test_the_subscription_stands_with_the_other_addressing_flags(self):
        argv = self.backend(subscription=SUBSCRIPTION).argv_read(self.ref())
        self.assertLess(argv.index("--subscription"), argv.index("--query"),
                        "the addressing flags belong together, before the projection")

    def test_the_read_runs_the_argv_this_backend_says_it_runs(self):
        # argv_read() is worth nothing as a promise if read() assembles its own.
        expected = self.backend(subscription=SUBSCRIPTION).argv_read(self.ref())
        _, fake = self.reading(stdout=self.value + "\n", subscription=SUBSCRIPTION)
        self.assertEqual(fake.calls[0]["argv"], tuple(expected))

    def test_a_reference_with_no_secret_name_is_refused_before_anything_runs(self):
        # The grammar refuses this one first, so it has to be built by hand to
        # reach the backend at all. It is still worth a case: the backstop is
        # what stands between a hand assembled Ref and an `az` call that asks
        # the vault for the secret called `--query`.
        headless = refs.Ref(scheme="azure-keyvault", store=self.VAULT, path=(),
                            field=None, raw="azure-keyvault://" + self.VAULT)
        fake = self.runner()
        with self.assertRaises(errors.Refused) as caught:
            self.backend(fake).read(headless)
        self.assertIn("no secret", str(caught.exception))
        self.assertEqual(fake.calls, [], "the refusal came after a call to az")


class TheValueComesBackAsTsvPrintedIt(AzureCase):
    """tsv prints the field and one terminating newline.

    That newline belongs to the output format, not to the value, and every byte
    before it does belong to the value. Both halves matter: a stripped trailing
    newline that was part of a PEM key breaks the key, and a kept one breaks an
    Authorization header in a way that is invisible in a terminal.
    """

    def read_printing(self, stdout: str):
        reading, _ = self.reading(stdout=stdout)
        return reading

    def test_the_newline_tsv_adds_is_removed(self):
        self.assertEqual(self.read_printing(self.value + "\n").secret.expose(),
                         self.value.encode("utf-8"))

    def test_a_value_that_itself_ends_in_a_newline_keeps_it(self):
        reading = self.read_printing(self.value + "\n\n")
        self.assertEqual(reading.secret.expose(), self.value.encode("utf-8") + b"\n")

    def test_a_value_with_spaces_arrives_whole(self):
        self.assertEqual(self.read_printing("two words here\n").secret.expose(),
                         b"two words here")

    def test_a_value_outside_ascii_arrives_whole(self):
        self.assertEqual(self.read_printing("Straße\n").secret.expose(),
                         "Straße".encode("utf-8"))

    def test_the_reading_names_the_vault_it_came_from(self):
        self.assertEqual(self.read_printing(self.value + "\n").store, self.VAULT)

    def test_the_reading_carries_the_canonical_reference(self):
        self.assertEqual(self.read_printing(self.value + "\n").ref, TOKEN_REF)

    def test_the_wrapped_value_knows_where_it_came_from(self):
        self.assertEqual(self.read_printing(self.value + "\n").secret.origin, TOKEN_REF)

    def test_the_backend_hands_back_a_wrapped_value_and_not_a_string(self):
        # The wrapper is what makes printing a value an explicit act. A backend
        # that returned a str would put the value into the next log line that
        # interpolates a Reading.
        with self.assertRaises(TypeError):
            str(self.read_printing(self.value + "\n").secret)

    def test_the_value_that_came_back_was_never_in_an_argv(self):
        _, fake = self.reading(stdout=self.value + "\n")
        self.assertFalse(fake.argv_carried(self.value),
                         "the value appeared in argv:\n" + fake.joined_calls)

    def test_a_secret_that_exists_with_no_bytes_in_it_is_a_miss(self):
        # `az` exits 0 and prints the terminating newline alone. Every caller
        # that tested existence rather than length carried the emptiness one
        # layer further before anything failed.
        reading = self.read_printing("\n")
        self.assertFalse(reading.present)
        self.assertIn("empty", reading.note)

    def test_the_empty_reading_still_carries_a_secret_of_zero_bytes(self):
        reading = self.read_printing("\n")
        self.assertIsNotNone(reading.secret)
        self.assertEqual(reading.length, 0)


class StderrDecidesWhetherAFailedReadIsAMissOrAFault(AzureCase):
    """The split the exit code contract rests on.

    The wordings below are the BRANCHES this backend takes, not a claim about
    which version of `az` prints which sentence. What matters is that a miss and
    a refusal leave the backend by different doors, because a daemon reading a
    refusal as a miss rotates a secret that was never gone.
    """

    def read_failing(self, stderr: str, rc: int = 1):
        reading, _ = self.reading(rc=rc, stderr=stderr)
        return reading

    def raises_from(self, exception_type, stderr: str, rc: int = 1):
        return self.raised(exception_type, rc=rc, stderr=stderr)

    def test_a_missing_secret_comes_back_as_a_reading_rather_than_an_error(self):
        reading = self.read_failing(
            "ERROR: (SecretNotFound) A secret with (name/id) storecove-api-token "
            "was not found in this key vault.\n")
        self.assertFalse(reading.present)

    def test_the_miss_says_there_is_no_secret_of_that_name_in_this_vault(self):
        reading = self.read_failing("ERROR: (SecretNotFound) not in this key vault.\n")
        self.assertIn("no secret of that name", reading.note)

    def test_a_miss_carries_no_secret_at_all(self):
        # Not an empty one. A caller that tests the secret rather than `present`
        # must not find an object it can hand on as if it were a value.
        reading = self.read_failing("ERROR: (SecretNotFound) gone.\n")
        self.assertIsNone(reading.secret)

    def test_the_miss_still_names_the_vault_it_looked_in(self):
        self.assertEqual(self.read_failing("ERROR: (SecretNotFound) gone.\n").store,
                         self.VAULT)

    def test_a_forbidden_is_not_readable_here_and_not_a_miss(self):
        error = self.raises_from(
            errors.NotReadableHere,
            "ERROR: (Forbidden) The user, group or application does not have "
            "secrets get permission on key vault bridge-kv.\n")
        self.assertEqual(error.exit_code, errors.EX_UNAVAILABLE)

    def test_the_refusal_says_the_secret_may_well_be_there(self):
        # The sentence a person needs at three in the morning: nothing has been
        # lost, this identity simply may not ask.
        error = self.raises_from(errors.NotReadableHere, "ERROR: (Forbidden) denied.\n")
        self.assertIn("may be there", error.hint)

    def test_the_refusal_names_both_ways_a_tenant_can_grant_this(self):
        error = self.raises_from(errors.NotReadableHere, "ERROR: (Forbidden) denied.\n")
        for cause in ("access policy", "RBAC", "subscription"):
            self.assertIn(cause, error.hint)

    def test_every_wording_that_means_this_identity_may_not_ask(self):
        for stderr in ("ERROR: (Forbidden) Caller is not authorized.",
                       "ERROR: the caller does not have secrets get permission here."):
            with self.subTest(stderr=stderr):
                self.raises_from(errors.NotReadableHere, stderr + "\n")

    def test_anything_else_raises_rather_than_returning_a_reading(self):
        self.raises_from(errors.SecretsError,
                         "ERROR: the command failed with an unexpected error.\n", rc=2)

    def test_an_unclassified_failure_names_the_exit_code_the_tool_left(self):
        error = self.raises_from(errors.SecretsError, "ERROR: unexpected.\n", rc=3)
        self.assertIn("3", str(error))

    def test_the_first_line_of_stderr_becomes_the_hint(self):
        # An `az` failure prints several lines and the later ones are usually
        # the traceback it offers to file as a bug. The first non-empty line is
        # the sentence a person needs, and blank leading lines are skipped
        # rather than passed on as an empty hint.
        error = self.raises_from(
            errors.SecretsError,
            "\n   ERROR: the command failed with an unexpected error.\n"
            "To open an issue, please run: 'az feedback'\n", rc=2)
        self.assertEqual(error.hint,
                         "ERROR: the command failed with an unexpected error.")

    def test_a_failure_with_a_silent_stderr_still_says_something(self):
        error = self.raises_from(errors.SecretsError, "", rc=2)
        self.assertIn("no message on stderr", error.hint)

    def test_an_unclassified_failure_is_never_reported_as_a_miss(self):
        # The one sentence this class exists for, stated as its own case so a
        # softening of the classification cannot pass unnoticed.
        error = self.raises_from(errors.SecretsError, "ERROR: unexpected.\n", rc=2)
        self.assertNotIsInstance(error, errors.SecretMissing)

    def test_a_refusal_is_never_reported_as_a_miss_either(self):
        with self.assertRaises(errors.NotReadableHere):
            self.read_failing("ERROR: (Forbidden) denied.\n")

    def test_a_failed_read_carries_the_reference_and_never_the_value(self):
        error = self.raises_from(errors.SecretsError, "ERROR: unexpected.\n", rc=2)
        self.assertEqual(error.ref, TOKEN_REF)
        self.assertNotIn(self.value, error.report())


class NoValueEverTravelsInArgvOnTheWayIntoTheVault(AzureCase):
    """The one assertion this skill exists for, on the path that carries a value.

    `az keyvault secret set --value <token>` is the single most common way a
    credential leaves a shell: it stands in `ps` for every process of the same
    user for as long as the call runs, and it lands in the shell history of the
    person who typed it. `--file` is the whole reason this backend exists rather
    than a two line wrapper.
    """

    def setUp(self):
        super().setUp()
        self.reading, self.fake = self.writing()

    def test_the_write_hands_the_value_over_in_a_file(self):
        self.assertIn("--file", self.set_argv(self.fake))

    def test_the_value_flag_is_never_used(self):
        self.assertNotIn("--value", self.set_argv(self.fake))

    def test_no_recorded_call_carries_the_value_in_argv(self):
        self.assertFalse(self.fake.argv_carried(self.value),
                         "the value appeared in argv:\n" + self.fake.joined_calls)

    def test_the_file_named_in_argv_is_a_path_and_not_the_value(self):
        argv = self.set_argv(self.fake)
        named = argv[argv.index("--file") + 1]
        self.assertTrue(named.startswith("/"), "the operand after --file is a path")
        self.assertNotIn(self.value, named)

    def test_the_value_does_not_travel_in_the_environment_either(self):
        # The third door out of a process, and the quiet one: an environment is
        # readable from /proc on Linux and inherited by every child.
        for call in self.fake.calls:
            with self.subTest(argv=call["joined"]):
                self.assertNotIn(self.value, str(call["env"] or {}))

    def test_the_write_argv_is_what_this_backend_says_it_is(self):
        recorded = self.set_argv(self.fake)
        argv = self.backend().argv_write(self.ref(), recorded[recorded.index("--file") + 1],
                                         {})
        self.assertEqual(list(recorded), argv)


class TheMetadataTravelsInTheSameCallAsTheValue(AzureCase):
    """One call, or an entry the portal shows and nobody can place.

    `az keyvault secret set --value x` alone creates a NEW VERSION whose content
    type is null and which carries no tags. The metadata of the previous version
    does not come along. The second call that would repair it is the one people
    forget, and what is left is an entry with no owner, no purpose and no date
    in a vault that holds forty of them.
    """

    def setUp(self):
        super().setUp()
        self.tags = {"owner": "platform", "rotated": "2026-09-20"}
        self.reading, self.fake = self.writing(tags=self.tags)
        self.argv = self.set_argv(self.fake)

    def test_the_content_type_is_set_in_the_call_that_writes(self):
        self.assertIn("--content-type", self.argv)
        self.assertEqual(self.argv[self.argv.index("--content-type") + 1], "text/plain")

    def test_the_tags_are_set_in_the_call_that_writes(self):
        self.assertIn("--tags", self.argv)

    def test_every_tag_is_one_operand_in_the_key_equals_value_shape(self):
        after = self.argv[self.argv.index("--tags") + 1:]
        for key, value in self.tags.items():
            with self.subTest(tag=key):
                self.assertIn("%s=%s" % (key, value), after)

    def test_the_value_and_the_metadata_stand_in_one_call(self):
        # The whole point. Two calls leave a window in which the version exists
        # with no context, and a failure between them leaves it there for good.
        for flag in ("--file", "--content-type", "--tags"):
            with self.subTest(flag=flag):
                self.assertIn(flag, self.argv)

    def test_exactly_one_call_writes(self):
        writes = [call for call in self.fake.calls if "secret set" in call["joined"]]
        self.assertEqual(len(writes), 1,
                         "a second set call is a second version:\n" + self.fake.joined_calls)

    def test_a_tag_declared_by_the_store_is_carried_too(self):
        _, fake = self.writing(declared_tags={"managed-by": "bridge"},
                               tags={"owner": "platform"})
        argv = self.set_argv(fake)
        self.assertIn("managed-by=bridge", argv)
        self.assertIn("owner=platform", argv)

    def test_a_tag_given_at_the_call_wins_over_the_one_the_store_declares(self):
        _, fake = self.writing(declared_tags={"owner": "unknown"},
                               tags={"owner": "platform"})
        argv = self.set_argv(fake)
        self.assertIn("owner=platform", argv)
        self.assertNotIn("owner=unknown", argv)

    def test_without_any_tags_the_flag_is_absent_rather_than_empty(self):
        # `--tags` with nothing after it is not "leave the tags alone", it is an
        # operand hunt: the next flag becomes the tag.
        _, fake = self.writing()
        self.assertNotIn("--tags", self.set_argv(fake))

    def test_a_store_that_declares_no_content_type_sends_no_empty_flag(self):
        _, fake = self.writing(content_type="")
        self.assertNotIn("--content-type", self.set_argv(fake))

    def test_the_write_asks_for_no_output_because_the_output_is_the_entry(self):
        # `az keyvault secret set` prints the whole entry as JSON when it is
        # done, value included. A wrapper that captured that would have the
        # value in a second place for no reason at all.
        self.assertEqual(list(self.argv[-2:]), ["-o", "none"])

    def test_replace_changes_nothing_because_a_write_always_adds_a_version(self):
        # Key Vault has no in place overwrite: `set` appends a version and the
        # previous one stays readable by its id. So `--replace` has nothing to
        # switch on here, and pretending otherwise would be a promise the store
        # cannot keep.
        _, plain = self.writing()
        _, replacing = self.writing(replace=True)
        self.assertEqual(self.without_the_temporary_path(self.set_argv(plain)),
                         self.without_the_temporary_path(self.set_argv(replacing)))


class TheFileTheValueTravelsThroughIsPrivateAndTemporary(AzureCase):
    """Mode 0600 from the first byte, and gone whatever the tool does.

    A file is the safe channel only for as long as it is unreadable and short
    lived. The mode is given to `os.open` rather than set afterwards, so there
    is no window in which the file exists with the umask's idea of a mode, and
    the removal sits in a `finally` rather than after the call, so a tool that
    fails does not leave a token in a temporary directory on a machine that
    never reboots.
    """

    def setUp(self):
        super().setUp()
        self.reading, self.fake = self.writing()
        self.seen = self.fake.seen[0]

    def test_the_tool_was_handed_a_file_that_existed_when_it_ran(self):
        # Without this the rest of the class is green over a file that was never
        # created, which is also what a broken recording looks like.
        self.assertEqual(len(self.fake.seen), 1)

    def test_the_file_carries_exactly_the_value_and_nothing_else(self):
        # No trailing newline of its own. `az` sends the bytes of the file as
        # the value, so a newline added here is a newline in the vault, and a
        # token with one fails an Authorization header while looking right.
        self.assertEqual(self.seen["content"], self.value.encode("utf-8"))

    def test_the_file_is_created_with_mode_0600(self):
        self.assertEqual(self.seen["mode"], 0o600, "expected 0600, found %o"
                         % self.seen["mode"])

    def test_nothing_of_the_mode_is_left_for_the_group_or_for_everyone(self):
        # The load bearing half of the case above, stated so that it holds under
        # an unusual umask as well: what matters is that no second account on
        # this machine can read the file while the call runs.
        self.assertEqual(self.seen["mode"] & 0o077, 0)

    def test_the_directory_it_sits_in_is_private_too(self):
        # Defence in depth. The mode of the file is given at creation, so there
        # is no race to lose, and a private directory means there is not even a
        # name to guess while the call runs.
        self.assertEqual(self.seen["directory_mode"] & 0o077, 0)

    def test_the_file_is_gone_when_the_write_returns(self):
        self.assertFalse(self.seen["path"].exists(),
                         "the value is still on disk at %s" % self.seen["path"])

    def test_the_directory_goes_with_it(self):
        self.assertFalse(self.seen["directory"].exists())

    def test_the_file_is_removed_although_the_tool_reported_a_failure(self):
        fake = self.RunnerThatReadsTheFileTheValueTravelsIn()
        with self.assertRaises(errors.SecretsError):
            self.writing(set_rc=1, set_stderr="ERROR: unexpected.\n", runner=fake)
        self.assertEqual(len(fake.seen), 1, "the file was never created")
        self.assertFalse(fake.seen[0]["path"].exists(),
                         "a failed write left the value on disk")

    def test_the_file_is_removed_although_the_call_raised(self):
        # The harder half. A tool that exits non zero returns; a process that
        # cannot be started at all raises through the call, and a cleanup that
        # sat after the call rather than in a `finally` would be skipped exactly
        # then. This is the case that tells the two shapes apart.
        fake = self.RunnerThatReadsTheFileTheValueTravelsIn()
        fake.add("secret set", raises=RuntimeError("the process could not be started"))
        with self.assertRaises(RuntimeError):
            self.writing(runner=fake)
        self.assertEqual(len(fake.seen), 1, "the file was never created")
        self.assertFalse(fake.seen[0]["path"].exists(),
                         "a write that raised left the value on disk")
        self.assertFalse(fake.seen[0]["directory"].exists())

    def test_the_file_does_not_stand_in_the_working_directory(self):
        # A write from inside a repository checkout must not drop a file with a
        # token in it next to the code, where the next `git add .` picks it up.
        self.assertNotEqual(self.seen["directory"], Path.cwd())


class AWriteReadsBackWhatItStored(AzureCase):
    """A write that was not read back is a write nobody checked.

    Key Vault accepts a `set` and answers before the new version is the one a
    read returns in every region, and a wrapper that reported success from the
    exit code alone reported it for a version nobody could fetch yet. The read
    back is also what gives the caller a fingerprint to compare, which is how
    `resolve.store()` tells a write that landed from one that went somewhere
    else.
    """

    def setUp(self):
        super().setUp()
        self.reading, self.fake = self.writing()

    def test_the_write_returns_a_reading_of_what_is_now_in_the_vault(self):
        self.assertTrue(self.reading.present)
        self.assertEqual(self.reading.secret.expose(), self.value.encode("utf-8"))

    def test_the_read_back_carries_the_fingerprint_of_the_stored_value(self):
        self.assertEqual(self.reading.fingerprint,
                         values.fingerprint(self.value.encode("utf-8")))

    def test_the_read_back_uses_the_ordinary_read_argv(self):
        self.assertEqual(self.show_calls(self.fake)[0]["argv"],
                         tuple(self.backend().argv_read(self.ref())))

    def test_the_read_back_happens_after_the_write_and_not_before(self):
        self.assertLess(self.fake.index_of("secret set"),
                        self.fake.index_of("secret show"))

    def test_exactly_one_read_back_happens(self):
        self.assertEqual(len(self.show_calls(self.fake)), 1)

    def test_a_failed_write_never_reads_back(self):
        # A read after a failed write would answer with the OLD version and look
        # exactly like a write that worked.
        fake = self.RunnerThatReadsTheFileTheValueTravelsIn()
        with self.assertRaises(errors.SecretsError):
            self.writing(set_rc=1, set_stderr="ERROR: unexpected.\n", runner=fake)
        self.assertEqual(self.show_calls(fake), [],
                         "a failed write still asked the vault what is there")

    def test_a_read_back_that_finds_something_else_is_visible_to_the_caller(self):
        # The backend does not judge; it hands back what the vault answered, and
        # the fingerprint is what makes the difference visible one layer up.
        other = synthetic_token("someother")  # pragma: allowlist secret
        reading, _ = self.writing(read_back=other)
        self.assertNotEqual(reading.fingerprint,
                            values.fingerprint(self.value.encode("utf-8")))

    def test_the_value_was_never_in_an_argv_on_either_leg(self):
        self.assertFalse(self.fake.argv_carried(self.value),
                         "the value appeared in argv:\n" + self.fake.joined_calls)


class LocateNamesThePlaceAndNeverTheValue(AzureCase):
    """Where a person would click, printed into a report an agent may read."""

    def test_the_vault_and_the_secret_are_both_named(self):
        where = self.backend().locate(self.ref())
        self.assertIn(self.VAULT, where)
        self.assertIn(self.SECRET, where)

    def test_the_declared_vault_url_is_used_when_there_is_one(self):
        # The url is what a person pastes into a browser. The bare name is a
        # guess about which tenant, and this skill exists partly because that
        # guess was wrong once.
        url = "https://bridge-kv.vault.azure.net/"
        self.assertIn(url, self.backend(vault_url=url).locate(self.ref()))

    def test_the_subscription_is_named_when_there_is_one(self):
        self.assertIn(SUBSCRIPTION,
                      self.backend(subscription=SUBSCRIPTION).locate(self.ref()))

    def test_the_value_is_not_in_it(self):
        # `locate` runs nothing, so it cannot have the value. The case is the
        # tripwire for the day somebody makes it helpful.
        self.assertNotIn(self.value, self.backend().locate(self.ref()))
