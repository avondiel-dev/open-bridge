"""`secrets store` and `secrets stores`: putting a value in, and never out.

`store` is the only verb of this skill that carries a value into a store, so it
is the one place where the rule the whole skill exists for can be broken in the
opposite direction from all the others. The rule is the same either way: A
VALUE NEVER STANDS IN ARGV. Everything in argv is visible through `ps` to every
process of the same user, which is how tokens ended up in the process list of
two machines in this fleet before anyone looked, and it is why this verb takes
its value from a pipe, the clipboard or a hidden prompt and offers no way at
all to type it as an argument.

The second rule is that a write is not believed until it has been read back.
An entry that exists and holds nothing exits 0 from every tool involved, and a
value that lost two characters to a quoting rule is indistinguishable from a
correct one until something tries to use it. So every case that writes also
asserts what the report says about the read that followed.

HOW THE CASES ARE DRIVEN. `engine.cli.main(argv, out=..., err=...)` with two
`StringIO` buffers, and `engine.cli.Resolver` replaced by a factory that hands
the REAL resolver a `runner=`, a `context=` and, where the case is about
policy, the declarations. Everything below the command line then runs for real,
including each backend and its own argv building, and only the process is a
double. `engine.exec.which` is answered as well, so a Linux runner without
`security`, `az` or `op` measures the same thing a Mac does rather than
reporting "no backend here" and passing for the wrong reason.

Where a case needs declarations ON DISK rather than injected, it writes them as
JSON, which is a subset of YAML, and substitutes `json.loads` for PyYAML on a
runner that has none. `test_where.py` carries the same helper and the reasoning
behind it.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import types
from unittest import mock

from tests.conftest import (
    FakeRunner,
    MachineGuard,
    completed,
    keychain_attributes,
    keychain_report,
    mod,
    synthetic_token,
)


#: The verbs this file drives with a live value in play.
#: `test_acceptance.EveryVerbIsDrivenWithALiveValueSomewhere` unions this with
#: the lists of the sibling files and holds the result against `cli.COMMANDS`.
COVERED_VERBS = {"store", "stores"}

cli = mod("engine.cli")
base = mod("engine.backends.base")
errors = mod("engine.errors")
resolve = mod("engine.resolve")
stores_mod = mod("engine.stores")
values = mod("engine.values")

#: The exit codes this file pins, from `engine.errors`. A wrapper reads
#: numbers, and these four mean four different repairs: it worked, the entry
#: came back empty, the operation was understood and refused, the command line
#: was wrong.
EX_OK = 0
EX_MISSING = 3
EX_REFUSED = 5
EX_USAGE = 64
EX_CONFIG = 78

SERVICE = "svc-mailer"
ACCOUNT = "agent"
REF = "keychain://" + SERVICE + "/" + ACCOUNT

#: Assembled at runtime rather than pasted. Nothing in this tree is a
#: credential, not even a revoked one, and the way to keep that true is to have
#: no literal worth copying.
TOKEN = synthetic_token("store")      # pragma: allowlist secret
OTHER = synthetic_token("other")      # pragma: allowlist secret

#: True when this runner has PyYAML. See the module docstring.
HAS_REAL_YAML = importlib.util.find_spec("yaml") is not None

VAULT = "bridge-vault"
VAULT_REF = "azure-keyvault://" + VAULT + "/agent-token"

CHILD_ECHOES_THE_VARIABLE = (
    "import os, sys\n"
    "sys.stdout.write(os.environ.get('SUITE_TOKEN', '<unset>'))\n"
)


def keychain_fake(value: str = TOKEN, *, read_stderr=None, write_rc: int = 0,
                  write_stderr: str = "") -> FakeRunner:
    """A fake `security`: one answer for the write, one for the read back.

    Two routes and not one, because the write and the read that follows it are
    what this verb is: `security -i` takes the command line on stdin, and
    `find-generic-password -g` is what says whether anything arrived.
    """
    runner = FakeRunner()
    runner.add("security -i", completed(rc=write_rc, stderr=write_stderr))
    runner.add("find-generic-password", completed(
        rc=0, stdout=keychain_attributes(SERVICE, ACCOUNT),
        stderr=keychain_report(value=value) if read_stderr is None else read_stderr))
    return runner


def keyvault_fake(value: str = TOKEN) -> FakeRunner:
    """A fake `az`: the set, then the show that reads it back."""
    runner = FakeRunner()
    runner.add("secret set", completed(rc=0))
    runner.add("secret show", completed(rc=0, stdout=value + "\n"))
    return runner


def store_object(**fields):
    """One declaration as the engine holds it, without going through a file.

    The cases about placement policy are about the policy, not about the
    parser, and a mapping written here reads as the rule it stands for.
    `TheStoreListingSaysWhatIsDeclaredAndWhatIsWrongWithIt` takes the other
    route and puts real files on disk.
    """
    fields.setdefault("source", "infra/secret-stores/%s.yaml" % fields["name"])
    return stores_mod.Store(**fields)


class StoreCase(MachineGuard):
    """Drives `store` and `stores` with both streams captured."""

    # -- the session --------------------------------------------------------

    def desktop(self):
        return base.Context(platform="darwin", interactive=True,
                            over_ssh=False, display=True)

    def resolver_factory(self, runner, context, declared):
        def build(options=None, **kwargs):
            kwargs.setdefault("runner", runner)
            kwargs.setdefault("context", context)
            if declared is not None:
                kwargs.setdefault("stores", list(declared))
            return resolve.Resolver(options, **kwargs)
        return build

    @contextlib.contextmanager
    def the_loader_this_runner_has(self):
        """PyYAML where it exists, `json.loads` where it does not.

        ONE KEY IS SET AND ONE KEY IS PUT BACK, deliberately not
        `mock.patch.dict(sys.modules, ...)`: that one restores by clearing the
        dictionary and writing the old contents back, so a module imported
        inside the window is evicted on exit. `engine.cli` is imported lazily
        in there, and the next `mock.patch("engine.cli.Resolver", ...)` then
        patched a second, freshly imported copy while this file still held the
        first. A case passed alone and failed in the file.
        """
        if HAS_REAL_YAML:
            yield
            return
        previous = sys.modules.get("yaml")
        sys.modules["yaml"] = types.SimpleNamespace(safe_load=json.loads)
        try:
            yield
        finally:
            if previous is None:
                sys.modules.pop("yaml", None)
            else:
                sys.modules["yaml"] = previous

    def run_cli(self, argv, *, runner=None, context=None, declared=None,
                stdin=None, clipboard=None, prompted=None):
        """Run one command line. Returns (exit code, stdout, stderr).

        `stdin`, `clipboard` and `prompted` are the three doors a value may
        come in through, and each one is patched at the seam the engine reads
        it from rather than further down: the clipboard reader is replaced
        whole, because the real one shells out to `pbpaste` and would read
        whatever the person running this suite last copied.
        """
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.the_loader_this_runner_has())
            stack.enter_context(mock.patch("engine.exec.which",
                                           lambda binary: "/usr/bin/" + binary))
            stack.enter_context(mock.patch(
                "engine.cli.Resolver",
                self.resolver_factory(runner, context or self.desktop(), declared)))
            if stdin is not None:
                stack.enter_context(mock.patch("sys.stdin", self.piped(stdin)))
            if clipboard is not None:
                stack.enter_context(mock.patch("engine.cli.read_clipboard",
                                               lambda: clipboard))
            if prompted is not None:
                stack.enter_context(mock.patch("getpass.getpass",
                                               lambda *a, **kw: prompted))
            code = cli.main(argv, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def piped(raw):
        """A stdin that is a pipe rather than a terminal.

        `read_value` asks `isatty()` to decide between a pipe and a prompt, and
        reads bytes off `.buffer`, so a double needs both. A `StringIO` has
        neither and the verb would fall through to a prompt that nobody in a
        suite can answer.
        """
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return types.SimpleNamespace(isatty=lambda: False, buffer=io.BytesIO(raw))

    # -- declarations -------------------------------------------------------

    def keychain_store(self, *, name="service-keychain", addresses=("svc-*",),
                       kinds=("service-runtime",), owner=""):
        return store_object(
            name=name, backend="keychain", addresses=tuple(addresses),
            summary="The service keychain of this machine",
            location={}, unlock={}, reachable_from={},
            holds=tuple({"kind": kind, "owner": owner,
                         "naming": "<service>-<role>"} for kind in kinds),
            recovery={})

    def keepass_store(self, *, name="work-vault", addresses=("work",),
                      kinds=("personal-token",)):
        return store_object(
            name=name, backend="keepass", addresses=tuple(addresses),
            summary="The personal database",
            location={"path": "/home/opuser/vaults/work.kdbx"},
            unlock={"method": "password-ref",
                    "password_ref": "keychain://keepass-work/master"},
            reachable_from={}, holds=tuple({"kind": kind} for kind in kinds),
            recovery={})

    def keyvault_store(self, *, name="bridge-vault", addresses=(VAULT,)):
        return store_object(
            name=name, backend="azure-keyvault", addresses=tuple(addresses),
            summary="The service principal vault",
            location={"vault_url": "https://%s.vault.azure.net/" % VAULT,
                      "subscription": "00000000-0000-0000-0000-000000000000"},
            unlock={"method": "cli-login"}, reachable_from={},
            holds=({"kind": "org-credential"},), recovery={})

    def file_store(self, folder, *, name="runtime-files"):
        return store_object(
            name=name, backend="file", addresses=(str(folder) + "/*",),
            summary="Where a machine with no keychain keeps its runtime secrets",
            location={"path": str(folder)}, unlock={"method": "none"},
            reachable_from={}, holds=({"kind": "service-runtime"},), recovery={})

    # -- declarations on disk ----------------------------------------------

    def tree(self, *declarations):
        """A root holding `infra/secret-stores/`, one JSON file per mapping."""
        root = self.tmpdir()
        folder = root / stores_mod.FAMILY
        folder.mkdir(parents=True, exist_ok=True)
        for mapping in declarations:
            (folder / (mapping["name"] + ".yaml")).write_text(
                json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return root


# ---------------------------------------------------------------------------
# a value on stdin
# ---------------------------------------------------------------------------

class AValuePipedInIsWrittenWithoutEverStandingInArgv(StoreCase):
    """The ordinary way a value arrives, and the assertion this skill is for.

    `security add-generic-password -w` does not read stdin: it takes the next
    argument, so a piped value is discarded in silence and the flag that
    follows is stored instead. The entry then exists, every existence check is
    green, and the failure arrives wherever the secret is used. `security -i`
    reads whole command lines from stdin, which is the one way the value
    reaches the tool without passing the process list.
    """

    def setUp(self):
        super().setUp()
        self.runner = keychain_fake()
        self.code, self.out, self.err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=self.runner,
            declared=[self.keychain_store()], stdin=TOKEN)

    def test_it_exits_zero(self):
        self.assertEqual(self.code, EX_OK, self.err)

    def test_the_value_travels_on_stdin_and_not_in_argv(self):
        self.assertFalse(self.runner.argv_carried(TOKEN),
                         "the value stood in argv, where ps shows it to the machine")
        written = self.runner.calls[self.runner.index_of("security -i")]
        self.assertIn(TOKEN.encode("utf-8"), written["stdin_bytes"])

    def test_the_value_does_not_travel_in_the_environment_either(self):
        # The third channel into a child, and the one a reader forgets: an
        # environment is readable from /proc on Linux for the same user.
        for call in self.runner.calls:
            self.assertNotIn(TOKEN, json.dumps(call["env"] or {}))

    def test_the_report_names_the_reference(self):
        self.assertIn(REF, self.out)

    def test_the_report_names_where_it_landed(self):
        self.assertIn("stored in", self.out)
        self.assertIn(SERVICE, self.out)

    def test_the_report_carries_the_byte_count(self):
        self.assertIn("%d bytes" % len(TOKEN), self.out)

    def test_the_report_carries_the_fingerprint(self):
        # The measurement that says the value came back whole without saying
        # what it is. Without it "stored" is a claim about an exit code.
        self.assertIn(values.fingerprint(TOKEN), self.out)

    def test_neither_stream_carries_the_value(self):
        self.assertNotIn(TOKEN, self.out + self.err)

    def test_the_report_names_the_declared_store_and_its_file(self):
        self.assertIn("service-keychain", self.out)
        self.assertIn("service-keychain.yaml", self.out)

    def test_the_read_back_happens_after_the_write_and_not_before(self):
        self.assertLess(self.runner.index_of("security -i"),
                        self.runner.index_of("find-generic-password"))

    def test_a_trailing_newline_from_the_pipe_is_not_part_of_the_value(self):
        # `printf '%s\\n' "$token" | secrets store …` is how a person does
        # this, and a token with a newline on the end fails at the far end in
        # a way that reads like a wrong token rather than like a wrong pipe.
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN + "\n")
        self.assertEqual(code, EX_OK, err)
        self.assertIn("%d bytes" % len(TOKEN), out)
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_a_pipe_is_the_default_source_when_stdin_is_not_a_terminal(self):
        # `--from auto` is the default, and auto has to mean the pipe when
        # there is one. A verb that prompted here would hang a script.
        runner = keychain_fake()
        code, out, err = self.run_cli(["store", REF], runner=runner,
                                      declared=[self.keychain_store()], stdin=TOKEN)
        self.assertEqual(code, EX_OK, err)
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_the_json_form_carries_the_measurements_and_no_value(self):
        runner = keychain_fake()
        code, out, _ = self.run_cli(
            ["store", REF, "--from", "stdin", "--json"], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN)
        payload = json.loads(out)
        self.assertEqual(code, EX_OK)
        self.assertEqual(payload["ref"], REF)
        self.assertEqual(payload["bytes"], len(TOKEN))
        self.assertEqual(payload["fingerprint"], values.fingerprint(TOKEN))
        self.assertEqual(payload["store"], "service-keychain")
        self.assertNotIn(TOKEN, out)

    def test_replace_is_asked_for_on_the_stdin_line_and_not_in_argv(self):
        runner = keychain_fake()
        code, _, err = self.run_cli(
            ["store", REF, "--from", "stdin", "--replace"], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN)
        self.assertEqual(code, EX_OK, err)
        written = runner.calls[runner.index_of("security -i")]
        self.assertIn(b"-U", written["stdin_bytes"])
        self.assertFalse(runner.argv_carried(TOKEN))

    def test_an_entry_that_is_already_there_is_refused_without_replace(self):
        # Overwriting by default is how a working credential is lost to a
        # typo in the account name.
        runner = keychain_fake(write_rc=45, write_stderr=(
            "security: SecKeychainItemCreateFromContent (25299,0): The specified "
            "item already exists in the keychain."))
        code, _, err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN)
        self.assertEqual(code, EX_REFUSED)
        self.assertIn("--replace", err)
        self.assertNotIn(TOKEN, err)


# ---------------------------------------------------------------------------
# the other two sources
# ---------------------------------------------------------------------------

class TheOtherTwoSourcesKeepTheValueOutOfArgvToo(StoreCase):
    """A hidden prompt and the clipboard, because a person has to type it once.

    Both exist so that the value is never in a shell history, never in a
    transcript and never in a file. The clipboard is the only channel that
    persists nothing by itself, and the prompt is the only one that works over
    a connection where there is nothing to paste from.
    """

    def test_a_hidden_prompt_supplies_the_value_when_the_source_says_prompt(self):
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "prompt"], runner=runner,
            declared=[self.keychain_store()], prompted=TOKEN)
        self.assertEqual(code, EX_OK, err)
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_the_prompt_is_the_one_that_does_not_echo(self):
        # `input()` would put the value on the terminal, into the scrollback,
        # and into whatever records the session. The case asserts the engine
        # asks `getpass` and nothing else, by answering only that.
        seen = []

        def hidden_prompt(*arguments, **keywords):
            seen.append(arguments)
            return TOKEN

        runner = keychain_fake()
        with mock.patch("getpass.getpass", hidden_prompt):
            with mock.patch("engine.exec.which", lambda binary: "/usr/bin/" + binary):
                with mock.patch("engine.cli.Resolver", self.resolver_factory(
                        runner, self.desktop(), [self.keychain_store()])):
                    out, err = io.StringIO(), io.StringIO()
                    code = cli.main(["store", REF, "--from", "prompt"], out=out, err=err)
        self.assertEqual(code, EX_OK, err.getvalue())
        self.assertEqual(len(seen), 1, "the hidden prompt was not the way in")

    def test_the_prompted_value_does_not_reach_argv(self):
        runner = keychain_fake()
        self.run_cli(["store", REF, "--from", "prompt"], runner=runner,
                     declared=[self.keychain_store()], prompted=TOKEN)
        self.assertFalse(runner.argv_carried(TOKEN))

    def test_the_prompted_value_is_in_neither_stream(self):
        runner = keychain_fake()
        _, out, err = self.run_cli(["store", REF, "--from", "prompt"], runner=runner,
                                   declared=[self.keychain_store()], prompted=TOKEN)
        self.assertNotIn(TOKEN, out + err)

    def test_the_clipboard_supplies_the_value_when_the_source_says_clipboard(self):
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "clipboard"], runner=runner,
            declared=[self.keychain_store()], clipboard=TOKEN.encode("utf-8"))
        self.assertEqual(code, EX_OK, err)
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_the_clipboard_value_does_not_reach_argv_or_either_stream(self):
        runner = keychain_fake()
        _, out, err = self.run_cli(
            ["store", REF, "--from", "clipboard"], runner=runner,
            declared=[self.keychain_store()], clipboard=TOKEN.encode("utf-8"))
        self.assertFalse(runner.argv_carried(TOKEN))
        self.assertNotIn(TOKEN, out + err)

    def test_the_report_says_the_clipboard_still_holds_it(self):
        # The value survives this command in a place the next paste reaches,
        # and nothing else in the session will mention it again.
        runner = keychain_fake()
        _, out, _ = self.run_cli(
            ["store", REF, "--from", "clipboard"], runner=runner,
            declared=[self.keychain_store()], clipboard=TOKEN.encode("utf-8"))
        self.assertIn("clipboard still holds the value", out)

    def test_the_clipboard_is_read_through_the_platform_tool(self):
        # Driven directly, because the reader is patched out above: this is
        # the case that says which program it would have been. `pbpaste` is
        # first on macOS and the wayland and x11 tools follow.
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            return completed(rc=0, stdout=TOKEN + "\n")

        with mock.patch("engine.exec.which", lambda binary: "/usr/bin/" + binary):
            with mock.patch("engine.exec.run", fake_run):
                raw = cli.read_clipboard()
        self.assertEqual(raw, TOKEN.encode("utf-8"))
        self.assertEqual(calls[0][0], "pbpaste")

    def test_a_machine_with_no_clipboard_tool_is_an_error_and_not_an_empty_value(self):
        # Silently reading nothing would write an empty entry, which exits 0
        # from every tool involved and fails wherever the secret is used.
        with mock.patch("engine.exec.which", lambda binary: None):
            with self.assertRaises(errors.SecretsError) as caught:
                cli.read_clipboard()
        self.assertIn("no clipboard tool", str(caught.exception))
        self.assertIn("pbpaste", caught.exception.hint)


# ---------------------------------------------------------------------------
# an empty value
# ---------------------------------------------------------------------------

class AnEmptyValueIsAUsageErrorAndNothingIsWritten(StoreCase):
    """Nothing arrived, so nothing is written, and the store is never touched.

    An empty entry is the worst outcome of the three: it exists, every
    existence check is green, and the emptiness travels to wherever the secret
    is used. The pipe that produced it is usually a command that failed
    upstream and wrote nothing.
    """

    def empty_run(self, raw=""):
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=runner,
            declared=[self.keychain_store()], stdin=raw)
        return runner, code, out, err

    def test_the_exit_code_is_the_usage_code(self):
        _, code, _, _ = self.empty_run()
        self.assertEqual(code, EX_USAGE)

    def test_the_message_says_nothing_arrived(self):
        _, _, _, err = self.empty_run()
        self.assertIn("nothing arrived", err)

    def test_the_message_names_the_two_places_to_look(self):
        _, _, _, err = self.empty_run()
        self.assertIn("pipe", err)
        self.assertIn("clipboard", err)

    def test_the_store_is_never_touched(self):
        runner, _, _, _ = self.empty_run()
        self.assertEqual(runner.calls, [],
                         "an empty value reached the store: " + runner.joined_calls)

    def test_a_pipe_holding_only_a_newline_is_empty_too(self):
        # `echo -n "$token"` with an unset variable produces exactly this.
        runner, code, _, _ = self.empty_run("\n")
        self.assertEqual(code, EX_USAGE)
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# the placement policy at the moment of the write
# ---------------------------------------------------------------------------

class AKindTheTargetStoreDoesNotHoldIsRefusedAndTheMessageSaysWhereItBelongs(StoreCase):
    """A policy nothing reads at the moment of the write is documentation.

    The loose token file gets written anyway, next to a file that says it
    should not be. So `--kind` is checked against the store the reference
    addresses, and the refusal carries the other half of the answer: which
    store does hold this kind, and which verb prints the shape of an entry
    there.
    """

    def setUp(self):
        super().setUp()
        self.declared = [self.keychain_store(), self.keepass_store()]

    def refused(self, kind="personal-token"):
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin", "--kind", kind], runner=runner,
            declared=self.declared, stdin=TOKEN)
        return runner, code, out, err

    def test_the_exit_code_is_the_refusal_code(self):
        _, code, _, _ = self.refused()
        self.assertEqual(code, EX_REFUSED)

    def test_the_message_names_the_store_that_refused(self):
        _, _, _, err = self.refused()
        self.assertIn("service-keychain", err)

    def test_the_message_says_what_that_store_does_hold(self):
        _, _, _, err = self.refused()
        self.assertIn("service-runtime", err)

    def test_the_message_names_where_this_kind_belongs(self):
        # Without it the reader is refused and left with the same question
        # they started with, which is how the loose file gets written.
        _, _, _, err = self.refused()
        self.assertIn("work-vault", err)

    def test_the_message_names_the_verb_that_prints_the_shape(self):
        _, _, _, err = self.refused()
        self.assertIn("secrets where personal-token", err)

    def test_nothing_was_written(self):
        runner, _, _, _ = self.refused()
        self.assertEqual(runner.calls, [],
                         "the refusal came after the write: " + runner.joined_calls)

    def test_the_value_is_in_neither_stream_of_a_refusal(self):
        _, _, out, err = self.refused()
        self.assertNotIn(TOKEN, out + err)

    def test_the_kind_the_store_declares_is_written_without_complaint(self):
        # The positive control. A check that refuses everything is also a check
        # that refuses nothing worth refusing.
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin", "--kind", "service-runtime"],
            runner=runner, declared=self.declared, stdin=TOKEN)
        self.assertEqual(code, EX_OK, err)
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_a_reference_no_store_declares_is_written_with_a_note_on_stderr(self):
        # Refusing here would make the verb unusable on a machine that has not
        # declared its stores yet, and the note is what keeps that visible
        # rather than silent.
        runner = keychain_fake()
        code, _, err = self.run_cli(
            ["store", "keychain://undeclared/agent", "--from", "stdin",
             "--kind", "service-runtime"],
            runner=runner, declared=[self.keepass_store()], stdin=TOKEN)
        self.assertEqual(code, EX_OK, err)
        self.assertIn("no store declares this reference", err)

    def test_the_policy_is_read_from_the_tree_when_nothing_is_injected(self):
        # The wiring, end to end: declarations on disk, found through --root,
        # and the same refusal. Every other case here hands the resolver its
        # stores, so this is the one that says the path from a file to a
        # refusal exists at all.
        root = self.tree({
            "name": "service-keychain", "scope": "user", "backend": "keychain",
            "summary": "The service keychain of this machine",
            "addresses": ["svc-*"],
            "holds": [{"kind": "service-runtime", "naming": "<service>-<role>"}],
        }, {
            "name": "work-vault", "scope": "user", "backend": "keepass",
            "summary": "The personal database", "addresses": ["work"],
            "location": {"path": "/home/opuser/vaults/work.kdbx"},
            "holds": [{"kind": "personal-token", "naming": "<provider>-<role>"}],
        })
        runner = keychain_fake()
        code, _, err = self.run_cli(
            ["store", REF, "--from", "stdin", "--kind", "personal-token",
             "--root", str(root)], runner=runner, stdin=TOKEN)
        self.assertEqual(code, EX_REFUSED, err)
        self.assertIn("work-vault", err)
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# what is not a secret
# ---------------------------------------------------------------------------

class WhatIdentifiesRatherThanAuthenticatesIsNotStored(StoreCase):
    """An IBAN is on every invoice the user writes.

    Putting it in a vault makes it useless for the thing it is for and buys
    nothing, because knowing it grants nothing. The refusal at the moment of
    the write is what stops a well meaning tidy-up from moving a whole
    identity into a store nobody can read from an invoice template.
    """

    def stored(self, kind):
        runner = keychain_fake()
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin", "--kind", kind], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN)
        return runner, code, out, err

    def test_iban_is_refused_with_the_refusal_code(self):
        _, code, _, _ = self.stored("iban")
        self.assertEqual(code, EX_REFUSED)

    def test_the_reason_is_printed(self):
        _, _, _, err = self.stored("iban")
        self.assertIn("identifying, not authenticating", err)

    def test_nothing_was_written(self):
        runner, _, _, _ = self.stored("iban")
        self.assertEqual(runner.calls, [])

    def test_every_word_the_engine_calls_not_a_kind_is_refused(self):
        for word in stores_mod.NOT_A_KIND:
            with self.subTest(word=word):
                runner, code, _, err = self.stored(word)
                self.assertEqual(code, EX_REFUSED)
                self.assertEqual(runner.calls, [])

    def test_an_unknown_kind_is_refused_with_the_declared_list(self):
        runner, code, _, err = self.stored("api-key")
        self.assertEqual(code, EX_REFUSED)
        self.assertEqual(runner.calls, [])
        for kind in stores_mod.KINDS:
            self.assertIn(kind, err)


# ---------------------------------------------------------------------------
# the read back
# ---------------------------------------------------------------------------

class AWriteIsNotBelievedUntilItHasBeenReadBack(StoreCase):
    """An exit code is not a proof that a value arrived.

    Two failures this catches, both of them seen: an entry that exists and
    holds nothing, which every existence check calls healthy, and a value that
    lost characters to a quoting rule, which is indistinguishable from a
    correct one until the far end rejects it and the rejection reads like a
    wrong password.
    """

    def mismatched(self):
        runner = keychain_fake(value=OTHER)
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN)
        return runner, code, out, err

    def empty_read_back(self):
        runner = keychain_fake(read_stderr=keychain_report(empty=True))
        code, out, err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=runner,
            declared=[self.keychain_store()], stdin=TOKEN)
        return runner, code, out, err

    def test_a_value_that_reads_back_different_is_a_failure(self):
        _, code, _, err = self.mismatched()
        self.assertEqual(code, EX_REFUSED)
        self.assertIn("read back is not the value written", err)

    def test_that_failure_reports_no_success_line(self):
        _, _, out, _ = self.mismatched()
        self.assertNotIn("read back   ", out)

    def test_that_failure_names_neither_value(self):
        # It names two fingerprints instead, which is enough to tell the two
        # apart in a report and useless to anyone holding only the report.
        _, _, out, err = self.mismatched()
        self.assertNotIn(TOKEN, out + err)
        self.assertNotIn(OTHER, out + err)
        self.assertIn(values.fingerprint(TOKEN), err)

    def test_that_failure_says_nothing_was_rolled_back(self):
        # The entry now holds something unexpected. A message that implied a
        # clean failure would send the reader past the entry that needs
        # looking at.
        _, _, _, err = self.mismatched()
        self.assertIn("Nothing was rolled back", err)

    def test_an_entry_that_reads_back_empty_is_a_failure_too(self):
        _, code, _, err = self.empty_read_back()
        self.assertEqual(code, EX_MISSING)
        self.assertIn("reads back empty", err)

    def test_the_empty_read_back_says_the_write_reported_success(self):
        # The distinction that makes the message actionable: the tool said yes
        # and the store holds nothing, so the thing to look at is the store.
        _, _, _, err = self.empty_read_back()
        self.assertIn("reported success", err)

    def test_the_empty_read_back_reports_no_measurement(self):
        _, _, out, _ = self.empty_read_back()
        self.assertNotIn("sha256", out)

    def test_both_failures_did_reach_the_store_first(self):
        # Otherwise these two would also pass for a verb that refused before
        # writing anything, and that is a different behaviour with a different
        # repair.
        for label, run in (("different value", self.mismatched),
                           ("empty entry", self.empty_read_back)):
            with self.subTest(failure=label):
                runner, _, _, _ = run()
                self.assertTrue(runner.called_with("security -i"))


# ---------------------------------------------------------------------------
# the file backend, which has no process at all
# ---------------------------------------------------------------------------

class AFileStoreWriteLandsInsideADeclaredDirectoryAtModeSixHundred(StoreCase):
    """The fallback for a machine with no keychain and no agent.

    It is the one backend where a careless reader finds the value by following
    the locator, so the mode is set at creation rather than by a `chmod`
    afterwards, and the path has to be inside a declared store. Without the
    second rule this backend is "write the token wherever", which is the habit
    the whole skill exists to end.
    """

    def setUp(self):
        super().setUp()
        self.folder = self.tmpdir() / "secrets"
        self.folder.mkdir()
        self.path = self.folder / "mailer-token"
        self.ref = "file://" + str(self.path)
        self.declared = [self.file_store(self.folder)]

    def write(self, ref=None):
        return self.run_cli(["store", ref or self.ref, "--from", "stdin"],
                            declared=self.declared, stdin=TOKEN)

    def test_the_file_holds_the_value(self):
        code, _, err = self.write()
        self.assertEqual(code, EX_OK, err)
        self.assertEqual(self.path.read_bytes(), TOKEN.encode("utf-8"))

    def test_the_file_is_readable_by_its_owner_and_nobody_else(self):
        self.write()
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600, "the file is mode %s" % oct(mode))

    def test_the_report_names_the_path_and_measures_the_value(self):
        _, out, _ = self.write()
        self.assertIn(str(self.path), out)
        self.assertIn("%d bytes" % len(TOKEN), out)
        self.assertIn(values.fingerprint(TOKEN), out)
        self.assertNotIn(TOKEN, out)

    def test_a_path_outside_every_declared_store_is_refused(self):
        outside = self.tmpdir() / "loose-token"
        code, _, err = self.write(ref="file://" + str(outside))
        self.assertEqual(code, EX_REFUSED)
        self.assertIn("not inside any declared store", err)

    def test_that_refusal_leaves_no_file_behind(self):
        outside = self.tmpdir() / "loose-token"
        self.write(ref="file://" + str(outside))
        self.assertFalse(outside.exists(),
                         "the refusal still created the file it refused to create")


# ---------------------------------------------------------------------------
# Key Vault metadata
# ---------------------------------------------------------------------------

class TheMetadataOfAKeyVaultWriteTravelsInTheCallThatWritesTheValue(StoreCase):
    """One call, or a secret nobody can place afterwards.

    `az keyvault secret set --value` alone creates a version with
    `contentType: null` and no tags, and the second call that would fix it is
    the one people forget. Doing it in one is free. The value goes in through
    `--file`, never `--value`, for the same reason everything else here goes
    over stdin.
    """

    def setUp(self):
        super().setUp()
        self.runner = keyvault_fake()
        self.code, self.out, self.err = self.run_cli(
            ["store", VAULT_REF, "--from", "stdin", "--tag", "owner=platform"],
            runner=self.runner, declared=[self.keyvault_store()], stdin=TOKEN)

    def written(self):
        return self.runner.calls[self.runner.index_of("secret set")]

    def test_it_exits_zero(self):
        self.assertEqual(self.code, EX_OK, self.err)

    def test_the_value_goes_in_through_a_file_and_never_through_value(self):
        joined = self.written()["joined"]
        self.assertIn("--file", joined)
        self.assertNotIn("--value", joined)
        self.assertFalse(self.runner.argv_carried(TOKEN))

    def test_the_subscription_is_named_rather_than_defaulted(self):
        # The default subscription of a machine is not always the tenant of
        # the vault, and `az` answers for the wrong one without a word, which
        # reads as "the secret is gone".
        self.assertIn("--subscription", self.written()["joined"])

    def test_the_content_type_travels_in_the_same_call(self):
        self.assertIn("--content-type", self.written()["joined"])

    def test_there_is_exactly_one_write_call(self):
        sets = [call for call in self.runner.calls if "secret set" in call["joined"]]
        self.assertEqual(len(sets), 1)

    def test_the_temporary_file_that_carried_the_value_does_not_survive(self):
        argv = self.written()["argv"]
        path = argv[argv.index("--file") + 1]
        self.assertFalse(os.path.exists(path),
                         "the file holding the value is still on disk at " + path)

    def test_a_tag_given_on_the_command_line_reaches_the_call_that_writes(self):
        # RED, and it is the engine rather than the case. `--tag` is parsed at
        # engine/cli.py:79 and read nowhere: `command_store` calls
        # `resolver.store(ref, secret, replace=args.replace)` at
        # engine/cli.py:312, and `Resolver.store` (engine/resolve.py:200) has
        # no parameter for metadata, so the tags never reach
        # `AzureKeyVaultBackend.write(..., tags=...)`. The flag is accepted,
        # the command reports success, and the secret lands in the vault with
        # no tags on it, which is the exact state the backend's own docstring
        # says the one-call write exists to prevent.
        self.assertIn("--tags", self.written()["joined"])
        self.assertIn("owner=platform", self.written()["joined"])

    def test_neither_stream_carries_the_value(self):
        self.assertNotIn(TOKEN, self.out + self.err)


# ---------------------------------------------------------------------------
# the stores listing
# ---------------------------------------------------------------------------

#: A declaration that cannot be opened: its own password is an entry in itself.
#: The loop is the first thing the listing has to catch, because the failure
#: without it is a password prompt for the password.
SELF_LOCKING = {
    "name": "self-locking", "scope": "user", "backend": "keychain",
    "summary": "A keychain whose own password is inside it",
    "addresses": ["*"],
    "unlock": {"method": "password-ref",
               "password_ref": "keychain://self-locking/master"},
    "holds": [{"kind": "personal-token"}],
}

#: Answers nothing, because `addresses` is empty. A store like this is invisible
#: at resolve time and looks like a missing secret rather than a missing line.
ANSWERS_NOTHING = {
    "name": "orphan-store", "scope": "user", "backend": "keepass",
    "summary": "A database nothing addresses",
    "addresses": [],
    "location": {"path": "/home/opuser/vaults/orphan.kdbx"},
    "holds": [{"kind": "personal-token"}],
}

HEALTHY = {
    "name": "login-keychain", "scope": "user", "backend": "keychain",
    "summary": "The login keychain of this laptop",
    "addresses": ["*"],
    "holds": [{"kind": "personal-token", "naming": "<provider>-<tenant>-<role>"}],
}


class TheStoreListingSaysWhatIsDeclaredAndWhatIsWrongWithIt(StoreCase):
    """`stores` is the inventory plus the audit, in one answer.

    A declaration that cannot be opened, or that answers no reference at all,
    fails at the worst moment: at the first read, in whatever wrapper needed
    the secret. Reading the files is free and says so beforehand.
    """

    def listing(self, *declarations, json_form=False):
        argv = ["stores", "--root", str(self.tree(*declarations))]
        if json_form:
            argv.append("--json")
        return self.run_cli(argv)

    def test_every_declaration_is_listed_with_its_backend(self):
        code, out, err = self.listing(HEALTHY)
        self.assertEqual(code, EX_OK, err)
        self.assertIn("login-keychain", out)
        self.assertIn("keychain", out)

    def test_the_addresses_it_answers_are_listed(self):
        _, out, _ = self.listing(HEALTHY)
        self.assertIn("*", out)

    def test_the_kinds_a_store_holds_are_listed(self):
        _, out, _ = self.listing(HEALTHY)
        self.assertIn("holds: personal-token", out)

    def test_a_clean_set_exits_zero_and_says_it_found_no_problem(self):
        code, out, _ = self.listing(HEALTHY)
        self.assertEqual(code, EX_OK)
        self.assertIn("no problems", out)

    def test_a_store_whose_own_password_lives_inside_itself_is_reported(self):
        code, out, _ = self.listing(SELF_LOCKING)
        self.assertEqual(code, EX_CONFIG)
        self.assertIn("nothing can open it", out)

    def test_a_declaration_that_answers_no_reference_is_reported(self):
        code, out, _ = self.listing(ANSWERS_NOTHING)
        self.assertEqual(code, EX_CONFIG)
        self.assertIn("answers no reference", out)

    def test_a_problem_names_the_file_it_is_in(self):
        _, out, _ = self.listing(SELF_LOCKING)
        self.assertIn("self-locking.yaml", out)

    def test_the_problems_are_counted(self):
        _, out, _ = self.listing(SELF_LOCKING, ANSWERS_NOTHING)
        self.assertIn("2 problem", out)

    def test_a_healthy_store_beside_a_broken_one_is_still_listed(self):
        # A listing that stopped at the first problem would hide the inventory
        # exactly when somebody is looking for it.
        code, out, _ = self.listing(HEALTHY, SELF_LOCKING)
        self.assertEqual(code, EX_CONFIG)
        self.assertIn("login-keychain", out)

    def test_an_empty_tree_is_not_a_problem_and_points_at_the_template(self):
        # A fresh clone declares nothing, and that is a starting point rather
        # than a fault. Exiting non-zero here would make every new instance
        # look broken.
        code, out, _ = self.run_cli(["stores", "--root", str(self.tmpdir())])
        self.assertEqual(code, EX_OK)
        self.assertIn("_template.yaml", out)

    def test_the_json_form_carries_the_stores_and_the_problems(self):
        code, out, _ = self.listing(HEALTHY, SELF_LOCKING, json_form=True)
        payload = json.loads(out)
        self.assertEqual(code, EX_CONFIG)
        self.assertEqual({store["name"] for store in payload["stores"]},
                         {"login-keychain", "self-locking"})
        self.assertEqual(len(payload["problems"]), 1)

    def test_the_json_form_of_a_clean_set_exits_zero_with_no_problems(self):
        code, out, _ = self.listing(HEALTHY, json_form=True)
        self.assertEqual(code, EX_OK)
        self.assertEqual(json.loads(out)["problems"], [])


# ---------------------------------------------------------------------------
# the property that holds across every verb
# ---------------------------------------------------------------------------

#: Every verb the command line has. Asserted against `cli.COMMANDS` below, so a
#: seventh verb cannot arrive without a case here saying what it prints.
VERBS = {"refs", "check", "run", "where", "stores", "store"}


class NoVerbOfThisCommandLinePrintsTheValue(StoreCase):
    """The constraint the whole skill is built on, measured once per verb.

    An agent reads this output. Anything printed here is in the model's context
    for the rest of the session, in the transcript, and in whatever log the
    harness keeps, and none of those three can be unprinted. So every verb is
    run with a live value in play, and both streams are asserted on.
    """

    def declared_tree(self):
        return str(self.tree(HEALTHY))

    def test_every_verb_the_command_line_has_is_driven_here(self):
        self.assertEqual(set(cli.COMMANDS), VERBS)

    def test_refs_prints_no_value(self):
        root = self.tmpdir()
        (root / "channel.yaml").write_text("token: %s\n" % REF, encoding="utf-8")
        runner = keychain_fake()
        _, out, err = self.run_cli(["refs", "--root", str(root)], runner=runner)
        self.assertNotIn(TOKEN, out + err)
        self.assertEqual(runner.calls, [], "the inventory opened a store")

    def test_check_prints_no_value(self):
        _, out, err = self.run_cli(["check", REF], runner=keychain_fake(),
                                   declared=[self.keychain_store()])
        self.assertNotIn(TOKEN, out + err)

    def test_check_prints_the_fingerprint_instead(self):
        # Otherwise "no value was printed" would also be true of a verb that
        # printed nothing at all, and that is not the property claimed here.
        _, out, _ = self.run_cli(["check", REF], runner=keychain_fake(),
                                 declared=[self.keychain_store()])
        self.assertIn(values.fingerprint(TOKEN), out)

    def test_run_prints_no_value(self):
        _, out, err = self.run_cli(
            ["run", "--env", "SUITE_TOKEN=" + REF, "--",
             sys.executable, "-c", CHILD_ECHOES_THE_VARIABLE],
            runner=keychain_fake(), declared=[self.keychain_store()])
        self.assertNotIn(TOKEN, out + err)

    def test_where_prints_no_value(self):
        _, out, err = self.run_cli(
            ["where", "personal-token", "--root", self.declared_tree()],
            runner=keychain_fake())
        self.assertNotIn(TOKEN, out + err)

    def test_stores_prints_no_value(self):
        _, out, err = self.run_cli(["stores", "--root", self.declared_tree()],
                                   runner=keychain_fake())
        self.assertNotIn(TOKEN, out + err)

    def test_store_prints_no_value(self):
        _, out, err = self.run_cli(
            ["store", REF, "--from", "stdin"], runner=keychain_fake(),
            declared=[self.keychain_store()], stdin=TOKEN)
        self.assertNotIn(TOKEN, out + err)

    def test_the_value_is_in_no_argv_of_any_verb(self):
        # The same property, measured on the other side of the seam: a verb
        # that kept the value out of its own output and put it in a child's
        # command line would pass every case above.
        runner = keychain_fake()
        self.run_cli(["store", REF, "--from", "stdin"], runner=runner,
                     declared=[self.keychain_store()], stdin=TOKEN)
        self.assertFalse(runner.argv_carried(TOKEN))
