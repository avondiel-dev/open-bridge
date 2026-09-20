"""`secrets where`: the verb that answers the question nobody could answer.

An agent handed a fresh token used to decide for itself where to keep it, and
the result was small text files with credentials in working folders on two
machines. `where` is the declared answer instead: it reads
`infra/secret-stores/*.yaml`, says which store holds this KIND of secret, what
an entry of that kind is called there, and hands back a reference ready to
paste. A file answering it is not cleverer than the agent, it is merely the
same answer every time, and reviewable.

Every case drives `engine.cli.main(argv, out=..., err=...)` with two `StringIO`
buffers, so nothing here writes to a terminal and the two streams can be
asserted on apart. The declarations are real files in a throwaway tree, read
through `engine.stores.load`, because the behaviour under test includes the
glob, the `_`-prefix rule and the mapping from fields to a `Store`, and a test
that handed the engine a list of objects would exercise none of the three.

TWO THINGS ARE PATCHED, AND BOTH ARE ABOUT DETERMINISM RATHER THAN SAFETY.

`engine.cli.Resolver` is replaced by a factory that fills in a `Context`, so the
reachability line is decided by the case and not by whether the machine running
the suite happens to have a terminal attached or an `SSH_CONNECTION` in its
environment. `command_where` builds its own resolver purely to ask the context
that question, so this is the smallest seam that reaches it.

The YAML loader is replaced ONLY on a runner that has no PyYAML, and the
declarations below are written as JSON for exactly that reason: JSON is a
subset of YAML, PyYAML reads these files byte for byte the same way
`json.loads` does, and the last class in this file pins that claim rather than
assuming it. Without the stand-in `engine.stores.load` raises `MissingParser`
on a bare CI runner and every case here would report "no declarations at all",
which is a green-looking failure in the one direction this verb must never get
wrong. The block-style spelling a person writes is `_template.yaml`'s business
and `check-jsonschema` validates that; the surface syntax is not what these
cases measure.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import types
from unittest import mock

from tests.conftest import FakeRunner, MachineGuard, mod


#: The verbs this file drives with a live value in play.
#: `test_acceptance.EveryVerbIsDrivenWithALiveValueSomewhere` unions this with
#: the lists of the sibling files and holds the result against `cli.COMMANDS`.
COVERED_VERBS = {"where"}

cli = mod("engine.cli")
base = mod("engine.backends.base")
resolve = mod("engine.resolve")
stores_mod = mod("engine.stores")

#: The exit codes this file pins, from `engine.errors`. Spelled out because a
#: wrapper script reads numbers, and because a verb that answers "where does
#: this go" has to tell "nothing is declared" (78) from "that word is not a
#: kind of secret" (5): the first is a file to fill in, the second is a
#: misunderstanding about what a vault is for.
EX_OK = 0
EX_REFUSED = 5
EX_CONFIG = 78

#: True when this runner has PyYAML. See the module docstring: on a runner
#: without it the declarations are read by `json.loads` instead, on text that
#: is JSON either way.
HAS_REAL_YAML = importlib.util.find_spec("yaml") is not None


# ---------------------------------------------------------------------------
# Declarations
#
# Written as Python mappings and serialised per case, so a fixture reads as
# data rather than as indentation. Paths are neutral by rule: no home directory
# of any real account appears in this tree.
# ---------------------------------------------------------------------------

LOGIN_KEYCHAIN = {
    "name": "login-keychain",
    "scope": "user",
    "backend": "keychain",
    "summary": "The login keychain of this laptop",
    "addresses": ["*"],
    "location": {"keychain_path": ""},
    "reachable_from": {"contexts": ["interactive", "launchd-gui"]},
    "holds": [{
        "kind": "personal-token",
        "naming": "<provider>-<tenant>-<role>",
        "note": "the provider's audit log shows the person, so it stays personal",
    }],
}

ACME_VAULT = {
    "name": "acme-vault",
    "scope": "user",
    "backend": "keepass",
    "summary": "Customer database for Acme",
    "addresses": ["acme"],
    "location": {"path": "/home/opuser/vaults/acme.kdbx"},
    "unlock": {"method": "password-ref",
               "password_ref": "keychain://keepass-acme/master"},
    "reachable_from": {"contexts": ["any"]},
    "holds": [{
        "kind": "customer-credential",
        "owner": "acme",
        "naming": "<system>/<role>",
        "note": "one customer per database, so a wrong read cannot cross a customer line",
    }],
}

GLOBEX_VAULT = {
    "name": "globex-vault",
    "scope": "user",
    "backend": "keepass",
    "summary": "Customer database for Globex",
    "addresses": ["globex"],
    "location": {"path": "/home/opuser/vaults/globex.kdbx"},
    "reachable_from": {"contexts": ["any"]},
    "holds": [{
        "kind": "customer-credential",
        "owner": "globex",
        "naming": "<system>/<role>",
    }],
}

SHARED_VAULT = {
    "name": "shared-vault",
    "scope": "user",
    "backend": "keepass",
    "summary": "The database every engagement falls back to",
    "addresses": ["shared"],
    "location": {"path": "/home/opuser/vaults/shared.kdbx"},
    "reachable_from": {"contexts": ["any"]},
    "holds": [{
        "kind": "customer-credential",
        "naming": "<customer>/<system>/<role>",
        "note": "no owner on this line, so it answers for every customer",
    }],
}

SSH_ONLY_STORE = {
    "name": "service-keychain",
    "scope": "user",
    "backend": "keychain",
    "summary": "The service keychain of the build host",
    "addresses": ["svc-*"],
    "location": {"keychain_path": "/home/opuser/Library/Keychains/service.keychain-db"},
    "reachable_from": {"contexts": ["ssh"]},
    "holds": [{
        "kind": "service-runtime",
        "naming": "<service>-<role>",
        "note": "a daemon reads it at start, with nobody at the screen",
    }],
}


class WhereCase(MachineGuard):
    """Drives `where` against a throwaway tree of declarations."""

    # -- the tree -----------------------------------------------------------

    def tree(self, *declarations, hidden=()):
        """A root holding `infra/secret-stores/`, one file per declaration.

        `hidden` writes a declaration under a `_`-prefixed name, which the
        engine reserves for the template and the schema. A case uses it to
        prove the reservation is honoured, because a tree in which
        `_template.yaml` counted as a store would propose the template's
        example placement as if somebody had declared it.
        """
        root = self.tmpdir()
        folder = root / stores_mod.FAMILY
        folder.mkdir(parents=True, exist_ok=True)
        for mapping in declarations:
            self.write_declaration(folder / (mapping["name"] + ".yaml"), mapping)
        for mapping in hidden:
            self.write_declaration(folder / ("_" + mapping["name"] + ".yaml"), mapping)
        return root

    @staticmethod
    def write_declaration(path, mapping) -> str:
        text = json.dumps(mapping, indent=2, sort_keys=True) + "\n"
        path.write_text(text, encoding="utf-8")
        return text

    def empty_tree(self):
        """A root with no `infra/secret-stores/` at all, which is a fresh clone."""
        return self.tmpdir()

    # -- the session --------------------------------------------------------

    def desktop(self):
        return base.Context(platform="darwin", interactive=True,
                            over_ssh=False, display=True)

    def over_ssh(self):
        return base.Context(platform="darwin", interactive=True,
                            over_ssh=True, display=False)

    @contextlib.contextmanager
    def the_loader_this_runner_has(self):
        """PyYAML where it exists, `json.loads` where it does not.

        The stand-in is not a YAML parser and does not pretend to be one. It
        reads the fixtures in this file, which are JSON, and the last class
        here asserts that the two loaders agree on every one of them.

        ONE KEY IS SET AND ONE KEY IS PUT BACK, deliberately not
        `mock.patch.dict(sys.modules, ...)`. That one restores by clearing the
        dictionary and writing the old contents back, so every module imported
        inside the window is EVICTED on exit. `engine.cli` is imported lazily
        in there, the next `mock.patch("engine.cli.Resolver", ...)` then
        imported a second, fresh copy and patched that one, while the proxy in
        this file still held the first. The result was a case that passed
        alone, passed as a class, and failed in the file: the context was the
        real session's rather than the one the case named, and the reachability
        line said so.
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

    def resolver_factory(self, runner, context):
        def build(options=None, **kwargs):
            kwargs.setdefault("runner", runner)
            kwargs.setdefault("context", context)
            return resolve.Resolver(options, **kwargs)
        return build

    def run_cli(self, argv, *, context=None, runner=None):
        """Run one command line. Returns (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.the_loader_this_runner_has())
            stack.enter_context(mock.patch(
                "engine.cli.Resolver",
                self.resolver_factory(runner, context or self.desktop())))
            code = cli.main(argv, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def where(self, *arguments, root=None, context=None, runner=None):
        argv = ["where", *arguments]
        if root is not None:
            argv += ["--root", str(root)]
        return self.run_cli(argv, context=context, runner=runner)


# ---------------------------------------------------------------------------
# the bare verb
# ---------------------------------------------------------------------------

class TheBareVerbListsEveryKindAndWhatIsDeliberatelyNotOne(WhereCase):
    """`where` with no kind is the vocabulary, and it is half the point.

    A closed list of kinds is only useful if the person choosing one can read
    it without opening the schema, and the second list matters more: an IBAN
    and a tax id kept turning up in requests to "put this in the vault", and
    the answer is not a kind of store, it is that they authenticate nothing.
    """

    def listing(self, *arguments):
        code, out, err = self.where(*arguments, root=self.empty_tree())
        self.assertEqual(code, EX_OK, err)
        return out

    def test_every_declared_kind_is_listed(self):
        out = self.listing()
        for kind in stores_mod.KINDS:
            with self.subTest(kind=kind):
                self.assertIn(kind, out)

    def test_every_kind_carries_its_one_line_meaning(self):
        # A list of seven slugs is a list of seven guesses. The meaning is what
        # decides between `personal-token` and `org-credential`, and getting
        # that one wrong puts a token somebody else can act with into a shared
        # vault.
        out = self.listing()
        for kind, summary in stores_mod.KIND_SUMMARY.items():
            with self.subTest(kind=kind):
                self.assertIn(summary, out)

    def test_what_is_not_a_kind_is_listed_with_the_reason(self):
        out = self.listing()
        for word, why in stores_mod.NOT_A_KIND.items():
            with self.subTest(word=word):
                self.assertIn(word, out)
                self.assertIn(why, out)

    def test_the_two_lists_are_not_run_together(self):
        # Printed as one block they read as eleven kinds, four of which have an
        # odd description, and the refusal further down becomes a surprise.
        out = self.listing()
        head, marker, tail = out.partition("not kinds")
        self.assertTrue(marker, "the second list has no heading of its own")
        for kind in stores_mod.KINDS:
            self.assertIn(kind, head)
        for word in stores_mod.NOT_A_KIND:
            self.assertIn(word, tail)
            self.assertNotIn(word, head)

    def test_it_needs_no_declarations_and_exits_zero(self):
        # The vocabulary is the engine's, not the tree's, so this answer has to
        # work on a clone where nothing has been declared yet. That is exactly
        # the session in which somebody is deciding where the first secret goes.
        code, out, _ = self.where(root=self.empty_tree())
        self.assertEqual(code, EX_OK)
        self.assertTrue(out.strip())

    def test_the_json_form_carries_both_tables(self):
        payload = json.loads(self.listing("--json"))
        self.assertEqual(set(payload["kinds"]), set(stores_mod.KINDS))
        self.assertEqual(set(payload["not_a_kind"]), set(stores_mod.NOT_A_KIND))

    def test_no_store_is_opened_to_answer_it(self):
        # `where` is a policy question. A verb that unlocked a vault to answer
        # it would prompt for a master password to print a naming convention.
        runner = FakeRunner()
        code, _, _ = self.where(root=self.empty_tree(), runner=runner)
        self.assertEqual(code, EX_OK)
        self.assertEqual(runner.calls, [])


# ---------------------------------------------------------------------------
# a kind one store declares
# ---------------------------------------------------------------------------

class WhereNamesTheStoreTheShapeAndAReferenceToPaste(WhereCase):
    """One declaration, and the three things the answer has to carry.

    The store alone is not an answer: "put it in the login keychain" leaves the
    entry name to whoever is typing, and an entry nobody can find again is a
    secret that gets stored a second time under a second name.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree(LOGIN_KEYCHAIN)
        self.code, self.out, self.err = self.where("personal-token", root=self.root)

    def test_it_exits_zero(self):
        self.assertEqual(self.code, EX_OK, self.err)

    def test_the_store_is_named(self):
        self.assertIn("login-keychain", self.out)

    def test_the_backend_is_named(self):
        # Two stores of the same name on different backends are two different
        # places, and the backend is what says which tool opens this one.
        self.assertIn("keychain", self.out)

    def test_the_summary_of_the_store_is_printed(self):
        self.assertIn(LOGIN_KEYCHAIN["summary"], self.out)

    def test_the_naming_shape_is_printed(self):
        self.assertIn("<provider>-<tenant>-<role>", self.out)

    def test_the_reference_is_ready_to_paste(self):
        # The shape with the naming convention already in it. Anything less and
        # the next step is a guess about how many segments a keychain reference
        # takes, which is the guess that produced the broken references this
        # skill's `refs` verb found in the tree.
        self.assertIn("keychain://<provider>-<tenant>-<role>/<account>", self.out)

    def test_the_note_on_the_placement_is_printed(self):
        self.assertIn(LOGIN_KEYCHAIN["holds"][0]["note"], self.out)

    def test_the_declaration_file_is_named(self):
        # So that disagreeing with the answer is a file to edit rather than an
        # argument with the tool.
        self.assertIn("login-keychain.yaml", self.out)

    def test_the_kind_is_explained_before_the_stores_are_listed(self):
        summary = stores_mod.KIND_SUMMARY["personal-token"]
        self.assertIn(summary, self.out)
        self.assertLess(self.out.index(summary), self.out.index("login-keychain"))

    def test_the_answer_comes_from_the_file_on_disk(self):
        # Rewriting the declaration changes the answer. Without this case every
        # assertion above would also hold for a verb that had the placement
        # policy compiled into it, which is the thing this design replaced.
        changed = dict(LOGIN_KEYCHAIN)
        changed["holds"] = [{"kind": "personal-token", "naming": "<provider>-<role>"}]
        self.write_declaration(
            self.root / stores_mod.FAMILY / "login-keychain.yaml", changed)
        _, out, _ = self.where("personal-token", root=self.root)
        self.assertIn("<provider>-<role>", out)
        self.assertNotIn("<provider>-<tenant>-<role>", out)

    def test_a_file_whose_name_begins_with_an_underscore_is_not_a_declaration(self):
        # `_template.yaml` ships filled in, with an example placement in it. A
        # tree that read it as a store would answer every question with the
        # example, and the example names a store that does not exist here.
        root = self.tree(hidden=(LOGIN_KEYCHAIN,))
        code, out, _ = self.where("personal-token", root=root)
        self.assertEqual(code, EX_CONFIG)
        self.assertNotIn("login-keychain", out)


# ---------------------------------------------------------------------------
# a kind nobody declares
# ---------------------------------------------------------------------------

class AKindNoStoreDeclaresSaysWhichOfTheTwoSituationsItIs(WhereCase):
    """Nothing declared at all, and declared but not for this: two repairs.

    The first is "copy the template and fill it in", the second is "add one
    line to the store you already have". One message covering both sends half
    the readers to build a second store beside the one they are already using,
    which is how the same customer ends up with two vaults.
    """

    def nothing_declared(self):
        return self.where("personal-token", root=self.empty_tree())

    def declared_but_not_this(self):
        return self.where("ci-secret", root=self.tree(LOGIN_KEYCHAIN))

    def test_an_empty_tree_says_there_are_no_declarations_at_all(self):
        _, out, _ = self.nothing_declared()
        self.assertIn("no declarations at all", out)

    def test_an_empty_tree_names_the_template_to_copy(self):
        _, out, _ = self.nothing_declared()
        self.assertIn("_template.yaml", out)

    def test_declarations_that_do_not_hold_this_kind_say_so_instead(self):
        _, out, _ = self.declared_but_not_this()
        self.assertIn("none of them for this kind", out)
        self.assertNotIn("no declarations at all", out)

    def test_that_message_counts_the_declarations_that_do_exist(self):
        # "1 store(s) are declared" is the line that tells a reader the tree
        # was found and read, rather than looked for in the wrong root.
        _, out, _ = self.declared_but_not_this()
        self.assertIn("1 store", out)

    def test_both_situations_exit_78(self):
        for label, run in (("nothing declared", self.nothing_declared),
                           ("declared but not this kind", self.declared_but_not_this)):
            with self.subTest(situation=label):
                code, _, _ = run()
                self.assertEqual(code, EX_CONFIG)

    def test_the_two_messages_are_not_the_same_sentence(self):
        # The case that keeps the two apart when somebody simplifies the branch.
        _, empty, _ = self.nothing_declared()
        _, other, _ = self.declared_but_not_this()
        self.assertNotEqual(empty, other)

    def test_nothing_is_proposed_when_nothing_is_declared(self):
        # A proposed reference here would be invented rather than declared, and
        # an invented one is indistinguishable from a real one once it is in a
        # file.
        _, out, _ = self.nothing_declared()
        self.assertNotIn("reference   ", out)


# ---------------------------------------------------------------------------
# --owner
# ---------------------------------------------------------------------------

class TheOwnerPicksTheLineWhenTwoStoresHoldTheSameKind(WhereCase):
    """Two customers, two databases, one kind. The owner is what decides.

    Without it the answer to "where does an Acme credential go" lists both
    customer databases, and the reader picks one. A credential in the wrong
    customer's database is not a filing mistake: it is one customer's operator
    holding a key to another customer's system.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree(ACME_VAULT, GLOBEX_VAULT)

    def test_without_an_owner_every_store_that_holds_the_kind_is_listed(self):
        code, out, err = self.where("customer-credential", root=self.root)
        self.assertEqual(code, EX_OK, err)
        self.assertIn("acme-vault", out)
        self.assertIn("globex-vault", out)

    def test_the_named_owner_gets_their_own_line(self):
        _, out, _ = self.where("customer-credential", "--owner", "acme", root=self.root)
        self.assertIn("acme-vault", out)

    def test_the_other_owners_line_is_gone(self):
        _, out, _ = self.where("customer-credential", "--owner", "acme", root=self.root)
        self.assertNotIn("globex-vault", out)

    def test_a_store_with_no_owner_stays_for_every_owner(self):
        # A fallback line is declared without an owner on purpose, so filtering
        # it away would leave a customer with no answer at all rather than with
        # a second-best one.
        root = self.tree(ACME_VAULT, SHARED_VAULT)
        _, out, _ = self.where("customer-credential", "--owner", "globex", root=root)
        self.assertIn("shared-vault", out)

    def test_a_line_that_names_the_owner_sorts_before_one_that_does_not(self):
        root = self.tree(ACME_VAULT, SHARED_VAULT)
        _, out, _ = self.where("customer-credential", "--owner", "acme", root=root)
        self.assertLess(out.index("acme-vault"), out.index("shared-vault"),
                        "the specific answer has to stand above the fallback")

    def test_an_owner_nobody_declares_falls_back_to_the_lines_without_one(self):
        root = self.tree(ACME_VAULT, SHARED_VAULT)
        code, out, _ = self.where("customer-credential", "--owner", "initech", root=root)
        self.assertEqual(code, EX_OK)
        self.assertIn("shared-vault", out)
        self.assertNotIn("acme-vault", out)

    def test_an_owner_nobody_declares_and_no_fallback_is_a_configuration_error(self):
        code, out, _ = self.where("customer-credential", "--owner", "initech", root=self.root)
        self.assertEqual(code, EX_CONFIG)
        self.assertIn("no store declares this kind", out)


# ---------------------------------------------------------------------------
# --json
# ---------------------------------------------------------------------------

class TheJsonFormCarriesWhatTheLinesCarry(WhereCase):
    """The machine readable form is what a wrapper reads before it writes.

    A wrapper that has to scrape the human lines to learn the entry name is a
    wrapper that breaks the day the layout changes, and the layout is the part
    of this output nobody treats as a contract.
    """

    def payload(self, *arguments, root=None):
        code, out, err = self.where(*arguments, root=root or self.tree(ACME_VAULT))
        return code, json.loads(out), err

    def test_one_object_per_placement(self):
        root = self.tree(ACME_VAULT, GLOBEX_VAULT)
        code, payload, _ = self.payload("customer-credential", "--json", root=root)
        self.assertEqual(code, EX_OK)
        self.assertEqual(len(payload), 2)

    def test_the_fields_are_the_ones_the_lines_print(self):
        _, payload, _ = self.payload("customer-credential", "--json")
        entry = payload[0]
        self.assertEqual(entry["store"], "acme-vault")
        self.assertEqual(entry["backend"], "keepass")
        self.assertEqual(entry["owner"], "acme")
        self.assertEqual(entry["naming"], "<system>/<role>")
        self.assertEqual(entry["note"], ACME_VAULT["holds"][0]["note"])
        self.assertTrue(entry["source"].endswith("acme-vault.yaml"), entry["source"])
        self.assertEqual(entry["reference"], "keepass://acme/<system>/<role>/<field>")

    def test_the_reference_is_the_same_string_in_both_forms(self):
        # Two renderings of the same shape drift, and the one a person copies
        # and the one a script copies then address different entries.
        _, payload, _ = self.payload("customer-credential", "--json")
        _, lines, _ = self.where("customer-credential", root=self.tree(ACME_VAULT))
        self.assertIn(payload[0]["reference"], lines)

    def test_the_owner_filter_applies_to_the_json_form_too(self):
        root = self.tree(ACME_VAULT, GLOBEX_VAULT)
        _, payload, _ = self.payload("customer-credential", "--owner", "globex",
                                     "--json", root=root)
        self.assertEqual([entry["store"] for entry in payload], ["globex-vault"])

    def test_a_kind_nobody_declares_is_an_empty_list_with_exit_78(self):
        code, payload, _ = self.payload("ci-secret", "--json")
        self.assertEqual(payload, [])
        self.assertEqual(code, EX_CONFIG)

    def test_the_json_form_is_not_wrapped_in_prose(self):
        # `json.loads` in the helper above already proves it for the cases that
        # use it; this one says so on its own, because a stray human line on
        # stdout is the usual way a machine readable mode stops being one.
        _, out, _ = self.where("customer-credential", "--json", root=self.tree(ACME_VAULT))
        self.assertTrue(out.lstrip().startswith("["))


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------

class AStoreThisSessionCannotReachIsStillWhereTheSecretBelongs(WhereCase):
    """Not reachable from here is a note on the answer, never a reason to hide it.

    A verb that dropped the store would send the reader to invent a second
    place for the same secret, and two places for one secret is how a rotation
    leaves half of a fleet on the old value. The right answer is the declared
    store plus the sentence that says this session cannot write it, so the work
    moves to the session that can.
    """

    def setUp(self):
        super().setUp()
        self.root = self.tree(SSH_ONLY_STORE)

    def test_the_store_is_listed_although_this_session_cannot_reach_it(self):
        code, out, err = self.where("service-runtime", root=self.root)
        self.assertEqual(code, EX_OK, err)
        self.assertIn("service-keychain", out)

    def test_the_line_says_it_is_not_reachable_from_this_session(self):
        _, out, _ = self.where("service-runtime", root=self.root)
        self.assertIn("reachable", out)
        self.assertIn("no, from this session", out)

    def test_the_reason_names_the_contexts_the_store_declares(self):
        # "not reachable" with no reason reads like a broken tool. The contexts
        # are what tells the reader to open a terminal on the other machine.
        _, out, _ = self.where("service-runtime", root=self.root)
        self.assertIn("ssh", out)

    def test_a_session_that_does_reach_it_carries_no_such_line(self):
        _, out, _ = self.where("service-runtime", root=self.root, context=self.over_ssh())
        self.assertIn("service-keychain", out)
        self.assertNotIn("no, from this session", out)

    def test_a_store_that_is_reachable_from_anywhere_carries_no_such_line(self):
        _, out, _ = self.where("customer-credential", root=self.tree(ACME_VAULT))
        self.assertNotIn("no, from this session", out)

    def test_an_unreachable_store_does_not_change_the_exit_code(self):
        # 78 here would tell a wrapper the declaration is wrong, and the
        # declaration is right: it is this session that is in the wrong place.
        code, _, _ = self.where("service-runtime", root=self.root)
        self.assertEqual(code, EX_OK)


# ---------------------------------------------------------------------------
# what is not a kind
# ---------------------------------------------------------------------------

class WhatIdentifiesRatherThanAuthenticatesIsRefused(WhereCase):
    """An IBAN is on every invoice the user writes.

    Moving it into a vault makes it useless for the thing it is for and buys no
    security at all, because knowing it grants nothing. The refusal is the
    teaching: the answer to "where do I put this" is sometimes "it is not a
    secret, and treating it as one costs you the use of it".
    """

    def test_iban_is_refused(self):
        code, _, err = self.where("iban", root=self.tree(LOGIN_KEYCHAIN))
        self.assertEqual(code, EX_REFUSED, err)

    def test_the_reason_is_that_it_identifies_and_does_not_authenticate(self):
        _, _, err = self.where("iban", root=self.tree(LOGIN_KEYCHAIN))
        self.assertIn("identifying, not authenticating", err)

    def test_the_refusal_proposes_no_store(self):
        _, out, _ = self.where("iban", root=self.tree(LOGIN_KEYCHAIN))
        self.assertNotIn("login-keychain", out)

    def test_it_is_refused_before_any_declaration_is_read(self):
        # The answer does not depend on the tree, so an empty one gets the same
        # refusal rather than "nothing is declared", which would read as an
        # invitation to declare a store for IBANs.
        code, _, err = self.where("iban", root=self.empty_tree())
        self.assertEqual(code, EX_REFUSED)
        self.assertIn("not a kind of secret", err)

    def test_every_word_the_engine_calls_not_a_kind_is_refused(self):
        root = self.tree(LOGIN_KEYCHAIN)
        for word, why in stores_mod.NOT_A_KIND.items():
            with self.subTest(word=word):
                code, _, err = self.where(word, root=root)
                self.assertEqual(code, EX_REFUSED)
                self.assertIn(why, err)

    def test_an_unknown_word_is_refused_with_the_list_of_declared_kinds(self):
        code, _, err = self.where("api-key", root=self.tree(LOGIN_KEYCHAIN))
        self.assertEqual(code, EX_REFUSED)
        for kind in stores_mod.KINDS:
            self.assertIn(kind, err)


# ---------------------------------------------------------------------------
# the loader
# ---------------------------------------------------------------------------

class TheDeclarationsAreReadFromDiskByWhateverLoaderThisRunnerHas(WhereCase):
    """The fixtures are JSON, and JSON is a subset of YAML.

    A CI runner without PyYAML would otherwise turn every case in this file
    into "no declarations at all", which exits 78 with a plausible message and
    proves nothing. The stand-in keeps the engine's own glob, `_`-prefix rule
    and field mapping in the run and swaps only the parser, on text both
    parsers read the same way. This class is where that last claim is measured
    instead of assumed.
    """

    FIXTURES = (LOGIN_KEYCHAIN, ACME_VAULT, GLOBEX_VAULT, SHARED_VAULT, SSH_ONLY_STORE)

    def test_the_fixtures_round_trip_through_the_json_form(self):
        for mapping in self.FIXTURES:
            with self.subTest(store=mapping["name"]):
                text = json.dumps(mapping, indent=2, sort_keys=True) + "\n"
                self.assertEqual(json.loads(text), mapping)

    def test_both_loaders_read_the_same_mapping(self):
        # On a runner with PyYAML this compares the two parsers. On one without
        # it compares `json.loads` with itself, and says so rather than looking
        # like a check that ran.
        for mapping in self.FIXTURES:
            with self.subTest(store=mapping["name"]):
                text = json.dumps(mapping, indent=2, sort_keys=True) + "\n"
                if HAS_REAL_YAML:
                    import yaml  # noqa: PLC0415 - only where the runner has it

                    self.assertEqual(yaml.safe_load(text), mapping)
                else:
                    self.assertEqual(json.loads(text), mapping)

    def test_the_engine_reads_the_file_this_test_wrote(self):
        # The end of the chain: a store that exists only as bytes in a
        # temporary directory shows up in the answer, so the path really does
        # run through `engine.stores.load` and the filesystem.
        root = self.tree(SHARED_VAULT)
        _, out, _ = self.where("customer-credential", root=root)
        self.assertIn("shared-vault", out)
        self.assertIn(str(root), out)
