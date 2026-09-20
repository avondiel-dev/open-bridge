"""stores: the declarations, and the placement policy they carry.

Every case here builds its own `infra/secret-stores/` folder under `tempfile`
and loads THAT. The real family is read exactly once, by the last class in this
file, and then only to prove the shipped template is a declaration the loader
accepts. A suite that measured the live tree would report a different number
every time somebody declares a store, and the number would be the finding
rather than the behaviour.

Nothing here reaches a store. `stores.py` opens no vault: it reads YAML, matches
a pattern and sorts a list, which is why this file passes a FakeRunner to
nothing. The machine guard still stands under every class, because a module that
grows one `subprocess` call later should turn this file red rather than green.

The four questions with a scar behind them:

* WHICH STORE ANSWERS. Matching is first hit wins, so the order of the files in
  the folder is load bearing. A wildcard store listed before a specific one
  swallows the specific one's entries, and the report reads as if the specific
  store were empty.
* WHERE A NEW SECRET GOES. This is the half that had no answer at all. An agent
  handed a token decided for itself where to keep it, and the result was small
  text files with credentials in working folders on two machines. `holds:` is
  that decision, made once, in a file a person can read.
* WHAT IS NOT A KIND. An IBAN is on every invoice the user writes. Moving it
  into a vault makes it useless for the thing it is for and buys no security,
  so the refusal has to carry the reason or somebody will declare it anyway.
* WHETHER THE STORE ANSWERS FROM HERE. A login keychain answers in a desktop
  session and refuses over ssh. A wrapper that could not tell those apart
  rotated a secret that was never gone.
"""

from __future__ import annotations

import os
from unittest import mock

from tests.conftest import SKILL_DIR, MachineGuard, mod

stores = mod("engine.stores")
refs = mod("engine.refs")
errors = mod("engine.errors")
base = mod("engine.backends.base")

#: A home directory that exists in no fleet and reads the same on every runner.
#: Spelled here rather than taken from the machine so that an expansion case can
#: assert on a literal string instead of on whatever `$HOME` happens to be.
NEUTRAL_HOME = "/home/opuser"


# ---------------------------------------------------------------------------
# Writing declarations
# ---------------------------------------------------------------------------

def _scalar(value) -> str:
    """One YAML scalar, or a flow list when a block holds one."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_scalar(item) for item in value) + "]"
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _flow_map(block: dict) -> str:
    return "{" + ", ".join(f"{key}: {_scalar(value)}" for key, value in block.items()) + "}"


def declaration(name="login-keychain", backend="keychain", addresses=("*",),
                summary="", location=None, unlock=None, reachable_from=None,
                holds=(), recovery=None, scope="user") -> str:
    """The text of one declaration, as a person would have written the file.

    Flow style for the inner blocks keeps a case to a few lines; the first class
    in this file hand writes a full block-style declaration instead, so that the
    loader is measured against a realistic file and not only against whatever
    shape this helper happens to emit.
    """
    lines = ["# yaml-language-server: $schema=./_schema.yaml", "---"]
    if name is not None:
        lines.append(f"name: {name}")
    lines.append(f"scope: {scope}")
    if backend is not None:
        lines.append(f"backend: {backend}")
    if summary:
        lines.append(f"summary: {_scalar(summary)}")
    if addresses is not None:
        lines.append(f"addresses: {_scalar(list(addresses))}")
    for key, block in (("location", location), ("unlock", unlock),
                       ("reachable_from", reachable_from), ("recovery", recovery)):
        if block:
            lines.append(f"{key}: {_flow_map(block)}")
    if holds:
        lines.append("holds:")
        for line in holds:
            lines.append(f"  - {_flow_map(line)}")
    return "\n".join(lines) + "\n"


class StoreCase(MachineGuard):
    """A store family in a temporary directory, and a context that is stated.

    The context is spelled out rather than detected. Run over ssh, the same case
    would meet a different `Context` and, for `reaches`, a different answer, and
    a suite whose verdict depends on how the developer opened the terminal is
    not a suite.
    """

    def family(self, files: dict):
        """Write `{filename: text}` into a fresh `infra/secret-stores/`."""
        root = self.tmpdir()
        folder = root / stores.FAMILY
        folder.mkdir(parents=True)
        for filename, content in files.items():
            (folder / filename).write_text(content, encoding="utf-8")
        return root

    def load(self, files: dict) -> list:
        return stores.load(str(self.family(files)))

    def one(self, filename="login-keychain.yaml", **fields):
        """Load a single declaration and hand back the `Store` itself."""
        loaded = self.load({filename: declaration(**fields)})
        self.assertEqual(len(loaded), 1, "the fixture did not load as one store")
        return loaded[0]

    def context(self, **overrides):
        fields = {"platform": "darwin", "interactive": True,
                  "over_ssh": False, "display": True}
        fields.update(overrides)
        return base.Context(**fields)

    def neutral_home(self, **extra):
        """Pin `$HOME` and any extra variable, so expansion has one answer."""
        environment = {"HOME": NEUTRAL_HOME}
        environment.update(extra)
        patcher = mock.patch.dict(os.environ, environment, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)


# ---------------------------------------------------------------------------
# Reading a declaration
# ---------------------------------------------------------------------------

#: A full declaration, hand written in block style with a modeline and a comment
#: in front of it, because that is what the files in the family actually look
#: like. Every block the loader knows about is present exactly once.
WORK_KEEPASS = """\
# yaml-language-server: $schema=./_schema.yaml
# The work database, on the share both machines mount.
---
name: work-keepass
scope: user
backend: keepass
summary: "The work KeePass database on the shared drive"
addresses:
  - work
  - work-*
location:
  path: "${WORK_SECRETS}/work.kdbx"
unlock:
  method: password-ref
  password_ref: "keychain://keepass-work/master"
  key_file: "~/.config/keepass/work.keyx"
reachable_from:
  machines: [desk-mini]
  contexts: [interactive, ssh]
holds:
  - kind: org-credential
    owner: example-org
    naming: "<org>/<system>/<role>"
    note: "One group per system, so a rotation touches one group."
  - kind: customer-credential
    naming: "<customer>/<system>/<role>"
recovery:
  backed_up: true
  offsite: false
  break_glass: "the sealed envelope in the office safe"
"""


class ADeclarationIsReadWithEveryBlockItCarries(StoreCase):
    """Every block, because each one is the only copy of what it says.

    A loader that quietly dropped `unlock` would send a KeePass read to a
    database with no master password and surface as a wrong password. A loader
    that dropped `reachable_from` would report a store as broken in the one
    session where it was never supposed to answer.
    """

    def setUp(self):
        super().setUp()
        self.store = self.load({"work-keepass.yaml": WORK_KEEPASS})[0]

    def test_the_declared_name_is_what_the_file_says(self):
        self.assertEqual(self.store.name, "work-keepass")

    def test_the_backend_is_read(self):
        self.assertEqual(self.store.backend, "keepass")

    def test_the_addresses_arrive_in_the_declared_order(self):
        # Order is not decoration here: `reference_shape` proposes the first
        # address, and matching walks the list from the front.
        self.assertEqual(self.store.addresses, ("work", "work-*"))

    def test_the_summary_is_read(self):
        self.assertEqual(self.store.summary,
                         "The work KeePass database on the shared drive")

    def test_the_location_block_is_read_unexpanded(self):
        # Unexpanded on purpose: `expand` runs when a backend asks for the path,
        # so the declaration keeps the variable a person wrote.
        self.assertEqual(self.store.location["path"], "${WORK_SECRETS}/work.kdbx")

    def test_the_unlock_block_is_read(self):
        self.assertEqual(self.store.unlock["method"], "password-ref")
        self.assertEqual(self.store.unlock["key_file"], "~/.config/keepass/work.keyx")

    def test_the_password_reference_is_reachable_through_its_own_accessor(self):
        self.assertEqual(self.store.password_ref(), "keychain://keepass-work/master")

    def test_the_reachable_from_block_is_read(self):
        self.assertEqual(self.store.reachable_from["contexts"], ["interactive", "ssh"])
        self.assertEqual(self.store.reachable_from["machines"], ["desk-mini"])

    def test_both_holds_lines_survive_the_read(self):
        self.assertEqual([placement.kind for placement in self.store.placements()],
                         ["org-credential", "customer-credential"])

    def test_a_holds_line_carries_its_owner_naming_and_note(self):
        first = self.store.placements()[0]
        self.assertEqual(first.owner, "example-org")
        self.assertEqual(first.naming, "<org>/<system>/<role>")
        self.assertIn("one group", first.note.lower())

    def test_a_holds_line_without_an_owner_reads_as_empty_rather_than_none(self):
        # `where` prints `for {owner}` when there is one, so None would print
        # the word None beside a perfectly good placement.
        self.assertEqual(self.store.placements()[1].owner, "")

    def test_a_placement_knows_the_store_it_came_from(self):
        self.assertIs(self.store.placements()[0].store, self.store)

    def test_the_recovery_block_keeps_its_booleans_as_booleans(self):
        self.assertIs(self.store.recovery["backed_up"], True)
        self.assertIs(self.store.recovery["offsite"], False)
        self.assertIn("safe", self.store.recovery["break_glass"])

    def test_the_source_names_the_file_the_declaration_came_from(self):
        # A problem line says `{source}: ...`, and a reader edits that path.
        self.assertTrue(self.store.source.endswith("work-keepass.yaml"),
                        self.store.source)
        self.assertTrue(os.path.exists(self.store.source), self.store.source)

    def test_a_file_without_a_name_falls_back_to_its_own_stem(self):
        store = self.one("cf-tokens.yaml", name=None)
        self.assertEqual(store.name, "cf-tokens")

    def test_a_block_nobody_declared_is_empty_rather_than_missing(self):
        # Every consumer does `store.location.get(...)`, so None here would be
        # an AttributeError in the middle of a read rather than a clean answer.
        bare = self.one()
        self.assertEqual(bare.location, {})
        self.assertEqual(bare.unlock, {})
        self.assertEqual(bare.reachable_from, {})
        self.assertEqual(bare.recovery, {})
        self.assertEqual(bare.holds, ())
        self.assertEqual(bare.password_ref(), "")


# ---------------------------------------------------------------------------
# The underscore rule
# ---------------------------------------------------------------------------

class TheUnderscoreFilesAreTemplatesAndNotStores(StoreCase):
    """`_template.yaml` and `_schema.yaml` are furniture, not declarations.

    The rule is the same one every family in this tree follows, and it is worth
    a case of its own here: the template declares `addresses: ["*"]`, so a
    loader that read it would hand every reference in the fleet to a store
    nobody created, listed first because an underscore sorts before a letter.
    """

    def setUp(self):
        super().setUp()
        self.loaded = self.load({
            "_template.yaml": declaration(name="login-keychain"),
            "_schema.yaml": "type: object\n",
            "cf-tokens.yaml": declaration(name="cf-tokens", addresses=["cf-*"]),
            "README.md": "This folder holds one declaration per store.\n",
        })

    def test_only_the_real_declaration_is_loaded(self):
        self.assertEqual([store.name for store in self.loaded], ["cf-tokens"])

    def test_the_template_is_not_among_the_sources(self):
        self.assertNotIn("_template.yaml", " ".join(s.source for s in self.loaded))

    def test_the_schema_is_not_among_the_sources(self):
        self.assertNotIn("_schema.yaml", " ".join(s.source for s in self.loaded))

    def test_a_file_that_is_not_yaml_is_not_a_declaration_either(self):
        self.assertNotIn("README", " ".join(s.source for s in self.loaded))

    def test_the_control_is_that_the_same_text_does_load_under_a_plain_name(self):
        # Without this, the three cases above also pass against a loader that
        # reads nothing at all.
        loaded = self.load({"login-keychain.yaml": declaration(name="login-keychain")})
        self.assertEqual([store.name for store in loaded], ["login-keychain"])


# ---------------------------------------------------------------------------
# Matching an address
# ---------------------------------------------------------------------------

class AnAddressMatchesExactlyOrByPrefixOrByStar(StoreCase):
    """Three shapes, and a fourth that has to stay a miss.

    `cf-*` is the shape in use, and the two ways to get it wrong are both
    silent: a prefix that also matched the bare stem would route
    `keychain://cf/...` into the token store, and a prefix matched anywhere in
    the string would route `keychain://my-cf-token/...` there too.
    """

    def answers(self, addresses, reference, backend="keychain"):
        store = self.one(addresses=addresses, backend=backend)
        return store.answers(refs.parse(reference))

    def test_an_exact_address_answers_its_own_reference(self):
        self.assertTrue(self.answers(["github"], "keychain://github/token"))

    def test_an_exact_address_is_not_a_prefix_by_accident(self):
        self.assertFalse(self.answers(["github"], "keychain://github-actions/token"))

    def test_a_trailing_star_answers_everything_under_it(self):
        self.assertTrue(self.answers(["cf-*"], "keychain://cf-bks-agent/agent"))

    def test_a_trailing_star_still_demands_the_separator_it_names(self):
        self.assertFalse(self.answers(["cf-*"], "keychain://cf/agent"))

    def test_a_trailing_star_does_not_match_in_the_middle(self):
        self.assertFalse(self.answers(["cf-*"], "keychain://my-cf-token/agent"))

    def test_the_lone_star_answers_anything_of_its_own_scheme(self):
        self.assertTrue(self.answers(["*"], "keychain://anything-at-all/token"))

    def test_a_store_with_several_addresses_answers_for_each_of_them(self):
        store = self.one(addresses=["github", "cf-*"])
        self.assertTrue(store.answers(refs.parse("keychain://github/token")))
        self.assertTrue(store.answers(refs.parse("keychain://cf-bks-agent/agent")))

    def test_an_address_nobody_declared_is_answered_by_nobody(self):
        self.assertFalse(self.answers(["github"], "keychain://gitlab/token"))

    def test_a_file_store_addresses_a_directory_by_the_same_prefix_rule(self):
        # The `file` scheme puts an absolute path where the other schemes put a
        # name, so the star rule has to hold for a path or a file store cannot
        # be declared at all.
        self.assertTrue(self.answers([NEUTRAL_HOME + "/secrets/*"],
                                     "file://" + NEUTRAL_HOME + "/secrets/token",
                                     backend="file"))
        self.assertFalse(self.answers([NEUTRAL_HOME + "/secrets/*"],
                                      "file:///tmp/token", backend="file"))

    def test_for_reference_hands_back_nothing_when_nothing_matches(self):
        loaded = self.load({"github.yaml": declaration(name="github",
                                                       addresses=["github"])})
        self.assertIsNone(stores.for_reference(loaded, refs.parse("keychain://gitlab/token")))


class TheFirstStoreThatAnswersWinsAndTheFolderOrderDecides(StoreCase):
    """Two stores match, and the file names decide which one is asked.

    `load` sorts by filename, so the order in `ls` is the order of the list, and
    a catch-all that sorts early swallows every specific store behind it. This
    is the failure that reads as an empty store rather than as a routing
    mistake, so both orders are measured.
    """

    SPECIFIC = declaration(name="cf-tokens", addresses=["cf-*"],
                           summary="The Cloudflare agent tokens")
    CATCH_ALL = declaration(name="login-keychain", addresses=["*"],
                            summary="Everything else on this laptop")
    REFERENCE = "keychain://cf-bks-agent/agent"

    def answering(self, files):
        loaded = self.load(files)
        self.assertEqual(len(loaded), 2)
        return stores.for_reference(loaded, refs.parse(self.REFERENCE))

    def test_the_specific_store_answers_when_it_sorts_first(self):
        chosen = self.answering({"a-cf-tokens.yaml": self.SPECIFIC,
                                 "b-login-keychain.yaml": self.CATCH_ALL})
        self.assertEqual(chosen.name, "cf-tokens")

    def test_the_very_same_pair_answers_differently_in_the_other_order(self):
        chosen = self.answering({"a-login-keychain.yaml": self.CATCH_ALL,
                                 "b-cf-tokens.yaml": self.SPECIFIC})
        self.assertEqual(chosen.name, "login-keychain")

    def test_both_stores_really_do_match_so_the_order_is_what_decided(self):
        # Otherwise the pair of cases above would also pass against a loader
        # that simply never matched the wildcard.
        loaded = self.load({"a-cf-tokens.yaml": self.SPECIFIC,
                            "b-login-keychain.yaml": self.CATCH_ALL})
        parsed = refs.parse(self.REFERENCE)
        self.assertEqual([store.answers(parsed) for store in loaded], [True, True])

    def test_the_loaded_order_is_the_sorted_filename_order(self):
        loaded = self.load({"b-login-keychain.yaml": self.CATCH_ALL,
                            "a-cf-tokens.yaml": self.SPECIFIC})
        self.assertEqual([store.name for store in loaded],
                         ["cf-tokens", "login-keychain"])


class AReferenceOfAnotherSchemeIsNotAnsweredHere(StoreCase):
    """The backend is half of the match, and the half that is easy to forget.

    A keychain store declaring `*` looks like a catch-all, and a catch-all that
    answered a `keepass://` reference would send a database read to `security`,
    which reports "not found" for a database it never opened.
    """

    def test_a_catch_all_keychain_store_does_not_answer_a_keepass_reference(self):
        store = self.one(backend="keychain", addresses=["*"])
        self.assertFalse(store.answers(refs.parse("keepass://work/acme/api-token")))

    def test_the_keepass_store_is_chosen_even_though_the_star_sorts_first(self):
        loaded = self.load({
            "a-login-keychain.yaml": declaration(name="login-keychain",
                                                 backend="keychain", addresses=["*"]),
            "b-work-keepass.yaml": declaration(name="work-keepass", backend="keepass",
                                               addresses=["work"],
                                               location={"path": "/srv/work.kdbx"}),
        })
        chosen = stores.for_reference(loaded, refs.parse("keepass://work/acme/api-token"))
        self.assertEqual(chosen.name, "work-keepass")

    def test_two_vault_shaped_schemes_are_not_interchangeable(self):
        store = self.one(backend="azure-keyvault", addresses=["*"])
        self.assertTrue(store.answers(refs.parse("azure-keyvault://bks-prod/token")))
        self.assertFalse(store.answers(refs.parse("vault://bks-prod/app/token")))

    def test_the_alias_spelling_is_matched_as_the_scheme_it_canonicalises_to(self):
        # `op://` is what the 1Password CLI prints, and it arrives in files as
        # such. `parse` canonicalises it, so the store declares the long name
        # once rather than both.
        store = self.one(backend="1password", addresses=["private"])
        self.assertTrue(store.answers(refs.parse("op://private/api/credential")))


# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------

def placement_family():
    """Three stores that hold overlapping kinds, for the placement cases."""
    return {
        "a-login-keychain.yaml": declaration(
            name="login-keychain", backend="keychain", addresses=["*"],
            holds=[{"kind": "personal-token", "naming": "<provider>-<tenant>-<role>"},
                   {"kind": "service-runtime", "naming": "<service>-<role>"}]),
        "b-work-keepass.yaml": declaration(
            name="work-keepass", backend="keepass", addresses=["work"],
            location={"path": "/srv/secrets/work.kdbx"},
            holds=[{"kind": "org-credential", "owner": "example-org",
                    "naming": "<org>/<system>/<role>"},
                   {"kind": "personal-token", "owner": "opuser",
                    "naming": "<provider>/<role>"}]),
        "c-customer-keepass.yaml": declaration(
            name="customer-keepass", backend="keepass", addresses=["customers"],
            location={"path": "/srv/secrets/customers.kdbx"},
            holds=[{"kind": "customer-credential", "owner": "example-customer",
                    "naming": "<customer>/<system>/<role>"}]),
    }


class PlacementsForNamesEveryPlaceAKindMayGo(StoreCase):
    """The answer to "where does this token go", read off a file.

    The question used to have no answer at all, so each agent invented one, and
    the inventions were small text files with credentials in working folders.
    The order of the answer matters as much as its content: a line that names an
    owner is the specific answer, and it has to be the one a reader sees first.
    """

    def setUp(self):
        super().setUp()
        self.loaded = self.load(placement_family())

    def places(self, kind, owner=""):
        return stores.placements_for(self.loaded, kind, owner)

    def test_every_store_that_holds_the_kind_is_named(self):
        found = {placement.store.name for placement in self.places("personal-token")}
        self.assertEqual(found, {"login-keychain", "work-keepass"})

    def test_a_line_that_names_an_owner_sorts_before_a_generic_one(self):
        first = self.places("personal-token")[0]
        self.assertEqual(first.owner, "opuser")
        self.assertEqual(first.store.name, "work-keepass")

    def test_the_generic_line_is_still_offered_behind_it(self):
        # Specific first is not specific only: the generic store is where a
        # token for a provider nobody declared belongs.
        self.assertEqual([placement.owner for placement in self.places("personal-token")],
                         ["opuser", ""])

    def test_asking_for_one_owner_drops_the_line_of_another(self):
        found = [(placement.store.name, placement.owner)
                 for placement in self.places("org-credential", "example-org")]
        self.assertEqual(found, [("work-keepass", "example-org")])
        self.assertEqual(self.places("org-credential", "somebody-else"), [])

    def test_asking_for_an_owner_keeps_the_line_that_names_nobody(self):
        # A generic line is not a line for a different owner, it is the
        # fallback, and dropping it leaves a caller with no answer at all.
        found = [placement.owner for placement in self.places("personal-token", "opuser")]
        self.assertEqual(found, ["opuser", ""])

    def test_a_kind_nobody_declared_is_an_empty_answer_and_not_a_refusal(self):
        # `ci-secret` is a declared kind with no store behind it here, which is
        # a gap in the declarations rather than a mistake by the caller. The
        # command line prints what to add; it does not raise.
        self.assertEqual(self.places("ci-secret"), [])

    def test_each_placement_carries_the_store_it_was_read_from(self):
        for placement in self.places("personal-token"):
            with self.subTest(store=placement.store.name):
                self.assertIn(placement, placement.store.placements())
                self.assertTrue(placement.store.source.endswith(".yaml"))

    def test_two_generic_lines_are_ordered_by_store_name(self):
        loaded = self.load({
            "b-second.yaml": declaration(name="zulu-store", addresses=["z"],
                                         holds=[{"kind": "break-glass"}]),
            "a-first.yaml": declaration(name="alpha-store", addresses=["a"],
                                        holds=[{"kind": "break-glass"}]),
        })
        found = [placement.store.name
                 for placement in stores.placements_for(loaded, "break-glass")]
        self.assertEqual(found, ["alpha-store", "zulu-store"])

    def test_a_holds_line_that_is_not_a_mapping_is_skipped_rather_than_fatal(self):
        # A hand edited file that wrote `holds: [personal-token]` is wrong, and
        # it should cost that one line rather than every placement in the tree.
        root = self.family({"login-keychain.yaml":
                            declaration(name="login-keychain") + "holds:\n  - personal-token\n"})
        store = stores.load(str(root))[0]
        self.assertEqual(store.placements(), [])


class AKindThatIsNotAKindIsRefusedWithTheReason(StoreCase):
    """The refusal carries WHY, because otherwise somebody declares it anyway.

    An IBAN is on every invoice the user writes. It identifies a person, it does
    not authenticate one, and moving it into a vault makes it useless for the
    thing it is for while buying no security at all. A bare "unknown kind" reads
    like a spelling mistake and invites a second attempt.
    """

    def setUp(self):
        super().setUp()
        self.loaded = self.load(placement_family())

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(errors.Refused):
            stores.placements_for(self.loaded, "ssh-key")

    def test_the_refusal_of_an_unknown_kind_lists_the_kinds_that_exist(self):
        with self.assertRaises(errors.Refused) as caught:
            stores.placements_for(self.loaded, "ssh-key")
        for kind in stores.KINDS:
            with self.subTest(kind=kind):
                self.assertIn(kind, caught.exception.hint)

    def test_an_iban_is_refused_as_identifying_rather_than_authenticating(self):
        with self.assertRaises(errors.Refused) as caught:
            stores.placements_for(self.loaded, "iban")
        self.assertIn("identifying, not authenticating", caught.exception.hint)

    def test_the_refusal_says_the_data_stays_where_it_is(self):
        # The next question after "not a kind" is "then where does it go", and
        # the answer is nowhere: audit reports it where it lies.
        with self.assertRaises(errors.Refused) as caught:
            stores.placements_for(self.loaded, "iban")
        self.assertIn("where it lies", caught.exception.hint)

    def test_every_entry_of_the_not_a_kind_table_is_refused_with_its_reason(self):
        for kind, why in stores.NOT_A_KIND.items():
            with self.subTest(kind=kind):
                with self.assertRaises(errors.Refused) as caught:
                    stores.placements_for(self.loaded, kind)
                self.assertIn(why, caught.exception.hint)

    def test_a_refusal_carries_the_exit_code_a_wrapper_reads(self):
        with self.assertRaises(errors.Refused) as caught:
            stores.placements_for(self.loaded, "iban")
        self.assertEqual(caught.exception.exit_code, errors.EX_REFUSED)

    def test_the_two_tables_cannot_disagree_about_one_word(self):
        # A kind in both lists would be refused and declarable at once, and
        # which of the two happened would depend on the call.
        self.assertEqual(set(stores.KINDS) & set(stores.NOT_A_KIND), set())

    def test_every_declared_kind_carries_a_summary_a_reader_can_read(self):
        # `where` prints the summary beside the kind, so a kind without one
        # prints a KeyError in the middle of a report.
        for kind in stores.KINDS:
            with self.subTest(kind=kind):
                self.assertTrue(stores.KIND_SUMMARY.get(kind))


class TheProposedReferenceHasTheShapeItsBackendReads(StoreCase):
    """`where` proposes a reference, so the shape has to be one `parse` accepts.

    The naming convention lives in the declaration as a shape, and the point of
    rendering it is that a person copies the line rather than inventing a name.
    A proposal that does not parse is worse than no proposal: it is pasted into
    a config file and fails on the day the wrapper first runs.
    """

    def shape(self, backend, naming="<provider>-<tenant>-<role>", addresses=("work",),
              location=None):
        store = self.one(backend=backend, addresses=addresses, location=location,
                         holds=[{"kind": "personal-token", "naming": naming}])
        return store.placements()[0].reference_shape()

    def test_a_keychain_store_proposes_a_service_and_an_account(self):
        self.assertEqual(self.shape("keychain"),
                         "keychain://<provider>-<tenant>-<role>/<account>")

    def test_a_file_store_proposes_a_path_under_its_declared_directory(self):
        shape = self.shape("file", naming="<service>-token",
                           addresses=[NEUTRAL_HOME + "/secrets/*"],
                           location={"path": NEUTRAL_HOME + "/secrets"})
        self.assertEqual(shape, "file://" + NEUTRAL_HOME + "/secrets/<service>-token")

    def test_a_keepass_store_proposes_the_database_and_leaves_the_field_open(self):
        self.assertEqual(self.shape("keepass", naming="<org>/<system>/<role>"),
                         "keepass://work/<org>/<system>/<role>/<field>")

    def test_a_vault_store_proposes_the_mount_and_leaves_the_field_open(self):
        self.assertEqual(self.shape("vault", naming="<app>-<role>", addresses=["kv"]),
                         "vault://kv/<app>-<role>/<field>")

    def test_an_azure_vault_proposes_the_vault_and_the_secret_name(self):
        self.assertEqual(self.shape("azure-keyvault", naming="<app>-<role>",
                                    addresses=["bks-prod"]),
                         "azure-keyvault://bks-prod/<app>-<role>")

    def test_a_line_without_a_naming_convention_proposes_a_placeholder(self):
        # Better an obvious `<name>` than an empty segment, which parses as a
        # reference one segment short and fails somewhere else entirely.
        self.assertEqual(self.shape("keychain", naming=""),
                         "keychain://<name>/<account>")

    def test_a_wildcard_address_does_not_leak_a_bare_star_into_the_proposal(self):
        shape = self.shape("keepass", naming="<role>", addresses=["*"])
        self.assertNotIn("*", shape)
        self.assertEqual(shape, "keepass://<store>/<role>/<field>")

    def test_a_prefix_address_keeps_only_the_part_before_the_star(self):
        shape = self.shape("keepass", naming="<role>", addresses=["work-*"])
        self.assertEqual(shape, "keepass://work-/<role>/<field>")

    def test_every_proposed_shape_parses_back_through_the_grammar(self):
        # The placeholders are ordinary segments as far as the parser is
        # concerned, so a shape that does not parse is a shape with a missing
        # or an empty segment in it.
        cases = {
            "keychain": self.shape("keychain"),
            "keepass": self.shape("keepass", naming="<org>/<role>"),
            "vault": self.shape("vault", naming="<app>", addresses=["kv"]),
            "azure-keyvault": self.shape("azure-keyvault", naming="<app>",
                                         addresses=["bks-prod"]),
            "file": self.shape("file", naming="<service>-token",
                               addresses=[NEUTRAL_HOME + "/secrets/*"],
                               location={"path": NEUTRAL_HOME + "/secrets"}),
            "1password": self.shape("1password", naming="<item>",
                                    addresses=["private"]),
        }
        for backend, shape in cases.items():
            with self.subTest(backend=backend):
                parsed = refs.parse(shape)
                self.assertEqual(parsed.scheme, backend)

    def test_the_proposed_reference_for_one_password_names_its_field(self):
        # `references/resolve.md` writes the scheme as
        # `1password://<vault>/<item>/<field>`, and the CLI spelling `op read`
        # takes a field in every call. The two other field bearing schemes get a
        # `<field>` placeholder in their proposal; this one does not, so the
        # proposal silently means the default field `password`, and an item
        # whose value sits in `credential` is addressed wrongly by a line the
        # skill itself printed.
        shape = self.shape("1password", naming="<item>", addresses=["private"])
        self.assertEqual(shape, "1password://private/<item>/<field>")


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

class AStoreSaysWhetherThisSessionCanReachIt(StoreCase):
    """Readable is a property of the store AND the session, never of the entry.

    The login keychain answers in a desktop session and refuses over ssh. A
    wrapper that read that refusal as "the entry is gone" scheduled a rotation
    for a secret that was never gone, and the rotation is the expensive half.
    """

    def store_for(self, *contexts):
        return self.one(reachable_from={"contexts": list(contexts)})

    def test_a_store_that_lists_ssh_answers_in_an_ssh_session(self):
        reaches, why = self.store_for("ssh").reaches(
            self.context(platform="linux", over_ssh=True, display=False))
        self.assertTrue(reaches)
        self.assertEqual(why, "")

    def test_the_same_store_refuses_a_desktop_session(self):
        reaches, _ = self.store_for("ssh").reaches(self.context())
        self.assertFalse(reaches)

    def test_the_message_names_the_store_the_declaration_and_this_session(self):
        # All three, because the reader has to know which file to edit and what
        # to edit it to. Two of the three leaves them guessing.
        _, why = self.store_for("ssh").reaches(self.context())
        self.assertIn("login-keychain", why)
        self.assertIn("ssh", why)
        self.assertIn("interactive", why)

    def test_a_declaration_with_several_contexts_names_all_of_them(self):
        _, why = self.store_for("interactive", "launchd-gui").reaches(
            self.context(platform="linux", over_ssh=True, display=False))
        self.assertIn("interactive", why)
        self.assertIn("launchd-gui", why)
        self.assertIn("ssh", why)

    def test_a_desktop_store_refuses_the_session_that_came_in_over_ssh(self):
        reaches, _ = self.store_for("interactive", "launchd-gui").reaches(
            self.context(platform="linux", over_ssh=True, display=False))
        self.assertFalse(reaches)

    def test_a_store_that_declares_nothing_is_reachable_everywhere(self):
        # A missing block is not a refusal. Most stores are readable from
        # anywhere, and requiring the block would make the common case noisy.
        store = self.one()
        for name, context in (("desktop", self.context()),
                              ("over ssh", self.context(over_ssh=True))):
            with self.subTest(session=name):
                self.assertEqual(store.reaches(context), (True, ""))

    def test_the_word_any_is_reachable_everywhere_too(self):
        store = self.store_for("any")
        self.assertTrue(store.reaches(self.context(over_ssh=True))[0])
        self.assertTrue(store.reaches(self.context())[0])

    def test_a_session_with_no_terminal_is_the_service_session(self):
        reaches, _ = self.store_for("launchd-gui").reaches(
            self.context(interactive=False))
        self.assertTrue(reaches)

    def test_a_linux_service_session_is_not_described_as_a_launchd_session(self):
        # `reaches` derives the session kind from `interactive` and `over_ssh`
        # alone and never looks at `context.platform`, so a daemon on Linux is
        # told it is a `launchd-gui` session. launchd is macOS only, and the
        # message is the whole output of this call: a reader on Linux is sent
        # looking for a domain that does not exist on the machine.
        _, why = self.store_for("interactive").reaches(
            self.context(platform="linux", interactive=False, display=False))
        self.assertNotIn("launchd", why)


# ---------------------------------------------------------------------------
# What the backend is told
# ---------------------------------------------------------------------------

class AStoreHandsItsBackendWhatOnlyTheDeclarationKnows(StoreCase):
    """`backend_options` is the seam between a file and a running tool.

    A keychain path and a database path are exactly the things a command line
    cannot be expected to repeat on every call, and they are exactly the things
    that are wrong in a way nobody sees: the wrong keychain answers "not found"
    with the same words as an empty one.
    """

    def test_a_keychain_store_contributes_the_file_it_names(self):
        self.neutral_home()
        store = self.one(backend="keychain", addresses=["*"],
                         location={"keychain_path": "~/Library/Keychains/work.keychain-db"})
        self.assertEqual(store.backend_options(),
                         {"keychain_path": NEUTRAL_HOME + "/Library/Keychains/work.keychain-db"})

    def test_a_keychain_store_with_no_path_contributes_nothing(self):
        # The login keychain has no path worth naming, and an empty string
        # handed to `security -k` addresses a keychain called "".
        store = self.one(backend="keychain", location={"keychain_path": ""})
        self.assertEqual(store.backend_options(), {})

    def test_a_keepass_store_maps_every_address_it_answers_to_its_database(self):
        # Every alias has to resolve to the same file, or a reference spelled
        # with the second name opens nothing while the first one works.
        store = self.one(backend="keepass", addresses=["work", "work-archive"],
                         location={"path": "/srv/secrets/work.kdbx"})
        self.assertEqual(store.backend_options()["databases"],
                         {"work": "/srv/secrets/work.kdbx",
                          "work-archive": "/srv/secrets/work.kdbx"})

    def test_a_keepass_database_path_is_expanded_before_it_is_handed_over(self):
        self.neutral_home(WORK_SECRETS="/srv/shared")
        store = self.one(backend="keepass", addresses=["work"],
                         location={"path": "${WORK_SECRETS}/work.kdbx"})
        self.assertEqual(store.backend_options()["databases"]["work"],
                         "/srv/shared/work.kdbx")

    def test_a_declared_key_file_is_passed_through_expanded(self):
        self.neutral_home()
        store = self.one(backend="keepass", addresses=["work"],
                         location={"path": "/srv/secrets/work.kdbx"},
                         unlock={"method": "key-file",
                                 "key_file": "~/.config/keepass/work.keyx"})
        self.assertEqual(store.backend_options()["key_file"],
                         NEUTRAL_HOME + "/.config/keepass/work.keyx")

    def test_a_keepass_store_without_a_key_file_does_not_invent_one(self):
        store = self.one(backend="keepass", addresses=["work"],
                         location={"path": "/srv/secrets/work.kdbx"})
        self.assertNotIn("key_file", store.backend_options())

    def test_a_vault_store_contributes_nothing_here_by_design(self):
        # The resolver reads `subscription` and `vault_url` off `location`
        # itself, so this returning empty is the split working rather than the
        # declaration being ignored. The case is here so that a later change
        # which moves them has to move this line too.
        store = self.one(backend="azure-keyvault", addresses=["bks-prod"],
                         location={"vault_url": "https://example-vault.vault.azure.net/",
                                   "subscription": "example-subscription"})
        self.assertEqual(store.backend_options(), {})
        self.assertEqual(store.location["subscription"], "example-subscription")


class ADeclaredPathIsExpandedWithoutInventingAValue(StoreCase):
    """`~` and `${VAR}` are what people write, and one of them can be unset.

    An unset variable that expanded to nothing would turn
    `${WORK_SECRETS}/work.kdbx` into `/work.kdbx`, which is a path at the root
    of the disk and a "database not found" that names a file nobody ever
    declared.
    """

    def test_a_tilde_becomes_the_home_directory(self):
        self.neutral_home()
        self.assertEqual(stores.expand("~/.config/keepass/work.keyx"),
                         NEUTRAL_HOME + "/.config/keepass/work.keyx")

    def test_a_variable_that_is_set_becomes_its_value(self):
        self.neutral_home(WORK_SECRETS="/srv/shared")
        self.assertEqual(stores.expand("${WORK_SECRETS}/work.kdbx"),
                         "/srv/shared/work.kdbx")

    def test_a_variable_nobody_set_is_left_exactly_as_it_was_written(self):
        environment = {key: value for key, value in os.environ.items()
                       if key != "SECRETS_TEST_UNSET"}
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual(stores.expand("${SECRETS_TEST_UNSET}/work.kdbx"),
                             "${SECRETS_TEST_UNSET}/work.kdbx")

    def test_a_plain_path_comes_back_unchanged(self):
        self.assertEqual(stores.expand("/srv/secrets/work.kdbx"),
                         "/srv/secrets/work.kdbx")

    def test_the_expansion_happens_when_the_backend_asks_and_not_at_load(self):
        # The declaration keeps what a person wrote, so a report can print the
        # line as it stands in the file.
        self.neutral_home(WORK_SECRETS="/srv/shared")
        store = self.one(backend="keepass", addresses=["work"],
                         location={"path": "${WORK_SECRETS}/work.kdbx"})
        self.assertEqual(store.location["path"], "${WORK_SECRETS}/work.kdbx")
        self.assertEqual(store.backend_options()["databases"]["work"],
                         "/srv/shared/work.kdbx")


# ---------------------------------------------------------------------------
# Checking the declarations
# ---------------------------------------------------------------------------

class CheckDeclarationsNamesWhatAReaderHasToFix(StoreCase):
    """Six ways a declaration is wrong, and the one that is a trap.

    The trap is the loop: a store whose own password lives inside itself cannot
    be opened, and nothing about the file says so. Without this check the
    failure arrives later, as an unlock that asks for a credential which is
    behind the unlock, and the message then names whatever gave way first.
    """

    def problems(self, files):
        return stores.check_declarations(self.load(files))

    def test_a_sound_set_of_declarations_has_nothing_to_report(self):
        # The control. Every case below is a difference from this one.
        self.assertEqual(self.problems(placement_family()), [])

    def test_a_backend_nobody_implements_is_reported(self):
        found = self.problems({"cloud.yaml": declaration(
            name="cloud", backend="cloud-secrets", addresses=["*"])})
        self.assertEqual(len(found), 1, found)
        self.assertIn("unknown backend", found[0])
        self.assertIn("cloud-secrets", found[0])

    def test_a_store_that_answers_no_reference_is_reported(self):
        found = self.problems({"empty.yaml": declaration(name="empty", addresses=[])})
        self.assertEqual(len(found), 1, found)
        self.assertIn("addresses", found[0])

    def test_a_password_reference_that_does_not_parse_is_reported(self):
        found = self.problems({"work-keepass.yaml": declaration(
            name="work-keepass", backend="keepass", addresses=["work"],
            location={"path": "/srv/secrets/work.kdbx"},
            unlock={"method": "password-ref", "password_ref": "the master password"})})
        self.assertEqual(len(found), 1, found)
        self.assertIn("password_ref", found[0])
        self.assertIn("does not parse", found[0])

    def test_a_keepass_store_without_a_database_path_is_reported(self):
        found = self.problems({"work-keepass.yaml": declaration(
            name="work-keepass", backend="keepass", addresses=["work"])})
        self.assertEqual(len(found), 1, found)
        self.assertIn("location.path", found[0])

    def test_a_holds_line_naming_a_kind_that_does_not_exist_is_reported(self):
        found = self.problems({"login-keychain.yaml": declaration(
            name="login-keychain", holds=[{"kind": "ssh-key"}])})
        self.assertEqual(len(found), 1, found)
        self.assertIn("unknown kind", found[0])
        self.assertIn("ssh-key", found[0])

    def test_a_store_whose_own_password_lives_inside_itself_is_reported(self):
        # The loop. `addresses: ["*"]` means the store answers the very
        # reference that is supposed to open it, so opening it requires opening
        # it. The message says that rather than recursing until something else
        # gives way.
        found = self.problems({"login-keychain.yaml": declaration(
            name="login-keychain", backend="keychain", addresses=["*"],
            unlock={"method": "password-ref",
                    "password_ref": "keychain://login-keychain/master"})})
        self.assertEqual(len(found), 1, found)
        self.assertIn("nothing can open it", found[0])

    def test_a_keepass_database_whose_password_is_in_that_database_is_reported(self):
        # The same loop in the shape it actually turns up in: the master
        # password of a database, filed as an entry of that database.
        found = self.problems({"work-keepass.yaml": declaration(
            name="work-keepass", backend="keepass", addresses=["work"],
            location={"path": "/srv/secrets/work.kdbx"},
            unlock={"method": "password-ref",
                    "password_ref": "keepass://work/admin/master/password"})})
        self.assertEqual(len(found), 1, found)
        self.assertIn("nothing can open it", found[0])

    def test_a_password_kept_in_a_different_store_is_not_a_loop(self):
        # The control for the two cases above. This is the arrangement the
        # skill recommends, and a check that flagged it would be switched off.
        found = self.problems({"work-keepass.yaml": declaration(
            name="work-keepass", backend="keepass", addresses=["work"],
            location={"path": "/srv/secrets/work.kdbx"},
            unlock={"method": "password-ref",
                    "password_ref": "keychain://keepass-work/master"})})
        self.assertEqual(found, [])

    def test_every_problem_names_the_file_it_came_from(self):
        found = self.problems({
            "cloud.yaml": declaration(name="cloud", backend="cloud-secrets",
                                      addresses=["*"]),
            "empty.yaml": declaration(name="empty", addresses=[]),
        })
        self.assertEqual(len(found), 2, found)
        for problem in found:
            with self.subTest(problem=problem):
                self.assertTrue(problem.split(":")[0].endswith(".yaml"), problem)

    def test_a_stray_empty_file_is_surfaced_rather_than_loaded_in_silence(self):
        # An empty placeholder file parses into a store that answers nothing.
        # It is reported through its empty address list, which is the line a
        # reader needs in order to delete the file.
        found = self.problems({"placeholder.yaml": "\n"})
        self.assertEqual(len(found), 1, found)
        self.assertIn("placeholder.yaml", found[0])

    def test_a_store_with_a_broken_password_ref_still_reports_its_unknown_kind(self):
        # Two independent faults in one file, and the reader should learn about
        # both in one run. `check_declarations` continues to the next STORE
        # after a reference that does not parse, so the `holds` lines of that
        # store are never read: the second fault appears only after the first
        # one is fixed, which is one edit and one full run too many.
        found = self.problems({"work-keepass.yaml": declaration(
            name="work-keepass", backend="keepass", addresses=["work"],
            location={"path": "/srv/secrets/work.kdbx"},
            unlock={"method": "password-ref", "password_ref": "the master password"},
            holds=[{"kind": "ssh-key"}])})
        self.assertEqual(len(found), 2, found)
        self.assertTrue(any("unknown kind" in problem for problem in found), found)


class ATreeWithNoStoreFamilyIsEmptyRatherThanAFailure(StoreCase):
    """No declarations is a state, not an error.

    Every instance starts there, and `secrets where` has to be able to say
    "copy the template" rather than raise. A loader that raised would make the
    first run of the skill on a fresh clone a traceback.
    """

    def test_a_tree_without_the_family_loads_nothing(self):
        self.assertEqual(stores.load(str(self.tmpdir())), [])

    def test_a_path_that_does_not_exist_at_all_loads_nothing(self):
        self.assertEqual(stores.load(str(self.tmpdir() / "nowhere")), [])

    def test_an_empty_family_folder_loads_nothing(self):
        self.assertEqual(self.load({}), [])

    def test_a_family_holding_only_the_template_and_schema_loads_nothing(self):
        self.assertEqual(self.load({"_template.yaml": declaration(),
                                    "_schema.yaml": "type: object\n"}), [])

    def test_nothing_declared_is_nothing_to_report(self):
        self.assertEqual(stores.check_declarations([]), [])


# ---------------------------------------------------------------------------
# The shipped template
# ---------------------------------------------------------------------------

class TheShippedTemplateIsItselfAValidDeclaration(StoreCase):
    """The one case that reads the real family, and it reads the template.

    A template nobody validates is how a family starts drifting on day one:
    every store in the tree begins as a copy of this file, so a kind it names
    that `KINDS` does not carry becomes a declaration that fails its own check
    the moment somebody fills it in.

    The file is copied under a plain slug before it is loaded, because `load`
    skips `_`-prefixed names by design, which is the very rule the class above
    measures.
    """

    def setUp(self):
        super().setUp()
        repo_root = SKILL_DIR.parent.parent
        self.template = repo_root / stores.FAMILY / "_template.yaml"
        self.assertTrue(self.template.is_file(),
                        f"the shipped template is missing at {self.template}")
        self.store = self.load({
            "login-keychain.yaml": self.template.read_text(encoding="utf-8"),
        })[0]

    def test_the_template_parses_into_a_store(self):
        self.assertIsInstance(self.store, stores.Store)
        self.assertTrue(self.store.name)

    def test_the_backend_it_names_is_one_a_reference_can_address(self):
        self.assertIn(self.store.backend, refs.SCHEME_NAMES)

    def test_it_answers_at_least_one_reference(self):
        self.assertTrue(self.store.addresses)

    def test_it_carries_at_least_one_holds_line(self):
        # `holds` is the half of the model that did not exist before, so a
        # template without it teaches every copy to leave it out.
        self.assertGreaterEqual(len(self.store.placements()), 1)

    def test_every_kind_it_names_is_a_declared_kind(self):
        for placement in self.store.placements():
            with self.subTest(kind=placement.kind):
                self.assertIn(placement.kind, stores.KINDS)

    def test_the_template_passes_the_check_it_ships_with(self):
        self.assertEqual(stores.check_declarations([self.store]), [])

    def test_the_reference_the_template_proposes_parses(self):
        for placement in self.store.placements():
            with self.subTest(kind=placement.kind):
                parsed = refs.parse(placement.reference_shape())
                self.assertEqual(parsed.scheme, self.store.backend)

    def test_the_file_that_was_read_is_the_one_in_the_family(self):
        # Without this the whole class passes against a path that resolved
        # somewhere else and happened to hold a valid declaration.
        self.assertEqual(self.template.parent.name, "secret-stores")
        self.assertIn(stores.FAMILY, self.template.as_posix())
