"""Declarations: which store answers a reference."""

from tests.support import Guarded, mod


class MatchingAddresses(Guarded):
    def store(self, root, name, addresses):
        quoted = ", ".join(f'"{a}"' for a in addresses)
        self.declare(root, name, f"name: {name}\nscope: user\nbackend: local\naddresses: [{quoted}]\n"
                     f"location:\n  path: /tmp/{name}\nholds:\n  - class: recording\nreplicated: false\n"
                     "recovery:\n  backed_up: false\n")

    def resolve(self, root, uri):
        stores, refs = mod("objstore.stores"), mod("objstore.refs")
        return stores.for_reference(stores.load(root), refs.parse(uri))

    def test_an_exact_address_beats_a_wildcard_whatever_the_file_order(self):
        """Review finding: first match by filename order let `archive.yaml`
        with addresses ["*"] take a reference meant for a named local store,
        and content declared as staying on this machine went to a bucket."""
        root = self.bridge()
        self.store(root, "a-archive", ["*"])
        self.store(root, "z-laptop", ["recordings"])
        self.assertEqual(self.resolve(root, "object://recordings/x").name, "z-laptop")

    def test_a_longer_prefix_beats_a_shorter_one(self):
        root = self.bridge()
        self.store(root, "a-broad", ["rec*"])
        self.store(root, "b-narrow", ["recordings-*"])
        self.assertEqual(self.resolve(root, "object://recordings-2026/x").name, "b-narrow")
        self.assertEqual(self.resolve(root, "object://receipts/x").name, "a-broad")

    def test_two_equal_claims_on_one_store_are_refused(self):
        root = self.bridge()
        self.store(root, "a-one", ["recordings"])
        self.store(root, "b-two", ["recordings"])
        with self.refuses(mod("objstore.errors").DeclarationError):
            self.resolve(root, "object://recordings/x")

    def test_a_star_answers_everything_and_an_exact_name_only_itself(self):
        stores, refs = mod("objstore.stores"), mod("objstore.refs")
        root = self.bridge()
        self.declare_local(root, "docs", self.tmp / "d")
        loaded = stores.load(root)
        self.assertIsNone(stores.for_reference(loaded, refs.parse("object://recordings/x")))
        self.assertEqual(stores.for_reference(loaded, refs.parse("object://docs/x")).name, "docs")

    def test_an_unknown_backend_is_refused_at_load(self):
        stores, errors = mod("objstore.stores"), mod("objstore.errors")
        root = self.bridge()
        self.declare(root, "odd", "name: odd\nscope: user\nbackend: ftp\naddresses: [odd]\n"
                     "holds:\n  - class: export\nreplicated: false\nrecovery:\n  backed_up: false\n")
        with self.refuses(errors.DeclarationError):
            stores.load(root)

    def test_templates_and_underscore_files_are_not_stores(self):
        stores = mod("objstore.stores")
        root = self.bridge()
        (root / "infra" / "object-stores" / "_template.yaml").write_text("name: x\n", encoding="utf-8")
        self.assertEqual(stores.load(root), [])
