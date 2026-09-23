"""The acceptance criteria of #226, at the level a caller meets them: the CLI.

Every case here corresponds to one line of the issue. The unit tests say the
parts work; these say the promise holds where somebody would rely on it.
"""

import os
from unittest import mock

from tests.support import ACCESS_KEY, MARKER, SECRET_KEY, FakeS3, Guarded, closed_port, mod, sha256

MARKER_TEXT = MARKER.decode().strip()


class ContentNeverReachesTheOutput(Guarded):
    """The resolver returns a path, a stream or a handle. Never the bytes."""

    def test_no_command_prints_the_bytes_it_moves(self):
        root = self.bridge()
        self.declare_local(root, "recordings", self.tmp / "local-store")
        self.local_root(self.tmp / "local-store")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        outputs = []
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            for store in ("recordings", "exports"):
                uri = f"object://{store}/2026-09/a.bin"
                for argv in (("put", uri, "--from", str(source)),
                             ("stat", uri),
                             ("path", uri, "--sha256", sha256(MARKER)),
                             ("fetch", uri, "--to", str(self.tmp / f"out-{store}.bin")),
                             ("stores",)):
                    code, out, err = self.cli(*argv, root=root, credentials=self.credentials())
                    self.assertEqual(code, 0, f"{argv}: {err}")
                    outputs.append((argv, out + err))
        for argv, text in outputs:
            self.assertNotIn(MARKER_TEXT, text, f"{argv[0]} printed the content it moved")
            self.assertNotIn(ACCESS_KEY, text, f"{argv[0]} printed an access key")
            self.assertNotIn(SECRET_KEY, text, f"{argv[0]} printed a secret key")
        self.assertEqual((self.tmp / "out-exports.bin").read_bytes(), MARKER)


class ThreeNamedOutcomes(Guarded):
    """A read that cannot be served names its reason. None of them is empty."""

    def assertOutcome(self, result, code, word):
        got, out, err = result
        self.assertEqual(got, code, err)
        self.assertIn(word, err)
        self.assertEqual(out, "", "a failure must not also print something that reads like an answer")

    def test_a_store_this_instance_does_not_declare(self):
        root = self.bridge()
        self.assertOutcome(self.cli("stat", "object://nosuch/a.bin", root=root), 4, "store-not-declared")

    def test_an_object_that_is_not_there(self):
        root = self.bridge()
        self.local_root(self.tmp / "local-store")
        self.declare_local(root, "recordings", self.tmp / "local-store")
        self.assertOutcome(self.cli("stat", "object://recordings/nothing.bin", root=root), 3, "not-found")

    def test_a_store_that_is_not_reachable_from_here(self):
        root = self.bridge()
        self.declare_local(root, "recordings", self.tmp / "unmounted")
        self.declare_s3(root, "exports", f"http://127.0.0.1:{closed_port()}")
        self.assertOutcome(self.cli("stat", "object://recordings/a.bin", root=root), 69, "not-reachable")
        self.assertOutcome(self.cli("stat", "object://exports/a.bin", root=root,
                                    credentials=self.credentials()), 69, "not-reachable")

    def test_a_malformed_reference_is_a_different_answer(self):
        root = self.bridge()
        self.assertOutcome(self.cli("stat", "s3://bucket/a.bin", root=root), 78, "malformed-reference")


class NoWriteIsQueued(Guarded):
    """A write that cannot land fails. Nothing is spooled, queued or retried."""

    def test_a_failed_put_leaves_nothing_behind(self):
        root = self.bridge()
        self.declare_local(root, "recordings", self.tmp / "unmounted")
        self.declare_s3(root, "exports", f"http://127.0.0.1:{closed_port()}")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        before = self.snapshot(self.tmp)
        for uri in ("object://recordings/a.bin", "object://exports/a.bin"):
            code, out, err = self.cli("put", uri, "--from", str(source), root=root,
                                      credentials=self.credentials())
            self.assertEqual(code, 69, err)
            self.assertIn("not-reachable", err)
        self.assertEqual(self.snapshot(self.tmp), before)


class ACacheHitSaysSo(Guarded):
    def test_path_reports_where_the_bytes_came_from(self):
        root = self.bridge()
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            self.cli("put", "object://exports/a.bin", "--from", str(source), root=root,
                     credentials=self.credentials())
            argv = ("path", "object://exports/a.bin", "--sha256", sha256(MARKER))
            first = self.cli(*argv, root=root, credentials=self.credentials())
            second = self.cli(*argv, root=root, credentials=self.credentials())
        self.assertIn("served from: store", first[2])
        self.assertIn("served from: cache", second[2])

    def test_fetch_reports_where_the_bytes_came_from(self):
        root = self.bridge()
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            self.cli("put", "object://exports/a.bin", "--from", str(source), root=root,
                     credentials=self.credentials())
            argv = ("fetch", "object://exports/a.bin", "--sha256", sha256(MARKER))
            first = self.cli(*argv, "--to", str(self.tmp / "one.bin"), root=root, credentials=self.credentials())
            second = self.cli(*argv, "--to", str(self.tmp / "two.bin"), root=root, credentials=self.credentials())
        self.assertIn("served from: store", first[2])
        self.assertIn("served from: cache", second[2])


class CredentialsAreReferences(Guarded):
    def test_credentials_can_come_from_the_environment(self):
        """What `secrets run --env` hands a child process, the resolver accepts."""
        root = self.bridge()
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            env = {"OBJECT_STORE_EXPORTS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                   "OBJECT_STORE_EXPORTS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
            with mock.patch.dict(os.environ, env):
                code, out, err = self.cli("put", "object://exports/a.bin", "--from", str(source), root=root)
        self.assertEqual(code, 0, err)

    def test_one_stores_keys_in_the_environment_do_not_open_another(self):
        """Review finding: one generic pair of variables went to EVERY S3 store,
        so store B's endpoint received store A's access key and a request
        signed with it, and the refusal read as a policy problem."""
        root = self.bridge()
        self.declare_s3(root, "docs", f"http://127.0.0.1:{closed_port()}")
        env = {"OBJECT_STORE_EXPORTS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
               "OBJECT_STORE_EXPORTS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
               "OBJECT_STORE_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
               "OBJECT_STORE_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
        clean = {k: v for k, v in os.environ.items() if not k.startswith("OBJECT_STORE_")}
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True), \
                mock.patch("objstore.credentials.SECRETS_SKILL", self.tmp / "no-secrets-skill"):
            code, out, err = self.cli("stat", "object://docs/a.bin", root=root)
        self.assertEqual(code, 78, err)
        self.assertIn("credentials-unavailable", err)

    def test_no_way_to_resolve_a_credential_is_named_as_such(self):
        root = self.bridge()
        self.declare_s3(root, "exports", f"http://127.0.0.1:{closed_port()}")
        clean = {k: v for k, v in os.environ.items() if not k.startswith("OBJECT_STORE_")}
        with mock.patch.dict(os.environ, clean, clear=True), \
                mock.patch("objstore.credentials.SECRETS_SKILL", self.tmp / "no-secrets-skill"):
            code, out, err = self.cli("stat", "object://exports/a.bin", root=root)
        self.assertEqual(code, 78, err)
        self.assertIn("credentials-unavailable", err)


class UsageIsNamedAndNeverATraceback(Guarded):
    """Review finding: anything that was not an ObjectStoreError escaped the
    CLI as a traceback with no outcome word, and one of them carried the
    signed Authorization header."""

    def assertUsage(self, result):
        code, out, err = result
        self.assertEqual(code, 64, err)
        self.assertIn("usage", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(out, "")

    def setUp(self):
        super().setUp()
        self.root = self.bridge()
        self.store_dir = self.local_root(self.tmp / "local-store")
        self.declare_local(self.root, "recordings", self.store_dir)
        self.source = self.tmp / "in.bin"
        self.source.write_bytes(MARKER)
        self.cli("put", "object://recordings/a.bin", "--from", str(self.source), root=self.root)

    def test_an_uppercase_hash_is_the_same_hash(self):
        """Get-FileHash and shasum -a 256 on some platforms print upper case."""
        code, out, err = self.cli("path", "object://recordings/a.bin", "--sha256",
                                  sha256(MARKER).upper(), root=self.root)
        self.assertEqual(code, 0, err)

    def test_a_hash_that_is_not_one_is_a_usage_error(self):
        self.assertUsage(self.cli("path", "object://recordings/a.bin", "--sha256", "abc", root=self.root))

    def test_a_missing_source_file_is_a_usage_error(self):
        self.assertUsage(self.cli("put", "object://recordings/b.bin", "--from",
                                  str(self.tmp / "nope.bin"), root=self.root))

    def test_a_target_in_a_missing_directory_is_a_usage_error(self):
        self.assertUsage(self.cli("fetch", "object://recordings/a.bin", "--to",
                                  str(self.tmp / "no" / "such" / "dir" / "a.bin"), root=self.root))

    def test_a_cache_limit_that_is_not_a_number_is_a_usage_error(self):
        with mock.patch.dict(os.environ, {"OBJECT_STORE_CACHE_MAX_BYTES": "two gigabytes"}):
            self.assertUsage(self.cli("stores", root=self.root))


class AMissExplainsItself(Guarded):
    def test_the_declared_reachability_is_named_in_a_miss(self):
        """The schema promised this and nothing read reachable_from."""
        root = self.bridge()
        self.declare(root, "archive", (
            "name: archive\nscope: user\nbackend: local\naddresses: [archive]\n"
            f"location:\n  path: \"{self.tmp / 'unmounted'}\"\n"
            "reachable_from:\n  machines: [nas-box]\n  contexts: [interactive]\n"
            "holds:\n  - class: corpus\nreplicated: false\nrecovery:\n  backed_up: false\n"))
        code, out, err = self.cli("stat", "object://archive/a.bin", root=root)
        self.assertEqual(code, 69, err)
        self.assertIn("nas-box", err)


class InitAndForget(Guarded):
    def test_init_marks_a_declared_local_store(self):
        root = self.bridge()
        (self.tmp / "store").mkdir()
        self.declare_local(root, "recordings", self.tmp / "store")
        code, out, err = self.cli("init", "recordings", root=root)
        self.assertEqual(code, 0, err)
        self.assertTrue((self.tmp / "store" / ".object-store").is_file())

    def test_forget_drops_a_cached_copy(self):
        """An object erased from its store must be erasable from the cache too:
        the cache is content addressed and would otherwise serve it for as long
        as somebody knows its hash."""
        root = self.bridge()
        cache = mod("objstore.cache").Cache(root / ".bridge" / "objects")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        cache.add(source, sha256(MARKER))
        code, out, err = self.cli("forget", "--sha256", sha256(MARKER), root=root)
        self.assertEqual(code, 0, err)
        self.assertIsNone(cache.get(sha256(MARKER)))


class CredentialValuesStayOutOfSight(Guarded):
    def provider(self, access):
        table = {"keychain://test/access": access, "keychain://test/secret": SECRET_KEY}
        return lambda ref: table[ref]

    def test_a_trailing_newline_in_a_stored_key_is_forgiven(self):
        """Stored secrets often end in a newline; that is not a broken key."""
        root = self.bridge()
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            code, out, err = self.cli("put", "object://exports/a.bin", "--from", str(source), root=root,
                                      credentials=self.provider(ACCESS_KEY + "\n"))
        self.assertEqual(code, 0, err)

    def test_a_key_with_a_line_break_inside_is_named_without_being_shown(self):
        root = self.bridge()
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            code, out, err = self.cli("stat", "object://exports/a.bin", root=root,
                                      credentials=self.provider(ACCESS_KEY[:8] + "\n" + ACCESS_KEY[8:]))
        self.assertEqual(code, 78, err)
        self.assertIn("credentials-unavailable", err)
        self.assertNotIn(ACCESS_KEY[:8], out + err)

    def test_an_unexpected_failure_shows_its_type_and_not_its_message(self):
        root = self.bridge()
        leak = "AKIA-SOMETHING-THAT-MUST-NOT-PRINT"
        with mock.patch("objstore.resolver.Resolver.stat", side_effect=KeyError(leak)):
            code, out, err = self.cli("stat", "object://anything/a.bin", root=root)
        self.assertEqual(code, 70, err)
        self.assertIn("unexpected", err)
        self.assertIn("KeyError", err)
        self.assertNotIn(leak, out + err)
        self.assertNotIn("Traceback", err)
