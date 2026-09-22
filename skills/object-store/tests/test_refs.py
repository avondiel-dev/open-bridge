"""object://<store>/<key>: what parses, and what a reference must never be."""

from tests.support import Guarded, mod


class ParsingAReference(Guarded):
    def test_a_well_formed_reference_names_store_and_key(self):
        ref = mod("objstore.refs").parse("object://recordings/2026-09/session.m4a")
        self.assertEqual((ref.store, ref.key), ("recordings", "2026-09/session.m4a"))
        self.assertEqual(ref.canonical, "object://recordings/2026-09/session.m4a")

    def test_a_backend_uri_is_not_a_reference(self):
        refs, errors = mod("objstore.refs"), mod("objstore.errors")
        for uri in ("s3://bucket/key", "file:///tmp/x", "object:/recordings/x", "recordings/x"):
            with self.subTest(uri=uri), self.refuses(errors.MalformedReference):
                refs.parse(uri)

    def test_a_key_that_climbs_out_is_refused(self):
        refs, errors = mod("objstore.refs"), mod("objstore.errors")
        for uri in ("object://recordings/../secrets.yaml", "object://recordings/a/../../b",
                    "object://recordings/./a"):
            with self.subTest(uri=uri), self.refuses(errors.MalformedReference):
                refs.parse(uri)

    def test_an_absolute_or_empty_key_is_refused(self):
        refs, errors = mod("objstore.refs"), mod("objstore.errors")
        for uri in ("object://recordings//etc/passwd", "object://recordings/", "object://recordings/a//b"):
            with self.subTest(uri=uri), self.refuses(errors.MalformedReference):
                refs.parse(uri)

    def test_a_store_name_follows_the_schema_pattern(self):
        refs, errors = mod("objstore.refs"), mod("objstore.errors")
        with self.refuses(errors.MalformedReference):
            refs.parse("object://Recordings/x")
        with self.refuses(errors.MalformedReference):
            refs.parse("object://9store/x")
