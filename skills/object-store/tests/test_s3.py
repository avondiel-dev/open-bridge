"""The S3 backend against an in-memory fake on loopback."""

from tests.support import ACCESS_KEY, MARKER, SECRET_KEY, FakeS3, Guarded, closed_port, mod, sha256


class S3Store(Guarded):
    def backend(self, endpoint, prefix=""):
        return mod("objstore.backends.s3").S3Backend(
            endpoint=endpoint, bucket="bucket", region="us-east-1", prefix=prefix,
            access_key=ACCESS_KEY, secret_key=SECRET_KEY, timeout=5)

    def test_put_stat_and_fetch_round_trip(self):
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            backend = self.backend(fake.endpoint, prefix="instances/x")
            backend.put("2026-09/a b.m4a", source)
            stat = backend.stat("2026-09/a b.m4a")
            dest = self.tmp / "out.bin"
            got = backend.fetch("2026-09/a b.m4a", dest)
        self.assertEqual(dest.read_bytes(), MARKER)
        self.assertEqual((stat.size, stat.sha256, got.sha256), (len(MARKER), sha256(MARKER), sha256(MARKER)))
        self.assertIn(("PUT", "/bucket/instances/x/2026-09/a%20b.m4a"), fake.requests)

    def test_the_payload_hash_travels_with_the_request(self):
        """The fake refuses a PUT whose x-amz-content-sha256 is not the body's."""
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER * 3)
        with FakeS3() as fake:
            with self.succeeds("an upload the service checks against its signed payload hash"):
                self.backend(fake.endpoint).put("k", source)
            self.assertEqual(fake.objects["/bucket/k"][0], MARKER * 3)

    def test_a_closed_port_is_not_reachable(self):
        with self.refuses(mod("objstore.errors").NotReachable):
            self.backend(f"http://127.0.0.1:{closed_port()}").stat("k")

    def test_a_404_is_not_found(self):
        with FakeS3() as fake, self.refuses(mod("objstore.errors").NotFound):
            self.backend(fake.endpoint).stat("nothing")

    def test_a_403_is_denied_and_not_missing(self):
        with FakeS3() as fake:
            fake.deny = True
            with self.refuses(mod("objstore.errors").Denied):
                self.backend(fake.endpoint).stat("k")


class WhatTheServiceMustNotGetAwayWith(Guarded):
    """Review findings of #226, each first reproduced here, then fixed."""

    def backend(self, endpoint, access_key=ACCESS_KEY):
        return mod("objstore.backends.s3").S3Backend(
            endpoint=endpoint, bucket="bucket", region="us-east-1", prefix="",
            access_key=access_key, secret_key=SECRET_KEY, timeout=5)

    def stored(self, fake, content=MARKER * 64):
        source = self.tmp / "in.bin"
        source.write_bytes(content)
        with self.succeeds("the upload that sets up this case"):
            self.backend(fake.endpoint).put("k", source)
        return content

    def test_a_download_cut_short_is_not_a_success(self):
        """The connection closes halfway. Before the fix: exit 0, a truncated
        file, and the hash of the truncated bytes printed as if it were the object's."""
        dest = self.tmp / "out.bin"
        with FakeS3() as fake:
            self.stored(fake)
            fake.truncate = True
            with self.refuses(mod("objstore.errors").NotReachable):
                self.backend(fake.endpoint).fetch("k", dest)
        self.assertFalse(dest.exists(), "a partial download must not be left where the caller looks")

    def test_bytes_that_differ_from_the_recorded_hash_are_refused(self):
        dest = self.tmp / "out.bin"
        with FakeS3() as fake:
            self.stored(fake)
            fake.lie_about_hash = "0" * 64
            with self.refuses(mod("objstore.errors").Refused):
                self.backend(fake.endpoint).fetch("k", dest)
        self.assertFalse(dest.exists())

    def test_a_redirect_is_not_followed_and_the_signature_stays_home(self):
        """urlopen follows a 307 and copies the signed headers to the new host."""
        with FakeS3() as elsewhere, FakeS3() as fake:
            fake.redirect_to = elsewhere.endpoint
            with self.refuses(mod("objstore.errors").Refused):
                self.backend(fake.endpoint).stat("k")
            self.assertEqual(elsewhere.requests, [], "the redirect target received a signed request")

    def test_a_credential_a_header_cannot_carry_is_refused_without_showing_it(self):
        """A key with a newline in it: http.client raised a ValueError whose
        message carried the Authorization header, access key and signature included."""
        broken = ACCESS_KEY[:10] + "\n" + ACCESS_KEY[10:]
        with FakeS3() as fake:
            try:
                self.backend(fake.endpoint, access_key=broken).stat("k")
            except mod("objstore.errors").ObjectStoreError as exc:
                text = exc.report()
            except Exception as exc:  # noqa: BLE001
                self.fail(f"escaped as {type(exc).__name__}, which the CLI would print raw")
            else:
                self.fail("a request with a broken credential was sent")
        self.assertNotIn(ACCESS_KEY[:10], text)
        self.assertNotIn("Signature=", text)
