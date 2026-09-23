"""The request signature, measured against an independent signer.

The three expected signatures below were produced by botocore 1.43
(`botocore.auth.S3SigV4Auth`, payload signing enabled) with the AWS example
credentials and a frozen clock, NOT by this skill. The first one is also the
value AWS publishes for its "GET Object" example, so it is confirmed by two
sources. A signer tested against its own output would prove nothing; these
vectors are the only thing in the suite that knows what S3 actually expects.
"""

import datetime

from tests.support import ACCESS_KEY, SECRET_KEY, Guarded, mod, sha256

EMPTY = sha256(b"")


def signature(auth: str) -> str:
    return auth.rsplit("Signature=", 1)[1]


class SignatureMatchesAnIndependentSigner(Guarded):
    def sign(self, method, url, headers, payload_hash, region, when):
        return mod("objstore.sigv4").sign(
            method, url, headers, payload_hash,
            access_key=ACCESS_KEY, secret_key=SECRET_KEY, region=region, when=when)

    def test_the_published_aws_example(self):
        signed = self.sign("GET", "https://examplebucket.s3.amazonaws.com/test.txt",
                           {"Range": "bytes=0-9"}, EMPTY, "us-east-1",
                           datetime.datetime(2013, 5, 24, 0, 0, 0, tzinfo=datetime.timezone.utc))
        self.assertIn("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,", signed["Authorization"])
        self.assertEqual(signature(signed["Authorization"]),
                         "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
        self.assertEqual(signed["x-amz-date"], "20130524T000000Z")

    def test_a_path_style_put_with_metadata_and_a_port(self):
        body_hash = sha256(b"hello")
        signed = self.sign("PUT", "http://127.0.0.1:9000/recordings/2026-09/session%201.m4a",
                           {"x-amz-meta-sha256": body_hash}, body_hash, "eu-central-1",
                           datetime.datetime(2026, 9, 22, 12, 0, 0, tzinfo=datetime.timezone.utc))
        self.assertEqual(signature(signed["Authorization"]),
                         "b8e2ccb5fb1acf8ad909627df9c403dc6fd6489850388e81970f13dc07f2db88")
        self.assertEqual(signed["host"], "127.0.0.1:9000")

    def test_a_key_that_needs_encoding(self):
        signed = self.sign("HEAD", "http://127.0.0.1:9000/recordings/instances/x/a%20b/%C3%BC.m4a",
                           {}, EMPTY, "us-east-1",
                           datetime.datetime(2026, 9, 22, 12, 0, 0, tzinfo=datetime.timezone.utc))
        self.assertEqual(signature(signed["Authorization"]),
                         "59ec486f01e737a40e479b2da65b0318e3f96991844c3a9510cc62405584f36d")
