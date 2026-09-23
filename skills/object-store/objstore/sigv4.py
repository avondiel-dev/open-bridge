"""AWS Signature Version 4 for S3, standard library only.

Written here rather than imported because the skill promises to run on nothing
but the standard library, like the secrets skill, and an S3 client library is
the largest dependency either skill would otherwise carry. What keeps this
honest is tests/test_sigv4.py: three signatures produced by an independent
signer, one of them the value AWS publishes for its own example. A signer
tested against its own output would only prove it agrees with itself.

S3 differs from the other services in one place that matters: the canonical URI
is the path exactly as sent, already percent-encoded, and is NOT encoded a
second time.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_PAYLOAD = hashlib.sha256(b"").hexdigest()


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def _query(query: str) -> str:
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = sorted((urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~"))
                     for k, v in pairs)
    return "&".join(f"{k}={v}" for k, v in encoded)


def sign(method: str, url: str, headers: dict, payload_sha256: str, *, access_key: str,
         secret_key: str, region: str, when: datetime.datetime | None = None,
         service: str = "s3") -> dict:
    """The headers to send: the given ones plus host, date, payload hash and Authorization."""
    when = when or datetime.datetime.now(datetime.timezone.utc)
    if when.tzinfo is not None:
        when = when.astimezone(datetime.timezone.utc)
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    day = amz_date[:8]

    parts = urllib.parse.urlsplit(url)
    out = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    out["host"] = parts.netloc.lower()
    out["x-amz-date"] = amz_date
    out["x-amz-content-sha256"] = payload_sha256

    signed = sorted(out)
    canonical_headers = "".join(f"{name}:{out[name]}\n" for name in signed)
    signed_headers = ";".join(signed)
    canonical_request = "\n".join([
        method.upper(), parts.path or "/", _query(parts.query),
        canonical_headers, signed_headers, payload_sha256,
    ])

    scope = f"{day}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        ALGORITHM, amz_date, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), day)
    key = _hmac(key, region)
    key = _hmac(key, service)
    key = _hmac(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out["Authorization"] = (f"{ALGORITHM} Credential={access_key}/{scope}, "
                            f"SignedHeaders={signed_headers}, Signature={signature}")
    return out
