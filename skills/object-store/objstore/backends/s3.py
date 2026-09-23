"""An S3 compatible service as a store, path-style, standard library only.

Path-style (https://host/bucket/key) because that is what self-hosted services
answer without DNS per bucket, and what AWS itself still accepts.

The distinctions a caller needs, and the status each comes from:

    connection refused, DNS, timeout, 5xx,
    a download cut short                     not-reachable
    404                                      not-found
    403                                      denied: the store is there and said no
    a redirect, any other 4xx                refused

Three rules, each a review finding of #226 that was reproduced before it was fixed:

* REDIRECTS ARE NOT FOLLOWED. urllib follows a 307 and copies every header,
  the signed Authorization included, to whatever host `Location` names. A
  signature is valid for about fifteen minutes; handing one to a third host is
  handing it the object.
* A DOWNLOAD IS CHECKED, not trusted. `read()` returns an empty chunk on an
  early close without raising, so a connection that drops at sixty percent
  looked like the end of the object. The byte count has to match
  Content-Length, and the sha256 has to match `x-amz-meta-sha256` when the
  object carries one. A download that fails either never reaches the caller.
* A REQUEST THAT CANNOT BE BUILT names no header. http.client refuses a header
  value with a newline and puts the value in its message; for the
  Authorization header that is the access key and the signature.

The sha256 travels as `x-amz-meta-sha256`, written by `put`. An object this
resolver did not write has none, and `stat` says `unknown` instead of inventing
one from an ETag, which is not a sha256 and not even an MD5 for a multipart
upload. Uploads are a single PUT, which S3 limits to 5 GiB.

A missing key answers 404 only to a principal allowed to list the bucket. With
a GetObject-only credential, S3 answers 403 for a key that does not exist, and
this resolver then reports `denied`: it cannot tell the two apart and does not
pretend to.
"""

from __future__ import annotations

import hashlib
import os
import socket
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..errors import Denied, NotFound, NotReachable, Refused
from ..sigv4 import EMPTY_PAYLOAD, sign
from .base import CHUNK, Stat, hash_file

META_SHA = "x-amz-meta-sha256"
_NETWORK = (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError, OSError)


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()   # the redirect response itself; left open it surfaces later as a ResourceWarning
        raise Refused(
            f"the store answered {code} and pointed at another address",
            hint="redirects are not followed: the request carries a signature valid for "
                 "minutes, and following would hand it to that other host") from None


_OPENER = urllib.request.build_opener(_RefuseRedirects)


class S3Backend:
    def __init__(self, *, endpoint: str, bucket: str, region: str = "us-east-1", prefix: str = "",
                 access_key: str, secret_key: str, timeout: float = 30):
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.region = region or "us-east-1"
        self.prefix = prefix.strip("/")
        self._access = access_key
        self._secret = secret_key
        self.timeout = timeout

    @property
    def where(self) -> str:
        return f"{self.endpoint}/{self.bucket}"

    def _url(self, key: str) -> str:
        segments = [self.bucket] + (self.prefix.split("/") if self.prefix else []) + key.split("/")
        return self.endpoint + "/" + "/".join(urllib.parse.quote(s, safe="-_.~") for s in segments)

    def _open(self, method: str, key: str, *, payload_sha256: str = EMPTY_PAYLOAD,
              body=None, length: int | None = None, extra: dict | None = None):
        url = self._url(key)
        headers = sign(method, url, extra or {}, payload_sha256, access_key=self._access,
                       secret_key=self._secret, region=self.region)
        if length is not None:
            headers["Content-Length"] = str(length)
        try:
            request = urllib.request.Request(url, data=body, method=method, headers=headers)
            return _OPENER.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404:
                raise NotFound(f"no object {key!r} in {self.where}") from None
            if exc.code == 403:
                raise Denied(f"{self.where} refused access to {key!r} (403)",
                             hint="the credential exists and is not allowed this; with a "
                                  "GetObject-only credential S3 also answers 403 for a key "
                                  "that is not there") from None
            if exc.code >= 500:
                raise NotReachable(f"{self.where} answered {exc.code}") from None
            raise Refused(f"{self.where} answered {exc.code} for {method} {key!r}") from None
        except ValueError:
            # http.client names the offending header VALUE in this message.
            raise Refused("the request could not be built: a credential or header value "
                          "contains a character a request header cannot carry",
                          hint="check the stored credential for a trailing newline or a space") from None
        except _NETWORK as exc:
            reason = getattr(exc, "reason", exc)
            raise NotReachable(f"{self.endpoint} did not answer: {type(reason).__name__}",
                               hint="measured live; a declared reachable_from does not change this") from None

    def stat(self, key: str) -> Stat:
        with self._open("HEAD", key) as response:
            length = response.headers.get("Content-Length")
            return Stat(int(length) if length is not None else None, response.headers.get(META_SHA))

    def fetch(self, key: str, dest) -> Stat:
        dest = Path(dest)
        response = self._open("GET", key)
        expected_size = response.headers.get("Content-Length")
        expected_sha = response.headers.get(META_SHA)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
        try:
            digest, size = hashlib.sha256(), 0
            with response, os.fdopen(fd, "wb") as out:
                try:
                    for chunk in iter(lambda: response.read(CHUNK), b""):
                        digest.update(chunk)
                        size += len(chunk)
                        out.write(chunk)
                except _NETWORK as exc:
                    raise NotReachable(f"{self.where} stopped sending {key!r} after {size} bytes: "
                                       f"{type(exc).__name__}") from None
            if expected_size is not None and size != int(expected_size):
                raise NotReachable(f"{self.where} sent {size} of {expected_size} bytes of {key!r}",
                                   hint="the connection closed early; nothing was kept")
            got = digest.hexdigest()
            if expected_sha and got != expected_sha:
                raise Refused(f"the bytes of {key!r} do not match the sha256 recorded with them",
                              hint=f"recorded {expected_sha[:12]}, received {got[:12]}")
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return Stat(size, got)

    def put(self, key: str, source) -> Stat:
        size, sha = hash_file(source)
        with open(source, "rb") as body:
            with self._open("PUT", key, payload_sha256=sha, body=body, length=size,
                            extra={META_SHA: sha}):
                pass
        return Stat(size, sha)
