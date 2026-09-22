"""Shared scaffolding for the object-store suite.

Three jobs.

1. NOTHING HERE REACHES A REAL STORE. `Guarded` patches `socket.socket.connect`
   so that only loopback is reachable, and patches `subprocess.Popen` so that no
   program starts at all. The resolver speaks S3 itself and never needs a child
   process; a test that manages to start one, or to open a connection to a real
   endpoint, fails loudly instead of passing on the strength of somebody's live
   bucket. The person running this suite may well have one configured.

2. A FAKE S3 SERVICE on 127.0.0.1, path-style, in memory. It is deliberately
   dumb about everything except the two things a wrong client gets wrong in
   silence: it refuses a request without a SigV4 Authorization header, and it
   refuses a PUT whose x-amz-content-sha256 does not match the body it carries.
   Signature correctness itself is proved elsewhere, against vectors produced by
   an independent signer (tests/test_sigv4.py), because a fake that verified
   signatures with the resolver's own code would only prove the code agrees with
   itself.

3. `mod()` imports engine modules inside the test body, so a missing module
   turns every case that needs it red, one by one, instead of collapsing a file
   into a single collection error. The count of red cases is the evidence that
   the suite examines something.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import importlib
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
SKILL_DIR = TESTS_DIR.parent
if str(SKILL_DIR) not in sys.path:
    sys.path.insert(0, str(SKILL_DIR))

#: Content that must never appear in anything the resolver prints.
MARKER = b"MARKER-7f3c-these-bytes-are-content-and-never-output\n"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
LOOPBACK = ("127.0.0.1", "::1", "localhost")


def mod(name: str):
    return importlib.import_module(name)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex


def _loopback_only(real):
    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in LOOPBACK:
            raise AssertionError(f"the suite tried to reach {address!r}; only loopback is allowed")
        return real(self, address)
    return guarded


def _no_programs(*args, **kwargs):
    raise AssertionError(f"the suite tried to start a program: {args[0] if args else kwargs!r}")


class Guarded(unittest.TestCase):
    """Every case in this suite derives from here."""

    @contextlib.contextmanager
    def refuses(self, cls):
        """Like assertRaises, except that the WRONG exception is a failure.

        assertRaises lets any other exception escape, and unittest scores an
        escaped exception as an ERROR. The mutation battery counts only
        failures, because an error cannot be told apart from a needle that
        simply broke the engine. So a wrong class has to fail, not crash.
        """
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - classifying is the point
            if not isinstance(exc, cls):
                self.fail(f"expected {cls.__name__}, got {type(exc).__name__}: {exc}")
            return
        self.fail(f"expected {cls.__name__}, nothing was raised")

    @contextlib.contextmanager
    def succeeds(self, what: str):
        """The block has to work. An exception is a FAILURE with a sentence, not an error."""
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - the verdict is the point
            self.fail(f"{what} did not work: {type(exc).__name__}: {exc}")

    def setUp(self):
        for target, replacement in (
            ("socket.socket.connect", _loopback_only(_REAL_CONNECT)),
            ("socket.socket.connect_ex", _loopback_only(_REAL_CONNECT_EX)),
            ("subprocess.Popen", _no_programs),
        ):
            patcher = mock.patch(target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.tmp = Path(tempfile.mkdtemp(prefix="objstore-test-"))
        self.addCleanup(_rmtree, self.tmp)

    # -- a Bridge root with declarations ------------------------------------

    def bridge(self) -> Path:
        root = self.tmp / "bridge"
        (root / "infra" / "object-stores").mkdir(parents=True, exist_ok=True)
        return root

    def declare(self, root: Path, name: str, body: str) -> Path:
        path = root / "infra" / "object-stores" / f"{name}.yaml"
        path.write_text(body, encoding="utf-8")
        return path

    def local_root(self, directory: Path) -> Path:
        """A directory that says it is a store, the way `init` leaves one."""
        directory.mkdir(parents=True, exist_ok=True)
        (directory / ".object-store").write_text("object store root\n", encoding="utf-8")
        return directory

    def declare_local(self, root: Path, name: str, directory: Path) -> Path:
        return self.declare(root, name, (
            f"name: {name}\nscope: user\nbackend: local\naddresses: [{name}]\n"
            f"location:\n  path: \"{directory}\"\n"
            "holds:\n  - class: recording\nreplicated: false\nrecovery:\n  backed_up: false\n"
        ))

    def declare_s3(self, root: Path, name: str, endpoint: str, *, bucket: str = "bucket",
                   prefix: str = "") -> Path:
        extra = f"  prefix: \"{prefix}\"\n" if prefix else ""
        return self.declare(root, name, (
            f"name: {name}\nscope: user\nbackend: s3\naddresses: [{name}]\n"
            f"location:\n  endpoint: \"{endpoint}\"\n  bucket: {bucket}\n  region: us-east-1\n{extra}"
            "credentials:\n  access_key_ref: \"keychain://test/access\"\n"
            "  secret_key_ref: \"keychain://test/secret\"\n"
            "holds:\n  - class: export\nreplicated: true\nrecovery:\n  backed_up: true\n"
        ))

    def credentials(self):
        """A provider that answers the two references of `declare_s3`."""
        table = {"keychain://test/access": ACCESS_KEY, "keychain://test/secret": SECRET_KEY}

        def provide(ref: str) -> str:
            return table[ref]
        return provide

    def snapshot(self, root: Path) -> dict:
        """Every file under root with its size, to prove nothing was left behind."""
        found = {}
        if root.exists():
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    found[str(path.relative_to(root))] = path.stat().st_size
                elif path.is_dir():
                    found[str(path.relative_to(root)) + "/"] = 0
        return found

    def cli(self, *argv, root: Path | None = None, credentials=None) -> tuple[int, str, str]:
        """Run the CLI in-process and capture both streams."""
        cli = mod("objstore.cli")
        out, err = io.StringIO(), io.StringIO()
        args = list(argv)
        if root is not None:
            args = ["--root", str(root), *args]
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(args, credentials=credentials)
        return code, out.getvalue(), err.getvalue()


def _rmtree(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def closed_port() -> int:
    """A loopback port nothing listens on, so a connection is refused."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class FakeS3(http.server.ThreadingHTTPServer):
    """Path-style, in memory: /<bucket>/<key>."""

    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.objects: dict[str, tuple[bytes, dict]] = {}
        self.requests: list[tuple[str, str]] = []
        self.deny = False
        #: Send the full Content-Length, write half the body, close.
        self.truncate = False
        #: Answer every request with a 307 to this URL.
        self.redirect_to = ""
        #: Serve this x-amz-meta-sha256 instead of the stored one.
        self.lie_about_hash = ""
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.shutdown()
        self.server_close()


class _Handler(http.server.BaseHTTPRequestHandler):
    server: FakeS3

    def log_message(self, *args):  # silence
        pass

    def _refuse(self, code: int, why: str):
        body = why.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _authorised(self) -> bool:
        self.server.requests.append((self.command, self.path))
        if self.server.redirect_to:
            self.send_response(307)
            self.send_header("Location", self.server.redirect_to + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        if self.server.deny:
            self._refuse(403, "AccessDenied")
            return False
        if not self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 "):
            self._refuse(403, "missing SigV4 authorization")
            return False
        return True

    def do_PUT(self):
        if not self._authorised():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.headers.get("x-amz-content-sha256") != sha256(body):
            self._refuse(400, "XAmzContentSHA256Mismatch")
            return
        meta = {k.lower(): v for k, v in self.headers.items() if k.lower().startswith("x-amz-meta-")}
        self.server.objects[self.path] = (body, meta)
        self.send_response(200)
        self.send_header("ETag", '"' + hashlib.md5(body).hexdigest() + '"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _object(self):
        if not self._authorised():
            return None
        found = self.server.objects.get(self.path)
        if found is None:
            self._refuse(404, "NoSuchKey")
        return found

    def do_HEAD(self):
        found = self._object()
        if found is None:
            return
        body, meta = found
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        for key, value in self._meta(meta).items():
            self.send_header(key, value)
        self.end_headers()

    def _meta(self, meta: dict) -> dict:
        if self.server.lie_about_hash:
            return {**meta, "x-amz-meta-sha256": self.server.lie_about_hash}
        return meta

    def do_GET(self):
        found = self._object()
        if found is None:
            return
        body, meta = found
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        for key, value in self._meta(meta).items():
            self.send_header(key, value)
        self.end_headers()
        if self.server.truncate:
            self.wfile.write(body[: len(body) // 2])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(body)
