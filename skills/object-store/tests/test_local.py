"""The local backend: a directory is a store, with a store's discipline."""

import os

from tests.support import MARKER, Guarded, mod, sha256


class LocalStore(Guarded):
    def backend(self, root):
        return mod("objstore.backends.local").LocalBackend(root)

    def test_put_then_stat_reports_size_and_hash(self):
        root = self.local_root(self.tmp / "store")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        backend = self.backend(root)
        backend.put("2026-09/a.m4a", source)
        stat = backend.stat("2026-09/a.m4a")
        self.assertEqual((stat.size, stat.sha256), (len(MARKER), sha256(MARKER)))

    def test_a_missing_object_is_not_found(self):
        root = self.local_root(self.tmp / "store")
        with self.refuses(mod("objstore.errors").NotFound):
            self.backend(root).stat("nothing/here")

    def test_a_put_into_a_missing_root_creates_nothing(self):
        """An unmounted volume looks exactly like a missing directory.

        Creating it would put the bytes on whatever disk holds the mount point,
        report success, and leave the real volume without them.
        """
        root = self.tmp / "Volumes" / "archive"
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with self.refuses(mod("objstore.errors").NotReachable):
            self.backend(root).put("a.m4a", source)
        self.assertFalse(root.exists())
        self.assertFalse((self.tmp / "Volumes").exists())

    def test_a_key_cannot_escape_the_root_through_a_link(self):
        root = self.local_root(self.tmp / "store")
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_bytes(MARKER)
        os.symlink(outside, root / "link")
        with self.refuses(mod("objstore.errors").Refused):
            self.backend(root).stat("link/secret.txt")

    def test_a_put_is_atomic_and_leaves_no_temporary_file(self):
        root = self.local_root(self.tmp / "store")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        self.backend(root).put("a/b.bin", source)
        self.assertEqual(sorted(p.name for p in (root / "a").iterdir()), ["b.bin"])


class WhereALocalStoreMayLive(Guarded):
    """Review findings of #226, each first reproduced here, then fixed."""

    def test_a_relative_or_empty_root_is_refused(self):
        """Path("") and Path("recordings") both resolve against the current
        directory, which is usually the Bridge's own work tree."""
        errors = mod("objstore.errors")
        local = mod("objstore.backends.local")
        for root in ("", "recordings", "./x"):
            with self.subTest(root=root), self.refuses(errors.DeclarationError):
                local.LocalBackend(root).probe()

    def test_an_empty_mount_point_is_not_a_store(self):
        """An unmounted volume on Linux, or a stale /Volumes/x on macOS, leaves
        an empty directory behind. is_dir() says yes; the bytes would land on
        the boot disk."""
        mount_point = self.tmp / "mnt" / "archive"
        mount_point.mkdir(parents=True)
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with self.refuses(mod("objstore.errors").NotReachable):
            mod("objstore.backends.local").LocalBackend(mount_point).put("a.bin", source)
        self.assertEqual(list(mount_point.iterdir()), [])

    def test_init_marks_an_existing_directory_and_creates_nothing_else(self):
        local = mod("objstore.backends.local")
        present = self.tmp / "store"
        present.mkdir()
        local.LocalBackend(present).init()
        self.assertTrue((present / ".object-store").is_file())
        missing = self.tmp / "Volumes" / "archive"
        with self.refuses(mod("objstore.errors").NotReachable):
            local.LocalBackend(missing).init()
        self.assertFalse((self.tmp / "Volumes").exists())
