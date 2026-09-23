"""The guard in tests/support.py, measured.

In a green run the guard never fires, so nothing but these two cases (and the
needles that soften it) would notice the day it stopped refusing. It is the
only thing between this suite and a live bucket on the machine running it.
"""

import socket
import subprocess

from tests.support import Guarded


class TheGuardHolds(Guarded):
    def test_a_connection_off_loopback_is_refused(self):
        # An explicit socket, closed afterwards. create_connection() leaks the
        # socket when the guard raises, and the ResourceWarning that follows
        # lands in the middle of this case's verdict line.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.settimeout(1)   # unguarded (a needle), TEST-NET must not hang a CI runner
        with self.refuses(AssertionError):
            sock.connect(("192.0.2.1", 9))

    def test_starting_a_program_is_refused(self):
        with self.refuses(AssertionError):
            subprocess.run(["true"], check=False)
