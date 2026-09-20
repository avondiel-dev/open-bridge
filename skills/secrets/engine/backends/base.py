"""What every backend has to answer, and what none of them may do.

A backend is a thin translation between one scheme and one tool. It builds argv,
hands the value in over stdin, reads the value out of a stream it captured, and
returns a `Reading`. It does not print, does not log, does not decide policy and
does not cache.

`Context` is the second half of the contract, and it is the half that was
missing everywhere before. "Is this readable" is not a property of the entry; it
is a property of the entry AND the session asking. The same keychain item is
readable from a desktop session and refused over ssh, and a wrapper that could
not tell those apart rotated a secret that was never gone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..errors import BackendUnavailable
from ..refs import Ref
from ..values import Reading, Secret


#: Environment variables every common runner sets.
CI_MARKERS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "TF_BUILD", "JENKINS_URL")


@dataclass(frozen=True)
class Context:
    """Where this process is running, as far as a secret store cares."""

    platform: str          # darwin | linux | windows | other
    interactive: bool      # a terminal is attached
    over_ssh: bool         # the session came in over ssh
    display: bool          # a desktop session is available
    #: A pipeline runner: no person, no desktop, no keychain. Read from the
    #: environment HERE and nowhere else, because a caller that describes a
    #: session explicitly must not be overruled by the environment the tool
    #: happens to run in. It was: on a GitHub runner every synthetic context
    #: answered "ci", and five cases that pin other sessions failed for a
    #: reason that had nothing to do with what they measure.
    ci: bool = False

    @classmethod
    def detect(cls, environ=None, platform_name: str | None = None) -> "Context":
        env = os.environ if environ is None else environ
        import sys

        raw = platform_name or sys.platform
        platform = {"darwin": "darwin", "win32": "windows"}.get(raw, "linux" if raw.startswith("linux") else "other")
        over_ssh = bool(env.get("SSH_CONNECTION") or env.get("SSH_TTY") or env.get("SSH_CLIENT"))
        in_ci = any(env.get(name) for name in CI_MARKERS)
        display = bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")) or platform == "darwin"
        try:
            interactive = os.isatty(0)
        except (OSError, ValueError):  # pragma: no cover - closed stdin in a daemon
            interactive = False
        return cls(platform=platform, interactive=interactive, over_ssh=over_ssh,
                   display=display, ci=in_ci)


class Backend:
    """One scheme, one tool."""

    #: The scheme this backend answers, as spelled in `refs.SCHEMES`.
    scheme = ""
    #: The executable it needs, or None when it needs none.
    binary: str | None = None

    def __init__(self, *, runner=None, context: Context | None = None,
                 assume_available: bool | None = None):
        self.runner = runner
        self.context = context or Context.detect()
        #: Overrides the PATH probe. Without it the probe is the one part of a
        #: backend that ignores the runner seam, so a suite driving everything
        #: through a fake still behaved differently per host: on a machine
        #: without `security` every keychain read raised before it built an
        #: argv, and the argv tier was a macOS tier wearing a disguise.
        self.assume_available = assume_available

    # -- capability ---------------------------------------------------------

    def available(self) -> bool:
        """True when the tool exists here. Says nothing about the entry."""
        if self.assume_available is not None:
            return self.assume_available
        if self.binary is None:
            return True
        from .. import exec as exec_mod

        return exec_mod.which(self.binary) is not None

    def require_available(self, ref: Ref) -> None:
        if not self.available():
            raise BackendUnavailable(
                f"{self.binary} is not installed here",
                ref=ref.canonical,
                hint=self.install_hint(),
            )

    def install_hint(self) -> str:
        return ""

    def readable_here(self, ref: Ref) -> tuple[bool, str]:
        """Whether a read can work in THIS session, and why not when it cannot.

        A backend answers from what it knows about the session, before it runs
        anything. A wrong "yes" is corrected by the read itself; a wrong "no"
        would hide a working path, so the default is yes.
        """
        return True, ""

    # -- the two directions -------------------------------------------------

    def read(self, ref: Ref) -> Reading:
        raise NotImplementedError

    def write(self, ref: Ref, secret: Secret, *, replace: bool = False) -> Reading:
        raise NotImplementedError(
            f"{self.scheme}:// cannot be written by this Bridge yet"
        )

    # -- description --------------------------------------------------------

    def locate(self, ref: Ref) -> str:
        """Where a human would click to find this entry. Never a value."""
        return ref.canonical
