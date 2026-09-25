"""What a plaintext secret looks like, in one place instead of three.

Before this file the repo carried three pattern sets that had drifted apart:
the table in `rules/promote-safety.md`, `RAW_SECRET_PATTERNS` in
`scripts/overlay.py`, and a third one in an instance-only rule that never
reached CORE at all. Each of them knew something the others did not. The promote
scan had no `AIza` and no `github_pat_`; the overlay scan had no `AIza` and no
`Bearer`; the instance one had both and also IBAN, which does not belong in a
secret scan at all and is the reason the `pii` group below exists separately.

Two things this module is careful about.

**A finding is a location, never a value.** `Finding.excerpt` is capped at eight
characters. A report that quotes the whole match materialises the secret in the
log that was supposed to protect it, and that has happened here: a verify pass
once decoded a base64 credential into the transcript while checking whether the
credential was really there.

**PII is not a credential.** An IBAN is on every invoice, a tax id identifies a
person and unlocks nothing. Both are worth REPORTING where they lie in a repo
that ships, and neither may be proposed for a vault: locking them away makes
them useless for their own purpose and buys no security. So they carry
`kind: pii`, and `audit` never suggests a store for them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: What a line says to be exempt. Spelled the way `detect-secrets` spells it, so
#: one convention covers both tools. A synthetic fixture carries it; a real
#: secret never does, which is the whole contract.
PRAGMA = "pragma: allowlist secret"


@dataclass(frozen=True)
class Pattern:
    """One thing worth finding, and what a reader should do about it."""

    name: str
    #: The literal that makes this pattern recognisable in the other copies of
    #: the list. `scripts/check-secret-patterns.py` greps for it, so the three
    #: places can be compared without comparing regular expressions.
    marker: str
    regex: re.Pattern
    #: credential: rotate it. pii: it is not a secret, move nothing.
    kind: str
    #: The kind of secret store this belongs in, for `audit --suggest`.
    suggests: str = ""
    note: str = ""
    #: A second question asked about the match, for the patterns whose SHAPE is
    #: not evidence on its own. Without it, `token = request.headers[...]` reads
    #: exactly like `token = "wJalrXUtnFEMI"`: measured over this repo, the
    #: assignment pattern alone produced 106 findings and 5 of them were real.
    confirm: object = None
    #: Other spellings that count as carrying this pattern. `gh[pousr]_` in a
    #: regex IS `ghp_` plus its siblings, and a comparison that demanded the
    #: literal would report a gap where there is none.
    aliases: tuple = ()
    #: Which other copies of this list have to carry the pattern too.
    #: `scripts/check-secret-patterns.py` holds them to it. Not every pattern
    #: belongs everywhere: the overlay scan deliberately runs no key-and-value
    #: heuristic over CODE, because there it is wrong more often than right, and
    #: personal data is not what a promote scan is for.
    copies: tuple = ("overlay", "promote")


CREDENTIALS: tuple = (
    Pattern("private-key", "BEGIN", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            "credential", "service-runtime",
            "a private key in a tracked file is disclosed the moment the repo is cloned"),
    Pattern("ssh-public-with-key", "ssh-rsa", re.compile(r"\bssh-(?:rsa|ed25519) AAAA[0-9A-Za-z+/]{20,}"),
            "credential", "personal-token",
            "a public key is not secret; it is here because it usually travels with the private one",
            aliases=("ssh-(rsa|ed25519)",), copies=("promote",)),
    Pattern("aws-access-key", "AKIA", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "credential", "org-credential"),
    Pattern("aws-temp-key", "ASIA", re.compile(r"\bASIA[0-9A-Z]{16}\b"),
            "credential", "org-credential"),
    Pattern("github-token", "ghp_", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
            "credential", "personal-token", aliases=("gh[pousr]_",)),
    Pattern("github-fine-grained", "github_pat_", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
            "credential", "personal-token",
            "the newer format, which the promote scan did not know"),
    Pattern("slack-token", "xox", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
            "credential", "org-credential", aliases=("xox[bp]-", "xox[baprs]-")),
    Pattern("openai-style-key", "sk-", re.compile(r"\bsk-[-A-Za-z0-9_]{20,}\b"),
            "credential", "personal-token",
            "a real key is random and carries digits; a hyphenated id such as "
            "`sk-task-close-postmortem` has none, and measured on 2026-09-25 those "
            "ids were every hit in one instance's config",
            confirm=lambda match: any(ch.isdigit() for ch in match.group(0)[3:])),
    Pattern("google-api-key", "AIza", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
            "credential", "org-credential",
            "known to the instance rule and to neither of the two CORE scans"),
    Pattern("jwt", "eyJ",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            "credential", "service-runtime"),
    Pattern("azure-account-key", "AccountKey=", re.compile(r"AccountKey=[A-Za-z0-9+/]{20,}={0,2}"),
            "credential", "org-credential"),
    Pattern("bearer-token", "Bearer ", re.compile(r"\bBearer [-A-Za-z0-9._~+/=]{20,}"),
            "credential", "service-runtime",
            "known to the promote scan and not to the overlay one"),
    Pattern("password-assignment", "password",
            re.compile(r"(?i)\b(?:password|passwort|kennwort|api[_-]?key|client[_-]?secret|token)"
                       r"\s*[:=]\s*[\"']?(?P<value>[^\s\"',;]{8,})"),
            "credential", "",
            "the shape a person writes by hand, which no prefix pattern catches",
            confirm=lambda match: looks_opaque(match.groupdict().get("value", "")),
            copies=()),
)

PII: tuple = (
    Pattern("iban", "IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}\b"),
            "pii", "",
            "an IBAN is on every invoice the user writes. Report it, never move it",
            copies=()),
    Pattern("german-tax-id", "Steuer", re.compile(r"(?i)\bsteuer(?:-|\s)?(?:id|identifikationsnummer)\b\D{0,10}\d{11}\b"),
            "pii", "",
            "identifying, and it unlocks nothing",
            copies=()),
)

ALL: tuple = CREDENTIALS + PII

BY_NAME = {pattern.name: pattern for pattern in ALL}

#: The markers, for the parity check that holds the other copies to this list.
MARKERS = tuple(pattern.marker for pattern in ALL)


#: Words that appear where a value would and are not one. A scanner that
#: reports these teaches its reader to skim the report, which is how a real hit
#: gets skimmed too.
PLACEHOLDER_WORDS = (
    "example", "redacted", "placeholder", "changeme", "change-me", "dummy",
    "fake", "synthetic", "fixture", "your-", "none", "null", "true", "false",
    "xxxx", "secret-goes-here", "test-value", "sample",
)


def looks_opaque(value: str) -> bool:
    """Whether a value ASSIGNED to a secret-shaped name is itself secret-shaped.

    The name says what the variable is for; only the value says whether this
    line carries one. Three things disqualify it: it is code rather than a
    literal, it is a word a person wrote as a stand-in, or it is too short and
    too uniform to be a credential.
    """
    value = value.strip().strip("\"'")
    if len(value) < 12:
        return False
    if any(ch in value for ch in "()$<>{}%,; \\"):
        return False            # a call, an interpolation, a template
    lowered = value.lower()
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return False
    if "." in value and not any(ch.isdigit() for ch in value):
        return False            # `request.headers`, `self.token`, a dotted path
    classes = sum((any(ch.islower() for ch in value),
                   any(ch.isupper() for ch in value),
                   any(ch.isdigit() for ch in value)))
    return classes >= 2


def excerpt(match_text: str, width: int = 8) -> str:
    """At most eight characters of what was found.

    Enough to recognise the hit in a file, not enough to use. The rule is older
    than this module: a report that quotes the whole match writes the secret
    into the log that exists to protect it.
    """
    if len(match_text) <= width:
        return match_text
    return match_text[:width] + "…"


def exempt(line: str) -> bool:
    """True when the line declares itself a deliberate fixture."""
    return PRAGMA in line


def scan_line(line: str, *, include_pii: bool = True) -> list:
    """Every pattern that fires on one line, as `(Pattern, excerpt)`.

    The line is taken RAW, before any comment is stripped. The one live
    credential that reached a tracked file in this repo sat in a comment, put
    there by the very commit that added the detector for it.
    """
    if exempt(line):
        return []
    found = []
    for pattern in ALL:
        if pattern.kind == "pii" and not include_pii:
            continue
        match = pattern.regex.search(line)
        if match and (pattern.confirm is None or pattern.confirm(match)):
            found.append((pattern, excerpt(match.group(0))))
    return found
