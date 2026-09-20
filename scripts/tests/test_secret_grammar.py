"""The grammar parity check, tested against drift it is supposed to catch.

Two layers, and the second is the one that matters. The first walks the real
repo and asserts that every copy of the scheme list agrees today. The second
builds small fake repos where one copy has drifted, in each of the ways the copies
have actually drifted before, and asserts that the check says so and names the
file. A guard that only ever runs against a green tree has never been measured.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "check_secret_grammar", REPO / "scripts" / "check-secret-grammar.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


grammar = _load()


# ---------------------------------------------------------------------------
# the live tree
# ---------------------------------------------------------------------------

def test_the_rule_table_is_where_the_list_comes_from():
    schemes = grammar.schemes_in_rule((REPO / grammar.RULE).read_text(encoding="utf-8"))
    assert {"azure-keyvault", "keychain", "1password", "keepass"} <= schemes
    assert "keeper" not in schemes, "keeper:// was never defined anywhere; it may not appear now"


def test_every_copy_in_this_repo_agrees_with_the_rule():
    measured, problems = grammar.compare(REPO)
    assert problems == [], "\n".join(problems)
    assert len(measured) == len(grammar.SOURCES) + 1


def test_every_mutation_anchor_still_exists_exactly_once():
    # A needle whose anchor has drifted applies to nothing and proves nothing
    # from that day on, silently. This is the cheap check for that.
    for needle in grammar.NEEDLES:
        text = (REPO / needle.path).read_text(encoding="utf-8")
        assert text.count(needle.search) == 1, (
            f"{needle.name}: the anchor {needle.search!r} appears "
            f"{text.count(needle.search)} times in {needle.path}")


# ---------------------------------------------------------------------------
# the extractors, one shape each
# ---------------------------------------------------------------------------

def test_the_rule_extractor_reads_only_the_table():
    text = (
        "Prose mentioning fictional://somewhere must not count.\n"
        "| Azure Key Vault | `azure-keyvault://<vault>/<name>` | a secret |\n"
        "| macOS Keychain | `keychain://<service>` | an item |\n"
    )
    assert grammar.schemes_in_rule(text) == {"azure-keyvault", "keychain"}


def test_the_parser_extractor_reads_specs_and_aliases():
    text = (
        'SCHEMES = (\n    SchemeSpec("keychain", 1, 2, None, None, "service", "x"),\n)\n'
        'ALIASES = {"op": "1password"}\n'
    )
    assert grammar.schemes_in_refs(text) == {"keychain", "op"}


def test_the_tuple_extractor_reads_the_overlay_skip_list():
    text = 'SECRET_URI_PREFIXES = ("keychain://", "keepass://",\n                       "op://")\n'
    assert grammar.schemes_in_tuple(text) == {"keychain", "keepass", "op"}


def test_the_pattern_extractor_reads_an_alternation():
    text = 'ENV_VALUE_PATTERN = re.compile(r"^(keychain|keepass|file)://\\S+$")'
    assert grammar.schemes_in_env_pattern(text) == {"keychain", "keepass", "file"}


def test_the_comment_extractor_reads_a_notes_block():
    text = "# - Never store raw secrets:\n#     keychain://<service>\n#     vault://<mount>/<path>\n"
    assert grammar.schemes_in_comment_block(text) == {"keychain", "vault"}


# ---------------------------------------------------------------------------
# drift, in the shapes it has actually taken
# ---------------------------------------------------------------------------

def _fake_repo(tmp_path: Path, *, rule=("keychain", "keepass"), parser=("keychain", "keepass"),
               overlay=("keychain", "keepass"), engine=("keychain", "keepass"),
               schema=("keychain", "keepass"), notes=("keychain", "keepass")) -> Path:
    def write(relative: str, text: str):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    write(grammar.RULE, "| x | `" + "` | y |\n| x | `".join(f"{s}://<a>/<b>" for s in rule) + "` | y |\n")
    write("skills/secrets/engine/refs.py",
          "SCHEMES = (\n" + "".join(f'    SchemeSpec("{s}", 1, 2, None, None, "s", "x"),\n' for s in parser)
          + ")\nALIASES = {}\n")
    write("scripts/overlay.py",
          "SECRET_URI_PREFIXES = (" + ", ".join(f'"{s}://"' for s in overlay) + ")\n")
    write("skills/workload/engine/model.py",
          'ENV_VALUE_PATTERN = re.compile(r"^(' + "|".join(engine) + ')://\\\\S+$")\n')
    write("workflow/workloads/_schema.yaml",
          "          pattern: '^(" + "|".join(schema) + ")://\\\\S+$'   # a locator, never a value\n")
    write("identity/accounts/_schema.yaml",
          "".join(f"#     {s}://<a>/<b>\n" for s in notes))
    return tmp_path


def test_a_copy_that_lost_a_scheme_is_reported_with_its_file(tmp_path):
    repo = _fake_repo(tmp_path, overlay=("keychain",))
    _, problems = grammar.compare(repo)
    assert any("scripts/overlay.py" in p and "keepass" in p for p in problems), problems
    assert any("scanned as if it were a value" in p for p in problems), problems


def test_a_copy_that_invented_a_scheme_is_reported_as_the_keeper_case(tmp_path):
    repo = _fake_repo(tmp_path, engine=("keychain", "keepass", "keeper"))
    _, problems = grammar.compare(repo)
    assert any("keeper" in p and "keeper://" in p for p in problems), problems


def test_the_two_workload_gates_are_compared_separately(tmp_path):
    # The engine and the schema are one pattern in two files, and they once
    # disagreed: --strict reported clean on a declaration the plain run refused.
    repo = _fake_repo(tmp_path, schema=("keychain",))
    _, problems = grammar.compare(repo)
    assert any("workflow/workloads/_schema.yaml" in p for p in problems), problems
    assert not any("skills/workload/engine/model.py" in p for p in problems), problems


def test_the_advisory_notes_may_lag_but_may_not_invent(tmp_path):
    lagging = _fake_repo(tmp_path / "a", notes=("keychain",))
    _, problems = grammar.compare(lagging)
    assert problems == [], problems

    inventing = _fake_repo(tmp_path / "b", notes=("keychain", "keepass", "keeper"))
    _, problems = grammar.compare(inventing)
    assert any("identity/accounts/_schema.yaml" in p for p in problems), problems


def test_a_missing_rule_table_fails_loudly_rather_than_passing_empty(tmp_path):
    repo = _fake_repo(tmp_path)
    (repo / grammar.RULE).write_text("no table here\n", encoding="utf-8")
    _, problems = grammar.compare(repo)
    assert any("no scheme table found" in p for p in problems), problems


def test_a_missing_copy_is_a_problem_not_a_pass(tmp_path):
    repo = _fake_repo(tmp_path)
    (repo / "scripts" / "overlay.py").unlink()
    _, problems = grammar.compare(repo)
    assert any("scripts/overlay.py" in p and "missing" in p for p in problems), problems


def test_render_names_every_source_and_the_verdict(tmp_path):
    measured, problems = grammar.compare(_fake_repo(tmp_path))
    text = grammar.render(measured, problems)
    for source in grammar.SOURCES:
        assert source.name in text
    assert "every copy carries the list" in text


@pytest.mark.parametrize("argv,expected", [(["--json"], 0), ([], 0)])
def test_the_command_line_reports_green_on_this_repo(argv, expected, capsys):
    assert grammar.main([*argv, "--repo", str(REPO)]) == expected
    assert "keepass" in capsys.readouterr().out
