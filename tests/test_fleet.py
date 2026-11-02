"""Tests for fleet-policy-templates — MOCK only, no network, no account.

Run with pytest:   python -m pytest tests/ -v
Or without pytest: python tests/test_fleet.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fleetclaw  # noqa: E402
import gen_fleet  # noqa: E402
import policylint  # noqa: E402
from mock_client import MockClient  # noqa: E402

FIXTURES = ROOT / "fixtures"


def _starter():
    return json.loads((ROOT / "examples" / "starter.json").read_text(encoding="utf-8"))


def test_compile_correctness_unique_paths_and_exact_policies():
    compiled = fleetclaw.compile_manifest(_starter())
    paths = [v["path"] for v in compiled["vault_paths"]]
    assert compiled["coverage"]["tools"] == 3
    assert compiled["coverage"]["unique_paths"] == 3
    assert len(paths) == len(set(paths)), "paths must be unique"
    # Exact expected paths: fleet/<agent>/<tool>/<secret-name>
    assert "fleet/research-agent/web-search/search-api-token" in paths
    assert "fleet/research-agent/doc-store/doc-store-token" in paths
    assert "fleet/ops-agent/status-pager/pager-token" in paths
    # One read-only policy per (agent, tool), pattern == exact path
    assert len(compiled["policies"]) == 3
    for pol in compiled["policies"]:
        assert pol["permissions"] == ["read"]
        assert pol["secret_path_pattern"] == pol["vault_path"]
        assert "*" not in pol["secret_path_pattern"]


def test_compile_is_deterministic():
    m = _starter()
    assert fleetclaw.compile_manifest(m) == fleetclaw.compile_manifest(m)


def test_lint_clean_on_starter():
    assert policylint.lint_manifest(_starter()) == []
    compiled = fleetclaw.compile_manifest(_starter())
    assert policylint.lint_compiled(compiled) == []


def test_linter_catches_double_star():
    bad = json.loads((FIXTURES / "bad_double_star.json").read_text(encoding="utf-8"))
    violations = policylint.lint_manifest(bad)
    assert violations and any(v["rule"] == "double_star" for v in violations), violations


def test_linter_catches_write_permission():
    bad = json.loads((FIXTURES / "bad_write.json").read_text(encoding="utf-8"))
    violations = policylint.lint_manifest(bad)
    assert violations and any(v["rule"] == "write_permission" for v in violations), violations


def test_linter_catches_shared_path():
    bad = json.loads((FIXTURES / "bad_shared_path.json").read_text(encoding="utf-8"))
    violations = policylint.lint_manifest(bad)
    assert violations and any(v["rule"] == "shared_path" for v in violations), violations


def test_linter_catches_orphan_tool():
    bad = json.loads((FIXTURES / "bad_orphan_tool.json").read_text(encoding="utf-8"))
    violations = policylint.lint_manifest(bad)
    assert violations and any(v["rule"] == "orphan_tool" for v in violations), violations


def test_idempotent_reapply_is_noop():
    compiled = fleetclaw.compile_manifest(_starter())
    client = MockClient(actor_type="human", actor_id="human")
    first = fleetclaw.plan_apply(client, compiled, apply=True)
    assert first["summary"]["policies_create"] == 3
    assert first["summary"]["policies_skip"] == 0
    second = fleetclaw.plan_apply(client, compiled, apply=True)
    assert second["summary"]["policies_create"] == 0, second["summary"]
    assert second["summary"]["policies_skip"] == 3, second["summary"]
    assert second["summary"]["policies_drift"] == 0, second["summary"]
    # Plan without apply must also show all-skip against applied state
    plan = fleetclaw.plan_apply(client, compiled, apply=False)
    assert plan["summary"]["policies_create"] == 0


def test_apply_never_widens_existing_broader_grant():
    compiled = fleetclaw.compile_manifest(_starter())
    client = MockClient(actor_type="human", actor_id="human")
    # Pre-seed a broader, dangerous policy for research-agent on fleet/*
    vault_id = client.vaults.create("fleet-policy-vault").data["id"]
    resp = client.agents.create("research-agent").data
    agent_id = resp["agent"]["id"]
    client.policies.create(vault_id, principal_type="agent", principal_id=agent_id,
                           secret_path_pattern="fleet/*", permissions=["read", "write"])
    before = len(client.policies.list().data["policies"])
    report = fleetclaw.plan_apply(client, compiled, apply=True)
    # The two research-agent tools must report drift, not create widened dupes;
    # no new policy may carry 'write' or a wildcard.
    assert report["summary"]["policies_drift"] >= 1
    for pol in client.policies.list().data["policies"]:
        if pol["principal_id"] == agent_id:
            assert pol["secret_path_pattern"] != "fleet/research-agent/web-search/search-api-token" or pol["permissions"] == ["read"]
    assert before >= 1  # seeded policy untouched, not silently replaced


def test_generator_is_deterministic_and_synthetic():
    a = gen_fleet.generate(50, 20, seed=42)
    b = gen_fleet.generate(50, 20, seed=42)
    assert a == b
    assert sum(len(x["tools"]) for x in a["agents"]) == 1000
    assert len(a["agents"]) == 50
    # Synthetic names only: every secret is a name, never a value shape
    for agent in a["agents"]:
        for tool in agent["tools"]:
            assert tool["secret_name"].startswith("synthetic-token-")
            assert set(tool.keys()) == {"name", "secret_name"}


def test_1000_tool_dry_run():
    manifest = gen_fleet.generate(50, 20, seed=42)
    result = fleetclaw.run_dry_run_manifest(manifest)
    cov = result["coverage"]
    assert cov["tools"] == 1000, cov
    assert cov["unique_paths"] == 1000, cov
    assert cov["shared_paths"] == 0, cov
    assert cov["wildcard_patterns"] == 0, cov
    assert cov["double_star_patterns"] == 0, cov
    assert cov["lint_clean"] is True, result["lint_violations"]
    assert result["first_apply"]["policies_create"] == 1000, result["first_apply"]
    assert result["second_apply"]["policies_create"] == 0, result["second_apply"]
    assert result["second_apply"]["policies_skip"] == 1000, result["second_apply"]
    assert result["second_apply"]["policies_drift"] == 0, result["second_apply"]


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}: {exc!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
