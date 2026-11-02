#!/usr/bin/env python3
"""fleetclaw.py — fleet-policy-templates CLI.

Compile a JSON manifest (agents -> tools -> secret names, never values)
into least-privilege 1Claw structure:

  * one vault path per tool:  fleet/<agent>/<tool>/<secret-name>
  * one read-only policy per (agent, tool) pair for exactly that path
  * a plan/apply runner: MOCK mode (local in-memory shim, mock_client.py)
    or LIVE mode via the official `oneclaw` SDK when ONECLAW_API_KEY is set.
    Apply is idempotent, reports drift, and never widens a grant.

Manifest format (JSON, stdlib only):

    {
      "fleet": "my-fleet",
      "agents": [
        {"name": "agent-001",
         "tools": [{"name": "github", "secret_name": "github-token"}]}
      ]
    }

Optional per-tool overrides (vault_path, permissions) exist so the
linter has dangerous shapes to catch — the compiler refuses to apply
a manifest that fails lint.

Commands:
    python fleetclaw.py compile --manifest m.json [--out plan.json]
    python fleetclaw.py lint    --manifest m.json
    python fleetclaw.py plan    --manifest m.json [--live]
    python fleetclaw.py apply   --manifest m.json [--live]
    python fleetclaw.py dry-run --manifest m.json   (MOCK plan+apply+coverage)

Run `python fleetclaw.py --help` for full usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import policylint  # noqa: E402


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def compile_manifest(manifest: dict) -> dict:
    """Compile manifest -> {vault_paths, policies, coverage}.

    Pure function, no I/O, no client. Deterministic ordering (sorted by
    agent, then tool) so plans are diff-able.
    """
    fleet = manifest.get("fleet", "fleet")
    vault_paths: list[dict] = []
    policies: list[dict] = []

    agents = sorted(manifest.get("agents", []) or [], key=lambda a: a.get("name", ""))
    for agent in agents:
        agent_name = agent.get("name", "")
        tools = sorted(agent.get("tools", []) or [], key=lambda t: t.get("name", ""))
        for tool in tools:
            tool_name = tool.get("name", "")
            secret_name = tool.get("secret_name", "")
            vault_path = tool.get("vault_path") or f"fleet/{agent_name}/{tool_name}/{secret_name}"
            permissions = list(tool.get("permissions") or ["read"])
            pattern = tool.get("secret_path_pattern") or vault_path
            vault_paths.append({
                "agent": agent_name, "tool": tool_name,
                "secret_name": secret_name, "path": vault_path,
            })
            policies.append({
                "agent": agent_name, "tool": tool_name,
                "principal_type": "agent",
                "secret_path_pattern": pattern,
                "permissions": permissions,
                "vault_path": vault_path,
            })

    paths = [v["path"] for v in vault_paths]
    patterns = [p["secret_path_pattern"] for p in policies]
    coverage = {
        "fleet": fleet,
        "agents": len({v["agent"] for v in vault_paths}) if vault_paths else len(agents),
        "tools": len(vault_paths),
        "unique_paths": len(set(paths)),
        "shared_paths": len(paths) - len(set(paths)),
        "wildcard_patterns": sum(1 for p in patterns if "*" in p),
        "double_star_patterns": sum(1 for p in patterns if "**" in p),
        "policies": len(policies),
        "write_policies": sum(1 for p in policies if any(x != "read" for x in p["permissions"])),
    }
    return {"fleet": fleet, "vault_paths": vault_paths, "policies": policies, "coverage": coverage}


def coverage_report(compiled: dict, lint_violations: list, elapsed_s: float | None = None, mode: str = "MOCK") -> dict:
    cov = dict(compiled["coverage"])
    cov["lint_clean"] = len(lint_violations) == 0
    cov["lint_violations"] = len(lint_violations)
    cov["mode"] = mode
    if elapsed_s is not None:
        cov["elapsed_seconds"] = round(elapsed_s, 3)
    return cov


def format_coverage(cov: dict) -> str:
    return (
        f"Coverage ({cov.get('mode', 'MOCK')}): "
        f"{cov['tools']} tools, {cov['unique_paths']} unique paths, "
        f"{cov['shared_paths']} shared, {cov['wildcard_patterns']} wildcards, "
        f"{cov['double_star_patterns']} double-star, {cov['policies']} policies, "
        f"lint_clean={cov['lint_clean']}"
        + (f", elapsed={cov['elapsed_seconds']}s" if "elapsed_seconds" in cov else "")
    )


# ---------------------------------------------------------------------------
# Client construction: LIVE (real SDK) or MOCK (local shim)
# ---------------------------------------------------------------------------

def build_client(live: bool = False):
    """Return (client, mode_label). LIVE requires ONECLAW_API_KEY + oneclaw SDK."""
    api_key = os.environ.get("ONECLAW_API_KEY", "").strip()
    if live or api_key:
        if not api_key:
            print("LIVE mode requested but ONECLAW_API_KEY is not set.")
            raise SystemExit(2)
        try:
            from oneclaw import create_client
        except ImportError:
            print("LIVE mode requested but `oneclaw` is not installed. Run: pip install oneclaw")
            raise SystemExit(2)
        return create_client(api_key=api_key), "LIVE (real 1Claw API via the official oneclaw SDK)"
    from mock_client import MockClient
    return MockClient(actor_type="human", actor_id="human"), "MOCK (local in-memory shim, no account, no network)"


def _data(resp) -> dict:
    data = getattr(resp, "data", None)
    if isinstance(data, dict):
        return data
    if isinstance(resp, dict):
        return resp
    return {}


# ---------------------------------------------------------------------------
# Plan / Apply
# ---------------------------------------------------------------------------

def plan_apply(client, compiled: dict, vault_name: str = "fleet-policy-vault", apply: bool = False) -> dict:
    """Compare compiled policies against the client's current state.

    Returns a report: {vault, agents: {create, skip}, policies: {create, skip, drift}, ...}
    With apply=False this is a pure plan (no mutations). With apply=True,
    missing vault/agents/policies are created. Existing exact matches are
    skipped (idempotent). An existing policy for the same agent+path with
    broader permissions or a broader pattern is reported as drift and is
    NEVER widened or silently replaced.
    """
    report = {
        "vault": {"name": vault_name, "action": "plan-only"},
        "agents_create": [], "agents_skip": [],
        "policies_create": [], "policies_skip": [], "policies_drift": [],
    }

    # --- vault ---
    existing_vaults = _data(client.vaults.list()).get("vaults", [])
    vault = next((v for v in existing_vaults if v.get("name") == vault_name), None)
    vault_id = vault["id"] if vault else None
    if vault:
        report["vault"] = {"name": vault_name, "id": vault_id, "action": "skip (exists)"}
    elif apply:
        created = _data(client.vaults.create(vault_name, description="fleet-policy-templates vault"))
        vault_id = created["id"]
        report["vault"] = {"name": vault_name, "id": vault_id, "action": "created"}
    else:
        report["vault"] = {"name": vault_name, "id": None, "action": "would-create"}

    # --- agents ---
    existing_agents = _data(client.agents.list()).get("agents", [])
    agent_id_by_name: dict[str, str] = {a["name"]: a["id"] for a in existing_agents}
    wanted_agents = sorted({p["agent"] for p in compiled["policies"]})
    for name in wanted_agents:
        if name in agent_id_by_name:
            report["agents_skip"].append(name)
        elif apply:
            resp = _data(client.agents.create(name, description=f"fleet agent {name}"))
            obj = resp.get("agent") or resp
            agent_id_by_name[name] = obj["id"]
            report["agents_create"].append(name)
        else:
            report["agents_create"].append(name)  # would-create

    # --- policies ---
    existing_policies = _data(client.policies.list()).get("policies", []) if vault_id else []
    # Index existing by (principal_id, pattern)
    def _is_broader(existing_pattern: str, wanted_pattern: str) -> bool:
        return existing_pattern != wanted_pattern and (
            "**" in existing_pattern or existing_pattern.endswith("/*") or "*" in existing_pattern
        )

    for pol in compiled["policies"]:
        agent_name = pol["agent"]
        agent_id = agent_id_by_name.get(agent_name)
        pattern = pol["secret_path_pattern"]
        wanted_perms = sorted(pol["permissions"])
        # Find existing policies for this agent (by id if known, else by any)
        matches = []
        if agent_id:
            matches = [e for e in existing_policies
                       if e.get("principal_id") == agent_id and e.get("vault_id") == vault_id]
        exact = next((e for e in matches
                      if e.get("secret_path_pattern") == pattern and sorted(e.get("permissions", [])) == wanted_perms), None)
        if exact:
            report["policies_skip"].append(pattern)
            continue
        # Drift: same agent has a policy on this path/area with different shape
        drift = next((e for e in matches
                      if e.get("secret_path_pattern") == pattern or _is_broader(e.get("secret_path_pattern", ""), pattern)), None)
        if drift:
            report["policies_drift"].append({
                "agent": agent_name, "wanted_pattern": pattern, "wanted_permissions": wanted_perms,
                "existing_pattern": drift.get("secret_path_pattern"), "existing_permissions": drift.get("permissions"),
                "action": "reported, not widened, not replaced",
            })
            continue
        if apply and vault_id and agent_id:
            client.policies.create(vault_id, principal_type="agent", principal_id=agent_id,
                                   secret_path_pattern=pattern, permissions=list(pol["permissions"]))
            report["policies_create"].append(pattern)
        else:
            report["policies_create"].append(pattern)  # would-create

    report["summary"] = {
        "agents_create": len(report["agents_create"]), "agents_skip": len(report["agents_skip"]),
        "policies_create": len(report["policies_create"]), "policies_skip": len(report["policies_skip"]),
        "policies_drift": len(report["policies_drift"]),
    }
    return report


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry_run_manifest(manifest: dict) -> dict:
    """Full MOCK dry run on an in-memory manifest dict (no file I/O)."""
    return _dry_run_core(manifest)


def run_dry_run(manifest_path: Path) -> dict:
    """Full MOCK dry run: lint -> compile -> apply -> re-apply (idempotency) -> coverage."""
    manifest = load_manifest(manifest_path)
    return _dry_run_core(manifest)


def _dry_run_core(manifest: dict) -> dict:
    start = time.perf_counter()
    violations = policylint.lint_manifest(manifest)
    compiled = compile_manifest(manifest)
    violations += policylint.lint_compiled(compiled)
    client, mode_label = build_client(live=False)
    # Force MOCK even if env has a key, for dry-run determinism
    from mock_client import MockClient
    if not getattr(client, "is_mock", False):
        client = MockClient(actor_type="human", actor_id="human")
        mode_label = "MOCK (local in-memory shim, no account, no network)"
    first = plan_apply(client, compiled, apply=True)
    second = plan_apply(client, compiled, apply=True)
    elapsed = time.perf_counter() - start
    cov = coverage_report(compiled, violations, elapsed_s=elapsed, mode="MOCK")
    return {"mode": mode_label, "coverage": cov, "first_apply": first["summary"],
            "second_apply": second["summary"], "lint_violations": violations, "compiled": compiled}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="fleetclaw", description="fleet-policy-templates: manifest -> least-privilege 1Claw policies")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("compile", "lint", "plan", "apply", "dry-run"):
        p = sub.add_parser(name)
        p.add_argument("--manifest", required=True)
        p.add_argument("--out", default=None)
        p.add_argument("--live", action="store_true", help="use LIVE 1Claw SDK (requires ONECLAW_API_KEY)")
        p.add_argument("--vault-name", default="fleet-policy-vault")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    manifest = load_manifest(manifest_path)

    if args.cmd == "lint":
        violations = policylint.lint_manifest(manifest)
        if violations:
            print(f"LINT FAIL: {len(violations)} violation(s)")
            for v in violations:
                print(f"  [{v['rule']}] {v['detail']}")
            return 1
        print("LINT PASS: clean")
        return 0

    if args.cmd == "compile":
        compiled = compile_manifest(manifest)
        violations = policylint.lint_manifest(manifest) + policylint.lint_compiled(compiled)
        cov = coverage_report(compiled, violations, mode="LIVE" if args.live else "MOCK")
        print(format_coverage(cov))
        if args.out:
            Path(args.out).write_text(json.dumps(compiled, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote compiled plan to {args.out}")
        else:
            print(json.dumps(compiled, indent=2))
        return 1 if violations else 0

    if args.cmd == "dry-run":
        result = run_dry_run(manifest_path)
        print("=" * 68)
        print("FLEET POLICY TEMPLATES — MOCK DRY RUN")
        print(f"Mode: {result['mode']}")
        print("=" * 68)
        print(format_coverage(result["coverage"]))
        print(f"First apply:  {result['first_apply']}")
        print(f"Second apply: {result['second_apply']} (idempotent re-apply must create 0, drift 0)")
        if result["lint_violations"]:
            print(f"LINT: FAIL ({len(result['lint_violations'])} violations)")
            for v in result["lint_violations"]:
                print(f"  [{v['rule']}] {v['detail']}")
        else:
            print("LINT: PASS (clean)")
        if args.out:
            out = {"coverage": result["coverage"], "first_apply": result["first_apply"],
                   "second_apply": result["second_apply"]}
            Path(args.out).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote coverage report to {args.out}")
        ok = (result["coverage"]["lint_clean"] and result["second_apply"]["policies_create"] == 0
              and result["second_apply"]["policies_drift"] == 0)
        print(f"RESULT: {'SUCCESS' if ok else 'CHECK FAILED'}")
        return 0 if ok else 1

    # plan / apply
    violations = policylint.lint_manifest(manifest)
    if violations:
        print(f"Refusing to {'apply' if args.cmd == 'apply' else 'plan'}: manifest fails lint ({len(violations)} violations)")
        for v in violations:
            print(f"  [{v['rule']}] {v['detail']}")
        return 1
    compiled = compile_manifest(manifest)
    start = time.perf_counter()
    client, mode_label = build_client(live=args.live)
    print(f"Mode: {mode_label}")
    do_apply = args.cmd == "apply"
    report = plan_apply(client, compiled, vault_name=args.vault_name, apply=do_apply)
    elapsed = time.perf_counter() - start
    cov = coverage_report(compiled, violations, elapsed_s=elapsed, mode="LIVE" if args.live else "MOCK")
    print(format_coverage(cov))
    print(json.dumps(report["summary"], indent=2))
    if report["policies_drift"]:
        print(f"DRIFT: {len(report['policies_drift'])} polic(ies) drifted — reported, never widened:")
        for d in report["policies_drift"]:
            print(f"  {d}")
    if args.out:
        Path(args.out).write_text(json.dumps({"coverage": cov, "report": report}, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote report to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
