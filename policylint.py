#!/usr/bin/env python3
"""policylint.py — dangerous-shape linter for fleet policy manifests.

Fails on:
  1. ** patterns anywhere (vault_path, secret_path_pattern, policy pattern)
  2. write permissions on secret paths (any permission != "read")
  3. a vault path shared by two different agents
  4. a tool with no owning agent (top-level tools, or agent with no name)

Stdlib only. Usable as a module (lint_manifest, lint_compiled) and as CLI:
    python policylint.py manifest.json
    python policylint.py --compiled plan.json
Exit 0 = clean, 1 = violations found.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _iter_tools(manifest: dict):
    """Yield (agent_name_or_None, tool_dict) for every tool entry."""
    for agent in manifest.get("agents", []) or []:
        agent_name = agent.get("name") if isinstance(agent, dict) else None
        for tool in (agent.get("tools", []) if isinstance(agent, dict) else []) or []:
            yield agent_name, tool
    # Top-level orphan tools (no owning agent)
    for tool in manifest.get("tools", []) or []:
        yield None, tool
    # Explicit unassigned bucket
    for tool in manifest.get("unassigned_tools", []) or []:
        yield None, tool


def lint_manifest(manifest: dict) -> list[dict]:
    """Return list of violations: {rule, detail}. Empty = clean."""
    violations: list[dict] = []

    # Rule 4: orphan tools + agents without names
    for agent in manifest.get("agents", []) or []:
        if not isinstance(agent, dict) or not agent.get("name"):
            violations.append({"rule": "orphan_tool", "detail": f"agent entry without a name owns tools: {agent!r}"})
    for tool in manifest.get("tools", []) or []:
        violations.append({"rule": "orphan_tool", "detail": f"tool {tool.get('name')!r} has no owning agent (top-level tools)"})
    for tool in manifest.get("unassigned_tools", []) or []:
        violations.append({"rule": "orphan_tool", "detail": f"tool {tool.get('name')!r} has no owning agent (unassigned_tools)"})

    # Collect paths per agent for shared-path check
    path_to_agents: dict[str, set] = {}

    for agent_name, tool in _iter_tools(manifest):
        if not isinstance(tool, dict):
            violations.append({"rule": "orphan_tool", "detail": f"malformed tool entry under agent {agent_name!r}: {tool!r}"})
            continue
        tool_name = tool.get("name", "?")
        secret_name = tool.get("secret_name", "")
        # Effective path
        vault_path = tool.get("vault_path") or (
            f"fleet/{agent_name}/{tool_name}/{secret_name}" if agent_name else None
        )
        pattern = tool.get("secret_path_pattern") or tool.get("pattern") or vault_path

        # Rule 1: ** patterns
        for field, val in (("vault_path", vault_path), ("secret_path_pattern", pattern),
                           ("secret_name", secret_name), ("name", tool_name)):
            if val and "**" in str(val):
                violations.append({"rule": "double_star", "detail": f"agent={agent_name} tool={tool_name} field={field} contains '**': {val!r}"})
        # Also check any explicit policies on the tool
        # Rule 2: write permissions
        perms = tool.get("permissions")
        if perms:
            for p in perms:
                if p != "read":
                    violations.append({"rule": "write_permission", "detail": f"agent={agent_name} tool={tool_name} has permission {p!r} on secret path {vault_path!r} (only 'read' allowed)"})
        # Track shared paths (only when we have a concrete path)
        if vault_path and agent_name:
            path_to_agents.setdefault(vault_path, set()).add(agent_name)
        elif vault_path and not agent_name:
            # orphan already recorded; still track
            path_to_agents.setdefault(vault_path, set()).add("<no-agent>")

    # Also scan any top-level explicit policies in the manifest
    for pol in manifest.get("policies", []) or []:
        pat = pol.get("secret_path_pattern", "") or pol.get("pattern", "")
        if "**" in pat:
            violations.append({"rule": "double_star", "detail": f"manifest policy contains '**': {pat!r}"})
        for p in pol.get("permissions", []) or []:
            if p != "read":
                violations.append({"rule": "write_permission", "detail": f"manifest policy for {pat!r} has permission {p!r}"})

    # Rule 3: shared path
    for path, agents in sorted(path_to_agents.items()):
        real_agents = {a for a in agents if a != "<no-agent>"}
        if len(real_agents) > 1:
            violations.append({"rule": "shared_path", "detail": f"path {path!r} shared by agents {sorted(real_agents)}"})

    return violations


def lint_compiled(compiled: dict) -> list[dict]:
    """Lint a compiled plan (output of fleetclaw.compile_manifest)."""
    violations: list[dict] = []
    path_to_agents: dict[str, set] = {}
    for pol in compiled.get("policies", []) or []:
        pat = pol.get("secret_path_pattern", "")
        agent = pol.get("agent", "")
        if "**" in pat:
            violations.append({"rule": "double_star", "detail": f"compiled policy agent={agent} pattern contains '**': {pat!r}"})
        for p in pol.get("permissions", []) or []:
            if p != "read":
                violations.append({"rule": "write_permission", "detail": f"compiled policy agent={agent} pattern={pat!r} has permission {p!r}"})
        if not agent:
            violations.append({"rule": "orphan_tool", "detail": f"compiled policy with no agent: {pol!r}"})
        path_to_agents.setdefault(pat, set()).add(agent)
    for path, agents in sorted(path_to_agents.items()):
        if len(agents) > 1:
            violations.append({"rule": "shared_path", "detail": f"compiled path {path!r} shared by agents {sorted(agents)}"})
    # Also lint vault_paths list directly
    for entry in compiled.get("vault_paths", []) or []:
        if isinstance(entry, dict):
            p = entry.get("path", "")
            if "**" in p:
                violations.append({"rule": "double_star", "detail": f"vault path contains '**': {p!r}"})
    return violations


def lint_file(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # Heuristic: compiled plans have "policies" with "agent" keys and "vault_paths"
    if "vault_paths" in data or ("policies" in data and data.get("policies") and "secret_path_pattern" in data["policies"][0]):
        # Could be either; run both and dedupe by (rule, detail)
        seen = set()
        out = []
        for v in lint_manifest(data) + lint_compiled(data):
            k = (v["rule"], v["detail"])
            if k not in seen:
                seen.add(k)
                out.append(v)
        return out
    return lint_manifest(data)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: policylint.py <manifest.json> [--compiled]")
        return 2
    compiled_flag = "--compiled" in argv
    files = [a for a in argv if not a.startswith("--")]
    failed = False
    for f in files:
        data = json.loads(Path(f).read_text(encoding="utf-8"))
        violations = lint_compiled(data) if compiled_flag else lint_manifest(data)
        if violations:
            failed = True
            print(f"LINT FAIL {f}: {len(violations)} violation(s)")
            for v in violations:
                print(f"  [{v['rule']}] {v['detail']}")
        else:
            print(f"LINT PASS {f}: clean")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
