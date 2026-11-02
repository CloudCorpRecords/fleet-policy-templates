#!/usr/bin/env python3
"""gen_fleet.py — deterministic seeded generator for fleet manifests.

Emits a synthetic manifest: by default 50 agents x 20 tools = 1,000 tools.
All names are synthetic (agent-001, connector-001, synthetic-token-001, ...).
No real secrets, no real services — secret *names* only, never values.

    python gen_fleet.py [--agents 50] [--tools-per-agent 20] [--seed 42] [--out fleet_1000.json]

Deterministic: same seed + same counts -> byte-identical output (sorted
keys, stable ordering, no timestamps).
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

# Synthetic tool-name stems (invented, not real product names-as-endpoints;
# they read as generic connector types a fleet might have)
STEMS = [
    "connector", "webhook", "sync", "exporter", "importer",
    "notifier", "scheduler", "monitor", "relay", "gateway",
]


def generate(num_agents: int = 50, tools_per_agent: int = 20, seed: int = 42, fleet: str = "synthetic-fleet-1000") -> dict:
    rng = random.Random(seed)
    agents = []
    counter = 0
    for a in range(1, num_agents + 1):
        agent_name = f"agent-{a:03d}"
        tools = []
        for _ in range(tools_per_agent):
            counter += 1
            stem = STEMS[rng.randrange(len(STEMS))]
            tool_name = f"{stem}-{counter:04d}"
            tools.append({"name": tool_name, "secret_name": f"synthetic-token-{counter:04d}"})
        agents.append({"name": agent_name, "tools": tools})
    return {"fleet": fleet, "agents": agents}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="gen_fleet", description="Generate a synthetic fleet manifest (deterministic, seeded)")
    parser.add_argument("--agents", type=int, default=50)
    parser.add_argument("--tools-per-agent", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fleet", default="synthetic-fleet-1000")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    manifest = generate(args.agents, args.tools_per_agent, args.seed, args.fleet)
    total = sum(len(a["tools"]) for a in manifest["agents"])
    text = json.dumps(manifest, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}: {len(manifest['agents'])} agents, {total} tools (seed={args.seed})")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
