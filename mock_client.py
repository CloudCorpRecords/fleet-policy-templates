"""MOCK 1Claw client — local, in-memory, clearly labelled.

Copied approach from ../secretless-agent/mock_client.py (our own code).
Implements the same interface subset of the official `oneclaw` SDK:

    client.vaults.create(name, description=...)   -> .data["id"]
    client.vaults.list() / .get() / .delete()
    client.secrets.set(vault_id, path, value, type=..., metadata=...)
    client.secrets.get(vault_id, path)            -> .data["value"]
    client.secrets.list(vault_id) / .delete(...)
    client.agents.create(name, description=...)   -> .data["agent"], .data["api_key"]
    client.agents.list() / .get()
    client.policies.create(vault_id, principal_type=..., principal_id=...,
                           secret_path_pattern=..., permissions=[...])
    client.policies.list() / .delete(...)

MOCK only: stores nothing to disk, no network, no real 1Claw.
When ONECLAW_API_KEY is set, fleetclaw.py uses the real SDK instead.
"""
from __future__ import annotations

import fnmatch
import secrets as _secrets
import uuid
from dataclasses import dataclass, field


@dataclass
class MockResponse:
    data: dict = field(default_factory=dict)
    error: str | None = None
    meta: dict = field(default_factory=dict)


class MockBackend:
    def __init__(self) -> None:
        self.vaults: dict[str, dict] = {}
        self.secrets: dict[tuple[str, str], dict] = {}
        self.agents: dict[str, dict] = {}
        self.agent_keys: dict[str, str] = {}
        self.policies: list[dict] = []


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class _Vaults:
    def __init__(self, client: "MockClient"):
        self._c = client

    def create(self, name, description: str = "") -> MockResponse:
        self._c._require_human("vaults.create")
        vid = _new_id("vault")
        self._c.backend.vaults[vid] = {"id": vid, "name": name, "description": description}
        return MockResponse(data={"id": vid, "name": name, "description": description})

    def list(self) -> MockResponse:
        return MockResponse(data={"vaults": list(self._c.backend.vaults.values())})

    def get(self, vault_id) -> MockResponse:
        v = self._c.backend.vaults.get(vault_id)
        if v is None:
            return MockResponse(error="vault not found")
        return MockResponse(data=dict(v))

    def delete(self, vault_id) -> MockResponse:
        self._c._require_human("vaults.delete")
        self._c.backend.vaults.pop(vault_id, None)
        return MockResponse(data={"deleted": True})


class _Secrets:
    def __init__(self, client: "MockClient"):
        self._c = client

    def set(self, vault_id, path, value, type: str = "api_key", metadata: dict | None = None) -> MockResponse:
        self._c._require_human("secrets.set")
        if vault_id not in self._c.backend.vaults:
            return MockResponse(error="vault not found")
        rec = self._c.backend.secrets.get((vault_id, path))
        version = 1 if rec is None else rec["version"] + 1
        self._c.backend.secrets[(vault_id, path)] = {
            "path": path, "value": value, "type": type,
            "metadata": metadata or {}, "version": version,
        }
        return MockResponse(data={"path": path, "version": version})

    def get(self, vault_id, path) -> MockResponse:
        self._c._authorize_read(vault_id, path)
        rec = self._c.backend.secrets.get((vault_id, path))
        if rec is None:
            return MockResponse(error="secret not found")
        return MockResponse(data={"path": path, "value": rec["value"], "version": rec["version"]})

    def list(self, vault_id) -> MockResponse:
        items = [
            {"path": r["path"], "type": r["type"], "version": r["version"]}
            for (vid, _), r in self._c.backend.secrets.items() if vid == vault_id
        ]
        return MockResponse(data={"secrets": items})

    def delete(self, vault_id, path) -> MockResponse:
        self._c._require_human("secrets.delete")
        self._c.backend.secrets.pop((vault_id, path), None)
        return MockResponse(data={"deleted": True})


class _Agents:
    def __init__(self, client: "MockClient"):
        self._c = client

    def create(self, name, description: str = "") -> MockResponse:
        self._c._require_human("agents.create")
        aid = _new_id("agent")
        api_key = "ocv_mock_" + _secrets.token_hex(12)
        agent = {"id": aid, "name": name, "description": description}
        self._c.backend.agents[aid] = agent
        self._c.backend.agent_keys[api_key] = aid
        return MockResponse(data={"agent": agent, "api_key": api_key})

    def list(self) -> MockResponse:
        return MockResponse(data={"agents": list(self._c.backend.agents.values())})

    def get(self, agent_id) -> MockResponse:
        a = self._c.backend.agents.get(agent_id)
        if a is None:
            return MockResponse(error="agent not found")
        return MockResponse(data=dict(a))


class _Policies:
    def __init__(self, client: "MockClient"):
        self._c = client

    def create(self, vault_id, principal_type: str, principal_id: str,
               secret_path_pattern: str, permissions: list[str]) -> MockResponse:
        self._c._require_human("policies.create")
        pol = {
            "id": _new_id("policy"), "vault_id": vault_id,
            "principal_type": principal_type, "principal_id": principal_id,
            "secret_path_pattern": secret_path_pattern,
            "permissions": list(permissions),
        }
        self._c.backend.policies.append(pol)
        return MockResponse(data=dict(pol))

    def list(self) -> MockResponse:
        return MockResponse(data={"policies": list(self._c.backend.policies)})

    def delete(self, policy_id) -> MockResponse:
        self._c._require_human("policies.delete")
        self._c.backend.policies = [p for p in self._c.backend.policies if p["id"] != policy_id]
        return MockResponse(data={"deleted": True})


class MockClient:
    is_mock = True

    def __init__(self, backend: MockBackend | None = None, *,
                 actor_type: str = "human", actor_id: str = "human",
                 api_key: str | None = None):
        self.backend = backend or MockBackend()
        if api_key is not None:
            resolved = self.backend.agent_keys.get(api_key)
            if resolved is None:
                raise PermissionError("mock: unknown agent api_key")
            actor_type, actor_id = "agent", resolved
        self.actor_type = actor_type
        self.actor_id = actor_id
        self.resolved_agent_id = actor_id if actor_type == "agent" else None
        self.vaults = _Vaults(self)
        self.secrets = _Secrets(self)
        self.agents = _Agents(self)
        self.policies = _Policies(self)

    def _require_human(self, op: str) -> None:
        if self.actor_type != "human":
            raise PermissionError(f"mock policy: agents may not perform {op} (human-only)")

    def _authorize_read(self, vault_id: str, path: str) -> None:
        if self.actor_type == "human":
            return
        for pol in self.backend.policies:
            if (
                pol["vault_id"] == vault_id
                and pol["principal_type"] == "agent"
                and pol["principal_id"] == self.actor_id
                and "read" in pol["permissions"]
                and fnmatch.fnmatchcase(path, pol["secret_path_pattern"])
            ):
                return
        raise PermissionError(
            f"mock policy: agent {self.actor_id} has no read grant for {path!r} in this vault"
        )
