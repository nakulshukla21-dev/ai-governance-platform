"""Tests for server config reload."""

from __future__ import annotations

import json

import server


def test_reload_config_picks_up_policy_change(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(server, "CONFIG_DIR", tmp_path)

    policies_path = tmp_path / "policies.json"
    roles_path = tmp_path / "roles.json"
    policies_path.write_text(
        json.dumps({"policies": [{"id": "p1", "enabled": True}]}),
        encoding="utf-8",
    )
    roles_path.write_text(
        json.dumps({"roles": [{"id": "r1", "permitted_query_types": [], "restricted_query_types": []}]}),
        encoding="utf-8",
    )

    server._reload_config()
    assert len(server._policies) == 1
    assert server._policies[0]["id"] == "p1"
    assert len(server._roles) == 1

    policies_path.write_text(
        json.dumps({"policies": [{"id": "p2", "enabled": False}]}),
        encoding="utf-8",
    )
    server._reload_config()
    assert server._policies[0]["id"] == "p2"

    active = server.get_active_policies()
    assert active == []


def test_reload_config_tool_returns_counts(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(server, "CONFIG_DIR", tmp_path)
    (tmp_path / "policies.json").write_text(json.dumps({"policies": []}), encoding="utf-8")
    (tmp_path / "roles.json").write_text(json.dumps({"roles": []}), encoding="utf-8")

    result = server.reload_config()
    assert result["reloaded"] is True
    assert result["policy_count"] == 0
    assert result["role_count"] == 0
