"""
AI Governance Platform — MCP policy engine server (stdio transport).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import anthropic
from fastmcp import FastMCP

CONFIG_DIR = Path(__file__).resolve().parent / "config"
MODEL_ID = "claude-haiku-4-5-20251001"
BLOCK_ACTION = "block"
MAX_CONCURRENT_LLM_SCANS = 4

mcp = FastMCP(
    "ai-governance-policy-engine",
    instructions=(
        "Policy engine for the AI governance platform. Use get_active_policies and "
        "get_role for configuration, scan_input/scan_output for content screening, "
        "and classify_query for role-based query authorization."
    ),
)

_policies: list[dict[str, Any]] = []
_roles: dict[str, dict[str, Any]] = {}
_policies_by_id: dict[str, dict[str, Any]] = {}
_all_query_types: list[str] = []
_anthropic_client: anthropic.Anthropic | None = None
_async_anthropic_client: anthropic.AsyncAnthropic | None = None


def _load_config() -> None:
    """Read all config files from CONFIG_DIR into process memory."""
    global _policies, _roles, _policies_by_id, _all_query_types

    with open(CONFIG_DIR / "policies.json", encoding="utf-8") as f:
        policies_doc = json.load(f)
    with open(CONFIG_DIR / "roles.json", encoding="utf-8") as f:
        roles_doc = json.load(f)

    _policies = policies_doc.get("policies", [])
    _policies_by_id = {p["id"]: p for p in _policies}
    _roles = {r["id"]: r for r in roles_doc.get("roles", [])}

    query_type_set: set[str] = set()
    for role in _roles.values():
        query_type_set.update(role.get("permitted_query_types", []))
        query_type_set.update(role.get("restricted_query_types", []))
    _all_query_types = sorted(query_type_set)


def _reload_config() -> None:
    """Reload every config file from disk (policies, roles, and future additions)."""
    _load_config()


def _get_client() -> anthropic.Anthropic:
    global _anthropic_client
    if _anthropic_client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
        _anthropic_client = anthropic.Anthropic(api_key=api_key)
    return _anthropic_client


def _get_async_client() -> anthropic.AsyncAnthropic:
    global _async_anthropic_client
    if _async_anthropic_client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
        _async_anthropic_client = anthropic.AsyncAnthropic(api_key=api_key)
    return _async_anthropic_client


def _parse_llm_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return json.loads(cleaned)


def _policy_instructions(llm_prompt: str) -> str:
    """Extract instruction text without inline user content placeholders."""
    marker = "Text:\n\n{text}"
    if marker in llm_prompt:
        return llm_prompt.split(marker, 1)[0].strip()
    marker_alt = "{text}"
    if marker_alt in llm_prompt:
        return llm_prompt.replace(marker_alt, "").strip()
    return llm_prompt.strip()


def _call_haiku(instructions: str, content: str) -> dict[str, Any]:
    client = _get_client()
    response = client.messages.create(
        model=MODEL_ID,
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    "<instructions>\n"
                    f"{instructions}\n"
                    "Respond with a single valid JSON object only. "
                    "Do not include markdown fences or commentary.\n"
                    "</instructions>\n\n"
                    "<content_to_evaluate>\n"
                    f"{content}\n"
                    "</content_to_evaluate>"
                ),
            }
        ],
    )
    raw = ""
    for block in response.content:
        if block.type == "text":
            raw += block.text
    return _parse_llm_json(raw)


async def _call_haiku_async(instructions: str, content: str) -> dict[str, Any]:
    client = _get_async_client()
    response = await client.messages.create(
        model=MODEL_ID,
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    "<instructions>\n"
                    f"{instructions}\n"
                    "Respond with a single valid JSON object only. "
                    "Do not include markdown fences or commentary.\n"
                    "</instructions>\n\n"
                    "<content_to_evaluate>\n"
                    f"{content}\n"
                    "</content_to_evaluate>"
                ),
            }
        ],
    )
    raw = ""
    for block in response.content:
        if block.type == "text":
            raw += block.text
    return _parse_llm_json(raw)


def _run_regex_scan(text: str, patterns: list[str]) -> dict[str, Any]:
    matches: list[str] = []
    for pattern in patterns:
        try:
            if re.search(pattern, text):
                matches.append(pattern)
        except re.error as exc:
            matches.append(f"invalid_pattern:{exc}")
    matched = any(
        m for m in matches if not str(m).startswith("invalid_pattern:")
    )
    return {
        "matched": matched,
        "patterns_matched": matches,
        "confidence": 1.0 if matched else 0.0,
    }


async def _run_llm_scan_async(policy: dict[str, Any], text: str) -> dict[str, Any]:
    instructions = _policy_instructions(policy.get("llm_prompt", ""))
    return await _call_haiku_async(instructions, text)


def _threshold_for_policy(policy: dict[str, Any], scope: str) -> float:
    thresholds = policy.get("thresholds", {})
    value = thresholds.get(scope)
    if value is None:
        legacy = policy.get("threshold")
        if legacy is not None:
            return float(legacy)
        raise KeyError(f"No threshold defined for scope '{scope}' on policy '{policy['id']}'")
    return float(value)


def _llm_violation_confidence(llm_payload: dict[str, Any] | None) -> float:
    if not llm_payload:
        return 0.0
    return float(llm_payload.get("violation_confidence", 0.0))


def _llm_detected(llm_payload: dict[str, Any] | None) -> bool:
    if not llm_payload:
        return False
    return bool(llm_payload.get("detected", False))


def _skip_llm_after_regex_block(
    policy: dict[str, Any], regex_result: dict[str, Any]
) -> bool:
    """Skip Haiku when regex already matched on a block-action policy."""
    return (
        policy.get("action") == BLOCK_ACTION
        and bool(regex_result.get("matched"))
    )


def _is_blocking_result(result: dict[str, Any]) -> bool:
    return bool(result.get("detected")) and result.get("action") == BLOCK_ACTION


def _policy_scan_groups(
    policies: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    block_policies = [p for p in policies if p.get("action") == BLOCK_ACTION]
    other_policies = [p for p in policies if p.get("action") != BLOCK_ACTION]
    return block_policies, other_policies


def _error_result(policy: dict[str, Any], exc: Exception) -> dict[str, Any]:
    return {
        "policy_id": policy["id"],
        "detected": False,
        "confidence": 0.0,
        "action": policy.get("action"),
        "severity": policy.get("severity"),
        "detail": {"error": str(exc)},
    }


async def _evaluate_policy_async(
    policy: dict[str, Any],
    text: str,
    scope: str,
    llm_semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    method = policy.get("detection_method", "llm")
    threshold = _threshold_for_policy(policy, scope)
    detail: dict[str, Any] = {"detection_method": method, "threshold": threshold}
    regex_confidence = 0.0
    violation_confidence = 0.0
    llm_payload: dict[str, Any] | None = None

    if method in ("regex", "ensemble"):
        regex_result = _run_regex_scan(text, policy.get("patterns", []))
        detail["regex"] = regex_result
        regex_confidence = float(regex_result.get("confidence", 0.0))

    run_llm = method in ("llm", "ensemble")
    if run_llm and method == "ensemble" and "regex" in detail:
        run_llm = not _skip_llm_after_regex_block(policy, detail["regex"])

    if run_llm:
        async with llm_semaphore:
            llm_payload = await _run_llm_scan_async(policy, text)
        detail["llm"] = llm_payload
        violation_confidence = _llm_violation_confidence(llm_payload)
    elif method in ("llm", "ensemble"):
        detail["llm_skipped"] = "regex_block_short_circuit"

    if method == "regex":
        confidence = regex_confidence
        detected = confidence >= threshold
    elif method == "llm":
        confidence = violation_confidence
        llm_hit = _llm_detected(llm_payload)
        detected = llm_hit and violation_confidence >= threshold
    else:
        regex_hit = detail.get("regex", {}).get("matched", False)
        llm_hit = _llm_detected(llm_payload)
        confidence = violation_confidence
        detected = regex_hit or (llm_hit and violation_confidence >= threshold)

    return {
        "policy_id": policy["id"],
        "detected": detected,
        "confidence": round(confidence, 4),
        "action": policy.get("action"),
        "severity": policy.get("severity"),
        "detail": detail,
    }


async def _evaluate_policies_parallel(
    policies: list[dict[str, Any]],
    text: str,
    scope: str,
) -> list[dict[str, Any]]:
    if not policies:
        return []

    llm_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LLM_SCANS)

    async def run_one(policy: dict[str, Any]) -> dict[str, Any]:
        try:
            return await _evaluate_policy_async(policy, text, scope, llm_semaphore)
        except Exception as exc:
            return _error_result(policy, exc)

    return list(await asyncio.gather(*(run_one(policy) for policy in policies)))


async def _scan_scope_async(
    text: str,
    policy_ids: list[str],
    scope: str,
) -> list[dict[str, Any]]:
    candidates = [
        p
        for p in _policies
        if p.get("enabled")
        and scope in p.get("scope", [])
        and (not policy_ids or p["id"] in policy_ids)
    ]

    block_policies, other_policies = _policy_scan_groups(candidates)

    block_results = await _evaluate_policies_parallel(block_policies, text, scope)
    if any(_is_blocking_result(result) for result in block_results):
        return block_results

    if not other_policies:
        return block_results

    other_results = await _evaluate_policies_parallel(other_policies, text, scope)
    return block_results + other_results


def _run_async(coro: Any) -> Any:
    """Run async scan logic from sync MCP tool handlers."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        return future.result()


def _scan_scope(
    text: str,
    policy_ids: list[str],
    scope: str,
) -> list[dict[str, Any]]:
    return _run_async(_scan_scope_async(text, policy_ids, scope))


def _classify_query_type(text: str) -> dict[str, Any]:
    instructions = (
        "Classify the user's message into exactly one query_type from the allowed list. "
        "Return JSON with fields: query_type (string), confidence (0.0-1.0), "
        "and rationale (brief string).\n\n"
        f"Allowed query types:\n{json.dumps(_all_query_types)}"
    )
    return _call_haiku(instructions, text)


def _role_access_decision(
    role: dict[str, Any],
    query_type: str,
) -> tuple[bool, str]:
    permitted = role.get("permitted_query_types", [])
    restricted = role.get("restricted_query_types", [])

    if query_type in restricted:
        return False, f"Query type '{query_type}' is restricted for role '{role['id']}'."
    if query_type in permitted:
        return True, f"Query type '{query_type}' is permitted for role '{role['id']}'."
    return (
        False,
        f"Query type '{query_type}' is not in the permitted list for role '{role['id']}'.",
    )


_load_config()


@mcp.tool
def reload_config() -> dict[str, Any]:
    """Reload all configuration from disk without restarting the policy engine."""
    _reload_config()
    return {
        "reloaded": True,
        "policy_count": len(_policies),
        "role_count": len(_roles),
        "config_dir": str(CONFIG_DIR),
    }


@mcp.tool
def get_active_policies() -> list[dict[str, Any]]:
    """Return all enabled policies with their full configuration."""
    _reload_config()
    return [dict(p) for p in _policies if p.get("enabled")]


@mcp.tool
def get_role(role_id: str) -> dict[str, Any]:
    """Return a role definition including permitted and restricted query types."""
    _reload_config()
    role = _roles.get(role_id)
    if role is None:
        return {"error": f"Role '{role_id}' not found", "available_roles": list(_roles.keys())}
    return dict(role)


@mcp.tool
def scan_input(text: str, policy_ids: list[str] | None = None) -> list[dict[str, Any]]:
    """
    Run enabled input-scoped policies against the text.
    Block policies run first in parallel; remaining policies are skipped if input is blocked.
    """
    _reload_config()
    ids = policy_ids or []
    return _scan_scope(text, ids, "input")


@mcp.tool
def scan_output(text: str, policy_ids: list[str] | None = None) -> list[dict[str, Any]]:
    """
    Run enabled output-scoped policies against the text.
    Block policies run first in parallel; scans use parallel Haiku calls with a concurrency cap.
    """
    _reload_config()
    ids = policy_ids or []
    return _scan_scope(text, ids, "output")


@mcp.tool
def classify_query(text: str, role_id: str) -> dict[str, Any]:
    """
    Classify the query type with Claude Haiku and check whether the role may run it.
    """
    _reload_config()
    role = _roles.get(role_id)
    if role is None:
        return {
            "classification": None,
            "permitted": False,
            "reason": f"Role '{role_id}' not found.",
            "available_roles": list(_roles.keys()),
        }

    try:
        llm_result = _classify_query_type(text)
        query_type = str(llm_result.get("query_type", "general"))
        permitted, reason = _role_access_decision(role, query_type)
        return {
            "classification": {
                "query_type": query_type,
                "confidence": llm_result.get("confidence"),
                "rationale": llm_result.get("rationale"),
            },
            "permitted": permitted,
            "reason": reason,
        }
    except Exception as exc:
        return {
            "classification": None,
            "permitted": False,
            "reason": f"Classification failed: {exc}",
        }


if __name__ == "__main__":
    mcp.run(transport="stdio")
