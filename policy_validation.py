"""
Validation for policies.json uploads and saves (demo-safe guardrails).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None  # type: ignore[assignment]

MAX_UPLOAD_BYTES = 1_000_000
MAX_POLICIES = 50
MAX_PATTERN_LENGTH = 500
MAX_LLM_PROMPT_LENGTH = 8_000
REGEX_PROBE_TIMEOUT_SEC = 0.25
REGEX_PROBE_SAMPLE = "x" * 2_000 + " test@example.com 123-45-6789 "

ALLOWED_ACTIONS = frozenset({"block", "redact", "warn", "escalate"})
ALLOWED_DETECTION_METHODS = frozenset({"regex", "llm", "ensemble"})
ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
ALLOWED_SCOPES = frozenset({"input", "output"})

# Heuristic: disallow nested quantifiers that commonly cause catastrophic backtracking.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")

POLICIES_DOCUMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["policies"],
    "additionalProperties": True,
    "properties": {
        "version": {"type": "string"},
        "description": {"type": "string"},
        "policies": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_POLICIES,
            "items": {
                "type": "object",
                "required": [
                    "id",
                    "name",
                    "enabled",
                    "scope",
                    "action",
                    "severity",
                    "detection_method",
                ],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string", "minLength": 1, "maxLength": 64},
                    "name": {"type": "string", "minLength": 1, "maxLength": 128},
                    "description": {"type": "string"},
                    "enabled": {"type": "boolean"},
                    "scope": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "enum": sorted(ALLOWED_SCOPES)},
                    },
                    "action": {"type": "string", "enum": sorted(ALLOWED_ACTIONS)},
                    "severity": {"type": "string", "enum": sorted(ALLOWED_SEVERITIES)},
                    "detection_method": {
                        "type": "string",
                        "enum": sorted(ALLOWED_DETECTION_METHODS),
                    },
                    "thresholds": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                        },
                    },
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string", "maxLength": MAX_PATTERN_LENGTH},
                    },
                    "llm_prompt": {"type": "string", "maxLength": MAX_LLM_PROMPT_LENGTH},
                },
            },
        },
    },
}


def validate_regex_pattern(pattern: str) -> str | None:
    """Return an error message if the regex is invalid or unsafe, else None."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"pattern exceeds max length ({MAX_PATTERN_LENGTH} characters)"
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return "nested quantifiers are not allowed (ReDoS risk)"

    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return f"invalid regex: {exc}"

    def probe() -> None:
        compiled.search(REGEX_PROBE_SAMPLE)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(probe)
        try:
            future.result(timeout=REGEX_PROBE_TIMEOUT_SEC)
        except FuturesTimeoutError:
            return "pattern evaluation timed out (possible ReDoS)"

    return None


def _validate_policy_logic(policy: dict[str, Any], index: int) -> list[str]:
    errors: list[str] = []
    prefix = f"policies[{index}]"
    policy_id = policy.get("id", f"index-{index}")

    method = policy.get("detection_method")
    patterns = policy.get("patterns") or []
    thresholds = policy.get("thresholds") or {}
    scope = policy.get("scope") or []

    if method in ("regex", "ensemble") and not patterns:
        errors.append(f"{prefix} ({policy_id}): regex/ensemble requires non-empty patterns")

    if method in ("llm", "ensemble") and not str(policy.get("llm_prompt", "")).strip():
        errors.append(f"{prefix} ({policy_id}): llm/ensemble requires llm_prompt")

    for scope_key, value in thresholds.items():
        if scope_key not in scope:
            errors.append(
                f"{prefix} ({policy_id}): threshold scope '{scope_key}' "
                f"not listed in policy scope {scope}"
            )
        if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
            errors.append(
                f"{prefix} ({policy_id}): threshold '{scope_key}' must be between 0.0 and 1.0"
            )

    if method in ("llm", "ensemble") and not thresholds:
        errors.append(f"{prefix} ({policy_id}): llm/ensemble requires thresholds for each scope")

    for pattern_index, pattern in enumerate(patterns):
        regex_error = validate_regex_pattern(str(pattern))
        if regex_error:
            errors.append(
                f"{prefix} ({policy_id}) patterns[{pattern_index}]: {regex_error}"
            )

    return errors


def validate_policies_doc(doc: Any) -> list[str]:
    """Return a list of validation errors (empty if valid)."""
    errors: list[str] = []

    if not isinstance(doc, dict):
        return ["document must be a JSON object"]

    if jsonschema is not None:
        validator = jsonschema.Draft7Validator(POLICIES_DOCUMENT_SCHEMA)
        for error in sorted(validator.iter_errors(doc), key=lambda e: e.path):
            path = ".".join(str(p) for p in error.path) or "root"
            errors.append(f"{path}: {error.message}")
    else:  # pragma: no cover
        if "policies" not in doc or not isinstance(doc.get("policies"), list):
            errors.append("missing 'policies' array")
            return errors

    policies = doc.get("policies", [])
    if not isinstance(policies, list):
        return errors

    if len(policies) > MAX_POLICIES:
        errors.append(f"at most {MAX_POLICIES} policies allowed")

    seen_ids: set[str] = set()
    for index, policy in enumerate(policies):
        if not isinstance(policy, dict):
            errors.append(f"policies[{index}]: must be an object")
            continue
        policy_id = policy.get("id")
        if policy_id in seen_ids:
            errors.append(f"duplicate policy id '{policy_id}'")
        elif isinstance(policy_id, str):
            seen_ids.add(policy_id)
        errors.extend(_validate_policy_logic(policy, index))

    return errors


def validate_upload_size(raw_bytes: bytes) -> str | None:
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return f"file exceeds maximum size ({MAX_UPLOAD_BYTES // 1000} KB)"
    return None
