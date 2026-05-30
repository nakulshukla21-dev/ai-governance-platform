"""
Redact sensitive patterns from audit records and exports (demo-safe).
"""

from __future__ import annotations

import copy
import re
from typing import Any

REDACTED_PLACEHOLDER = "[REDACTED]"

# Core PII-style patterns aligned with pii-detection policy.
DEFAULT_REDACTION_PATTERNS: list[str] = [
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
]

_COMPILED_PATTERNS: list[re.Pattern[str]] | None = None


def _compiled_patterns(extra: list[str] | None = None) -> list[re.Pattern[str]]:
    global _COMPILED_PATTERNS
    patterns = list(DEFAULT_REDACTION_PATTERNS)
    if extra:
        patterns.extend(extra)
    if _COMPILED_PATTERNS is None or extra:
        compiled: list[re.Pattern[str]] = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error:
                continue
        if not extra:
            _COMPILED_PATTERNS = compiled
        return compiled
    return _COMPILED_PATTERNS


def redact_text(text: str, extra_patterns: list[str] | None = None) -> str:
    if not text:
        return text
    redacted = text
    for compiled in _compiled_patterns(extra_patterns):
        redacted = compiled.sub(REDACTED_PLACEHOLDER, redacted)
    return redacted


def _redact_scan_results(scan_results: list[Any]) -> list[Any]:
    redacted_list: list[Any] = []
    for result in scan_results:
        if not isinstance(result, dict):
            redacted_list.append(result)
            continue
        item = copy.deepcopy(result)
        detail = item.get("detail")
        if isinstance(detail, dict):
            llm_detail = detail.get("llm")
            if isinstance(llm_detail, dict):
                for span in llm_detail.get("spans") or []:
                    if isinstance(span, dict) and "value_redacted" in span:
                        span["value_redacted"] = REDACTED_PLACEHOLDER
                for entity in llm_detail.get("entities") or []:
                    if isinstance(entity, dict) and "text" in entity:
                        entity["text"] = REDACTED_PLACEHOLDER
        redacted_list.append(item)
    return redacted_list


def redact_interaction_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of an interaction audit entry with text fields redacted."""
    redacted = copy.deepcopy(entry)
    for field in ("original_input", "processed_input", "final_response"):
        value = redacted.get(field)
        if isinstance(value, str):
            redacted[field] = redact_text(value)

    if isinstance(redacted.get("input_scan_results"), list):
        redacted["input_scan_results"] = _redact_scan_results(
            redacted["input_scan_results"]
        )
    if isinstance(redacted.get("output_scan_results"), list):
        redacted["output_scan_results"] = _redact_scan_results(
            redacted["output_scan_results"]
        )

    for action in redacted.get("remediation_actions") or []:
        if isinstance(action, dict):
            if isinstance(action.get("user_explanation"), str):
                action["user_explanation"] = redact_text(action["user_explanation"])
            if isinstance(action.get("reasoning"), str):
                action["reasoning"] = redact_text(action["reasoning"])

    redacted["audit_redacted"] = True
    return redacted
