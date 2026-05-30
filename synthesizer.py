"""
Policy Synthesis — extract enforceable obligations and map to policy candidates.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

import anthropic

SONNET_MODEL = "claude-sonnet-4-6"
LLM_PROMPT_TEXT_MARKER = "Text:\n\n{text}"

CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
ACTIONS = frozenset({"block", "redact", "warn", "escalate"})
METHODS = frozenset({"regex", "llm", "ensemble"})
SCOPES = frozenset({"input", "output", "both"})
SEVERITY_BY_ACTION: dict[str, str] = {
    "block": "critical",
    "escalate": "critical",
    "redact": "high",
    "warn": "medium",
}


@dataclass
class CandidateRule:
    obligation_text: str
    suggested_id: str
    suggested_name: str
    suggested_description: str
    detection_method: str
    suggested_threshold_input: float | None
    suggested_threshold_output: float | None
    suggested_action: str
    suggested_scope: str
    suggested_llm_prompt: str
    suggested_patterns: list[str] = field(default_factory=list)
    confidence: str = "medium"
    assumptions: list[str] = field(default_factory=list)
    alternative_interpretations: list[str] = field(default_factory=list)
    similar_existing_policy: str | None = None
    merge_candidate: bool = False
    merge_with_suggestion: str | None = None
    source_labels: list[str] = field(default_factory=list)
    candidate_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_llm_json(text: str) -> Any:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return json.loads(cleaned)


def _slugify_id(raw: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return slug[:64] or "synthesized-rule"


def unique_policy_id(base_id: str, existing_ids: set[str]) -> str:
    candidate = _slugify_id(base_id)
    if candidate not in existing_ids:
        return candidate
    for index in range(2, 100):
        proposed = f"{candidate}-{index}"
        if proposed not in existing_ids:
            return proposed
    return f"{candidate}-{len(existing_ids)}"


def _normalize_scope(scope: str) -> list[str]:
    if scope == "both":
        return ["input", "output"]
    if scope in SCOPES:
        return [scope] if scope != "both" else ["input", "output"]
    return ["input", "output"]


def _wrap_llm_prompt(prompt: str) -> str:
    text = prompt.strip()
    if not text:
        return ""
    if "{text}" in text or LLM_PROMPT_TEXT_MARKER in text:
        return text
    return f"{text}\n\n{LLM_PROMPT_TEXT_MARKER}"


def _default_thresholds(
    scope: list[str],
    input_t: float | None,
    output_t: float | None,
) -> dict[str, float]:
    thresholds: dict[str, float] = {}
    if "input" in scope:
        thresholds["input"] = input_t if input_t is not None else 0.85
    if "output" in scope:
        thresholds["output"] = output_t if output_t is not None else 0.85
    return thresholds


def candidate_to_policy(
    candidate: CandidateRule,
    *,
    existing_ids: set[str],
    enabled: bool = True,
) -> dict[str, Any]:
    """Convert an approved candidate into a policies.json policy object."""
    policy_id = unique_policy_id(candidate.suggested_id, existing_ids)
    scope = _normalize_scope(candidate.suggested_scope)
    method = candidate.detection_method
    if method not in METHODS:
        method = "llm"
    patterns = list(candidate.suggested_patterns or [])
    if method == "regex" and not patterns:
        method = "llm"
        patterns = []

    action = candidate.suggested_action
    if action not in ACTIONS:
        action = "warn"

    llm_prompt = ""
    if method in ("llm", "ensemble"):
        llm_prompt = _wrap_llm_prompt(candidate.suggested_llm_prompt)

    return {
        "id": policy_id,
        "name": candidate.suggested_name.strip() or policy_id,
        "description": candidate.suggested_description.strip()
        or candidate.obligation_text[:500],
        "enabled": enabled,
        "scope": scope,
        "action": action,
        "severity": SEVERITY_BY_ACTION.get(action, "medium"),
        "thresholds": _default_thresholds(
            scope,
            candidate.suggested_threshold_input,
            candidate.suggested_threshold_output,
        ),
        "detection_method": method,
        "patterns": patterns if method in ("regex", "ensemble") else [],
        "llm_prompt": llm_prompt,
    }


def _build_extraction_prompt(
    document_text: str,
    focus: str,
    existing_policies: list[dict[str, Any]],
) -> str:
    existing_summary = []
    for policy in existing_policies[:30]:
        existing_summary.append(
            f"- {policy.get('id')}: {policy.get('name')} "
            f"(action={policy.get('action')}, method={policy.get('detection_method')})"
        )
    existing_block = "\n".join(existing_summary) if existing_summary else "(none)"

    return f"""You are a compliance engineer extracting enforceable AI governance obligations from regulatory and internal policy text.

Focus for interpretation: {focus.strip() or "general AI governance obligations"}

Existing policies in the platform (avoid duplicate ids; flag similar_existing_policy when overlap):
{existing_block}

Document corpus:
---
{document_text}
---

Extract distinct, enforceable obligations suitable for automated screening (block, redact, warn, or escalate user/model text).

Return ONLY a JSON array. Each element must have:
- obligation_text (string)
- suggested_id (kebab-case, unique among new rules)
- suggested_name (short)
- suggested_description (1-2 sentences)
- detection_method: "regex", "llm", or "ensemble" (prefer llm unless clear regex applies)
- suggested_threshold_input (number 0-1 or null)
- suggested_threshold_output (number 0-1 or null)
- suggested_action: block|redact|warn|escalate
- suggested_scope: input|output|both
- suggested_llm_prompt (instructions for a classifier; will have {{text}} appended for content)
- suggested_patterns (array of regex strings; empty if not regex/ensemble)
- confidence: high|medium|low
- assumptions (array of strings)
- alternative_interpretations (array of strings)
- similar_existing_policy (existing policy id string or null)
- merge_candidate (boolean)
- merge_with_suggestion (string or null: id or short label of related obligation)

Generate separate rules for distinct obligations even if merge_candidate is true.
Limit to at most 12 candidates. Use conservative confidence when text is ambiguous."""


def _parse_candidate(raw: dict[str, Any], index: int) -> CandidateRule | None:
    try:
        obligation = str(raw.get("obligation_text", "")).strip()
        if not obligation:
            return None
        confidence = str(raw.get("confidence", "medium")).lower()
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "medium"
        method = str(raw.get("detection_method", "llm")).lower()
        if method not in METHODS:
            method = "llm"
        action = str(raw.get("suggested_action", "warn")).lower()
        if action not in ACTIONS:
            action = "warn"
        scope = str(raw.get("suggested_scope", "both")).lower()
        if scope not in SCOPES:
            scope = "both"

        def _float_or_none(value: Any) -> float | None:
            if value is None:
                return None
            try:
                return max(0.0, min(1.0, float(value)))
            except (TypeError, ValueError):
                return None

        patterns_raw = raw.get("suggested_patterns") or []
        patterns = [str(p) for p in patterns_raw if str(p).strip()]

        return CandidateRule(
            obligation_text=obligation,
            suggested_id=str(raw.get("suggested_id", f"rule-{index}")),
            suggested_name=str(raw.get("suggested_name", f"Rule {index + 1}")),
            suggested_description=str(raw.get("suggested_description", "")),
            detection_method=method,
            suggested_threshold_input=_float_or_none(raw.get("suggested_threshold_input")),
            suggested_threshold_output=_float_or_none(raw.get("suggested_threshold_output")),
            suggested_action=action,
            suggested_scope=scope,
            suggested_llm_prompt=str(raw.get("suggested_llm_prompt", "")),
            suggested_patterns=patterns,
            confidence=confidence,
            assumptions=[str(a) for a in (raw.get("assumptions") or [])],
            alternative_interpretations=[
                str(a) for a in (raw.get("alternative_interpretations") or [])
            ],
            similar_existing_policy=raw.get("similar_existing_policy") or None,
            merge_candidate=bool(raw.get("merge_candidate")),
            merge_with_suggestion=raw.get("merge_with_suggestion") or None,
            candidate_key=f"candidate-{index}",
        )
    except (TypeError, ValueError):
        return None


async def synthesize_policies_from_document(
    text: str,
    focus: str,
    existing_policies: list[dict[str, Any]],
) -> list[CandidateRule]:
    """
    Use Claude Sonnet to extract obligations and propose candidate enforcement rules.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY is not set.")

    if not text.strip():
        return []

    client = anthropic.AsyncAnthropic(api_key=api_key)
    prompt = _build_extraction_prompt(text, focus, existing_policies)

    response = await client.messages.create(
        model=SONNET_MODEL,
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )

    raw_text = "".join(block.text for block in response.content if block.type == "text")
    parsed = _parse_llm_json(raw_text)
    if not isinstance(parsed, list):
        raise ValueError("Synthesis model did not return a JSON array.")

    candidates: list[CandidateRule] = []
    for index, item in enumerate(parsed):
        if not isinstance(item, dict):
            continue
        candidate = _parse_candidate(item, index)
        if candidate is not None:
            candidate.candidate_key = f"candidate-{index}"
            candidates.append(candidate)
    return candidates


def synthesize_policies_from_document_sync(
    text: str,
    focus: str,
    existing_policies: list[dict[str, Any]],
) -> list[CandidateRule]:
    """Synchronous wrapper for Streamlit."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            synthesize_policies_from_document(text, focus, existing_policies)
        )

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            asyncio.run,
            synthesize_policies_from_document(text, focus, existing_policies),
        )
        return future.result()
