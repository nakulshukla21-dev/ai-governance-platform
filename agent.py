"""
AI Governance Platform — remediation agent.

Connects to the local policy-engine MCP server, enforces policies on input/output,
and produces governed responses via Claude Sonnet.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent

load_dotenv()

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent
SERVER_SCRIPT = ROOT_DIR / "server.py"

SONNET_MODEL = "claude-sonnet-4-6"
HAIKU_MODEL = "claude-haiku-4-5-20251001"
REDACTED_PLACEHOLDER = "[REDACTED]"
NEAR_MISS_MARGIN = 0.10
MCP_INTERACTION_TIMEOUT_SECONDS = 600

BLOCKED_AUTHORIZATION_MESSAGE = (
    "Your request cannot be processed because your role is not authorized "
    "for this type of query."
)
BLOCKED_POLICY_MESSAGE = (
    "Your request cannot be processed because it violates one or more "
    "governance policies."
)
BLOCKED_OUTPUT_MESSAGE = (
    "The assistant response was withheld because it violated one or more "
    "governance policies."
)

GOVERNED_ASSISTANT_SYSTEM_PROMPT = """You are an assistant operating inside a governed financial services platform. All interactions are subject to organizational policies, role-based access controls, and automated compliance screening.

Follow organizational policies strictly. Do not speculate about what might be permitted, what exceptions could apply, or how restrictions could be relaxed.

When you cannot fulfill a request due to policy, authorization, or data-access limits:
- Keep your response concise: one or two sentences only.
- Do not use bullet points or numbered lists, especially lists that suggest ways to work around the restriction.
- Never invite the user to provide additional context, credentials, authorization details, or confirming information in this chat.
- Never suggest that sharing more information in this conversation might unlock restricted functionality or broader access.
- Direct the user to official channels for access to restricted information—their manager, IT, or the finance team—as appropriate. Do not tell them to try again in this chat.

Do not disclose confidential data, PII, or other sensitive information unless policy explicitly allows it for this interaction."""


@dataclass
class RemediationAction:
    phase: str
    action: str
    policy_id: str | None
    reasoning: str
    user_explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InteractionResult:
    original_input: str
    processed_input: str
    role_id: str
    query_type: str | None
    authorized: bool
    input_scan_results: list[dict[str, Any]]
    output_scan_results: list[dict[str, Any]]
    violations: list[dict[str, Any]]
    remediation_actions: list[dict[str, Any]]
    final_response: str
    was_blocked: bool
    requires_escalation: bool
    timestamp: str
    near_misses: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _server_env() -> dict[str, str]:
    from mcp.client.stdio import get_default_environment

    env = get_default_environment()
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key
    return env


def _stdio_server_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_SCRIPT)],
        env=_server_env(),
        cwd=str(ROOT_DIR),
    )


def _parse_tool_result(result: CallToolResult) -> Any:
    if result.isError:
        parts = []
        for block in result.content:
            if isinstance(block, TextContent):
                parts.append(block.text)
        raise RuntimeError(f"MCP tool error: {' '.join(parts) or 'unknown error'}")

    if result.structuredContent is not None:
        if "result" in result.structuredContent:
            return result.structuredContent["result"]
        return result.structuredContent

    texts: list[str] = []
    for block in result.content:
        if isinstance(block, TextContent):
            texts.append(block.text)
    if not texts:
        return None

    combined = "\n".join(texts).strip()
    try:
        return json.loads(combined)
    except json.JSONDecodeError:
        return combined


async def _call_mcp_tool(session: ClientSession, name: str, arguments: dict[str, Any]) -> Any:
    result = await session.call_tool(name, arguments)
    return _parse_tool_result(result)


def _detected_results(scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in scan_results if r.get("detected")]


def _violations_from_scans(scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "policy_id": r.get("policy_id"),
            "action": r.get("action"),
            "severity": r.get("severity"),
            "confidence": r.get("confidence"),
            "detail": r.get("detail"),
        }
        for r in _detected_results(scan_results)
    ]


def _apply_regex_redactions(text: str, scan_result: dict[str, Any]) -> str:
    detail = scan_result.get("detail") or {}
    regex_detail = detail.get("regex") or {}
    patterns = regex_detail.get("patterns_matched") or []
    redacted = text
    for pattern in patterns:
        if str(pattern).startswith("invalid_pattern:"):
            continue
        try:
            redacted = re.sub(pattern, REDACTED_PLACEHOLDER, redacted)
        except re.error:
            logger.warning("Skipping invalid regex during redaction: %s", pattern)
    return redacted


def _apply_span_redactions(text: str, spans: list[dict[str, Any]]) -> str:
    if not spans:
        return text

    valid: list[tuple[int, int]] = []
    for span in spans:
        start = span.get("start")
        end = span.get("end")
        if start is None or end is None:
            continue
        try:
            valid.append((int(start), int(end)))
        except (TypeError, ValueError):
            continue

    if not valid:
        return text

    chars = list(text)
    for start, end in sorted(valid, key=lambda pair: pair[0], reverse=True):
        start = max(0, min(start, len(chars)))
        end = max(start, min(end, len(chars)))
        chars[start:end] = list(REDACTED_PLACEHOLDER)
    return "".join(chars)


def _apply_entity_redactions(text: str, entities: list[dict[str, Any]]) -> str:
    redacted = text
    for entity in sorted(
        entities,
        key=lambda e: len(e.get("text", "")),
        reverse=True,
    ):
        token = entity.get("text")
        if token and token in redacted:
            redacted = redacted.replace(token, REDACTED_PLACEHOLDER)
    return redacted


def _redact_text(text: str, scan_results: list[dict[str, Any]]) -> str:
    redacted = text
    for result in _detected_results(scan_results):
        if result.get("action") != "redact":
            continue
        redacted = _apply_regex_redactions(redacted, result)
        detail = result.get("detail") or {}
        llm_detail = detail.get("llm") or {}
        redacted = _apply_span_redactions(redacted, llm_detail.get("spans") or [])
        redacted = _apply_entity_redactions(redacted, llm_detail.get("entities") or [])
    return redacted


def _has_blocking_detection(scan_results: list[dict[str, Any]]) -> bool:
    return any(
        r.get("detected") and r.get("action") == "block"
        for r in scan_results
    )


def _collect_escalations(scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        r
        for r in _detected_results(scan_results)
        if r.get("action") == "escalate"
    ]


def _collect_warnings(scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        r
        for r in _detected_results(scan_results)
        if r.get("action") == "warn"
    ]


def _violation_confidence_from_scan(scan_result: dict[str, Any]) -> float:
    confidence = float(scan_result.get("confidence", 0.0))
    detail = scan_result.get("detail") or {}
    llm_detail = detail.get("llm") or {}
    if llm_detail.get("violation_confidence") is not None:
        confidence = max(confidence, float(llm_detail["violation_confidence"]))
    return confidence


def _collect_near_misses(
    scan_results: list[dict[str, Any]],
    scope: str,
) -> list[dict[str, Any]]:
    """Flag non-detected scans within 10% below threshold for the scope."""
    near_misses: list[dict[str, Any]] = []
    for result in scan_results:
        if result.get("detected"):
            continue
        detail = result.get("detail") or {}
        threshold = float(detail.get("threshold", 0.0))
        if threshold <= 0:
            continue
        confidence = _violation_confidence_from_scan(result)
        lower_bound = threshold * (1.0 - NEAR_MISS_MARGIN)
        if lower_bound <= confidence < threshold:
            near_misses.append(
                {
                    "policy_id": result.get("policy_id"),
                    "scope": scope,
                    "violation_confidence": round(confidence, 4),
                    "threshold": round(threshold, 4),
                    "gap": round(threshold - confidence, 4),
                }
            )
    return near_misses


async def _explain_remediation(
    client: anthropic.AsyncAnthropic,
    *,
    phase: str,
    action: str,
    policy_id: str | None,
    reasoning: str,
    original_snippet: str,
) -> str:
    prompt = (
        "Write one or two short, plain-language sentences for an end user explaining "
        "a governance remediation. Be factual and neutral. Do not mention internal "
        "systems or model names.\n\n"
        f"Phase: {phase}\n"
        f"Action: {action}\n"
        f"Policy: {policy_id or 'authorization'}\n"
        f"Agent reasoning: {reasoning}\n"
        f"Content snippet: {original_snippet[:500]}"
    )
    try:
        response = await client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        parts = [block.text for block in response.content if block.type == "text"]
        return " ".join(parts).strip() or reasoning
    except Exception as exc:
        logger.warning("Haiku explanation failed: %s", exc)
        return reasoning


async def _record_scan_remediations(
    client: anthropic.AsyncAnthropic,
    *,
    phase: str,
    text: str,
    scan_results: list[dict[str, Any]],
    remediation_actions: list[RemediationAction],
    requires_escalation: bool,
) -> bool:
    """Apply warn/escalate/redact bookkeeping. Returns updated requires_escalation."""
    for result in _detected_results(scan_results):
        action = result.get("action")
        policy_id = result.get("policy_id")
        if action == "warn":
            reasoning = (
                f"Policy '{policy_id}' triggered a warning (severity={result.get('severity')}, "
                f"confidence={result.get('confidence')}). Proceeding per policy configuration."
            )
            explanation = await _explain_remediation(
                client,
                phase=phase,
                action="warn",
                policy_id=policy_id,
                reasoning=reasoning,
                original_snippet=text,
            )
            remediation_actions.append(
                RemediationAction(
                    phase=phase,
                    action="warn",
                    policy_id=policy_id,
                    reasoning=reasoning,
                    user_explanation=explanation,
                )
            )
            logger.warning("Governance warning [%s]: %s", policy_id, reasoning)

        elif action == "escalate":
            requires_escalation = True
            reasoning = (
                f"Policy '{policy_id}' requires human review (severity={result.get('severity')}, "
                f"confidence={result.get('confidence')}). Proceeding with escalation flag set."
            )
            explanation = await _explain_remediation(
                client,
                phase=phase,
                action="escalate",
                policy_id=policy_id,
                reasoning=reasoning,
                original_snippet=text,
            )
            remediation_actions.append(
                RemediationAction(
                    phase=phase,
                    action="escalate",
                    policy_id=policy_id,
                    reasoning=reasoning,
                    user_explanation=explanation,
                )
            )

        elif action == "redact":
            reasoning = (
                f"Policy '{policy_id}' detected sensitive content (confidence={result.get('confidence')}). "
                "Autonomous remediation: redact flagged segments and continue processing."
            )
            explanation = await _explain_remediation(
                client,
                phase=phase,
                action="redact",
                policy_id=policy_id,
                reasoning=reasoning,
                original_snippet=text,
            )
            remediation_actions.append(
                RemediationAction(
                    phase=phase,
                    action="redact",
                    policy_id=policy_id,
                    reasoning=reasoning,
                    user_explanation=explanation,
                )
            )

    return requires_escalation


async def _generate_llm_response(
    client: anthropic.AsyncAnthropic,
    user_input: str,
    conversation_history: list[dict[str, Any]],
) -> str:
    messages: list[dict[str, str]] = []
    for turn in conversation_history:
        role = turn.get("role")
        content = turn.get("content")
        if role in ("user", "assistant") and isinstance(content, str):
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": user_input})

    response = await client.messages.create(
        model=SONNET_MODEL,
        max_tokens=4096,
        system=GOVERNED_ASSISTANT_SYSTEM_PROMPT,
        messages=messages,
    )
    return "".join(block.text for block in response.content if block.type == "text")


def _build_blocked_result(
    *,
    user_input: str,
    processed_input: str,
    role_id: str,
    query_type: str | None,
    authorized: bool,
    input_scan_results: list[dict[str, Any]],
    output_scan_results: list[dict[str, Any]],
    violations: list[dict[str, Any]],
    remediation_actions: list[RemediationAction],
    final_response: str,
    requires_escalation: bool,
    near_misses: list[dict[str, Any]] | None = None,
) -> InteractionResult:
    return InteractionResult(
        original_input=user_input,
        processed_input=processed_input,
        role_id=role_id,
        query_type=query_type,
        authorized=authorized,
        input_scan_results=input_scan_results,
        output_scan_results=output_scan_results,
        violations=violations,
        remediation_actions=[a.to_dict() for a in remediation_actions],
        final_response=final_response,
        was_blocked=True,
        requires_escalation=requires_escalation,
        near_misses=near_misses or [],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


async def _process_interaction_with_session(
    session: ClientSession,
    user_input: str,
    role_id: str,
    conversation_history: list[dict[str, Any]],
) -> InteractionResult:
    """Governance pipeline using an already-initialized MCP session."""
    history = conversation_history
    remediation_actions: list[RemediationAction] = []
    input_scan_results: list[dict[str, Any]] = []
    output_scan_results: list[dict[str, Any]] = []
    requires_escalation = False
    query_type: str | None = None
    authorized = False
    processed_input = user_input

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY is not set. Add it to .env or the environment.")

    anthropic_client = anthropic.AsyncAnthropic(api_key=api_key)

    classification = await _call_mcp_tool(
        session,
        "classify_query",
        {"text": user_input, "role_id": role_id},
    )
    permitted = bool(classification.get("permitted"))
    authorized = permitted
    class_info = classification.get("classification") or {}
    query_type = class_info.get("query_type")

    if not permitted:
        reason = classification.get("reason", "Query not permitted for this role.")
        explanation = await _explain_remediation(
            anthropic_client,
            phase="authorization",
            action="block",
            policy_id=None,
            reasoning=reason,
            original_snippet=user_input,
        )
        remediation_actions.append(
            RemediationAction(
                phase="authorization",
                action="block",
                policy_id=None,
                reasoning=reason,
                user_explanation=explanation,
            )
        )
        return _build_blocked_result(
            user_input=user_input,
            processed_input=user_input,
            role_id=role_id,
            query_type=query_type,
            authorized=False,
            input_scan_results=[],
            output_scan_results=[],
            violations=[],
            remediation_actions=remediation_actions,
            final_response=explanation or BLOCKED_AUTHORIZATION_MESSAGE,
            requires_escalation=False,
            near_misses=[],
        )

    input_scan_results = await _call_mcp_tool(
        session,
        "scan_input",
        {"text": user_input, "policy_ids": []},
    )
    if not isinstance(input_scan_results, list):
        input_scan_results = []

    if _has_blocking_detection(input_scan_results):
        violations = _violations_from_scans(input_scan_results)
        blockers = [v for v in violations if v.get("action") == "block"]
        policy_id = blockers[0].get("policy_id") if blockers else None
        reasoning = (
            f"Autonomous remediation: input blocked because policy '{policy_id}' "
            "detected a violation with action=block."
        )
        explanation = await _explain_remediation(
            anthropic_client,
            phase="input",
            action="block",
            policy_id=policy_id,
            reasoning=reasoning,
            original_snippet=user_input,
        )
        remediation_actions.append(
            RemediationAction(
                phase="input",
                action="block",
                policy_id=policy_id,
                reasoning=reasoning,
                user_explanation=explanation,
            )
        )
        input_near_misses = _collect_near_misses(input_scan_results, "input")
        return _build_blocked_result(
            user_input=user_input,
            processed_input=user_input,
            role_id=role_id,
            query_type=query_type,
            authorized=True,
            input_scan_results=input_scan_results,
            output_scan_results=[],
            violations=violations,
            remediation_actions=remediation_actions,
            final_response=explanation or BLOCKED_POLICY_MESSAGE,
            requires_escalation=False,
            near_misses=input_near_misses,
        )

    processed_input = _redact_text(user_input, input_scan_results)
    requires_escalation = await _record_scan_remediations(
        anthropic_client,
        phase="input",
        text=user_input,
        scan_results=input_scan_results,
        remediation_actions=remediation_actions,
        requires_escalation=requires_escalation,
    )

    llm_response = await _generate_llm_response(
        anthropic_client,
        processed_input,
        history,
    )

    output_scan_results = await _call_mcp_tool(
        session,
        "scan_output",
        {"text": llm_response, "policy_ids": []},
    )
    if not isinstance(output_scan_results, list):
        output_scan_results = []

    violations = _violations_from_scans(input_scan_results) + _violations_from_scans(
        output_scan_results
    )
    final_response = llm_response
    was_blocked = False

    if _has_blocking_detection(output_scan_results):
        was_blocked = True
        out_violations = _violations_from_scans(output_scan_results)
        blockers = [v for v in out_violations if v.get("action") == "block"]
        policy_id = blockers[0].get("policy_id") if blockers else None
        reasoning = (
            f"Autonomous remediation: output blocked because policy '{policy_id}' "
            "detected a violation with action=block."
        )
        explanation = await _explain_remediation(
            anthropic_client,
            phase="output",
            action="block",
            policy_id=policy_id,
            reasoning=reasoning,
            original_snippet=llm_response,
        )
        remediation_actions.append(
            RemediationAction(
                phase="output",
                action="block",
                policy_id=policy_id,
                reasoning=reasoning,
                user_explanation=explanation,
            )
        )
        final_response = explanation or BLOCKED_OUTPUT_MESSAGE
    else:
        redacted_output = _redact_text(llm_response, output_scan_results)
        if redacted_output != llm_response:
            final_response = redacted_output
        requires_escalation = await _record_scan_remediations(
            anthropic_client,
            phase="output",
            text=llm_response,
            scan_results=output_scan_results,
            remediation_actions=remediation_actions,
            requires_escalation=requires_escalation,
        )

    near_misses = _collect_near_misses(
        input_scan_results, "input"
    ) + _collect_near_misses(output_scan_results, "output")

    return InteractionResult(
        original_input=user_input,
        processed_input=processed_input,
        role_id=role_id,
        query_type=query_type,
        authorized=authorized,
        input_scan_results=input_scan_results,
        output_scan_results=output_scan_results,
        violations=violations,
        remediation_actions=[a.to_dict() for a in remediation_actions],
        final_response=final_response,
        was_blocked=was_blocked,
        requires_escalation=requires_escalation,
        near_misses=near_misses,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

async def process_interaction(
    user_input: str,
    role_id: str,
    conversation_history: list[dict[str, Any]] | None = None,
) -> InteractionResult:
    """
    Run the full governance pipeline with a one-shot MCP subprocess (CLI/tests).
    """
    history = conversation_history or []
    async with stdio_client(_stdio_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return await _process_interaction_with_session(
                session, user_input, role_id, history
            )


class PolicyEngineMcp:
    """
    Long-lived MCP connection to server.py on a background asyncio loop.

    Reuses one policy-engine subprocess across Streamlit messages. The server
    reloads all config from disk on each tool call.
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session: ClientSession | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._start_error: BaseException | None = None
        self._close_lock = threading.Lock()
        self._closed = False

    @property
    def is_running(self) -> bool:
        return (
            not self._closed
            and self._ready.is_set()
            and self._thread is not None
            and self._thread.is_alive()
        )

    def start(self) -> None:
        """Start the background MCP subprocess and session."""
        with self._close_lock:
            if self._closed:
                raise RuntimeError("PolicyEngineMcp is closed")
            if self._thread is not None:
                return
            self._thread = threading.Thread(
                target=self._thread_main,
                name="policy-engine-mcp",
                daemon=True,
            )
            self._thread.start()

        if not self._ready.wait(timeout=60):
            raise TimeoutError("Policy engine MCP did not start within 60s")
        if self._start_error is not None:
            raise RuntimeError("Policy engine MCP failed to start") from self._start_error

    def close(self) -> None:
        """Shut down the MCP subprocess and background loop."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True

        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=15)

    def run_interaction(
        self,
        user_input: str,
        role_id: str,
        conversation_history: list[dict[str, Any]] | None = None,
    ) -> InteractionResult:
        """Run the governance pipeline on the persistent MCP session (sync API)."""
        if not self.is_running:
            raise RuntimeError("PolicyEngineMcp is not running; call start() first")

        history = conversation_history or []
        assert self._loop is not None and self._session is not None
        coro = _process_interaction_with_session(
            self._session, user_input, role_id, history
        )
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=MCP_INTERACTION_TIMEOUT_SECONDS)
        except Exception:
            self.close()
            raise

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._serve_until_stopped())
        except BaseException as exc:
            if not self._ready.is_set():
                self._start_error = exc
                self._ready.set()
        finally:
            loop.close()

    async def _serve_until_stopped(self) -> None:
        try:
            async with stdio_client(_stdio_server_params()) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    self._session = session
                    self._ready.set()
                    while not self._stop.is_set():
                        await asyncio.sleep(0.2)
        except BaseException as exc:
            if not self._ready.is_set():
                self._start_error = exc
                self._ready.set()
            raise
