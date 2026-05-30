"""
Streamlit web interface for the AI Governance Platform.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import os
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

import anyio
import streamlit as st
from dotenv import load_dotenv

from agent import InteractionResult, process_interaction

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent
POLICIES_PATH = ROOT_DIR / "config" / "policies.json"

ROLE_OPTIONS: dict[str, str] = {
    "Admin": "admin",
    "Compliance Officer": "compliance-officer",
    "Analyst": "analyst",
    "Customer Service": "customer-service",
}

SEVERITY_STYLES: dict[str, str] = {
    "critical": "background-color:#dc3545;color:white;padding:2px 8px;border-radius:4px;",
    "high": "background-color:#fd7e14;color:white;padding:2px 8px;border-radius:4px;",
    "medium": "background-color:#ffc107;color:#212529;padding:2px 8px;border-radius:4px;",
    "low": "background-color:#0d6efd;color:white;padding:2px 8px;border-radius:4px;",
}


def load_policies_doc() -> dict[str, Any]:
    with open(POLICIES_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_policies_doc(doc: dict[str, Any]) -> None:
    with open(POLICIES_PATH, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def record_policy_version(doc: dict[str, Any], change_type: str) -> None:
    versions: list[dict[str, Any]] = st.session_state.policy_versions
    versions.append(
        {
            "version": len(versions) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "change_type": change_type,
            "snapshot": copy.deepcopy(doc),
        }
    )


def restore_policy_version(version_entry: dict[str, Any]) -> None:
    snapshot = copy.deepcopy(version_entry["snapshot"])
    save_policies_doc(snapshot)
    st.session_state.policies_doc = load_policies_doc()
    record_policy_version(st.session_state.policies_doc, "restored")


def init_session_state() -> None:
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "audit_trail" not in st.session_state:
        st.session_state.audit_trail = []
    if "policies_doc" not in st.session_state:
        st.session_state.policies_doc = load_policies_doc()
    if "policy_versions" not in st.session_state:
        st.session_state.policy_versions = []
        record_policy_version(st.session_state.policies_doc, "initial load")
    if "selected_role_label" not in st.session_state:
        st.session_state.selected_role_label = "Analyst"
    if "escalation_selected_row_key" not in st.session_state:
        st.session_state.escalation_selected_row_key = None


def format_thresholds(policy: dict[str, Any]) -> str:
    thresholds = policy.get("thresholds", {})
    if not thresholds:
        legacy = policy.get("threshold")
        return str(legacy) if legacy is not None else "—"
    return ", ".join(f"{scope}: {value}" for scope, value in thresholds.items())


def severity_badge(severity: str | None) -> str:
    key = (severity or "low").lower()
    style = SEVERITY_STYLES.get(key, SEVERITY_STYLES["low"])
    label = key.upper()
    return f'<span style="{style}">{label}</span>'


def run_interaction(
    user_input: str,
    role_id: str,
    conversation_history: list[dict[str, Any]],
) -> InteractionResult:
    return anyio.run(
        partial(
            process_interaction,
            user_input,
            role_id,
            conversation_history,
        )
    )


def policies_scanned(result: InteractionResult) -> list[str]:
    ids: list[str] = []
    for scan in result.input_scan_results + result.output_scan_results:
        policy_id = scan.get("policy_id")
        if policy_id and policy_id not in ids:
            ids.append(policy_id)
    return ids


def render_violations(violations: list[dict[str, Any]]) -> None:
    if not violations:
        st.caption("No violations detected.")
        return
    for violation in violations:
        severity = violation.get("severity", "low")
        policy_id = violation.get("policy_id", "unknown")
        action = violation.get("action", "—")
        confidence = violation.get("confidence", "—")
        st.markdown(
            f'{severity_badge(severity)} **{policy_id}** — action: `{action}`, '
            f"confidence: `{confidence}`",
            unsafe_allow_html=True,
        )


def render_governance_details(result: InteractionResult) -> None:
    with st.expander("Governance Details", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Query type**")
            st.write(result.query_type or "—")
            st.markdown("**Authorized**")
            st.write("Yes" if result.authorized else "No")
        with col2:
            st.markdown("**Blocked**")
            st.write("Yes" if result.was_blocked else "No")
            st.markdown("**Requires escalation**")
            st.write("Yes" if result.requires_escalation else "No")

        st.markdown("**Policies scanned**")
        scanned = policies_scanned(result)
        st.write(", ".join(scanned) if scanned else "—")

        st.markdown("**Violations**")
        render_violations(result.violations)

        st.markdown("**Remediation actions**")
        if result.remediation_actions:
            for action in result.remediation_actions:
                st.markdown(
                    f"- **{action.get('phase', '—')}** / `{action.get('action', '—')}` "
                    f"({action.get('policy_id') or 'authorization'}): "
                    f"{action.get('user_explanation') or action.get('reasoning', '—')}"
                )
        else:
            st.caption("None.")

        st.markdown("**Near misses**")
        if result.near_misses:
            for miss in result.near_misses:
                st.markdown(
                    f"- `{miss.get('policy_id')}` ({miss.get('scope')}): "
                    f"confidence `{miss.get('violation_confidence')}`, "
                    f"threshold `{miss.get('threshold')}`, gap `{miss.get('gap')}`"
                )
        else:
            st.caption("None.")


def build_conversation_history(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    """History for agent: all completed turns before the latest user message."""
    history: list[dict[str, str]] = []
    for msg in messages[:-1]:
        role = msg.get("role")
        content = msg.get("content")
        if role in ("user", "assistant") and isinstance(content, str):
            history.append({"role": role, "content": content})
    return history


def render_policy_dashboard() -> None:
    st.header("Policy Dashboard")
    doc = st.session_state.policies_doc
    policies: list[dict[str, Any]] = doc.get("policies", [])

    for index, policy in enumerate(policies):
        policy_id = policy.get("id", f"policy-{index}")
        enabled = st.toggle(
            f"Enable {policy.get('name', policy_id)}",
            value=bool(policy.get("enabled", True)),
            key=f"policy_enabled_{policy_id}",
        )
        policy["enabled"] = enabled

        st.markdown(
            f"**{policy.get('name', policy_id)}** "
            f"{severity_badge(policy.get('severity'))}",
            unsafe_allow_html=True,
        )
        st.caption(
            f"Method: `{policy.get('detection_method', '—')}` · "
            f"Threshold: {format_thresholds(policy)}"
        )
        st.divider()

    if st.button("Save policy changes", use_container_width=True):
        save_policies_doc(doc)
        st.session_state.policies_doc = load_policies_doc()
        record_policy_version(st.session_state.policies_doc, "manual edit")
        st.success("Policies saved to config/policies.json")

    with st.expander("Policy Version History", expanded=False):
        versions = list(reversed(st.session_state.policy_versions))
        if not versions:
            st.caption("No versions recorded yet.")
        for entry in versions:
            col_info, col_restore = st.columns([4, 1])
            with col_info:
                st.markdown(
                    f"**v{entry['version']}** · {entry['timestamp']} · "
                    f"`{entry['change_type']}`"
                )
            with col_restore:
                if st.button(
                    "Restore",
                    key=f"restore_v{entry['version']}",
                    use_container_width=True,
                ):
                    restore_policy_version(entry)
                    st.success(f"Restored policy version {entry['version']}.")
                    st.rerun()

    uploaded = st.file_uploader(
        "Upload custom policies.json",
        type=["json"],
        help="Replaces the active policy set in config/policies.json",
    )
    if uploaded is not None:
        try:
            new_doc = json.loads(uploaded.getvalue().decode("utf-8"))
            if "policies" not in new_doc or not isinstance(new_doc["policies"], list):
                st.error("Invalid policies.json: missing 'policies' array.")
            else:
                save_policies_doc(new_doc)
                st.session_state.policies_doc = load_policies_doc()
                record_policy_version(st.session_state.policies_doc, "upload")
                st.success("Uploaded policies applied.")
                st.rerun()
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")


def render_chat_tab(role_id: str) -> None:
    st.subheader("Governed Chat")

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg["role"] == "assistant" and msg.get("result") is not None:
                render_governance_details(msg["result"])

    if prompt := st.chat_input("Send a message"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        history = build_conversation_history(st.session_state.messages)

        with st.spinner("Running governance checks and generating response..."):
            try:
                result = run_interaction(prompt, role_id, history)
            except Exception as exc:
                st.error(f"Processing failed: {exc}")
                st.session_state.messages.pop()
                return

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": result.final_response,
                "result": result,
            }
        )
        st.session_state.audit_trail.append(result.to_dict())
        st.rerun()


def audit_summary_row(entry: dict[str, Any]) -> dict[str, Any]:
    violations = entry.get("violations") or []
    violation_labels = ", ".join(
        f"{v.get('policy_id', '?')} ({v.get('severity', '?')})" for v in violations
    )
    near_misses = entry.get("near_misses") or []
    return {
        "timestamp": entry.get("timestamp", ""),
        "role": entry.get("role_id", ""),
        "query_type": entry.get("query_type") or "—",
        "authorized": entry.get("authorized", False),
        "violations": violation_labels or "—",
        "near_misses": len(near_misses),
        "was_blocked": entry.get("was_blocked", False),
        "requires_escalation": entry.get("requires_escalation", False),
    }


def escalation_queue_items() -> list[dict[str, Any]]:
    """Flatten audit trail into escalation / near-miss queue rows."""
    items: list[dict[str, Any]] = []
    for audit_index, entry in enumerate(st.session_state.audit_trail):
        if not entry.get("requires_escalation") and not entry.get("near_misses"):
            continue

        if entry.get("requires_escalation"):
            escalated = [
                v
                for v in entry.get("violations", [])
                if v.get("action") == "escalate"
            ]
            if escalated:
                for violation in escalated:
                    items.append(
                        {
                            "audit_index": audit_index,
                            "timestamp": entry.get("timestamp", ""),
                            "role": entry.get("role_id", ""),
                            "policy_triggered": violation.get("policy_id", "—"),
                            "escalation_type": "Escalated",
                            "confidence": violation.get("confidence", "—"),
                            "threshold": (violation.get("detail") or {}).get(
                                "threshold", "—"
                            ),
                            "row_key": f"{audit_index}-escalated-{violation.get('policy_id')}",
                        }
                    )
            else:
                items.append(
                    {
                        "audit_index": audit_index,
                        "timestamp": entry.get("timestamp", ""),
                        "role": entry.get("role_id", ""),
                        "policy_triggered": "—",
                        "escalation_type": "Escalated",
                        "confidence": "—",
                        "threshold": "—",
                        "row_key": f"{audit_index}-escalated-general",
                    }
                )

        for near_miss in entry.get("near_misses") or []:
            items.append(
                {
                    "audit_index": audit_index,
                    "timestamp": entry.get("timestamp", ""),
                    "role": entry.get("role_id", ""),
                    "policy_triggered": near_miss.get("policy_id", "—"),
                    "escalation_type": "Near Miss",
                    "confidence": near_miss.get("violation_confidence", "—"),
                    "threshold": near_miss.get("threshold", "—"),
                    "near_miss": near_miss,
                    "row_key": f"{audit_index}-near-{near_miss.get('policy_id')}-{near_miss.get('scope')}",
                }
            )
    return items


def save_queue_review(
    audit_index: int,
    row_key: str,
    disposition: str,
    notes: str,
    *,
    adjusted_threshold: float | None = None,
) -> None:
    entry = st.session_state.audit_trail[audit_index]
    reviews: list[dict[str, Any]] = entry.setdefault("queue_reviews", [])
    reviews.append(
        {
            "row_key": row_key,
            "disposition": disposition,
            "notes": notes,
            "adjusted_threshold": adjusted_threshold,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }
    )


def apply_threshold_adjustment(
    policy_id: str,
    scope: str,
    new_threshold: float,
) -> None:
    doc = st.session_state.policies_doc
    for policy in doc.get("policies", []):
        if policy.get("id") == policy_id:
            thresholds = policy.setdefault("thresholds", {})
            thresholds[scope] = round(new_threshold, 4)
            break
    save_policies_doc(doc)
    st.session_state.policies_doc = load_policies_doc()
    record_policy_version(st.session_state.policies_doc, "manual edit")


def render_audit_trail_tab() -> None:
    st.subheader("Session Audit Trail")

    if not st.session_state.audit_trail:
        st.info("No interactions yet. Send a message in the Chat tab.")
        return

    rows = [audit_summary_row(e) for e in st.session_state.audit_trail]
    st.dataframe(rows, use_container_width=True, hide_index=True)

    options = [
        f"{row['timestamp']} | {row['role']} | blocked={row['was_blocked']}"
        for row in rows
    ]
    selected = st.selectbox("View interaction detail", options=options)
    if selected:
        index = options.index(selected)
        entry = st.session_state.audit_trail[index]
        with st.expander("Full interaction detail", expanded=True):
            st.json(entry)

    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    st.download_button(
        label="Export audit trail as CSV",
        data=buffer.getvalue(),
        file_name="audit_trail.csv",
        mime="text/csv",
        use_container_width=True,
    )


def render_escalation_queue_tab() -> None:
    st.subheader("Escalation Queue")

    items = escalation_queue_items()
    if not items:
        st.info(
            "No escalations or near misses in this session. "
            "Items appear when `requires_escalation` is true or near misses are detected."
        )
        return

    near_miss_count = sum(1 for i in items if i["escalation_type"] == "Near Miss")
    if near_miss_count == 0:
        st.warning(
            "This session has escalations but **no Near Miss rows**. "
            "The threshold slider only appears for **Near Miss** items. "
            "Try a compliance-officer chat with an SSN (e.g. `123-45-6789`) that scores "
            "within 10% below the policy threshold."
        )

    table_rows = [
        {
            "timestamp": item["timestamp"],
            "role": item["role"],
            "policy triggered": item["policy_triggered"],
            "escalation type": item["escalation_type"],
            "confidence": item["confidence"],
            "threshold": item["threshold"],
        }
        for item in items
    ]
    st.dataframe(table_rows, use_container_width=True, hide_index=True)

    row_keys = [item["row_key"] for item in items]
    label_by_key = {
        item["row_key"]: (
            f"{item['timestamp']} | {item['role']} | {item['policy_triggered']} | "
            f"{item['escalation_type']}"
        )
        for item in items
    }
    if st.session_state.get("escalation_selected_row_key") not in row_keys:
        st.session_state.escalation_selected_row_key = row_keys[0]

    selected_key = st.selectbox(
        "Review queue item",
        options=row_keys,
        index=row_keys.index(st.session_state.escalation_selected_row_key),
        format_func=lambda key: label_by_key[key],
        key="escalation_queue_select",
    )
    st.session_state.escalation_selected_row_key = selected_key

    item = next(i for i in items if i["row_key"] == selected_key)
    audit_index = item["audit_index"]
    entry = st.session_state.audit_trail[audit_index]

    with st.expander("Full interaction detail", expanded=False):
        st.json(entry)

    st.markdown("**Reviewer actions**")
    notes = st.text_area(
        "Reviewer notes",
        key=f"notes_{item['row_key']}",
        placeholder="Add comments about this escalation or near miss…",
    )

    if item["escalation_type"] == "Near Miss" and item.get("near_miss"):
        nm = item["near_miss"]
        st.markdown("### Adjust threshold")
        st.caption(
            f"Policy `{nm.get('policy_id')}` · scope `{nm.get('scope')}` · "
            f"current threshold **{nm.get('threshold')}** · "
            f"near-miss confidence **{nm.get('violation_confidence')}** "
            f"(gap **{nm.get('gap')}**)"
        )
        new_threshold = st.slider(
            "New threshold",
            min_value=0.0,
            max_value=1.0,
            value=float(nm.get("threshold", 0.85)),
            step=0.01,
            key=f"slider_{item['row_key']}",
        )
        if st.button("Confirm Adjustment", key=f"confirm_{item['row_key']}"):
            apply_threshold_adjustment(
                str(nm.get("policy_id")),
                str(nm.get("scope")),
                new_threshold,
            )
            save_queue_review(
                audit_index,
                item["row_key"],
                "Adjust Threshold",
                notes,
                adjusted_threshold=new_threshold,
            )
            st.success(
                f"Threshold for `{nm.get('policy_id')}` ({nm.get('scope')}) "
                f"set to {new_threshold:.2f}."
            )
            st.rerun()
        st.divider()

    btn_col1, btn_col2, btn_col3 = st.columns(3)
    with btn_col1:
        if st.button("True Positive", key=f"tp_{item['row_key']}"):
            save_queue_review(audit_index, item["row_key"], "True Positive", notes)
            st.success("Recorded: True Positive")
    with btn_col2:
        if st.button("False Positive", key=f"fp_{item['row_key']}"):
            save_queue_review(audit_index, item["row_key"], "False Positive", notes)
            st.success("Recorded: False Positive")
    with btn_col3:
        if st.button("Near Miss", key=f"nm_{item['row_key']}"):
            save_queue_review(audit_index, item["row_key"], "Near Miss", notes)
            st.success("Recorded: Near Miss")

    if item["escalation_type"] != "Near Miss":
        st.caption(
            "Threshold adjustment is only available when **escalation type** is "
            "**Near Miss**. Select a Near Miss row in the table above."
        )

    prior_reviews = entry.get("queue_reviews") or []
    if prior_reviews:
        st.markdown("**Review history**")
        for review in prior_reviews:
            st.caption(
                f"{review.get('reviewed_at')}: **{review.get('disposition')}** — "
                f"{review.get('notes') or '(no notes)'}"
            )


def main() -> None:
    st.set_page_config(
        page_title="AI Governance Platform",
        page_icon="🛡️",
        layout="wide",
    )
    init_session_state()

    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        st.warning(
            "ANTHROPIC_API_KEY is not set. Add it to `.env` before using the chat."
        )

    st.title("AI Governance Platform")
    st.caption("Governed financial services assistant with policy enforcement")

    with st.sidebar:
        role_labels = list(ROLE_OPTIONS.keys())
        role_index = (
            role_labels.index(st.session_state.selected_role_label)
            if st.session_state.selected_role_label in role_labels
            else 0
        )
        st.session_state.selected_role_label = st.selectbox(
            "Role",
            options=role_labels,
            index=role_index,
        )
        role_id = ROLE_OPTIONS[st.session_state.selected_role_label]
        st.caption(f"Role ID: `{role_id}`")
        render_policy_dashboard()

    tab_chat, tab_audit, tab_escalation = st.tabs(
        ["Chat", "Audit Trail", "Escalation Queue"]
    )

    with tab_chat:
        render_chat_tab(role_id)

    with tab_audit:
        render_audit_trail_tab()

    with tab_escalation:
        render_escalation_queue_tab()


if __name__ == "__main__":
    main()
