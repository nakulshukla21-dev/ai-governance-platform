"""
Streamlit UI for the Policy Synthesis tab (Phase 1).
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import streamlit as st

from policy_validation import MAX_POLICIES, validate_policies_doc
from regulatory_ingest import REGULATORY_SOURCES, build_synthesis_corpus
from synthesizer import CandidateRule, candidate_to_policy, synthesize_policies_from_document_sync

ROOT_DIR = Path(__file__).resolve().parent
POLICIES_PATH = ROOT_DIR / "config" / "policies.json"
CONFIG_DIR = ROOT_DIR / "config"
MAX_PDF_BYTES_PER_FILE = 2_000_000
MAX_PDF_FILES = 5

CONFIDENCE_STYLES = {
    "high": "background-color:#16a34a;color:white;padding:2px 8px;border-radius:4px;",
    "medium": "background-color:#ffc107;color:#212529;padding:2px 8px;border-radius:4px;",
    "low": "background-color:#dc3545;color:white;padding:2px 8px;border-radius:4px;",
}


def confidence_badge(level: str) -> str:
    key = (level or "medium").lower()
    style = CONFIDENCE_STYLES.get(key, CONFIDENCE_STYLES["medium"])
    return f'<span style="{style}">{key.upper()}</span>'


def _init_synthesis_state() -> None:
    if "synthesis_candidates" not in st.session_state:
        st.session_state.synthesis_candidates = []
    if "synthesis_approved_keys" not in st.session_state:
        st.session_state.synthesis_approved_keys = set()
    if "synthesis_edits" not in st.session_state:
        st.session_state.synthesis_edits = {}
    if "synthesis_corpus_cache" not in st.session_state:
        st.session_state.synthesis_corpus_cache = ""


def _get_edited_candidate(candidate: CandidateRule) -> CandidateRule:
    edits = st.session_state.synthesis_edits.get(candidate.candidate_key, {})
    if not edits:
        return candidate
    data = candidate.to_dict()
    for field_name, value in edits.items():
        if field_name in data:
            data[field_name] = value
    return CandidateRule(**data)


def _save_edits_from_form(candidate: CandidateRule) -> None:
    key = candidate.candidate_key
    scope_selected = st.session_state.get(f"syn_scope_{key}", ["input", "output"])
    if isinstance(scope_selected, list):
        if set(scope_selected) == {"input", "output"}:
            scope_value = "both"
        elif len(scope_selected) == 1:
            scope_value = scope_selected[0]
        else:
            scope_value = "both"
    else:
        scope_value = "both"

    patterns_raw = st.session_state.get(f"syn_patterns_{key}", "")
    patterns = [line.strip() for line in str(patterns_raw).splitlines() if line.strip()]

    st.session_state.synthesis_edits[key] = {
        "suggested_name": st.session_state.get(f"syn_name_{key}", candidate.suggested_name),
        "suggested_description": st.session_state.get(
            f"syn_desc_{key}", candidate.suggested_description
        ),
        "suggested_action": st.session_state.get(
            f"syn_action_{key}", candidate.suggested_action
        ),
        "suggested_scope": scope_value,
        "detection_method": st.session_state.get(
            f"syn_method_{key}", candidate.detection_method
        ),
        "suggested_threshold_input": float(
            st.session_state.get(f"syn_thresh_in_{key}", 0.85)
        ),
        "suggested_threshold_output": float(
            st.session_state.get(f"syn_thresh_out_{key}", 0.85)
        ),
        "suggested_llm_prompt": st.session_state.get(
            f"syn_prompt_{key}", candidate.suggested_llm_prompt
        ),
        "suggested_patterns": patterns,
    }


def backup_policies_file() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = CONFIG_DIR / f"policies_backup_{stamp}.json"
    backup_path.write_text(POLICIES_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    return backup_path


def render_policy_synthesis_tab(
    *,
    load_policies_doc: Callable[[], dict[str, Any]],
    save_policies_doc: Callable[[dict[str, Any]], None],
    refresh_policy_dashboard: Callable[[], None],
    record_policy_version: Callable[[dict[str, Any], str], None],
    close_policy_engine: Callable[[], None],
    show_validation_errors: Callable[[list[str]], None],
) -> None:
    _init_synthesis_state()
    st.subheader("Policy Synthesis")
    st.caption(
        "Ingest internal PDFs and/or allowlisted regulators → Sonnet extracts obligation-based "
        "candidate rules → you review and batch-commit into policies.json (sidebar dashboard updates)."
    )

    selected_sources = []
    st.markdown("**Regulatory sources** (allowlisted)")
    cols = st.columns(2)
    for index, source in enumerate(REGULATORY_SOURCES):
        with cols[index % 2]:
            if st.checkbox(source.label, key=f"syn_src_{source.id}"):
                selected_sources.append(source.id)

    uploaded_pdfs = st.file_uploader(
        "Upload internal policy documents (PDF)",
        type=["pdf"],
        accept_multiple_files=True,
        help=f"Up to {MAX_PDF_FILES} files, {MAX_PDF_BYTES_PER_FILE // 1_000_000} MB each.",
    )
    focus = st.text_input(
        "Optional context / focus",
        placeholder="e.g. model risk, customer PII in chat, third-party LLM vendors",
    )

    pdf_payload: list[tuple[str, bytes]] = []
    if uploaded_pdfs:
        for uploaded in uploaded_pdfs[:MAX_PDF_FILES]:
            raw = uploaded.getvalue()
            if len(raw) > MAX_PDF_BYTES_PER_FILE:
                st.warning(f"Skipped {uploaded.name}: exceeds per-file size limit.")
                continue
            pdf_payload.append((uploaded.name, raw))

    can_extract = bool(pdf_payload or selected_sources)
    if st.button(
        "Extract Obligations",
        type="primary",
        disabled=not can_extract,
        use_container_width=True,
    ):
        with st.spinner("Fetching sources and extracting obligations with Claude Sonnet..."):
            corpus, fetch_errors = build_synthesis_corpus(
                uploaded_pdfs=pdf_payload,
                regulatory_source_ids=selected_sources,
                focus=focus,
                mode="full",
            )
            for err in fetch_errors:
                st.warning(err)
            if not corpus.strip():
                st.error("No document text available to synthesize.")
            else:
                st.session_state.synthesis_corpus_cache = corpus
                existing = load_policies_doc().get("policies", [])
                try:
                    candidates = synthesize_policies_from_document_sync(
                        corpus, focus, existing
                    )
                except Exception as exc:
                    st.error(f"Extraction failed: {exc}")
                    candidates = []
                st.session_state.synthesis_candidates = candidates
                st.session_state.synthesis_approved_keys = set()
                st.session_state.synthesis_edits = {}
                if candidates:
                    st.success(f"Extracted {len(candidates)} candidate rule(s).")
                else:
                    st.info("No candidates returned. Try a broader focus or more sources.")

    candidates: list[CandidateRule] = st.session_state.synthesis_candidates
    if not candidates:
        return

    st.divider()
    st.markdown(f"**{len(candidates)} candidate rule(s)** — review each, then commit approved.")

    labels = [
        f"{idx + 1}. {c.suggested_name} ({c.confidence})" for idx, c in enumerate(candidates)
    ]
    selected_index = st.selectbox(
        "Select candidate to review",
        options=list(range(len(candidates))),
        format_func=lambda i: labels[i],
    )
    candidate = candidates[selected_index]
    edited = _get_edited_candidate(candidate)
    key = candidate.candidate_key

    st.markdown("**Obligation (from document)**")
    st.info(candidate.obligation_text)

    st.markdown(
        f"**Confidence** {confidence_badge(candidate.confidence)}",
        unsafe_allow_html=True,
    )
    if candidate.confidence == "low":
        st.warning(
            "This rule has low confidence. Please review assumptions carefully before approving."
        )

    if candidate.similar_existing_policy:
        st.warning(
            f"This may overlap with existing policy `{candidate.similar_existing_policy}`. "
            "Phase 1 only supports **create as new rule**."
        )
    if candidate.merge_candidate and candidate.merge_with_suggestion:
        st.caption(
            f"Agent suggests related obligation: {candidate.merge_with_suggestion} "
            "(merge not available in Phase 1)."
        )

    with st.expander("Assumptions and alternative interpretations", expanded=False):
        if candidate.assumptions:
            st.markdown("**Assumptions**")
            for item in candidate.assumptions:
                st.markdown(f"- {item}")
        else:
            st.caption("No assumptions listed.")
        if candidate.alternative_interpretations:
            st.markdown("**Alternative interpretations**")
            for item in candidate.alternative_interpretations:
                st.markdown(f"- {item}")

    default_scope = (
        ["input", "output"]
        if edited.suggested_scope == "both"
        else [edited.suggested_scope]
        if edited.suggested_scope in ("input", "output")
        else ["input", "output"]
    )

    st.text_input("Name", value=edited.suggested_name, key=f"syn_name_{key}")
    st.text_area("Description", value=edited.suggested_description, key=f"syn_desc_{key}")
    st.selectbox(
        "Action",
        options=["block", "redact", "warn", "escalate"],
        index=["block", "redact", "warn", "escalate"].index(edited.suggested_action)
        if edited.suggested_action in ("block", "redact", "warn", "escalate")
        else 2,
        key=f"syn_action_{key}",
    )
    st.multiselect(
        "Scope",
        options=["input", "output"],
        default=default_scope,
        key=f"syn_scope_{key}",
    )
    st.selectbox(
        "Detection method",
        options=["llm", "ensemble", "regex"],
        index=["llm", "ensemble", "regex"].index(edited.detection_method)
        if edited.detection_method in ("llm", "ensemble", "regex")
        else 0,
        key=f"syn_method_{key}",
    )
    col_in, col_out = st.columns(2)
    with col_in:
        st.slider(
            "Threshold (input)",
            0.0,
            1.0,
            float(edited.suggested_threshold_input or 0.85),
            0.05,
            key=f"syn_thresh_in_{key}",
        )
    with col_out:
        st.slider(
            "Threshold (output)",
            0.0,
            1.0,
            float(edited.suggested_threshold_output or 0.85),
            0.05,
            key=f"syn_thresh_out_{key}",
        )
    st.text_area(
        "LLM prompt",
        value=edited.suggested_llm_prompt,
        height=120,
        key=f"syn_prompt_{key}",
    )
    st.text_area(
        "Regex patterns (one per line, for regex/ensemble)",
        value="\n".join(edited.suggested_patterns),
        height=80,
        key=f"syn_patterns_{key}",
    )

    _save_edits_from_form(candidate)

    reviewed = st.checkbox(
        "I have reviewed this policy rule, understand its implications, "
        "and approve it for enforcement",
        key=f"syn_reviewed_{key}",
    )
    if st.button("Mark as approved", disabled=not reviewed, key=f"syn_approve_{key}"):
        st.session_state.synthesis_approved_keys.add(key)
        st.success(f"Marked `{edited.suggested_name}` as approved for commit.")

    approved_keys: set[str] = st.session_state.synthesis_approved_keys
    if approved_keys:
        st.caption(f"Approved for commit: {len(approved_keys)} rule(s)")

    st.divider()
    if st.button("Commit all approved rules", type="primary", use_container_width=True):
        if not approved_keys:
            st.warning("No approved rules to commit.")
            return

        doc = copy.deepcopy(load_policies_doc())
        policies: list[dict[str, Any]] = list(doc.get("policies", []))
        existing_ids = {str(p.get("id")) for p in policies if p.get("id")}

        if len(policies) + len(approved_keys) > MAX_POLICIES:
            st.error(
                f"Cannot add {len(approved_keys)} rule(s): policy count would exceed "
                f"{MAX_POLICIES}."
            )
            return

        for cand in candidates:
            if cand.candidate_key not in approved_keys:
                continue
            final = _get_edited_candidate(cand)
            enabled = final.confidence != "low"
            policy = candidate_to_policy(
                final, existing_ids=existing_ids, enabled=enabled
            )
            existing_ids.add(policy["id"])
            policies.append(policy)

        doc["policies"] = policies
        errors = validate_policies_doc(doc)
        if errors:
            show_validation_errors(errors)
            return

        try:
            backup_path = backup_policies_file()
        except OSError as exc:
            st.error(f"Backup failed: {exc}")
            return

        save_policies_doc(doc)
        refresh_policy_dashboard()
        record_policy_version(doc, "policy synthesis")
        close_policy_engine()
        st.session_state.synthesis_approved_keys = set()
        st.success(
            f"Committed {len(approved_keys)} rule(s). Backup: `{backup_path.name}`"
        )
        st.download_button(
            "Download updated policies.json",
            data=json.dumps(doc, indent=2) + "\n",
            file_name="policies.json",
            mime="application/json",
            use_container_width=True,
        )
        st.rerun()
