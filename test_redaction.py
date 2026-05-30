"""Tests for redaction module."""

from __future__ import annotations

from redaction import REDACTED_PLACEHOLDER, redact_interaction_entry, redact_text


def test_redact_text_masks_ssn_and_email() -> None:
    text = "Contact me at user@example.com or SSN 123-45-6789"
    redacted = redact_text(text)
    assert "user@example.com" not in redacted
    assert "123-45-6789" not in redacted
    assert REDACTED_PLACEHOLDER in redacted


def test_redact_interaction_entry_redacts_user_fields() -> None:
    entry = {
        "original_input": "SSN 123-45-6789",
        "processed_input": "SSN 123-45-6789",
        "final_response": "Email: a@b.co",
        "input_scan_results": [],
        "output_scan_results": [],
        "remediation_actions": [],
    }
    redacted = redact_interaction_entry(entry)
    assert "123-45-6789" not in redacted["original_input"]
    assert "a@b.co" not in redacted["final_response"]
    assert redacted.get("audit_redacted") is True
