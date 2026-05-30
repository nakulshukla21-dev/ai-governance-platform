"""Tests for regulatory_ingest.py."""

from __future__ import annotations

from io import BytesIO

import regulatory_ingest as ri


def test_regulatory_sources_count() -> None:
    assert len(ri.REGULATORY_SOURCES) == 6
    assert ri.source_by_id("eu-ai-act") is not None


def test_normalize_whitespace() -> None:
    assert ri._normalize_whitespace("a  \n\n\n  b") == "a \n\n b"


def test_extract_uploaded_pdf_empty() -> None:
    text, err = ri.extract_uploaded_pdf(BytesIO(b""), "empty.pdf")
    assert err is not None
    assert text == ""


def test_build_synthesis_corpus_no_sources() -> None:
    corpus, errors = ri.build_synthesis_corpus(
        uploaded_pdfs=[],
        regulatory_source_ids=[],
    )
    assert corpus == ""
    assert errors == []


def test_build_synthesis_corpus_unknown_source() -> None:
    corpus, errors = ri.build_synthesis_corpus(
        uploaded_pdfs=[],
        regulatory_source_ids=["not-a-real-source"],
    )
    assert corpus == ""
    assert len(errors) == 1
