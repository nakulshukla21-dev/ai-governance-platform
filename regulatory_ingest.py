"""
Regulatory source ingestion for Policy Synthesis.

Fetch/clean logic synced from ai-governance-navigator/server.py (ingest helpers).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO, Final, Literal

import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader

IngestMode = Literal["focused", "full"]

# Navigator-style Q&A excerpt cap
FOCUSED_MAX_CHARS: Final[int] = 8_000
# Policy synthesis: more text per source
SYNTHESIS_MAX_CHARS: Final[int] = 12_000
COMBINED_CORPUS_MAX_CHARS: Final[int] = 80_000
REQUEST_TIMEOUT: Final[int] = 30
USER_AGENT: Final[str] = "AI-Governance-Platform/1.0"

STRIP_TAGS: Final[tuple[str, ...]] = (
    "script",
    "style",
    "nav",
    "footer",
    "header",
    "aside",
    "noscript",
    "iframe",
)

DEFAULT_SYNTHESIS_FOCUS: Final[str] = (
    "enforceable obligations requirements prohibitions duties controls "
    "must shall prohibited compliance governance risk"
)


@dataclass(frozen=True)
class RegulatorySource:
    id: str
    label: str
    url: str
    kind: Literal["html", "pdf", "india_combined"]


REGULATORY_SOURCES: tuple[RegulatorySource, ...] = (
    RegulatorySource(
        id="eu-ai-act",
        label="EU AI Act",
        url="https://artificialintelligenceact.eu/the-act/",
        kind="html",
    ),
    RegulatorySource(
        id="nist-ai-rmf",
        label="NIST AI RMF",
        url="https://airc.nist.gov/Docs/1",
        kind="html",
    ),
    RegulatorySource(
        id="mas-ai-guidance",
        label="MAS AI Guidance (Singapore)",
        url="https://www.mas.gov.sg/regulation/explainers/ai-in-financial-services",
        kind="html",
    ),
    RegulatorySource(
        id="uk-ai-policy",
        label="UK AI Policy",
        url=(
            "https://www.gov.uk/government/publications/"
            "ai-regulation-a-pro-innovation-approach/white-paper"
        ),
        kind="html",
    ),
    RegulatorySource(
        id="fatf-ai-guidance",
        label="FATF AI Guidance",
        url=(
            "https://www.fatf-gafi.org/en/publications/Digitaltransformation/"
            "Guidance-AI-in-financial-crime.html"
        ),
        kind="html",
    ),
    RegulatorySource(
        id="india-ai-policy",
        label="India (NITI Aayog + DPDPA)",
        url="https://www.niti.gov.in/sites/default/files/2021-02/Responsible-AI-22022021.pdf",
        kind="india_combined",
    ),
)

INDIA_NITI_AI_URL: Final[str] = (
    "https://www.niti.gov.in/sites/default/files/2021-02/Responsible-AI-22022021.pdf"
)
INDIA_DPDP_URL: Final[str] = "https://www.meity.gov.in/data-protection-framework"

_SOURCES_BY_ID: dict[str, RegulatorySource] = {s.id: s for s in REGULATORY_SOURCES}


def source_by_id(source_id: str) -> RegulatorySource | None:
    return _SOURCES_BY_ID.get(source_id)


def _normalize_whitespace(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _topic_keywords(topic: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+", topic.lower())
    return [word for word in words if len(word) > 2]


def _select_relevant_text(full_text: str, topic: str, *, max_chars: int) -> str:
    if not full_text:
        return ""

    keywords = _topic_keywords(topic)
    if not keywords:
        return full_text[:max_chars]

    paragraphs = [part.strip() for part in re.split(r"\n{2,}", full_text) if part.strip()]
    if not paragraphs:
        return full_text[:max_chars]

    scored: list[tuple[int, str]] = []
    for paragraph in paragraphs:
        lowered = paragraph.lower()
        score = sum(lowered.count(keyword) for keyword in keywords)
        if score:
            scored.append((score, paragraph))

    if scored:
        scored.sort(key=lambda item: item[0], reverse=True)
        selected = "\n\n".join(paragraph for _, paragraph in scored)
        return selected[:max_chars]

    return full_text[:max_chars]


def _html_to_text(html: str, topic: str, *, max_chars: int, mode: IngestMode) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag_name in STRIP_TAGS:
        for tag in soup.find_all(tag_name):
            tag.decompose()

    text = soup.get_text(separator="\n")
    cleaned = _normalize_whitespace(text)
    if not cleaned:
        return "Error: page contained no readable text."

    if mode == "full":
        return cleaned[:max_chars]
    return _select_relevant_text(cleaned, topic, max_chars=max_chars)


def _pdf_bytes_to_text(pdf_bytes: bytes, topic: str, *, max_chars: int, mode: IngestMode) -> str:
    reader = PdfReader(BytesIO(pdf_bytes))
    pages: list[str] = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages.append(text.strip())

    cleaned = _normalize_whitespace("\n\n".join(pages))
    if not cleaned:
        return "Error: PDF contained no readable text."

    if mode == "full":
        return cleaned[:max_chars]
    return _select_relevant_text(cleaned, topic, max_chars=max_chars)


def _http_get(url: str) -> requests.Response:
    return requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )


def fetch_html_source(url: str, topic: str, *, mode: IngestMode = "full") -> str:
    max_chars = SYNTHESIS_MAX_CHARS if mode == "full" else FOCUSED_MAX_CHARS
    try:
        response = _http_get(url)
        response.raise_for_status()
    except requests.RequestException as exc:
        return f"Error fetching {url}: {exc}"

    try:
        excerpt = _html_to_text(response.text, topic, max_chars=max_chars, mode=mode)
        if excerpt.startswith("Error:"):
            return f"Error processing content from {url}: {excerpt.removeprefix('Error: ')}"
        header = f"Source: {url}\nTopic: {topic.strip() or 'general'}\n\n"
        return (header + excerpt)[:max_chars]
    except Exception as exc:
        return f"Error processing content from {url}: {exc}"


def fetch_pdf_url(url: str, topic: str, *, mode: IngestMode = "full") -> str:
    max_chars = SYNTHESIS_MAX_CHARS if mode == "full" else FOCUSED_MAX_CHARS
    try:
        response = _http_get(url)
        response.raise_for_status()
    except requests.RequestException as exc:
        return f"Error fetching {url}: {exc}"

    try:
        excerpt = _pdf_bytes_to_text(response.content, topic, max_chars=max_chars, mode=mode)
        if excerpt.startswith("Error:"):
            return f"Error processing content from {url}: {excerpt.removeprefix('Error: ')}"
        header = f"Source: {url}\n\n"
        return (header + excerpt)[:max_chars]
    except Exception as exc:
        return f"Error processing content from {url}: {exc}"


def fetch_india_combined(topic: str, *, mode: IngestMode = "full") -> str:
    max_chars = SYNTHESIS_MAX_CHARS if mode == "full" else FOCUSED_MAX_CHARS
    section_limit = max_chars // 2
    niti_content = fetch_pdf_url(INDIA_NITI_AI_URL, topic, mode=mode)
    dpdp_content = fetch_html_source(INDIA_DPDP_URL, topic, mode=mode)
    if len(niti_content) > section_limit:
        niti_content = niti_content[:section_limit]
    if len(dpdp_content) > section_limit:
        dpdp_content = dpdp_content[:section_limit]

    combined = "\n".join(
        [
            f"Topic: {topic.strip() or 'general'}",
            "",
            "=== NITI Aayog Responsible AI Principles ===",
            f"Source: {INDIA_NITI_AI_URL}",
            "",
            niti_content,
            "",
            "=== Digital Personal Data Protection Act (India) ===",
            f"Source: {INDIA_DPDP_URL}",
            "",
            dpdp_content,
        ]
    )
    return combined[:max_chars]


def fetch_regulatory_source(
    source_id: str,
    focus: str = "",
    *,
    mode: IngestMode = "full",
) -> str:
    """Fetch one allowlisted regulatory source by id."""
    source = source_by_id(source_id)
    if source is None:
        return f"Error: unknown regulatory source '{source_id}'"

    topic = focus.strip() or DEFAULT_SYNTHESIS_FOCUS
    if source.kind == "html":
        return fetch_html_source(source.url, topic, mode=mode)
    if source.kind == "pdf":
        return fetch_pdf_url(source.url, topic, mode=mode)
    if source.kind == "india_combined":
        return fetch_india_combined(topic, mode=mode)
    return f"Error: unsupported source kind for '{source_id}'"


def extract_uploaded_pdf(uploaded: BinaryIO, filename: str = "upload.pdf") -> tuple[str, str | None]:
    """Return (text, error_message). error_message is set on failure."""
    try:
        reader = PdfReader(uploaded)
        pages: list[str] = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                pages.append(text.strip())
        cleaned = _normalize_whitespace("\n\n".join(pages))
        if not cleaned:
            return "", f"{filename}: PDF contained no readable text."
        header = f"=== Uploaded internal document: {filename} ===\n\n"
        return header + cleaned[:SYNTHESIS_MAX_CHARS], None
    except Exception as exc:
        return "", f"{filename}: {exc}"


def build_synthesis_corpus(
    *,
    uploaded_pdfs: list[tuple[str, bytes]],
    regulatory_source_ids: list[str],
    focus: str = "",
    mode: IngestMode = "full",
) -> tuple[str, list[str]]:
    """
    Combine PDF uploads and selected regulatory sources into one document.

    Returns (corpus_text, list_of_error_messages).
    """
    errors: list[str] = []
    sections: list[str] = []
    topic = focus.strip() or DEFAULT_SYNTHESIS_FOCUS

    for filename, raw in uploaded_pdfs:
        text, err = extract_uploaded_pdf(BytesIO(raw), filename)
        if err:
            errors.append(err)
        elif text:
            sections.append(text)

    for source_id in regulatory_source_ids:
        label = source_by_id(source_id)
        name = label.label if label else source_id
        content = fetch_regulatory_source(source_id, topic, mode=mode)
        if content.startswith("Error"):
            errors.append(f"{name}: {content}")
        else:
            sections.append(f"=== Regulatory source: {name} ({source_id}) ===\n\n{content}")

    if not sections:
        return "", errors

    combined = "\n\n---\n\n".join(sections)
    if len(combined) > COMBINED_CORPUS_MAX_CHARS:
        combined = (
            combined[:COMBINED_CORPUS_MAX_CHARS]
            + "\n\n[Corpus truncated for synthesis context limit.]"
        )
    return combined, errors
