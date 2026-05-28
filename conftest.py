"""Pytest configuration for the AI Governance Platform."""

from __future__ import annotations

import os

import pytest

# Enable async tests via pytest-anyio (@pytest.mark.anyio).
pytest_plugins = ("pytest_anyio",)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: tests that call the Anthropic API and MCP policy server",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return

    skip_integration = pytest.mark.skip(
        reason="ANTHROPIC_API_KEY is not set; skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
