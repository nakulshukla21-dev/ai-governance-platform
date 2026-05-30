# AI Governance Platform

Policy engine (MCP server) and remediation agent for governed LLM interactions in financial services.

## Components

| File | Purpose |
|------|---------|
| `server.py` | FastMCP policy engine (stdio) — scans, roles, query classification |
| `agent.py` | Remediation agent — connects to MCP, enforces policies, calls Claude |
| `config/policies.json` | Detection policies (PII, prompt injection, etc.) |
| `config/roles.json` | Role-based query permissions |

## Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements-dev.txt
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY
```

## Dependencies and `pywin32`

`requirements.txt` does **not** include `pywin32` or Streamlit. On Windows, `mcp` may install `pywin32` automatically (`pywin32>=310; sys_platform == "win32"`). **Streamlit Cloud runs Linux** and will not install `pywin32`.

For local development only, avoid polluting deploy pins:

```bash
pip install -r requirements-dev.txt   # not a frozen export from .venv
```

## Tests

```bash
# Unit tests only (no API key required)
pytest test_agent.py -m "not integration" -v

# Full suite (requires ANTHROPIC_API_KEY)
pytest test_agent.py -v
```

## MCP server (Cursor / Claude Desktop)

```json
{
  "mcpServers": {
    "ai-governance": {
      "command": "python",
      "args": ["/path/to/ai-governance-platform/server.py"],
      "env": {
        "ANTHROPIC_API_KEY": "your-key"
      }
    }
  }
}
```

## Streamlit UI

**Local** (port **8503** via `.streamlit/config.toml` — 8501 = AML knowledge base, 8502 = other app):

```bash
streamlit run app.py
# or
.\run_app.ps1
# different port if needed:
streamlit run app.py --server.port 8504
```

**Streamlit Community Cloud** ignores `server.port` in config and serves on **8501** automatically.

Use `requirements.txt` as your Streamlit Cloud `packages` file (includes `streamlit`, no `pywin32`).

**Note:** The agent spawns `server.py` as a subprocess; hosted Streamlit needs `ANTHROPIC_API_KEY` in app secrets.
