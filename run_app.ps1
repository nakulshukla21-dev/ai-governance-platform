# Local launcher — explicit port override (default 8503).
param(
    [int]$Port = 8503
)

Set-Location $PSScriptRoot
& .\.venv\Scripts\streamlit.exe run app.py --server.port $Port
