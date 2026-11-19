@echo off
setlocal
set "ROOT=%~dp0..\.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
set "PYTHONPATH=%ROOT%\tools;%PYTHONPATH%"
if not defined CTF_DOCKER_BROKER_URL set "CTF_DOCKER_BROKER_URL=http://127.0.0.1:8765"
if not defined CTF_DOCKER_BROKER_TOKEN_FILE set "CTF_DOCKER_BROKER_TOKEN_FILE=%ROOT%\config\docker-broker-token"
if defined CTF_PYTHON (
  set "PYTHON=%CTF_PYTHON%"
) else if exist "%ROOT%\.venv\Scripts\python.exe" (
  set "PYTHON=%ROOT%\.venv\Scripts\python.exe"
) else (
  set "PYTHON=python"
)
"%PYTHON%" -m ctf_core.mcp_server
