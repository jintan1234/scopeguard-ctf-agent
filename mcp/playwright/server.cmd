@echo off
setlocal
set "ROOT=%~dp0..\.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
if not defined CTF_PLAYWRIGHT_OUTPUT_DIR set "CTF_PLAYWRIGHT_OUTPUT_DIR=%ROOT%\challenges\current\browser-output"
set "OUTPUT=%CTF_PLAYWRIGHT_OUTPUT_DIR%"
set "PLAYWRIGHT_BROWSERS_PATH=%ROOT%\mcp\playwright\browsers"
set "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1"
set "LOCALAPPDATA=%ROOT%\.cache\localappdata"
set "PWMCP_PROFILES_DIR_FOR_TEST=%ROOT%\mcp\playwright\profiles"
if not exist "%OUTPUT%" mkdir "%OUTPUT%"
if not exist "%PLAYWRIGHT_BROWSERS_PATH%" mkdir "%PLAYWRIGHT_BROWSERS_PATH%"
if not exist "%LOCALAPPDATA%" mkdir "%LOCALAPPDATA%"
if not exist "%PWMCP_PROFILES_DIR_FOR_TEST%" mkdir "%PWMCP_PROFILES_DIR_FOR_TEST%"
node "%ROOT%\mcp\playwright\launcher.js" ^
  --headless ^
  --browser chromium ^
  --no-sandbox ^
  --isolated ^
  --timeout-action 10000 ^
  --timeout-navigation 30000 ^
  --console-level warning ^
  --output-dir "%OUTPUT%" ^
  --blocked-origins "http://169.254.169.254;http://127.0.0.1:2375;http://localhost:2375"
