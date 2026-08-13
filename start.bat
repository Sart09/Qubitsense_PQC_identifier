@echo off
echo Starting Qubitsense Complete Stack...

REM Prefer this project's virtualenv if it exists (guarantees the exact
REM dependencies from requirements.txt, e.g. pyotp/qrcode for MFA, are
REM present) — otherwise fall back to whatever "python" resolves to on
REM PATH, which requires `pip install -r requirements.txt` to have been
REM run first. Without this, a global interpreter missing a dependency
REM crashes instantly and the /c window used to just vanish with no
REM visible error.
set "PYTHON_EXE=python"
if exist "%~dp0.venv\Scripts\python.exe" set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"

REM /k (not /c) keeps each window open after the command exits, so a
REM crash's traceback stays on screen instead of the window closing
REM itself before it can be read.
start "API Server" cmd /k ""%PYTHON_EXE%" backend\server.py"
start "Scan Worker" cmd /k ""%PYTHON_EXE%" workers\scan_worker.py"
start "Scheduler Worker" cmd /k ""%PYTHON_EXE%" workers\scheduler.py"

echo All processes started in background windows.
echo If a window shows a ModuleNotFoundError, run: pip install -r requirements.txt
pause
