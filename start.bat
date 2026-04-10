@echo off
echo Starting Qubitsense Complete Stack...

start "API Server" cmd /c "python backend/server.py"
start "Scan Worker" cmd /c "python workers/scan_worker.py"
start "Scheduler Worker" cmd /c "python workers/scheduler.py"

echo All processes started in background windows.
pause
