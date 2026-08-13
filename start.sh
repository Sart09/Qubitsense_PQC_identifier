#!/bin/bash
echo "Starting Qubitsense Complete Stack..."

# Terminate all child processes on exit
trap 'kill $(jobs -p)' EXIT

# Prefer this project's virtualenv if it exists (guarantees the exact
# dependencies from requirements.txt, e.g. pyotp/qrcode for MFA, are
# present) — otherwise fall back to whatever "python" resolves to on
# PATH, which requires `pip install -r requirements.txt` to have been
# run first.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="python"
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
fi

"$PYTHON_BIN" backend/server.py &
"$PYTHON_BIN" workers/scan_worker.py &
"$PYTHON_BIN" workers/scheduler.py &

echo "All processes started. Press Ctrl+C to stop all."
wait
