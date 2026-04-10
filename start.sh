#!/bin/bash
echo "Starting Qubitsense Complete Stack..."

# Terminate all child processes on exit
trap 'kill $(jobs -p)' EXIT

python backend/server.py &
python workers/scan_worker.py &
python workers/scheduler.py &

echo "All processes started. Press Ctrl+C to stop all."
wait
