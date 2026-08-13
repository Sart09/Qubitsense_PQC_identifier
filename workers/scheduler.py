"""
scheduler.py — Polls SQLite every 60 seconds for due scheduled scans
and enqueues them into the jobs (scans) table for scan_worker.py to process.
"""

import asyncio
import sqlite3
import sys
import os
from datetime import datetime, timedelta, timezone

# Ensure the backend package is on the path when running as a script.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from backend.database import get_connection

POLL_INTERVAL_SECONDS = 60

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

def calculate_next_run(frequency: str, custom_hours: int = None) -> datetime:
    now = datetime.now(timezone.utc)
    if frequency == 'daily':
        return now + timedelta(days=1)
    elif frequency == 'weekly':
        return now + timedelta(weeks=1)
    elif frequency == 'monthly':
        return now + timedelta(days=30)
    elif frequency == 'custom' and custom_hours:
        return now + timedelta(hours=custom_hours)
    return now + timedelta(days=1)

async def poll_and_enqueue():
    while True:
        conn = None
        try:
            conn = get_connection()
            now = datetime.now(timezone.utc).isoformat()

            # Find all active schedules whose next_run_at has passed
            due = conn.execute("""
                SELECT id, domain, frequency, custom_interval_hours, created_by
                FROM scheduled_scans
                WHERE is_active = 1 AND next_run_at <= ?
            """, (now,)).fetchall()

            for schedule in due:
                # Insert a new job into the scans table
                cursor = conn.execute("""
                    INSERT INTO scans (target_domain, parent_domain, status, source, created_at)
                    VALUES (?, ?, 'queued', 'scheduler', ?)
                """, (schedule['domain'], schedule['domain'], now))
                scan_id = cursor.lastrowid
                
                # Link to user
                conn.execute(
                    "INSERT INTO user_scans (user_id, scan_id, domain, status, created_at) VALUES (?, ?, ?, ?, ?);",
                    (schedule['created_by'], scan_id, schedule['domain'], 'queued', now)
                )

                # Insert into run history
                conn.execute("""
                    INSERT INTO schedule_run_history 
                    (schedule_id, scan_id, status, triggered_at)
                    VALUES (?, ?, 'triggered', ?)
                """, (schedule['id'], scan_id, now))

                # Calculate and update next_run_at
                next_run = calculate_next_run(
                    schedule['frequency'], 
                    schedule['custom_interval_hours']
                )
                conn.execute("""
                    UPDATE scheduled_scans
                    SET last_run_at = ?,
                        next_run_at = ?,
                        last_scan_id = ?,
                        run_count = run_count + 1
                    WHERE id = ?
                """, (now, next_run.isoformat(), scan_id, schedule['id']))
                
                print(f"[SCHEDULER] Queued scheduled scan for {schedule['domain']} (Scan ID: {scan_id})")

            conn.commit()

        except Exception as e:
            # A failure part-way through the `due` loop leaves an open write
            # transaction. Roll it back so the batch is all-or-nothing rather
            # than half-enqueued (a scan queued with no schedule_run_history
            # row, or next_run_at never advanced -> the same scan re-fires
            # every 60s).
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
            print(f"[SCHEDULER ERROR] {e}")
        finally:
            # get_connection() opens a NEW connection per call, so the old
            # close()-inside-try leaked one connection per poll whenever the
            # body raised — and a leaked connection mid-write holds SQLite's
            # write lock, which surfaces as "database is locked" over in
            # scan_worker/server rather than here.
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        await asyncio.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    print("[SCHEDULER] Starting — polling every 60 seconds")
    try:
        asyncio.run(poll_and_enqueue())
    except KeyboardInterrupt:
        # Ctrl+C cancels the pending asyncio.sleep, which asyncio.run
        # re-raises as KeyboardInterrupt. Expected shutdown, not a crash —
        # swallow it so the console shows a clean stop instead of a
        # two-deep CancelledError traceback.
        print("\n[SCHEDULER] Stopped")
