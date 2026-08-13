/**
 * Core Logic for Schedules Dashboard
 */

function authHeaders() {
    return { "Authorization": `Bearer ${localStorage.getItem('token')}` };
}

// If the token is missing/expired, send the user back to login with a
// reason instead of leaving every action on this page failing silently.
function handleAuthFailure() {
    localStorage.removeItem('token');
    localStorage.removeItem('email');
    localStorage.removeItem('user_id');
    window.location.href = '/login?reason=session_expired';
}

document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem('token');
    if (!token) window.location.href = "/login";
    // The signed-in email is shown by the shared sidebar (components/sidebar.js)
    // now, which reads it from localStorage itself — no local element to fill in.

    loadSchedules();
    setInterval(loadSchedules, 30000); // 30 sec auto-refresh

    document.getElementById("createForm").addEventListener("submit", async (e) => {
        e.preventDefault();
        const f = document.getElementById("frequency").value;
        const domain = document.getElementById("domain").value.trim();
        if (!domain) {
            alert("Enter a target domain first.");
            return;
        }
        const payload = {
            domain,
            frequency: f,
            custom_interval_hours: f === "custom" ? parseInt(document.getElementById("customHours").value, 10) : null,
            start_immediately: document.getElementById("startNow").checked,
            notify_on_change: document.getElementById("notifyChange").checked
        };
        if (f === "custom" && (!payload.custom_interval_hours || payload.custom_interval_hours < 1)) {
            alert("Enter a valid interval in hours for a custom schedule.");
            return;
        }

        const submitBtn = e.target.querySelector('button[type="submit"]');
        const origLabel = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Scheduling…';

        try {
            const res = await fetch("/api/schedules/create", {
                method: "POST",
                headers: { "Content-Type": "application/json", ...authHeaders() },
                body: JSON.stringify(payload)
            });
            if (res.status === 401) return handleAuthFailure();
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert("Error: " + (err.detail || `Failed to create schedule (${res.status})`));
                return;
            }
            closeCreateModal();
            await loadSchedules();
        } catch (err) {
            console.error(err);
            alert("Could not reach the server: " + err.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = origLabel;
        }
    });
});

function logout() {
    localStorage.clear();
    window.location.href = "/login";
}

function openCreateModal() {
    document.getElementById("createForm").reset();
    document.getElementById("customHoursWrapper").classList.add("hidden");
    document.getElementById("createModal").classList.remove("hidden");
}
function closeCreateModal() { document.getElementById("createModal").classList.add("hidden"); }
function toggleCustomHours() {
    const w = document.getElementById("customHoursWrapper");
    if (document.getElementById("frequency").value === "custom") w.classList.remove("hidden");
    else w.classList.add("hidden");
}

function closeHistoryModal() { document.getElementById("historyModal").classList.add("hidden"); }

// Countdown logic
function renderCountdown(nextRunAt) {
    const diff = new Date(nextRunAt) - new Date();
    if (diff <= 0) return '<span class="pnb-text-2 font-medium tracking-wide animate-pulse">Running/Due</span>';
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    if (h > 48) return `in ${Math.floor(h / 24)} days`;
    if (h > 0) return `in ${h}h ${m}m`;
    return `in ${m}m`;
}

function renderDate(isoString) {
    if (!isoString) return "—";
    return new Date(isoString).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

async function loadSchedules() {
    const tbody = document.getElementById("schedulesTable");
    try {
        const res = await fetch("/api/schedules/list", { headers: authHeaders() });
        if (res.status === 401) return handleAuthFailure();
        if (!res.ok) throw new Error(`API error ${res.status}`);

        const data = await res.json();
        if (data.schedules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center pnb-text-muted">No schedules configured yet. Click "+ New Schedule" to add one.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.schedules.map(s => {
            const deltaStr = s.risk_delta != null
                ? (s.risk_delta > 0 ? `<span class="score-worsen">▲ +${s.risk_delta}</span>` : (s.risk_delta < 0 ? `<span class="score-improve">▼ ${s.risk_delta}</span>` : `<span class="pnb-text-muted">—</span>`))
                : `<span class="pnb-text-muted">—</span>`;

            const badge = s.is_active ? `<span class="badge badge-active">Active</span>` : `<span class="badge badge-paused">Paused</span>`;
            const playPauseIcon = s.is_active ? `⏸️` : `▶️`;
            const playPauseAction = s.is_active ? `pauseSchedule(${s.id})` : `resumeSchedule(${s.id})`;
            // Icon-action buttons are compact enough that a full .pnb-btn
            // doesn't fit; colours are tied to design-system tokens via
            // inline style instead, per the same rule as the rest of this file.
            const actionBtnStyle = 'style="background:var(--pnb-surface-alt);border:1px solid var(--pnb-border-strong);"';
            const dangerBtnStyle = 'style="background:rgba(208,59,59,.12);border:1px solid rgba(208,59,59,.4);"';

            return `
                <tr class="transition">
                    <td class="p-4 font-bold pnb-text">${s.domain}</td>
                    <td class="p-4 capitalize">${s.frequency}</td>
                    <td class="p-4">${badge}</td>
                    <td class="p-4">${renderDate(s.last_run_at)}</td>
                    <td class="p-4">${s.is_active ? renderCountdown(s.next_run_at) : '—'}</td>
                    <td class="p-4">
                        <div class="flex items-center gap-2">
                            <span class="font-medium">${s.last_risk_score != null ? s.last_risk_score : '—'}</span>
                            <span class="text-xs">${deltaStr}</span>
                        </div>
                    </td>
                    <td class="p-4 text-right space-x-2">
                        <button onclick="runNow(${s.id})" title="Run Now" ${actionBtnStyle} class="hover:scale-110 transition rounded p-1.5 shadow-sm">⚡</button>
                        <button onclick="${playPauseAction}" title="Toggle State" ${actionBtnStyle} class="hover:scale-110 transition rounded p-1.5 shadow-sm">${playPauseIcon}</button>
                        <button onclick="loadHistory(${s.id})" title="History" ${actionBtnStyle} class="hover:scale-110 transition rounded p-1.5 shadow-sm">📜</button>
                        <button onclick="deleteSchedule(${s.id})" title="Delete" ${dangerBtnStyle} class="hover:scale-110 transition rounded p-1.5 shadow-sm">🗑️</button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (err) {
        console.error('[Schedules] Failed to load:', err);
        tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center" style="color:var(--pnb-risk-critical);">Couldn't load schedules: ${err.message}. <button onclick="loadSchedules()" class="underline font-semibold ml-1">Retry</button></td></tr>`;
    }
}

async function pauseSchedule(id) {
    try {
        const res = await fetch(`/api/schedules/${id}/pause`, { method: 'PATCH', headers: authHeaders() });
        if (res.status === 401) return handleAuthFailure();
        if (!res.ok) throw new Error(`API error ${res.status}`);
        await loadSchedules();
    } catch (err) {
        alert('Could not pause this schedule: ' + err.message);
    }
}

async function resumeSchedule(id) {
    try {
        const res = await fetch(`/api/schedules/${id}/resume`, { method: 'PATCH', headers: authHeaders() });
        if (res.status === 401) return handleAuthFailure();
        if (!res.ok) throw new Error(`API error ${res.status}`);
        await loadSchedules();
    } catch (err) {
        alert('Could not resume this schedule: ' + err.message);
    }
}

async function deleteSchedule(id) {
    if (!confirm("Delete this schedule? History runs will be dropped (previous scan results remain).")) return;
    try {
        const res = await fetch(`/api/schedules/${id}`, { method: 'DELETE', headers: authHeaders() });
        if (res.status === 401) return handleAuthFailure();
        if (!res.ok) throw new Error(`API error ${res.status}`);
        await loadSchedules();
    } catch (err) {
        alert('Could not delete this schedule: ' + err.message);
    }
}

async function runNow(id) {
    try {
        const res = await fetch(`/api/schedules/${id}/run-now`, { method: 'POST', headers: authHeaders() });
        if (res.status === 401) return handleAuthFailure();
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            alert("Couldn't queue this scan: " + (err.detail || `API error ${res.status}`));
            return;
        }
        await loadSchedules();
    } catch (err) {
        alert("Couldn't reach the server: " + err.message);
    }
}

async function loadHistory(id) {
    const c = document.getElementById("historyContent");
    document.getElementById("historyModal").classList.remove("hidden");
    c.innerHTML = `<div class="p-8 text-center pnb-text-muted">Loading history…</div>`;

    try {
        const res = await fetch(`/api/schedules/${id}/history`, { headers: authHeaders() });
        if (res.status === 401) return handleAuthFailure();
        if (!res.ok) throw new Error(`API error ${res.status}`);

        const data = await res.json();
        document.getElementById("historyDomain").textContent = data.domain;

        if (data.history.length === 0) {
            c.innerHTML = `<div class="p-8 text-center pnb-text-muted">No scheduled runs found yet.</div>`;
        } else {
            c.innerHTML = data.history.map(h => {
                const icon = h.status === 'completed' ? '✅' : (h.status === 'failed' ? '❌' : '⏳');
                return `
                    <div class="py-4 flex justify-between items-center text-sm">
                        <div>
                            <div class="font-semibold pnb-text">${icon} ${h.status.toUpperCase()}</div>
                            <div class="text-xs pnb-text-muted mt-1">${renderDate(h.triggered_at)} -> ${renderDate(h.completed_at)}</div>
                        </div>
                        <div class="text-right">
                            <div class="font-bold">Score: ${h.risk_score || '—'}</div>
                            <div class="text-xs pnb-text-muted">Subdomains: ${h.subdomains_scanned || '0'} scanned</div>
                        </div>
                    </div>
                `;
            }).join("");
        }
    } catch (err) {
        console.error('[History] Failed to load:', err);
        c.innerHTML = `<div class="p-8 text-center" style="color:var(--pnb-risk-critical);">Couldn't load history: ${err.message}</div>`;
    }
}
