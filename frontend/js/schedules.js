/**
 * Core Logic for Schedules Dashboard
 */

document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem('token');
    const email = localStorage.getItem('email');
    if (!token) window.location.href = "/login";
    document.getElementById("userEmail").textContent = email || '';
    
    loadSchedules();
    setInterval(loadSchedules, 30000); // 30 sec auto-refresh

    document.getElementById("createForm").addEventListener("submit", async (e) => {
        e.preventDefault();
        const f = document.getElementById("frequency").value;
        const payload = {
            domain: document.getElementById("domain").value,
            frequency: f,
            custom_interval_hours: f === "custom" ? parseInt(document.getElementById("customHours").value, 10) : null,
            start_immediately: document.getElementById("startNow").checked,
            notify_on_change: document.getElementById("notifyChange").checked
        };
        
        try {
            const res = await fetch("/api/schedules/create", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
                body: JSON.stringify(payload)
            });
            if (!res.ok) {
                const err = await res.json();
                alert("Error: " + (err.detail || "Failed to create schedule"));
            } else {
                closeCreateModal();
                loadSchedules();
            }
        } catch (e) {
            console.error(e);
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
    if(document.getElementById("frequency").value === "custom") w.classList.remove("hidden");
    else w.classList.add("hidden");
}

function closeHistoryModal() { document.getElementById("historyModal").classList.add("hidden"); }

// Countdown logic
function renderCountdown(nextRunAt) {
    const diff = new Date(nextRunAt) - new Date();
    if (diff <= 0) return '<span class="text-amber-600 font-medium tracking-wide animate-pulse">Running/Due</span>';
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    if (h > 48) return `in ${Math.floor(h/24)} days`;
    if (h > 0) return `in ${h}h ${m}m`;
    return `in ${m}m`;
}

function renderDate(isoString) {
    if (!isoString) return "—";
    return new Date(isoString).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

async function loadSchedules() {
    const res = await fetch("/api/schedules/list", { headers: {"Authorization": `Bearer ${localStorage.getItem('token')}`} });
    if(res.ok) {
        const data = await res.json();
        const tbody = document.getElementById("schedulesTable");
        if(data.schedules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-gray-500">No schedules configured yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.schedules.map(s => {
            const deltaStr = s.risk_delta != null 
                ? (s.risk_delta > 0 ? `<span class="score-worsen">▲ +${s.risk_delta}</span>` : (s.risk_delta < 0 ? `<span class="score-improve">▼ ${s.risk_delta}</span>` : `<span class="text-gray-400">—</span>`))
                : `<span class="text-gray-400">—</span>`;
            
            const badge = s.is_active ? `<span class="badge badge-active">Active</span>` : `<span class="badge badge-paused">Paused</span>`;
            const playPauseIcon = s.is_active ? `⏸️` : `▶️`;
            const playPauseAction = s.is_active ? `pauseSchedule(${s.id})` : `resumeSchedule(${s.id})`;

            return `
                <tr class="hover:bg-gray-50/50 transition border-b border-gray-100">
                    <td class="p-4 font-bold text-indigo-900">${s.domain}</td>
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
                        <button onclick="runNow(${s.id})" title="Run Now" class="hover:scale-110 transition bg-indigo-50 border border-indigo-200 rounded p-1.5 shadow-sm">⚡</button>
                        <button onclick="${playPauseAction}" title="Toggle State" class="hover:scale-110 transition bg-indigo-50 border border-indigo-200 rounded p-1.5 shadow-sm">${playPauseIcon}</button>
                        <button onclick="loadHistory(${s.id})" title="History" class="hover:scale-110 transition bg-indigo-50 border border-indigo-200 rounded p-1.5 shadow-sm">📜</button>
                        <button onclick="deleteSchedule(${s.id})" title="Delete" class="hover:scale-110 transition bg-red-50 border border-red-200 rounded p-1.5 shadow-sm">🗑️</button>
                    </td>
                </tr>
            `;
        }).join("");
    }
}

async function pauseSchedule(id) {
    await fetch(`/api/schedules/${id}/pause`, { method: 'PATCH', headers: {"Authorization": `Bearer ${localStorage.getItem('token')}`} });
    loadSchedules();
}

async function resumeSchedule(id) {
    await fetch(`/api/schedules/${id}/resume`, { method: 'PATCH', headers: {"Authorization": `Bearer ${localStorage.getItem('token')}`} });
    loadSchedules();
}

async function deleteSchedule(id) {
    if(!confirm("Delete this schedule? History runs will be dropped (previous scan results remain).")) return;
    await fetch(`/api/schedules/${id}`, { method: 'DELETE', headers: {"Authorization": `Bearer ${localStorage.getItem('token')}`} });
    loadSchedules();
}

async function runNow(id) {
    alert("Scan queued immediately in the background!");
    await fetch(`/api/schedules/${id}/run-now`, { method: 'POST', headers: {"Authorization": `Bearer ${localStorage.getItem('token')}`} });
    loadSchedules();
}

async function loadHistory(id) {
    const res = await fetch(`/api/schedules/${id}/history`, { headers: {"Authorization": `Bearer ${localStorage.getItem('token')}`} });
    if(res.ok) {
        const data = await res.json();
        document.getElementById("historyDomain").textContent = data.domain;
        const c = document.getElementById("historyContent");
        
        if (data.history.length === 0) {
            c.innerHTML = `<div class="p-8 text-center text-gray-500">No scheduled runs found yet.</div>`;
        } else {
            c.innerHTML = data.history.map(h => {
                const icon = h.status === 'completed' ? '✅' : (h.status === 'failed' ? '❌' : '⏳');
                return `
                    <div class="py-4 flex justify-between items-center text-sm">
                        <div>
                            <div class="font-semibold text-gray-800">${icon} ${h.status.toUpperCase()}</div>
                            <div class="text-xs text-gray-500 mt-1">${renderDate(h.triggered_at)} -> ${renderDate(h.completed_at)}</div>
                        </div>
                        <div class="text-right">
                            <div class="font-bold">Score: ${h.risk_score || '—'}</div>
                            <div class="text-xs text-gray-500">Subdomains: ${h.subdomains_scanned || '0'} scanned</div>
                        </div>
                    </div>
                `;
            }).join("");
        }
        document.getElementById("historyModal").classList.remove("hidden");
    }
}
