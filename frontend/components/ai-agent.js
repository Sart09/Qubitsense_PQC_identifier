const AGENT_SYSTEM_PROMPT = `You are Qubit, an AI assistant embedded in the Qubitsense PQC Identifier platform —
a security tool that scans domains for post-quantum cryptographic risk.

Your Capabilities
You can answer questions AND trigger actions on the platform. When you need to
perform an action, append it on a new line at the END of your response in this
exact format:
ACTION:FUNCTION_NAME:PARAMETER

Available actions:
ACTION:NAVIGATE:/page.html         → Navigate to a page
ACTION:START_SCAN:domain.com       → Trigger a domain scan
ACTION:SHOW_RESULTS:domain.com     → Open scan results for a domain
ACTION:OPEN_SCHEDULE_MODAL:domain  → Open the schedule creation modal
ACTION:CREATE_SCHEDULE:domain:freq → Directly create a schedule (freq: daily, weekly, monthly)
ACTION:FILTER_FAILURES:job_id      → Filter scan table to show only failures
ACTION:HIGHLIGHT_RISK:score        → Highlight all subdomains above risk score

Only include ONE action per response. If no action is needed, do not include the
ACTION line at all.

Platform Knowledge
Quantum Risk Score (0–100)
Weighted factors:
Key exchange risk: 30% (RSA, ECDH = high risk; Kyber = safe)
Signature risk: 20% (RSA, ECDSA = vulnerable to Shor's algorithm)
TLS version risk: 15% (TLS 1.0/1.1 = critical, TLS 1.2 = moderate, TLS 1.3 = low)
Key size: 15% (RSA < 2048 = critical, RSA 2048 = high, RSA 4096 = moderate)
Certificate validity: 10% (expired or expiring soon = higher risk)
Cipher strength: 10% (RC4, DES, 3DES = critical; AES-128 = moderate; AES-256 = low)

Score ranges:
0–25: Low quantum risk
26–50: Moderate risk — begin PQC migration planning
51–75: High risk — prioritize migration
76–100: Critical — immediate action required

Failure Codes
DNS_NO_RECORD: Ghost subdomain from CT logs — safe to ignore
TCP_TIMEOUT: Host behind firewall — unreachable publicly
TCP_REFUSED: Host up but no HTTPS on port 443
TLS_HANDSHAKE_FAIL: WAF/CDN blocking the scanner
TLS_LEGACY_CIPHER: Server uses outdated cipher suites
CERT_MISMATCH: Certificate doesn't match the hostname

HNDL (Harvest Now, Decrypt Later)
Adversaries record encrypted traffic today to decrypt later using quantum computers.
High HNDL risk services: banking, healthcare, government, authentication systems.
Any service transmitting data with a confidentiality requirement beyond 5–10 years
is at HNDL risk even before quantum computers exist.

PQC Safe Algorithms (NIST Standardized)
Key encapsulation: CRYSTALS-Kyber (ML-KEM)
Signatures: CRYSTALS-Dilithium (ML-DSA), FALCON, SPHINCS+
TLS hybrid: X25519Kyber768 (used in TLS 1.3 with PQC extension)

Pages in the Platform
/index.html or / → Main scan submission page
/dashboard.html  → Scan results and history
/schedules.html  → Scheduled scan management
/login.html      → Authentication

Current Page Context
The user is currently on: {CURRENT_PAGE}
The last scanned domain was: {LAST_DOMAIN}
The user's name is: {USERNAME}

Personality
Be concise — security professionals don't want long essays
Lead with the direct answer, then explain if needed
Use technical terms correctly but explain acronyms on first use
When a user asks what to DO about a risk, give specific, actionable steps
Never make up scan results — if you don't have the data, say so
Keep responses under 150 words unless the user asks for a detailed explanation`;

class QubitsenseAgent {
    constructor() {
        this.isOpen = false;
        this.conversationHistory = [];
        this.apiKey = null;
        this.currentPage = window.location.pathname;
        this.lastDomain = localStorage.getItem('last_scanned_domain') || 'None';
        this.username = localStorage.getItem('email') || 'User'; // Adjust mapping to match typical storage
        this.render();
        this.attachEvents();
        this.initKey();
    }

    async initKey() {
        const token = localStorage.getItem('token');
        if (!token) {
            this.apiKeyError = "NO_AUTH_TOKEN";
            return;
        }
        try {
            const res = await fetch('/api/config/agent-key', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                this.apiKey = data.key;
                window.QUBITSENSE_GEMINI_KEY = this.apiKey;
                if (!this.apiKey) { this.apiKeyError = "EMPTY_KEY_FROM_BACKEND_DOTENV"; }
            } else {
                this.apiKeyError = `API_HTTP_ERROR_${res.status}`;
            }
        } catch (e) {
            this.apiKeyError = "FETCH_EXCEPTION_" + e.message;
        }
    }

    // ACTION HANDLERS — map action strings to JS functions
    actionHandlers = {
        'NAVIGATE': (param) => { window.location.href = param; },

        'START_SCAN': (domain) => {
            const input = document.getElementById('targetInput') || document.getElementById('domain-input');
            const btn = document.getElementById('scanBtn') || document.getElementById('scan-btn');
            if (input && btn) {
                input.value = domain;
                btn.click();
            } else {
                window.location.href = `/?domain=${domain}&autostart=true`;
            }
        },

        'SHOW_RESULTS': (domain) => {
            window.location.href = `/user_dashboard.html`; // Generic routing, dashboard fetches domain logic normally
        },

        'OPEN_SCHEDULE_MODAL': (domain) => {
            if (typeof openCreateModal === 'function') {
                openCreateModal();
                setTimeout(() => {
                    const el = document.getElementById('domain');
                    if (el) el.value = domain;
                }, 100);
            } else {
                window.location.href = `/schedules.html`;
            }
        },

        'CREATE_SCHEDULE': async (param) => {
            const parts = param.split(':');
            const domain = parts[0];
            const frequency = parts[1] || 'daily';
            const token = localStorage.getItem('token');

            // Qubit specific feedback
            window.qubitAgent.addBubble('agent', `> Initiating ${frequency} schedule for ${domain}...`);

            if (!token) {
                window.qubitAgent.addBubble('agent', `> Error: You must be logged in to schedule scans.`);
                return;
            }

            try {
                const res = await fetch('/api/schedules/create', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({
                        domain: domain,
                        frequency: frequency,
                        start_immediately: true
                    })
                });
                if (res.ok) {
                    window.qubitAgent.addBubble('agent', `> Deployment Successful: ${domain} is now on a ${frequency} surveillance plan.`);
                    if (window.location.pathname.includes('schedules')) {
                        setTimeout(() => window.location.reload(), 1500);
                    }
                } else {
                    const data = await res.json();
                    window.qubitAgent.addBubble('agent', `> Failure: ${data.detail || 'Could not register schedule.'}`);
                }
            } catch (e) {
                window.qubitAgent.addBubble('agent', `> Error: Connection lost during scheduling operation.`);
            }
        },

        'FILTER_FAILURES': (jobId) => {
            // Assume UI implements filter function OR just console log for now
            if (typeof filterByStatus === 'function') filterByStatus('failed', jobId);
        },

        'HIGHLIGHT_RISK': (score) => {
            if (typeof highlightRiskAbove === 'function') highlightRiskAbove(score);
        }
    };

    parseAndExecuteAction(responseText) {
        let cleanText = responseText;
        const actionRegex = /ACTION:\s*([A-Z_]+)\s*:\s*([^\s<`]+)/i;
        const match = responseText.match(actionRegex);

        if (match) {
            const fn = match[1].toUpperCase();
            const param = match[2].trim();
            if (this.actionHandlers[fn]) {
                setTimeout(() => this.actionHandlers[fn](param), 600);
            }
            // Strip out action lines and aggressive code block artifacts natively
            const lines = cleanText.split('\n');
            cleanText = lines.filter(l => !l.includes('ACTION:') && l.trim() !== '```').join('\n').trim();
        }
        return cleanText;
    }

    buildSystemPrompt() {
        return AGENT_SYSTEM_PROMPT
            .replace('{CURRENT_PAGE}', this.currentPage)
            .replace('{LAST_DOMAIN}', this.lastDomain)
            .replace('{USERNAME}', this.username);
    }

    async sendMessage(userText) {
        // Prevent action if no key logic available
        if (!this.apiKey) {
            let contextErr = this.apiKeyError || "UNKNOWN_ERROR";
            this.addBubble('agent', `> ERROR: System unconfigured. Trace: [${contextErr}]<br>> Please authenticate into dashboard or fix .env payload.`);
            return;
        }

        this.addBubble('user', userText);
        this.showTypingIndicator();

        this.conversationHistory.push({ role: 'user', parts: [{ text: userText }] });

        try {
            const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${this.apiKey}`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    systemInstruction: {
                        parts: [{ text: this.buildSystemPrompt() }]
                    },
                    contents: this.conversationHistory
                })
            });

            const data = await response.json();

            if (!response.ok) {
                console.error("Qubit Error:", data.error.message);
                throw new Error(data.error?.message || "Unknown Gemini API Error");
            }

            const rawText = data.candidates[0].content.parts[0].text;
            const cleanText = this.parseAndExecuteAction(rawText);

            this.conversationHistory.push({ role: 'model', parts: [{ text: rawText }] });
            this.hideTypingIndicator();
            this.addBubble('agent', cleanText);

        } catch (err) {
            this.hideTypingIndicator();
            console.error("Qubit fetch error:", err);
            this.addBubble('agent', '> CONNECTION ERROR:: ' + err.message);
        }
    }

    addBubble(role, text) {
        const msgContainer = document.getElementById('qubit-messages');
        const typing = document.getElementById('qubit-typing');
        if (typing) typing.remove();

        msgContainer.insertAdjacentHTML('beforeend', `<div class="qubit-bubble ${role}">${text}</div>`);
        msgContainer.scrollTop = msgContainer.scrollHeight;
    }

    showTypingIndicator() {
        const msgContainer = document.getElementById('qubit-messages');
        msgContainer.insertAdjacentHTML('beforeend', `
            <div id="qubit-typing">
                <span></span><span></span><span></span>
            </div>
        `);
        msgContainer.scrollTop = msgContainer.scrollHeight;
    }

    hideTypingIndicator() {
        const typing = document.getElementById('qubit-typing');
        if (typing) typing.remove();
    }

    render() {
        // Shield Icon payload
        const shieldIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-half"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 22V2"/></svg>`;

        // Send Arrow Icon
        const sendArrowIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M22 12l-18 12v-24z"/></svg>`;

        document.body.insertAdjacentHTML('beforeend', `
            <div id="qubit-agent-btn" title="Ask Qubit">
                ${shieldIcon}
            </div>
            <div id="qubit-agent-panel" class="qubit-hidden">
                <div id="qubit-header">
                    <span class="header-label"><span class="qubit-pulse-dot"></span>QUBIT</span>
                    <button id="qubit-close">✕</button>
                </div>
                <div id="qubit-messages">
                    <div class="qubit-bubble agent">
                        > Qubit online.<br>
                        > I can help you scan domains, interpret risk scores, navigate the platform, and explain PQC concepts.<br>
                        > Awaiting query...
                    </div>
                </div>
                <div id="qubit-suggestions">
                    <button class="qubit-chip">Scan a domain</button>
                    <button class="qubit-chip">Explain my risk score</button>
                    <button class="qubit-chip">What is HNDL?</button>
                    <button class="qubit-chip">Schedule a scan</button>
                </div>
                <div id="qubit-input-row">
                    <input id="qubit-input" type="text" placeholder="cmd: " autocomplete="off"/>
                    <button id="qubit-send" title="Send Payload">${sendArrowIcon}</button>
                </div>
            </div>
        `);
    }

    attachEvents() {
        const btn = document.getElementById('qubit-agent-btn');
        const panel = document.getElementById('qubit-agent-panel');
        const closeBtn = document.getElementById('qubit-close');

        btn.addEventListener('click', () => {
            this.isOpen = !this.isOpen;
            if (this.isOpen) {
                panel.classList.remove('qubit-hidden');
            } else {
                panel.classList.add('qubit-hidden');
            }
        });

        closeBtn.addEventListener('click', () => {
            this.isOpen = false;
            panel.classList.add('qubit-hidden');
        });

        const sendBtn = document.getElementById('qubit-send');
        const inputFld = document.getElementById('qubit-input');

        const sendHandler = () => {
            const text = inputFld.value.trim();
            if (text) {
                this.sendMessage(text);
                inputFld.value = '';
            }
        };

        sendBtn.addEventListener('click', sendHandler);
        inputFld.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendHandler();
        });

        // Chips
        document.querySelectorAll('.qubit-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const text = chip.textContent;
                this.sendMessage(text);
            });
        });
    }
}

// Auto-initialize
window.addEventListener('DOMContentLoaded', () => {
    window.qubitAgent = new QubitsenseAgent();
});
