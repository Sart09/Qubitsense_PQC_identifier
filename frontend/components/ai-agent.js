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

const QUBIT_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" 
    viewBox="0 0 56 56" width="100%" height="100%">
  <!-- Hair -->
  <path d="M18 18 Q18 10 28 10 Q38 10 38 18 Q35 12 28 13 Q21 12 18 18Z" 
        fill="#1e293b"/>
  <!-- Head -->
  <circle cx="28" cy="21" r="10" fill="#fbbf24"/>
  <!-- Eyes -->
  <circle cx="24.5" cy="20" r="1.6" fill="#1e293b"/>
  <circle cx="31.5" cy="20" r="1.6" fill="#1e293b"/>
  <!-- Eye shine -->
  <circle cx="25.2" cy="19.3" r="0.5" fill="white"/>
  <circle cx="32.2" cy="19.3" r="0.5" fill="white"/>
  <!-- Smile -->
  <path d="M24 24 Q28 28 32 24" stroke="#1e293b" stroke-width="1.4" 
        fill="none" stroke-linecap="round"/>
  <!-- Body -->
  <ellipse cx="28" cy="38" rx="11" ry="9" fill="#4f46e5"/>
  <!-- Cape back (drawn before body) -->
  <path d="M17 35 Q11 47 20 51 Q28 45 36 51 Q45 47 39 35 Q34 41 28 41 
           Q22 41 17 35Z" fill="#ef4444"/>
  <!-- Cape collar -->
  <path d="M19 33 Q28 38 37 33" stroke="#dc2626" stroke-width="2.5" 
        fill="none" stroke-linecap="round"/>
  <!-- Star badge -->
  <polygon points="28,31 29.5,35 33.5,35 30.5,37.5 31.5,41 28,39 
                   24.5,41 25.5,37.5 22.5,35 26.5,35" fill="#fbbf24"/>
</svg>`;

class TranscriptProcessor {

    constructor() {
        // ── Punctuation & symbol replacements ──────────────────────────
        // Order matters — longer phrases must come before shorter ones
        this.punctuationMap = [

            // Domain-critical symbols — highest priority
            { pattern: /\b(dot|period|full stop|point)\b/gi, replacement: '.' },
            { pattern: /\b(dash|hyphen|minus)\b/gi, replacement: '-' },
            { pattern: /\b(underscore|under score|under-score)\b/gi, replacement: '_' },
            { pattern: /\b(at sign|at the rate|at)\b/gi, replacement: '@' },
            { pattern: /\b(slash|forward slash)\b/gi, replacement: '/' },
            { pattern: /\b(colon)\b/gi, replacement: ':' },
            { pattern: /\b(hash|hashtag|pound)\b/gi, replacement: '#' },
            { pattern: /\b(question mark)\b/gi, replacement: '?' },
            { pattern: /\b(equals|equal sign)\b/gi, replacement: '=' },
            { pattern: /\b(ampersand|and sign)\b/gi, replacement: '&' },
            { pattern: /\b(percent|percent sign)\b/gi, replacement: '%' },
            { pattern: /\b(tilde)\b/gi, replacement: '~' },
            { pattern: /\b(plus)\b/gi, replacement: '+' },

            // Common domain TLDs spoken as words — convert to lowercase
            // These run AFTER dot replacement so "dot com" → ".com" first
            // then these clean up any remaining spoken TLDs without dot
            { pattern: /\bwww\s+/gi, replacement: 'www.' },

            // Number words → digits (useful for ports, IPs)
            { pattern: /\bzero\b/gi, replacement: '0' },
            { pattern: /\bone\b/gi, replacement: '1' },
            { pattern: /\btwo\b/gi, replacement: '2' },
            { pattern: /\bthree\b/gi, replacement: '3' },
            { pattern: /\bfour\b/gi, replacement: '4' },
            { pattern: /\bfive\b/gi, replacement: '5' },
            { pattern: /\bsix\b/gi, replacement: '6' },
            { pattern: /\bseven\b/gi, replacement: '7' },
            { pattern: /\beight\b/gi, replacement: '8' },
            { pattern: /\bnine\b/gi, replacement: '9' },
        ];

        // ── Domain context patterns ────────────────────────────────────
        // Detects when the user is likely speaking a domain name
        // so aggressive symbol replacement can be applied
        this.domainTriggerPhrases = [
            /\bscan\b/i,
            /\bcheck\b/i,
            /\banalyse?\b/i,
            /\bschedule\b/i,
            /\badd\b/i,
            /\bdomain\b/i,
            /\bwebsite\b/i,
            /\bsite\b/i,
            /\burl\b/i,
        ];

        // ── Known TLD list for smart dot insertion ─────────────────────
        // If speech recognizer outputs "examplecom" (merged, no dot),
        // try to split it using known TLDs
        this.knownTLDs = [
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'io', 'co', 'ai', 'app', 'dev', 'tech', 'cloud',
            'bank', 'finance', 'security', 'crypto',
            'in', 'uk', 'us', 'au', 'de', 'fr', 'jp', 'cn',
            'info', 'biz', 'name', 'pro', 'aero', 'coop', 'museum',
            'store', 'shop', 'online', 'site', 'web', 'media',
        ];
    }

    // ── Main entry point — call this on every transcript ──────────────
    process(rawTranscript, isFinal = false) {
        if (!rawTranscript || !rawTranscript.trim()) return rawTranscript;

        let text = rawTranscript.trim();

        // Step 1: Normalize whitespace
        text = text.replace(/\s+/g, ' ');

        // Step 2: Fix common speech-to-text domain mishearings BEFORE aggressive string substitutions destroy context
        text = this.fixCommonMishearings(text);

        // Step 3: Apply all punctuation/symbol replacements
        text = this.applyPunctuationMap(text);

        // Step 4: Clean up spaces around inserted symbols
        text = this.cleanSymbolSpacing(text);

        // Step 5: Smart domain reconstruction
        // Only on final result — interim would flicker too much
        if (isFinal) {
            text = this.reconstructDomains(text);
        }

        // Step 6: Lowercase domain portions only
        text = this.lowercaseDomains(text);

        return text;
    }

    // ── Step 2: Apply punctuation map in order ────────────────────────
    applyPunctuationMap(text) {
        for (const { pattern, replacement } of this.punctuationMap) {
            text = text.replace(pattern, replacement);
        }
        return text;
    }

    // ── Step 3: Clean spaces around symbols ───────────────────────────
    // "example . com" → "example.com"
    // "example - corp . com" → "example-corp.com"
    cleanSymbolSpacing(text) {
        // Remove spaces immediately before and after domain symbols
        text = text.replace(/\s*\.\s*/g, '.');
        text = text.replace(/\s*-\s*/g, '-');
        text = text.replace(/\s*_\s*/g, '_');
        text = text.replace(/\s*@\s*/g, '@');
        text = text.replace(/\s*\/\s*/g, '/');
        text = text.replace(/\s*:\s*/g, ':');

        // BUT restore space after sentence-ending dots (not domain dots)
        // A sentence dot is followed by a capital letter or end of string
        // e.g. "scan example.com. Now show results" — the middle dot is sentence end
        text = text.replace(/\.(?=[A-Z])/g, '. ');

        return text;
    }

    // ── Step 4: Reconstruct domains where dot was dropped ─────────────
    // Handles: "examplecom" → "example.com"
    //          "examplecoin" → leave alone (not a TLD context)
    reconstructDomains(text) {
        const words = text.split(' ');
        const reconstructed = words.map(word => {
            // Skip words that already contain a dot (already processed)
            if (word.includes('.')) return word;

            // EXCLUSIONS: Prevent reconstructing common English words that happen to end in TLD letters
            // For example: "domain" -> "doma.in", "coin" -> "co.in", "admin" -> "adm.in"
            const englishExclusions = [
                'domain', 'main', 'coin', 'join', 'brain', 'train', 'pain', 'rain',
                'gain', 'admin', 'certain', 'curtain', 'captain', 'mountain',
                'remain', 'explain', 'maintain', 'contain'
            ];
            if (englishExclusions.includes(word.toLowerCase())) return word;

            // Try to find a known TLD suffix in this word
            for (const tld of this.knownTLDs) {
                // Match word ending in TLD (case insensitive)
                const tldRegex = new RegExp(`^(.+?)(${tld})$`, 'i');
                const match = word.match(tldRegex);
                if (match && match[1].length >= 2) {
                    // Candidate: "examplecom" → "example" + "com"
                    // Only reconstruct if the prefix looks domain-like
                    // (alphanumeric, at least 2 chars)
                    if (/^[a-z0-9][a-z0-9-]+$/i.test(match[1])) {
                        return `${match[1]}.${match[2].toLowerCase()}`;
                    }
                }
            }
            return word;
        });
        return reconstructed.join(' ');
    }

    // ── Step 5: Fix common speech-to-text mishearings ─────────────────
    fixCommonMishearings(text) {
        const mishearings = [
            // "double u double u double u" → "www"
            { pattern: /\bdouble\s*u\s*double\s*u\s*double\s*u\b/gi, replacement: 'www' },
            { pattern: /\bdouble you\s*double you\s*double you\b/gi, replacement: 'www' },
            { pattern: /\bw w w\b/gi, replacement: 'www' },

            // HTTP/HTTPS spoken versions
            { pattern: /\bhttp\s*colon\s*\/+/gi, replacement: 'http://' },
            { pattern: /\bhttps\s*colon\s*\/+/gi, replacement: 'https://' },
            { pattern: /\bh\s*t\s*t\s*p\s*s?\b/gi, replacement: (m) => m.replace(/\s/g, '').toLowerCase() },

            // Common TLD mishearings
            { pattern: /\bdot\s*com\b/gi, replacement: '.com' },
            { pattern: /\bdot\s*net\b/gi, replacement: '.net' },
            { pattern: /\bdot\s*org\b/gi, replacement: '.org' },
            { pattern: /\bdot\s*i\s*o\b/gi, replacement: '.io' },
            { pattern: /\bdot\s*in\b/gi, replacement: '.in' },
            { pattern: /\bdot\s*co\b/gi, replacement: '.co' },
            { pattern: /\bdot\s*ai\b/gi, replacement: '.ai' },
            { pattern: /\bdot\s*gov\b/gi, replacement: '.gov' },
            { pattern: /\bdot\s*edu\b/gi, replacement: '.edu' },
            { pattern: /\bdot\s*bank\b/gi, replacement: '.bank' },

            // Country code TLDs with "dot"
            { pattern: /\bdot\s*co\s*dot\s*in\b/gi, replacement: '.co.in' },
            { pattern: /\bdot\s*co\s*dot\s*uk\b/gi, replacement: '.co.uk' },
            { pattern: /\bdot\s*com\s*dot\s*au\b/gi, replacement: '.com.au' },

            // "bank dot in" → ".bank.in" (Indian banking domains)
            { pattern: /\bbank\s+dot\s+in\b/gi, replacement: '.bank.in' },

            // Web Speech API autocorrect failsafes (STT aggressively swaps bank.in to co.in)
            { pattern: /\bpnb\s*(?:\.|\s*dot\s*|\s+)co\s*(?:\.|\s*dot\s*|\s+)in\b/gi, replacement: 'pnb.bank.in' },
        ];

        for (const { pattern, replacement } of mishearings) {
            text = text.replace(pattern, replacement);
        }
        return text;
    }

    // ── Step 6: Lowercase domain portions ─────────────────────────────
    // Find anything that looks like a domain and lowercase it
    // Preserve case of surrounding natural language
    lowercaseDomains(text) {
        // Match patterns like word.word, word.word.word etc.
        return text.replace(
            /\b([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z]{2,})+)\b/g,
            (match) => match.toLowerCase()
        );
    }

    // ── Utility: detect if transcript likely contains a domain ─────────
    // Used to decide whether to show domain-mode hint in UI
    likelyContainsDomain(text) {
        return this.domainTriggerPhrases.some(p => p.test(text)) ||
            /\bdot\b/i.test(text) ||
            /\.[a-z]{2,}/i.test(text);
    }
}

class QubitsenseAgent {
    constructor() {
        this.isOpen = false;
        this.conversationHistory = [];
        this.apiKey = null;
        this.currentPage = window.location.pathname;
        this.lastDomain = localStorage.getItem('last_scanned_domain') || 'None';
        this.username = localStorage.getItem('email') || 'User'; // Adjust mapping to match typical storage
        this.render();

        const GREETING_MESSAGE = `Hi, I'm Qubit! 👋 How can I help you today? I can scan domains, explain your quantum risk score, help schedule scans, or guide you through the platform.`;
        this.conversationHistory = [{
            role: 'model',
            parts: [{ text: GREETING_MESSAGE }]
        }];
        this.addBubble('agent', GREETING_MESSAGE);

        this.attachEvents();
        this.initKey();
        this.initVoice();
    }

    // ── Voice Input Engine ─────────────────────────────────────
    initVoice() {
        const SpeechRecognition =
            window.SpeechRecognition || window.webkitSpeechRecognition;

        if (!SpeechRecognition) {
            const micBtn = document.getElementById('qubit-mic-btn');
            if (micBtn) micBtn.style.display = 'none';
            return;
        }

        // ── Instantiate processor ──────────────────────────────────────────
        this.transcriptProcessor = new TranscriptProcessor();

        this.recognition = new SpeechRecognition();
        this.recognition.continuous = false;
        this.recognition.interimResults = true;
        this.recognition.lang = 'en-US';
        this.isListening = false;

        // ── Live interim results ───────────────────────────────────────────
        this.recognition.onresult = (event) => {
            const input = document.getElementById('qubit-input');
            let interimTranscript = '';
            let finalTranscript = '';

            for (let i = event.resultIndex; i < event.results.length; i++) {
                const raw = event.results[i][0].transcript;
                if (event.results[i].isFinal) {
                    // Full post-processing on final result
                    finalTranscript += this.transcriptProcessor.process(raw, true);
                } else {
                    // Lightweight processing on interim — only apply dot/dash/underscore
                    // so the input doesn't flicker too much during speech
                    interimTranscript += this.transcriptProcessor.process(raw, false);
                }
            }

            const displayText = finalTranscript || interimTranscript;
            input.value = displayText;

            // Visual cue — italic grey while interim, normal when final
            if (interimTranscript && !finalTranscript) {
                input.classList.add('q-interim');
            } else {
                input.classList.remove('q-interim');
            }

            // Show domain hint if we detect a domain being spoken
            if (this.transcriptProcessor.likelyContainsDomain(displayText)) {
                this.showDomainHint();
            }
        };

        // ── Final result — auto-send ───────────────────────────────────────
        this.recognition.onend = () => {
            this.stopListening();
            const input = document.getElementById('qubit-input');
            input.classList.remove('q-interim');
            this.hideDomainHint();

            // Final cleanup pass on whatever is in the input field
            // Note: Use click() on send button since handleSend isn't explicitly defined as a direct method yet
            if (input.value.trim()) {
                input.value = this.transcriptProcessor.process(input.value, true);
                setTimeout(() => document.getElementById('qubit-send').click(), 400);
            }
        };

        this.recognition.onerror = (event) => {
            this.stopListening();
            this.hideDomainHint();
            const messages = {
                'not-allowed': 'Microphone access denied. Please allow mic permission in your browser.',
                'no-speech': 'No speech detected. Please try again.',
                'network': 'Network error during voice recognition.',
            };
            const msg = messages[event.error];
            if (msg) this.addBubble('agent', `🎤 ${msg}`);
        };
    }

    startListening() {
        if (!this.recognition || this.isListening) return;

        if (!this.isOpen) {
            document.getElementById('qubit-agent-btn').click();
        }

        this.isListening = true;
        this.recognition.start();

        const micBtn = document.getElementById('qubit-mic-btn');
        if (micBtn) {
            micBtn.classList.add('q-recording');
            micBtn.setAttribute('aria-label', 'Stop recording');
            micBtn.title = 'Click to stop';
        }

        this.showVoiceIndicator();

        const input = document.getElementById('qubit-input');
        input.value = '';
        input.placeholder = 'Listening...';
    }

    stopListening() {
        if (!this.recognition || !this.isListening) return;
        this.isListening = false;

        try { this.recognition.stop(); } catch (e) { }

        const micBtn = document.getElementById('qubit-mic-btn');
        if (micBtn) {
            micBtn.classList.remove('q-recording');
            micBtn.setAttribute('aria-label', 'Start voice input');
            micBtn.title = 'Voice input';
        }

        this.hideVoiceIndicator();
        document.getElementById('qubit-input').placeholder = 'Ask Qubit anything...';
    }

    toggleListening() {
        this.isListening ? this.stopListening() : this.startListening();
    }

    showVoiceIndicator() {
        let indicator = document.getElementById('qubit-voice-indicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.id = 'qubit-voice-indicator';
            indicator.innerHTML = `
                <div class="q-voice-waves">
                    <span></span><span></span><span></span>
                    <span></span><span></span>
                </div>
                <span class="q-voice-label">Listening... speak now</span>
                <button class="q-voice-cancel" id="qubit-voice-cancel">Cancel</button>
            `;
            const inputRow = document.getElementById('qubit-input-row');
            inputRow.parentNode.insertBefore(indicator, inputRow);

            document.getElementById('qubit-voice-cancel').addEventListener('click', () => {
                const input = document.getElementById('qubit-input');
                if (input) input.value = '';
                this.stopListening();
            });
        }
        indicator.style.display = 'flex';
    }

    hideVoiceIndicator() {
        const indicator = document.getElementById('qubit-voice-indicator');
        if (indicator) indicator.style.display = 'none';
    }

    showDomainHint() {
        let hint = document.getElementById('qubit-domain-hint');
        if (!hint) {
            hint = document.createElement('div');
            hint.id = 'qubit-domain-hint';
            hint.innerHTML = `
                🌐 <strong>Domain mode</strong> — 
                say <em>"dot"</em> for <code>.</code>, 
                <em>"dash"</em> for <code>-</code>
            `;
            const indicator = document.getElementById('qubit-voice-indicator');
            if (indicator) indicator.appendChild(hint);
        }
        hint.style.display = 'block';
    }

    hideDomainHint() {
        const hint = document.getElementById('qubit-domain-hint');
        if (hint) hint.style.display = 'none';
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
        document.body.insertAdjacentHTML('beforeend', `
            <div id="qubit-agent-btn" title="Ask Qubit">
                <div id="qubit-btn-inner" style="width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; z-index: 2;">
                    ${QUBIT_ICON_SVG}
                </div>
                <span id="qubit-btn-label">Ask Qubit</span>
                <span id="qubit-pulse-ring"></span>
            </div>
            <div id="qubit-agent-panel" class="qubit-hidden">
                <div id="qubit-header">
                    <div id="qubit-header-left">
                        <div id="qubit-avatar-small" style="width: 36px; height: 36px;">
                            ${QUBIT_ICON_SVG}
                        </div>
                        <div>
                            <div id="qubit-header-name">Qubit</div>
                            <div id="qubit-header-status">
                                <span class="qubit-status-dot"></span> Online
                            </div>
                        </div>
                    </div>
                    <button id="qubit-close" title="Close">✕</button>
                </div>
                <div id="qubit-greeting-banner">
                    <div id="qubit-greeting-mascot" style="width: 46px; height: 46px; flex-shrink: 0;">${QUBIT_ICON_SVG}</div>
                    <div id="qubit-greeting-text">
                        <p id="qubit-greeting-title">Hi, I'm Qubit! 👋</p>
                        <p id="qubit-greeting-sub">
                            Your PQC security assistant. I can help you scan domains, 
                            understand your quantum risk score, schedule scans, and 
                            navigate the platform.
                        </p>
                    </div>
                </div>
                <div id="qubit-messages"></div>
                <div id="qubit-suggestions">
                    <button class="qubit-chip">🔍 Scan a domain</button>
                    <button class="qubit-chip">📊 Explain risk score</button>
                    <button class="qubit-chip">⏰ Schedule a scan</button>
                    <button class="qubit-chip">❓ What is HNDL?</button>
                </div>
                <div id="qubit-input-row">
                    <input id="qubit-input" type="text" placeholder="Ask Qubit anything..." autocomplete="off"/>
                    <button id="qubit-mic-btn" aria-label="Start voice input" title="Voice input">
                        <svg id="qubit-mic-icon" width="16" height="16" viewBox="0 0 24 24" fill="white" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 1a4 4 0 0 1 4 4v6a4 4 0 0 1-8 0V5a4 4 0 0 1 4-4z"/>
                            <path d="M19 10a1 1 0 0 0-2 0 5 5 0 0 1-10 0 1 1 0 0 0-2 0 7 7 0 0 0 6 6.92V19H9a1 1 0 0 0 0 2h6a1 1 0 0 0 0-2h-2v-2.08A7 7 0 0 0 19 10z"/>
                        </svg>
                        <svg id="qubit-stop-icon" width="14" height="14" viewBox="0 0 24 24" fill="white" style="display:none">
                            <rect x="4" y="4" width="16" height="16" rx="2"/>
                        </svg>
                    </button>
                    <button id="qubit-send">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="white">
                            <path d="M2 21l21-9L2 3v7l15 2-15 2v7z"/>
                        </svg>
                    </button>
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
                btn.classList.add('panel-open');
                const banner = document.getElementById('qubit-greeting-banner');
                if (banner && this.conversationHistory.length > 1) {
                    banner.style.display = 'none';
                }
            } else {
                panel.classList.add('qubit-hidden');
                btn.classList.remove('panel-open');
            }
        });

        closeBtn.addEventListener('click', () => {
            this.isOpen = false;
            panel.classList.add('qubit-hidden');
            btn.classList.remove('panel-open');
        });

        const sendBtn = document.getElementById('qubit-send');
        const inputFld = document.getElementById('qubit-input');

        const sendHandler = () => {
            const text = inputFld.value.trim();
            if (text) {
                const banner = document.getElementById('qubit-greeting-banner');
                if (banner) banner.style.display = 'none';
                this.sendMessage(text);
                inputFld.value = '';
            }
        };

        sendBtn.addEventListener('click', sendHandler);
        inputFld.addEventListener('keydown', (e) => {
            if (this.isListening && e.key !== 'Enter') {
                this.stopListening();
            }
            if (e.key === 'Enter') sendHandler();
        });

        // Mic Button Logic
        const micBtn = document.getElementById('qubit-mic-btn');
        if (micBtn) {
            micBtn.addEventListener('click', () => this.toggleListening());
            const observer = new MutationObserver(() => {
                const recording = micBtn.classList.contains('q-recording');
                const micIcon = document.getElementById('qubit-mic-icon');
                const stopIcon = document.getElementById('qubit-stop-icon');
                if (micIcon) micIcon.style.display = recording ? 'none' : 'block';
                if (stopIcon) stopIcon.style.display = recording ? 'block' : 'none';
            });
            observer.observe(micBtn, { attributes: true, attributeFilter: ['class'] });
        }

        // Chips
        document.querySelectorAll('.qubit-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const text = chip.textContent;
                const banner = document.getElementById('qubit-greeting-banner');
                if (banner) banner.style.display = 'none';
                this.sendMessage(text);
            });
        });
    }
}

// Auto-initialize
window.addEventListener('DOMContentLoaded', () => {
    window.qubitAgent = new QubitsenseAgent();
});
