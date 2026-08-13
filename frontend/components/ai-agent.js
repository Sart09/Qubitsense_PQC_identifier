const AGENT_SYSTEM_PROMPT = `You are Qubit, an AI assistant embedded in the Qubitsense PQC Identifier platform —
a security tool that scans domains for post-quantum cryptographic risk.

Your Capabilities
Anything the user types or speaks to you is a QUESTION. Answer it in plain
natural language and nothing else. You do not move the user around the
platform — you cannot navigate, and you must never try to. Page changes are
driven exclusively by the quick-action buttons sitting above the message box,
which the user clicks themselves. If someone asks where a feature lives, name
the page in words and point them at those buttons; never yank them there.

This holds for every phrasing, including ones that sound like commands —
"show me my scans", "take me to schedules", "open the report", "go to
settings". The answer is a sentence telling them where it is, not a redirect.

The only things you may ever DO are in-page effects the user explicitly asked
for on the page they are already on. When (and only when) that happens, append
the action on a new line at the very END of your response in this exact format:
ACTION:FUNCTION_NAME:PARAMETER

Available actions:
ACTION:START_SCAN:domain.com       → Start a scan (only when the user names a domain AND says to scan it)
ACTION:CREATE_SCHEDULE:domain:freq → Create a schedule (freq: daily, weekly, monthly)
ACTION:FILTER_FAILURES:job_id      → Filter the scan table to show only failures
ACTION:HIGHLIGHT_RISK:score        → Highlight all subdomains above a risk score

Only include ONE action per response, and only ever as the last line.
There is no navigation action. Never emit ACTION:NAVIGATE or
ACTION:SHOW_RESULTS — they do not exist and will be discarded.

Do NOT include an ACTION line for informational requests — summarizing,
analyzing, explaining, comparing, or answering "what/why/how" questions about
a scan, a report, or the platform in general is a pure-answer scenario, even if
the report data you're citing came from a specific scan the user is currently
viewing. Talking ABOUT a scan's results is never the same as the user asking
you to change something. When genuinely unsure whether the user wants an
action, answer the question and do not include an ACTION line — an unwanted
answer is harmless, an unwanted side effect interrupts the user mid-read.

A message starting with "how", "why", or "what" (e.g. "how do I delete a
scan", "how do I rescan a domain", "why did this fail", "what happens if I
reschedule") is always asking you to EXPLAIN the process in words, never to
perform it. Answer in prose only — no ACTION line — even for a feature that
has a matching action above, and even if no matching action exists at all
(there is currently no delete action; if asked how to delete something,
say so and describe the UI control instead of inventing one).

Platform Knowledge
Quantum Risk Score (0–100, higher is worse) — scoring model v2.
Ten weighted components, weights summing to 1.00:
Key exchange: 22% (RSA/ECDHE/X25519 all Shor-breakable; only ML-KEM/Kyber hybrid scores 0)
Certificate signature: 14% (RSA/ECDSA Shor-breakable; MD5/SHA-1 signatures are broken classically)
Public key strength: 12% (RSA ≤1024 broken; RSA-2048 high; classical keys never score below 50)
Forward secrecy: 10% (static RSA key transport = one key decrypts all captured sessions)
TLS protocol version: 10% (TLS 1.3 = 0, TLS 1.2 = moderate, TLS 1.1/1.0 and SSL = critical)
Symmetric cipher strength: 8% (Grover halves key bits — AES-256 = 0, AES-128 penalised, RC4/DES critical)
Certificate trust chain: 7% (expired, self-signed, or hostname mismatch)
Cipher mode / AEAD: 6% (GCM/ChaCha20-Poly1305 = 0; CBC padding-oracle prone; ECB critical)
Hash strength: 6% (SHA-384/512 = 0, SHA-256 low, SHA-1/MD5 broken today)
Certificate lifetime hygiene: 5% (imminent expiry AND over-long lifetimes both penalised — long certs slow PQC rotation)

Then three further stages: floor gates (no PQC anywhere ⇒ at least Quantum Vulnerable;
one of two PQC ⇒ at least Transitioning; anything classically broken ⇒ at least Critical),
HNDL amplification (uplift = composite × (service multiplier − 1.0) × 0.15, multiplier 1.0–2.0),
then a clamp to 0–100. If asked for exact constants, tell the user they are served live at
the /scoring-model endpoint and shown in the dashboard's Scoring Methodology panel.

Score ranges (this is the platform's one canonical risk scale — use these exact
labels, never "Low/Moderate/High" or any other wording):
0–29: Quantum Safe
30–44: Transitioning — begin PQC migration planning
45–80: Quantum Vulnerable — prioritize migration
81–100: Critical — immediate action required

Enterprise Rating = (100 − average risk score) × 10, on a 0–1000 scale, divided into
five posture tiers: Elite-PQC 850–1000, Advanced 700–849, Standard 550–699,
Developing 400–549, Legacy 0–399.

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

Pages in the Platform (for telling the user where things are — you never go there yourself)
/                → Main scan submission page
/dashboard/{id}  → Scan results for a specific scan
/user-dashboard  → My Scans — the current user's scan history
/schedules       → Scheduled scan management
/login           → Authentication

Current Page Context
The user is currently on: {CURRENT_PAGE}
The last scanned domain was: {LAST_DOMAIN}
The user's name is: {USERNAME}

Report Analysis
When the user asks you to summarize, analyze, or explain "this scan" /
"this report" / "these results" / "the findings", and a "Current Scan
Report Data" section appears below, use those real numbers — cite them
specifically (counts, scores, hostnames). If no report data is present
(the user isn't on a scan's dashboard page, or the scan hasn't finished),
say so plainly rather than inventing numbers.

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

/* ── Quick questions — the ONLY place navigation lives ───────────────────
 *
 * Anything the user types is answered in words; it never moves them. Moving
 * between pages is a deliberate act, so it is bound to these buttons above
 * the message box and nothing else.
 *
 *   label  — chip text
 *   prompt — what gets sent to Qubit (clean, without the emoji)
 *   nav    — optional destination. Present ⇒ this chip navigates, and it does
 *            so client-side with a fixed path, so the destination never
 *            depends on the model getting an action line right.
 */
const QUBIT_CHIPS = [
    { label: '🔍 Scan a domain', prompt: 'Take me to the scan page', nav: '/' },
    { label: '📁 My scans', prompt: 'Show my scan history', nav: '/user-dashboard' },
    { label: '⏰ Schedule a scan', prompt: 'Take me to scheduled scans', nav: '/schedules' },
    { label: '📊 Explain risk score', prompt: 'Explain the quantum risk score and how it is calculated' },
    { label: '❓ What is HNDL?', prompt: 'What is HNDL?' },
];

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
        this.currentPage = window.location.pathname;
        this.lastDomain = localStorage.getItem('last_scanned_domain') || 'None';
        this.username = localStorage.getItem('email') || 'User'; // Adjust mapping to match typical storage
        // Populated lazily by fetchReportContext() when on a /dashboard/{id}
        // page — lets Qubit answer "summarize this scan" with real numbers
        // instead of generic platform knowledge.
        this.reportContext = null;
        this._reportContextScanId = null;

        // Voice output — spoken back like ChatGPT's voice mode, but only
        // for turns the user actually spoke (typing shouldn't suddenly
        // start talking at you). pendingVoiceReply is set right before the
        // voice-recognition auto-send fires and consumed once by
        // sendMessage(). voiceReplyEnabled is a persistent user toggle.
        this.pendingVoiceReply = false;
        this.voiceReplyEnabled = localStorage.getItem('qubit_voice_reply') !== 'off';
        if ('speechSynthesis' in window) window.speechSynthesis.getVoices(); // warm up async voice list

        this.render();

        const GREETING_MESSAGE = `Hi, I'm Qubit! 👋 How can I help you today? I can scan domains, explain your quantum risk score, summarize a scan report, help schedule scans, or guide you through the platform.`;
        this.conversationHistory = [{ role: 'assistant', content: GREETING_MESSAGE }];
        this.addBubble('agent', GREETING_MESSAGE);

        this.attachEvents();
        this.initVoice();
    }

    /* ── Report context — real data for "summarize this scan" ───────── */
    async fetchReportContext() {
        const match = this.currentPage.match(/^\/dashboard\/(\d+)/);
        if (!match) {
            this.reportContext = null;
            return;
        }
        const scanId = match[1];
        if (this._reportContextScanId === scanId && this.reportContext) return; // already cached

        try {
            const [statusRes, qrRes, failRes] = await Promise.all([
                fetch(`/scan/${scanId}`),
                fetch(`/scan/${scanId}/quantum-risk`),
                fetch(`/scan/${scanId}/failures`),
            ]);
            if (!statusRes.ok) { this.reportContext = null; return; }
            const status = await statusRes.json();
            const qr = qrRes.ok ? await qrRes.json() : { results: [] };
            const fail = failRes.ok ? await failRes.json() : { total_failures: 0, failures: [] };

            const results = qr.results || [];
            const total = results.length;
            const avgRisk = total > 0
                ? Math.round(results.reduce((s, r) => s + r.risk_score, 0) / total)
                : 0;
            const counts = { 'Quantum Safe': 0, 'Transitioning': 0, 'Quantum Vulnerable': 0, 'Critical': 0 };
            results.forEach(r => { if (counts[r.risk_label] !== undefined) counts[r.risk_label]++; });
            const topRisk = [...results]
                .sort((a, b) => b.risk_score - a.risk_score)
                .slice(0, 5)
                .map(r => `${r.hostname} (${r.risk_score}/100, ${r.risk_label})`)
                .join(', ');

            const failCounts = {};
            (fail.failures || []).forEach(f => {
                failCounts[f.failure_category] = (failCounts[f.failure_category] || 0) + 1;
            });
            const failSummary = Object.entries(failCounts).map(([code, n]) => `${code}: ${n}`).join(', ') || 'none';

            this.reportContext =
                `Scan #${scanId} for domain ${status.domain} — status: ${status.status}.\n` +
                `${total} assets successfully scanned, average quantum risk score ${avgRisk}/100.\n` +
                `Risk breakdown: ${counts['Critical']} Critical, ${counts['Quantum Vulnerable']} Quantum Vulnerable, ` +
                `${counts['Transitioning']} Transitioning, ${counts['Quantum Safe']} Quantum Safe.\n` +
                `Highest-risk assets: ${topRisk || 'none'}.\n` +
                `${fail.total_failures || 0} discovered hosts could not be reached. Failure breakdown: ${failSummary}.`;
            this._reportContextScanId = scanId;
            this.currentScanDomain = status.domain;
        } catch (e) {
            console.error('[Qubit] Failed to fetch report context:', e);
            this.reportContext = null;
        }
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
                this.pendingVoiceReply = true; // this turn's reply should be spoken back
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

    // ── Voice Output (speak Qubit's reply back) ─────────────────────────
    speak(text) {
        if (!this.voiceReplyEnabled || !('speechSynthesis' in window)) return;
        window.speechSynthesis.cancel(); // barge-in: don't overlap utterances
        const clean = text
            .replace(/\*\*(.*?)\*\*/g, '$1')
            .replace(/[*_`#]/g, '')
            .replace(/https?:\/\/\S+/g, 'link')
            .replace(/\s+/g, ' ')
            .trim();
        if (!clean) return;
        const utter = new SpeechSynthesisUtterance(clean);
        utter.rate = 1.03;
        const voice = this._pickVoice();
        if (voice) utter.voice = voice;
        window.speechSynthesis.speak(utter);
    }

    _pickVoice() {
        const voices = window.speechSynthesis.getVoices();
        if (!voices.length) return null;
        return voices.find(v => /Google US English/i.test(v.name))
            || voices.find(v => /en-US/i.test(v.lang) && /Natural|Online|Neural/i.test(v.name))
            || voices.find(v => /en-US/i.test(v.lang))
            || voices.find(v => v.lang.startsWith('en'))
            || voices[0];
    }

    _updateVoiceToggleUI() {
        const btn = document.getElementById('qubit-voice-toggle');
        const onIcon = document.getElementById('qubit-voice-on-icon');
        const offIcon = document.getElementById('qubit-voice-off-icon');
        if (!btn) return;
        const on = this.voiceReplyEnabled;
        if (onIcon) onIcon.style.display = on ? 'block' : 'none';
        if (offIcon) offIcon.style.display = on ? 'none' : 'block';
        btn.setAttribute('aria-label', on ? 'Voice replies on' : 'Voice replies off');
        btn.title = on ? 'Voice replies: on (click to mute)' : 'Voice replies: off (click to unmute)';
        btn.classList.toggle('q-voice-muted', !on);
    }

    startListening() {
        if (!this.recognition || this.isListening) return;
        if ('speechSynthesis' in window) window.speechSynthesis.cancel(); // barge-in over Qubit talking

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

    // ACTION HANDLERS — map action strings to JS functions.
    //
    // Deliberately contains NO navigation handler. Navigation is not a thing
    // the model is allowed to do: it belongs to the quick-action chips, which
    // the user clicks on purpose (see QUBIT_CHIPS). Because there is no
    // 'NAVIGATE'/'SHOW_RESULTS' key here, a hallucinated navigation action
    // has nowhere to land and is silently dropped — the guarantee is
    // structural, not a matter of the prompt behaving itself.
    actionHandlers = {
        'START_SCAN': (domain) => {
            // Only starts a scan if this page actually has the scan form.
            // If it doesn't, say so instead of redirecting — an answer must
            // never move the user off the page they are reading.
            const input = document.getElementById('targetInput') || document.getElementById('domain-input');
            const btn = document.getElementById('scanBtn') || document.getElementById('scan-btn');
            if (input && btn) {
                input.value = domain;
                btn.click();
            } else {
                window.qubitAgent.addBubble(
                    'agent',
                    `Scans start from the main scan page — use the “🔍 Scan a domain” button above the message box, then enter <strong>${domain}</strong>.`
                );
            }
        },

        'OPEN_SCHEDULE_MODAL': (domain) => {
            // Same rule: open the modal if it exists on this page, otherwise
            // explain where it is rather than navigating there.
            if (typeof openCreateModal === 'function') {
                openCreateModal();
                setTimeout(() => {
                    const el = document.getElementById('domain');
                    if (el) el.value = domain;
                }, 100);
            } else {
                window.qubitAgent.addBubble(
                    'agent',
                    `You can set that up on the Scheduled Scans page — the “⏰ Schedule a scan” button above the message box takes you there.`
                );
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

    // A message phrased as a question is asking for an explanation, never
    // asking Qubit to actually do the thing right now. Detected generically
    // — an interrogative opener or a trailing question mark — rather than as
    // a per-feature special case, so it holds for questions about features
    // that don't exist yet as much as for ones that do.
    isInformationalQuestion(userText) {
        const t = (userText || '').trim();
        return /\?\s*$/.test(t) ||
            /^(how|why|what|when|where|which|who|whose|is|are|was|were|do|does|did|can|could|will|would|should|am)\b/i.test(t) ||
            /\b(how (do|can|would|should|to)|what (if|happens|does|about)|tell me|explain|describe)\b/i.test(t);
    }

    parseAndExecuteAction(responseText, userText) {
        let cleanText = responseText;
        const actionRegex = /ACTION:\s*([A-Z_]+)\s*:\s*([^\s<`]+)/i;
        const match = responseText.match(actionRegex);

        if (match) {
            const fn = match[1].toUpperCase();
            const param = match[2].trim();
            // A model can attach an action line to an answer even when the
            // instruction was purely informational (e.g. "summarize this
            // scan", "how do I delete a scan"). Prompting alone doesn't
            // reliably suppress this, so guard structurally: never act on a
            // how/why/what question, and — because actionHandlers has no
            // navigation entry at all — never move the user off the page in
            // response to something they typed. Navigation is chip-only.
            const isQuestion = this.isInformationalQuestion(userText);
            if (this.actionHandlers[fn] && !isQuestion) {
                setTimeout(() => this.actionHandlers[fn](param), 600);
            }
        }
        // Strip action lines and code-block artifacts unconditionally — a
        // malformed or unknown ACTION line (e.g. a hallucinated NAVIGATE)
        // executes nothing, but it must still never be shown to the user.
        cleanText = cleanText
            .split('\n')
            .filter(l => !/ACTION\s*:/i.test(l) && l.trim() !== '```')
            .join('\n')
            .trim();
        return cleanText;
    }

    buildSystemPrompt() {
        let prompt = AGENT_SYSTEM_PROMPT
            .replace('{CURRENT_PAGE}', this.currentPage)
            .replace('{LAST_DOMAIN}', this.lastDomain)
            .replace('{USERNAME}', this.username);
        if (this.reportContext) {
            prompt += `\n\nCurrent Scan Report Data\n${this.reportContext}`;
        }
        return prompt;
    }

    async sendMessage(userText) {
        this.addBubble('user', userText);
        this.showTypingIndicator();

        // Consumed once: only speak the reply back if THIS turn was spoken
        // by the user (set in recognition.onend), not for typed messages.
        const spokenTurn = this.pendingVoiceReply;
        this.pendingVoiceReply = false;

        // Refresh report context first so a question asked right after the
        // page loads (or right after navigating to a different scan) still
        // gets real numbers, not stale/missing ones.
        await this.fetchReportContext();

        this.conversationHistory.push({ role: 'user', content: userText });

        try {
            const response = await fetch('/api/agent/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    system: this.buildSystemPrompt(),
                    messages: this.conversationHistory,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Unknown AI provider error');
            }

            const rawText = data.reply;
            const cleanText = this.parseAndExecuteAction(rawText, userText);

            this.conversationHistory.push({ role: 'assistant', content: rawText });
            this.hideTypingIndicator();
            this.addBubble('agent', cleanText);
            if (spokenTurn) this.speak(cleanText);

        } catch (err) {
            this.hideTypingIndicator();
            console.error("Qubit fetch error:", err);
            this.addBubble('agent', '> ERROR: ' + err.message);
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
                <div id="qubit-suggestions" aria-label="Quick questions">
                    <span id="qubit-suggestions-label">Quick questions</span>
                    ${QUBIT_CHIPS.map((c, i) =>
            `<button class="qubit-chip${c.nav ? ' qubit-chip-nav' : ''}" data-chip="${i}"${c.nav ? ` title="Go to ${c.nav}"` : ''}>${c.label}</button>`
        ).join('\n                    ')}
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
                    <button id="qubit-voice-toggle" aria-label="Voice replies on" title="Voice replies: on">
                        <svg id="qubit-voice-on-icon" width="16" height="16" viewBox="0 0 24 24" fill="white" xmlns="http://www.w3.org/2000/svg">
                            <path d="M5 9v6h4l5 5V4L9 9H5z"/>
                            <path d="M16.5 12c0-1.77-.77-3.29-2-4.32v8.64c1.23-1.03 2-2.55 2-4.32z"/>
                            <path d="M19 12c0-3.53-2.04-6.29-5-7.74v1.72c2.16 1.34 3.5 3.61 3.5 6.02s-1.34 4.68-3.5 6.02v1.72c2.96-1.45 5-4.21 5-7.74z" opacity="0.6"/>
                        </svg>
                        <svg id="qubit-voice-off-icon" width="16" height="16" viewBox="0 0 24 24" fill="white" xmlns="http://www.w3.org/2000/svg" style="display:none">
                            <path d="M5 9v6h4l5 5V4L9 9H5z"/>
                            <path d="M15 8.5l6 7M21 8.5l-6 7" stroke="white" stroke-width="2" stroke-linecap="round"/>
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
                if ('speechSynthesis' in window) window.speechSynthesis.cancel();
            }
        });

        closeBtn.addEventListener('click', () => {
            this.isOpen = false;
            panel.classList.add('qubit-hidden');
            btn.classList.remove('panel-open');
            if ('speechSynthesis' in window) window.speechSynthesis.cancel();
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

        // Voice reply toggle — persistent mute/unmute for spoken replies
        const voiceToggleBtn = document.getElementById('qubit-voice-toggle');
        if (voiceToggleBtn) {
            this._updateVoiceToggleUI();
            voiceToggleBtn.addEventListener('click', () => {
                this.voiceReplyEnabled = !this.voiceReplyEnabled;
                localStorage.setItem('qubit_voice_reply', this.voiceReplyEnabled ? 'on' : 'off');
                if (!this.voiceReplyEnabled && 'speechSynthesis' in window) window.speechSynthesis.cancel();
                this._updateVoiceToggleUI();
            });
        }

        // Quick questions. A chip carrying `nav` is the one and only way a
        // page change happens: the user clicked it, so we go straight there
        // without a model round-trip. A chip without `nav` is just a
        // pre-written question and behaves exactly like typing it.
        document.querySelectorAll('.qubit-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const spec = QUBIT_CHIPS[Number(chip.dataset.chip)];
                if (!spec) return;
                const banner = document.getElementById('qubit-greeting-banner');
                if (banner) banner.style.display = 'none';

                if (spec.nav) {
                    if (this.currentPage === spec.nav) {
                        this.addBubble('agent', `You're already on this page.`);
                        return;
                    }
                    this.addBubble('user', spec.label);
                    this.addBubble('agent', `Taking you there…`);
                    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
                    setTimeout(() => { window.location.href = spec.nav; }, 350);
                    return;
                }
                this.sendMessage(spec.prompt);
            });
        });
    }
}

// Auto-initialize
window.addEventListener('DOMContentLoaded', () => {
    window.qubitAgent = new QubitsenseAgent();
});
