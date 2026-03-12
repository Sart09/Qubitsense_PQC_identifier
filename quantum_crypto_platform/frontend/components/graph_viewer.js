/**
 * Graph Viewer component.
 * Builds and renders a Cytoscape.js attack-surface graph
 * from TLS, quantum risk, and HNDL data.
 */

class GraphViewer {
    /**
     * Colour a node by its risk level / label.
     */
    static riskColour(label) {
        if (!label) return '#94a3b8';
        const l = label.toLowerCase();
        if (l === 'critical' || l === 'quantum vulnerable') return '#f87171';
        if (l === 'high') return '#fb923c';
        if (l === 'medium' || l === 'transitioning') return '#fbbf24';
        if (l === 'low' || l === 'quantum safe') return '#34d399';
        return '#94a3b8';
    }

    /**
     * Render the attack-surface graph.
     *
     * @param {string} containerId  — DOM element id for the graph
     * @param {string} domain       — root target domain
     * @param {Array}  tlsResults   — from GET /scan/{id}/tls
     * @param {Array}  qrResults    — from GET /scan/{id}/quantum-risk
     * @param {Array}  hndlTargets  — from GET /scan/{id}/hndl  (.targets)
     */
    static render(containerId, domain, tlsResults, qrResults, hndlTargets) {
        const elements = [];
        const nodeIds = new Set();

        /* ---- helper ---- */
        const addNode = (id, label, type, colour) => {
            if (nodeIds.has(id)) return;
            nodeIds.add(id);
            elements.push({
                data: { id, label, type, colour },
            });
        };

        const addEdge = (src, tgt) => {
            elements.push({ data: { source: src, target: tgt } });
        };

        /* ---- Root domain node ---- */
        addNode(domain, domain, 'domain', '#818cf8');

        /* ---- Build maps for quick lookup ---- */
        const qrMap = {};
        qrResults.forEach((r) => (qrMap[r.hostname] = r));
        const hndlMap = {};
        hndlTargets.forEach((t) => (hndlMap[t.hostname] = t));

        /* ---- TLS results → subdomain + service + TLS + risk nodes ---- */
        tlsResults.forEach((tls) => {
            const host = tls.hostname;
            const qr = qrMap[host];
            const hndl = hndlMap[host];

            // Subdomain node
            const hostColour = qr
                ? GraphViewer.riskColour(qr.risk_label)
                : '#94a3b8';
            addNode(host, host, 'subdomain', hostColour);
            addEdge(domain, host);

            // TLS node
            const tlsId = `${host}-tls`;
            const tlsLabel = tls.tls_version || 'Unknown TLS';
            addNode(tlsId, tlsLabel, 'tls', tls.tls_version && tls.tls_version.includes('1.3') ? '#34d399' : '#fbbf24');
            addEdge(host, tlsId);

            // Quantum risk node
            if (qr) {
                const riskId = `${host}-risk`;
                addNode(riskId, `Risk: ${qr.risk_score}`, 'risk', GraphViewer.riskColour(qr.risk_label));
                addEdge(host, riskId);
            }

            // HNDL / service node
            if (hndl) {
                const svcId = `${host}-svc`;
                addNode(svcId, hndl.service, 'service', GraphViewer.riskColour(hndl.risk));
                addEdge(host, svcId);
            }
        });

        /* ---- Render with Cytoscape ---- */
        return cytoscape({
            container: document.getElementById(containerId),
            elements,
            style: [
                {
                    selector: 'node',
                    style: {
                        label: 'data(label)',
                        'background-color': 'data(colour)',
                        color: '#e2e8f0',
                        'font-size': '11px',
                        'font-family': "'Inter', sans-serif",
                        'text-valign': 'bottom',
                        'text-margin-y': 6,
                        'text-outline-width': 2,
                        'text-outline-color': '#0a0e1a',
                        width: 32,
                        height: 32,
                        'border-width': 2,
                        'border-color': 'data(colour)',
                        'border-opacity': 0.6,
                    },
                },
                {
                    selector: 'node[type="domain"]',
                    style: { width: 48, height: 48, 'font-size': '13px', 'font-weight': 'bold' },
                },
                {
                    selector: 'edge',
                    style: {
                        width: 1.5,
                        'line-color': 'rgba(99, 102, 241, 0.35)',
                        'target-arrow-color': 'rgba(99, 102, 241, 0.35)',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                    },
                },
            ],
            layout: {
                name: 'cose',
                animate: true,
                animationDuration: 1000,
                refresh: 20,
                fit: true,
                padding: 100,
                randomize: true,
                componentSpacing: 300,
                nodeRepulsion: function () { return 2000000; }, // Extreme repulsion
                nodeOverlap: 50,
                idealEdgeLength: function () { return 250; }, // Very long edges
                edgeElasticity: function () { return 50; }, // Looser edges
                nestingFactor: 1.2,
                gravity: 0.1, // Near zero gravity so they spread wide
                numIter: 2500,
                initialTemp: 800,
            },
        });
    }
}
