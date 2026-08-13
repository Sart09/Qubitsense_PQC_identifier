/**
 * Graph Viewer component.
 * Builds and renders a Cytoscape.js attack-surface graph from TLS, quantum
 * risk, and HNDL data.
 *
 * Rewritten from a flat star topology (domain -> host -> [tls-node,
 * risk-node, service-node], four nodes per host) to one that shows a real
 * relationship the old version never encoded: hosts sharing the same
 * resolved IP address. On a 76-host scan of a real bank domain, 8 of those
 * hosts turned out to share just 3 IPs — that's a genuine "these subdomains
 * are the same backend" finding, and the old graph had no way to show it;
 * every host hung off the root independently regardless of shared infra.
 *
 * The satellite nodes (a separate dot for TLS version, risk score, and
 * service type per host) are gone — that data was already in the Asset
 * Inventory table, so repeating it as extra graph nodes was pure clutter,
 * not new information. It now lives in the host node's color (risk_label),
 * size (HNDL harvest value), and border (certificate issues), with full
 * detail one click away via the existing asset drill-down modal.
 */

class GraphViewer {
    /**
     * Colour a node by its risk level / label. Matches the canonical
     * risk_label vocabulary used everywhere else on the dashboard.
     */
    static riskColour(label) {
        if (!label) return '#94a3b8';
        const l = label.toLowerCase();
        if (l === 'critical') return '#f87171';
        if (l === 'quantum vulnerable' || l === 'high') return '#fb923c';
        if (l === 'transitioning' || l === 'medium') return '#fbbf24';
        if (l === 'quantum safe' || l === 'low') return '#34d399';
        return '#94a3b8';
    }

    /**
     * Render the attack-surface graph.
     *
     * @param {string} containerId  — DOM element id for the graph
     * @param {string} domain       — root target domain
     * @param {Array}  tlsResults   — from GET /scan/{id}/tls (id, hostname,
     *                                ip_address, is_expired, is_self_signed,
     *                                hostname_mismatch)
     * @param {Array}  qrResults    — from GET /scan/{id}/quantum-risk
     * @param {Array}  hndlTargets  — from GET /scan/{id}/hndl  (.targets)
     */
    static render(containerId, domain, tlsResults, qrResults, hndlTargets) {
        const elements = [];
        const nodeIds = new Set();

        const addNode = (id, label, type, colour, extra = {}) => {
            if (nodeIds.has(id)) return;
            nodeIds.add(id);
            elements.push({ data: { id, label, type, colour, ...extra } });
        };
        const addEdge = (src, tgt, thick = false) => {
            elements.push({ data: { source: src, target: tgt, thick: thick ? 1 : 0 } });
        };

        addNode(domain, domain, 'domain', '#818cf8');

        const qrMap = {}; qrResults.forEach((r) => (qrMap[r.hostname] = r));
        const hndlMap = {}; hndlTargets.forEach((t) => (hndlMap[t.hostname] = t));

        // Group hosts by resolved IP — the real relationship worth showing.
        const ipGroups = {};
        tlsResults.forEach((tls) => {
            const ip = tls.ip_address || null;
            const key = ip || `__unresolved__${tls.hostname}`;
            (ipGroups[key] = ipGroups[key] || { ip, hosts: [] }).hosts.push(tls);
        });

        Object.values(ipGroups).forEach(({ ip, hosts }) => {
            const shared = ip && hosts.length > 1;
            let parent = domain;

            if (shared) {
                const ipNodeId = `ip-${ip}`;
                addNode(ipNodeId, `${ip}\n(${hosts.length} hosts)`, 'ip-hub', '#facc15');
                addEdge(domain, ipNodeId, true);
                parent = ipNodeId;
            }

            hosts.forEach((tls) => {
                const host = tls.hostname;
                const qr = qrMap[host];
                const hndl = hndlMap[host];
                const colour = qr ? GraphViewer.riskColour(qr.risk_label) : '#94a3b8';

                // Size encodes HNDL harvest value (1.0x-2.0x -> ~26-50px) —
                // a bigger node is a more attractive harvest-now target, not
                // just a bigger dot for its own sake.
                const mult = hndl ? hndl.multiplier : 1.0;
                const size = Math.round(26 + (mult - 1.0) * 24);

                // Thick red border flags a real certificate problem
                // (expired / self-signed / hostname mismatch) — data that
                // exists because of the cert-validation work, now visible
                // in the one view meant to show "where's the risk."
                const hasCertIssue = tls.is_expired || tls.is_self_signed || tls.hostname_mismatch;

                addNode(host, host, 'subdomain', colour, {
                    assetId: tls.id,
                    size,
                    borderColour: hasCertIssue ? '#ef4444' : colour,
                    borderWidth: hasCertIssue ? 4 : 2,
                });
                addEdge(parent, host);
            });
        });

        const cy = cytoscape({
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
                        'text-wrap': 'wrap',
                        width: 'data(size)',
                        height: 'data(size)',
                        'border-width': 'data(borderWidth)',
                        'border-color': 'data(borderColour)',
                        'border-opacity': 0.9,
                    },
                },
                {
                    selector: 'node[type="domain"]',
                    style: { width: 52, height: 52, 'font-size': '13px', 'font-weight': 'bold', 'border-width': 0 },
                },
                {
                    selector: 'node[type="ip-hub"]',
                    style: {
                        shape: 'diamond',
                        width: 34, height: 34,
                        'font-size': '9px',
                        'border-width': 0,
                    },
                },
                {
                    selector: 'node[type="subdomain"]',
                    style: { cursor: 'pointer' },
                },
                {
                    selector: 'edge',
                    style: {
                        width: 'mapData(thick, 0, 1, 1.5, 3)',
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
                animationDuration: 800,
                refresh: 20,
                fit: true,
                padding: 80,
                randomize: true,
                componentSpacing: 200,
                nodeRepulsion: function () { return 900000; },
                nodeOverlap: 40,
                idealEdgeLength: function () { return 130; },
                edgeElasticity: function () { return 80; },
                nestingFactor: 1.2,
                gravity: 0.3,
                numIter: 1500,
                initialTemp: 500,
            },
        });

        // Click a subdomain node -> reuse the existing asset drill-down
        // modal (same one the Asset Inventory table opens), instead of
        // building a second, separate detail surface.
        cy.on('tap', 'node[type="subdomain"]', (evt) => {
            const assetId = evt.target.data('assetId');
            if (assetId && typeof window.openAssetModal === 'function') {
                window.openAssetModal(assetId);
            }
        });

        return cy;
    }
}
