/**
 * Risk Chart component.
 * Renders a Chart.js doughnut chart showing quantum risk distribution (PQC Posture).
 *
 * Uses the backend's own risk_label on each result (from
 * analysis/quantum_risk_engine.py::get_risk_label) rather than recomputing
 * thresholds client-side — this used to independently re-bucket scores into
 * a different 3-tier scheme (Legacy/Standard/Elite-PQC) with different cutoffs
 * than the dashboard's own classification column, so the donut and the table
 * could disagree about the same asset. Now both read the same field.
 */

const RISK_LABEL_COLORS = {
    'Quantum Safe': { bg: 'rgba(52, 211, 153, 0.85)', border: 'rgba(52, 211, 153, 1)' },
    'Transitioning': { bg: 'rgba(251, 191, 36, 0.85)', border: 'rgba(251, 191, 36, 1)' },
    'Quantum Vulnerable': { bg: 'rgba(251, 146, 60, 0.85)', border: 'rgba(251, 146, 60, 1)' },
    'Critical': { bg: 'rgba(248, 113, 113, 0.85)', border: 'rgba(248, 113, 113, 1)' },
};
const RISK_LABEL_ORDER = ['Quantum Safe', 'Transitioning', 'Quantum Vulnerable', 'Critical'];

class RiskChart {
    /**
     * @param {string} canvasId — the <canvas> element ID
     * @param {Array}  quantumResults — array from GET /scan/{id}/quantum-risk
     */
    static render(canvasId, quantumResults) {
        const counts = { 'Quantum Safe': 0, 'Transitioning': 0, 'Quantum Vulnerable': 0, 'Critical': 0 };

        quantumResults.forEach((r) => {
            const label = RISK_LABEL_ORDER.includes(r.risk_label) ? r.risk_label : 'Transitioning';
            counts[label]++;
        });

        const ctx = document.getElementById(canvasId).getContext('2d');

        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: RISK_LABEL_ORDER,
                datasets: [
                    {
                        data: RISK_LABEL_ORDER.map((l) => counts[l]),
                        backgroundColor: RISK_LABEL_ORDER.map((l) => RISK_LABEL_COLORS[l].bg),
                        borderColor: RISK_LABEL_ORDER.map((l) => RISK_LABEL_COLORS[l].border),
                        borderWidth: 2,
                        hoverOffset: 8,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#e2e8f0',
                            padding: 16,
                            font: { family: "'Inter', sans-serif", size: 13 },
                            usePointStyle: true,
                            pointStyleWidth: 10,
                        },
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#a5b4fc',
                        bodyColor: '#e2e8f0',
                        borderColor: 'rgba(99, 102, 241, 0.3)',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                    },
                },
            },
        });
    }
}
