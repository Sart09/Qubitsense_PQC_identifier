/**
 * Risk Chart component.
 * Renders a Chart.js doughnut chart showing quantum risk distribution (PQC Posture).
 */

class RiskChart {
    /**
     * @param {string} canvasId — the <canvas> element ID
     * @param {Array}  quantumResults — array from GET /scan/{id}/quantum-risk
     */
    static render(canvasId, quantumResults) {
        const counts = { 'Legacy': 0, 'Standard': 0, 'Elite-PQC': 0 };

        quantumResults.forEach((r) => {
            const score = r.risk_score || 0;
            const rating = (100 - score) * 10;
            
            if (rating < 400) counts['Legacy']++;
            else if (rating >= 700) counts['Elite-PQC']++;
            else counts['Standard']++;
        });

        const ctx = document.getElementById(canvasId).getContext('2d');

        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Legacy (High Exposure)', 'Standard (Transitional)', 'Elite-PQC (Safe)'],
                datasets: [
                    {
                        data: [counts['Legacy'], counts['Standard'], counts['Elite-PQC']],
                        backgroundColor: [
                            'rgba(248, 113, 113, 0.85)',
                            'rgba(251, 191, 36, 0.85)',
                            'rgba(52, 211, 153, 0.85)',
                        ],
                        borderColor: [
                            'rgba(248, 113, 113, 1)',
                            'rgba(251, 191, 36, 1)',
                            'rgba(52, 211, 153, 1)',
                        ],
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
