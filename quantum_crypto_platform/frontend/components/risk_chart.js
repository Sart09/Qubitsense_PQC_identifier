/**
 * Risk Chart component.
 * Renders a Chart.js doughnut chart showing quantum risk distribution.
 */

class RiskChart {
    /**
     * @param {string} canvasId — the <canvas> element ID
     * @param {Array}  quantumResults — array from GET /scan/{id}/quantum-risk
     */
    static render(canvasId, quantumResults) {
        const counts = { 'Quantum Vulnerable': 0, 'Transitioning': 0, 'Quantum Safe': 0 };

        quantumResults.forEach((r) => {
            const label = r.risk_label || 'Quantum Vulnerable';
            if (counts[label] !== undefined) counts[label]++;
            else counts['Quantum Vulnerable']++;
        });

        const ctx = document.getElementById(canvasId).getContext('2d');

        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Quantum Vulnerable', 'Transitioning', 'Quantum Safe'],
                datasets: [
                    {
                        data: [counts['Quantum Vulnerable'], counts['Transitioning'], counts['Quantum Safe']],
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
