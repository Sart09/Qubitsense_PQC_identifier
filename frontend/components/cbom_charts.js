/**
 * CBOM Charts component.
 * Aggregates tlsData to render Cipher Suite distribution and Key Lengths using Chart.js.
 */

class CbomCharts {
    static cipherChartInst = null;
    static keyLenChartInst = null;

    static render(cipherCanvasId, keyLenCanvasId, tlsData) {
        if (!tlsData || tlsData.length === 0) return;

        // 1. Aggregate Cipher Suites
        const cipherCounts = {};
        // 2. Aggregate Key Lengths
        const keyLenCounts = {};

        tlsData.forEach(t => {
            const cipher = t.cipher_suite || 'Unknown Cipher';
            const keySize = t.key_size ? `${t.key_size} bits` : 'Unknown Size';

            cipherCounts[cipher] = (cipherCounts[cipher] || 0) + 1;
            keyLenCounts[keySize] = (keyLenCounts[keySize] || 0) + 1;
        });

        // Convert to sorted arrays for charting
        const cipherLabels = Object.keys(cipherCounts).sort((a,b) => cipherCounts[b] - cipherCounts[a]);
        const cipherData = cipherLabels.map(l => cipherCounts[l]);

        const keyLenLabels = Object.keys(keyLenCounts).sort((a,b) => keyLenCounts[b] - keyLenCounts[a]);
        const keyLenData = keyLenLabels.map(l => keyLenCounts[l]);

        // Destroy old instances if re-rendering
        if (this.cipherChartInst) this.cipherChartInst.destroy();
        if (this.keyLenChartInst) this.keyLenChartInst.destroy();

        // Render Cipher Chart (Bar)
        const ctxCipher = document.getElementById(cipherCanvasId).getContext('2d');
        this.cipherChartInst = new Chart(ctxCipher, {
            type: 'bar',
            data: {
                labels: cipherLabels,
                datasets: [{
                    label: 'Cipher Suite Frequency',
                    data: cipherData,
                    backgroundColor: 'rgba(99, 102, 241, 0.85)',
                    borderColor: 'rgba(99, 102, 241, 1)',
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y', // horizontal bar chart for long cipher names
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#a5b4fc',
                        bodyColor: '#e2e8f0',
                    }
                },
                scales: {
                    x: { ticks: { stepSize: 1, color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#cbd5e1', font: {family: 'monospace', size: 10} }, grid: { display: false } }
                }
            }
        });

        // Render Key Length Chart (Doughnut)
        const ctxKeyLen = document.getElementById(keyLenCanvasId).getContext('2d');
        this.keyLenChartInst = new Chart(ctxKeyLen, {
            type: 'doughnut',
            data: {
                labels: keyLenLabels,
                datasets: [{
                    data: keyLenData,
                    backgroundColor: [
                        'rgba(244, 114, 182, 0.85)',
                        'rgba(52, 211, 153, 0.85)',
                        'rgba(251, 191, 36, 0.85)',
                        'rgba(96, 165, 250, 0.85)'
                    ],
                    borderWidth: 0,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { position: 'right', labels: { color: '#e2e8f0' } },
                    title: { display: true, text: 'Key Size Architecture', color: '#94a3b8' }
                }
            }
        });
    }
}
