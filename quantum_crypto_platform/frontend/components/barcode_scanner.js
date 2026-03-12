/**
 * Barcode Scanner component.
 * Wraps QuaggaJS to provide barcode scanning via camera.
 * Supports Code128, EAN, and Code39 formats.
 */

class BarcodeScanner {
    constructor(containerId, onResult) {
        this.containerId = containerId;
        this.onResult = onResult;
        this.running = false;
    }

    /** Extract a bare domain from scanned text. */
    static extractDomain(text) {
        try {
            const url = new URL(text);
            return url.hostname;
        } catch {
            return text.replace(/^https?:\/\//i, '').split('/')[0].trim();
        }
    }

    /** Start the camera and begin scanning. */
    start() {
        if (typeof Quagga === 'undefined') {
            throw new Error('QuaggaJS library not loaded');
        }

        return new Promise((resolve, reject) => {
            Quagga.init(
                {
                    inputStream: {
                        name: 'Live',
                        type: 'LiveStream',
                        target: document.getElementById(this.containerId),
                        constraints: { facingMode: 'environment' },
                    },
                    decoder: {
                        readers: [
                            'code_128_reader',
                            'ean_reader',
                            'ean_8_reader',
                            'code_39_reader',
                        ],
                    },
                    locate: true,
                    frequency: 10,
                },
                (err) => {
                    if (err) return reject(err);
                    Quagga.start();
                    this.running = true;

                    Quagga.onDetected((result) => {
                        const code = result.codeResult.code;
                        if (code) {
                            const domain = BarcodeScanner.extractDomain(code);
                            this.stop();
                            this.onResult(domain);
                        }
                    });

                    resolve();
                }
            );
        });
    }

    /** Stop the camera. */
    stop() {
        if (this.running) {
            Quagga.stop();
            this.running = false;
            const el = document.getElementById(this.containerId);
            if (el) el.innerHTML = '';
        }
    }
}
