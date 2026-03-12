/**
 * QR Code Scanner component.
 * Wraps html5-qrcode library to provide QR/barcode scanning via camera.
 */

class QRScanner {
  constructor(containerId, onResult) {
    this.containerId = containerId;
    this.onResult = onResult;
    this.scanner = null;
  }

  /** Extract a bare domain from a URL or plain text. */
  static extractDomain(text) {
    try {
      const url = new URL(text);
      return url.hostname;
    } catch {
      return text.replace(/^https?:\/\//i, '').split('/')[0].trim();
    }
  }

  /** Start the camera and begin scanning. */
  async start() {
    if (typeof Html5Qrcode === 'undefined') {
      throw new Error('html5-qrcode library not loaded');
    }

    this.scanner = new Html5Qrcode(this.containerId);

    await this.scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      (decodedText) => {
        const domain = QRScanner.extractDomain(decodedText);
        this.stop();
        this.onResult(domain);
      },
      () => {} // ignore scan failures (no QR in frame)
    );
  }

  /** Stop the camera. */
  async stop() {
    if (this.scanner) {
      try {
        await this.scanner.stop();
      } catch { /* already stopped */ }
      this.scanner.clear();
      this.scanner = null;
    }
  }
}
