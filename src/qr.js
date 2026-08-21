import QRCode from 'qrcode';

export async function generateQrDataUrl(text) {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'L', width: 300 });
}
