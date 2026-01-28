'use client';

import { useEffect, useRef } from 'react';
import QRCode from 'qrcode';

interface QrCodeDisplayProps {
  barcodeUri: string;
  secret: string;
}

export function QrCodeDisplay({ barcodeUri, secret }: QrCodeDisplayProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (canvasRef.current && barcodeUri) {
      QRCode.toCanvas(canvasRef.current, barcodeUri, {
        width: 256,
        margin: 2,
      }).catch(err => {
        console.error('[Component:QRCode] Generation failed:', err);
      });
    }
  }, [barcodeUri]);

  return (
    <div className="flex flex-col items-center space-y-4">
      <div className="bg-white p-4 rounded-lg shadow-lg">
        <canvas ref={canvasRef} />
      </div>
      <div className="text-center">
        <p className="text-sm text-gray-600 mb-2">
          Or enter this code manually:
        </p>
        <code className="bg-gray-100 px-3 py-2 rounded text-sm font-mono">
          {secret}
        </code>
      </div>
      <div className="text-xs text-gray-500 max-w-md text-center">
        Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
      </div>
    </div>
  );
}
