"use client";

import { useEffect, useRef, useState } from "react";

import QRCode from "qrcode";

export function QrCode({ value, secret }: { value: string; secret?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [renderError, setRenderError] = useState(false);

  useEffect(() => {
    setRenderError(false);
  }, [value]);

  useEffect(() => {
    if (!renderError && canvasRef.current) {
      QRCode.toCanvas(canvasRef.current, value, { width: 160, margin: 2 }).catch(() => {
        setRenderError(true);
      });
    }
  }, [value, renderError]);

  return (
    <div className="space-y-3 text-center">
      {!renderError && <canvas ref={canvasRef} />}
      {(renderError || secret) && (
        <div className="space-y-1">
          {renderError && (
            <p className="text-xs text-red-600">QR code could not be rendered.</p>
          )}
          {secret && (
            <p className="text-xs text-gray-500">
              Can&apos;t scan? Enter this key manually:{" "}
              <code className="rounded bg-gray-100 px-1 py-0.5 font-mono text-gray-800 select-all">
                {secret}
              </code>
            </p>
          )}
        </div>
      )}
    </div>
  );
}
