"use client";

import { useEffect, useRef } from "react";

import QRCode from "qrcode";

export function QrCode({ value }: { value: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (canvasRef.current) {
      QRCode.toCanvas(canvasRef.current, value, { width: 160, margin: 2 }).catch(() => {});
    }
  }, [value]);

  return <canvas ref={canvasRef} />;
}
