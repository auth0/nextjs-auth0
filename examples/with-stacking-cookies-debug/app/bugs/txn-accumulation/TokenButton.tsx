"use client";

import { useState } from "react";

export default function TokenButton() {
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function fetchToken() {
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/token");
      const data = await res.json();
      if (data.error) {
        setResult(`Error: ${data.error}`);
      } else {
        setResult(`Access token (first 40 chars): ${data.accessToken?.slice(0, 40)}…\nExpires at: ${new Date(data.expiresAt * 1000).toISOString()}`);
      }
    } catch (e: any) {
      setResult(`Fetch failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ marginTop: 32, borderTop: "1px solid #e5e7eb", paddingTop: 24 }}>
      <button
        onClick={fetchToken}
        disabled={loading}
        style={{
          background: "#16a34a", color: "white", borderRadius: 6,
          padding: "10px 20px", fontWeight: 500, fontSize: 14,
          border: "none", cursor: loading ? "not-allowed" : "pointer",
          opacity: loading ? 0.7 : 1,
        }}
      >
        {loading ? "Fetching…" : "Get Access Token"}
      </button>
      {result && (
        <pre style={{
          marginTop: 12, background: "#f9fafb", border: "1px solid #e5e7eb",
          borderRadius: 6, padding: "12px 16px", fontSize: 12,
          color: result.startsWith("Error") ? "#dc2626" : "#111827",
          whiteSpace: "pre-wrap", wordBreak: "break-all",
        }}>
          {result}
        </pre>
      )}
    </div>
  );
}
