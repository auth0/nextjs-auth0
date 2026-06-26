"use client";

import { useState } from "react";

export function SessionCheckPanel() {
  const [result, setResult] = useState<object | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleCheck() {
    setLoading(true);
    const res = await fetch("/api/check-session");
    const data = await res.json();
    setResult(data);
    setLoading(false);
  }

  return (
    <div>
      <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
        Calls a server-side route that invokes <code>getSession()</code> and
        returns the result as JSON. After the ceiling passes, this returns{" "}
        <code>{`{ "session": null, "expired": true }`}</code> — the same null
        the page would receive before redirecting to login.
      </p>
      <button onClick={handleCheck} disabled={loading}>
        {loading ? "Checking…" : "Check Session"}
      </button>
      {result && (
        <pre className="token" style={{ whiteSpace: "pre-wrap", marginTop: "0.75rem" }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}
