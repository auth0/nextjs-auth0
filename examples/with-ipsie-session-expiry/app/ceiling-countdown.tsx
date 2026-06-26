"use client";

import { useEffect, useState } from "react";

// The SDK enforces the ceiling 30s early (leeway for clock skew).
// Show time until enforcement, not time until the raw ceiling timestamp.
const LEEWAY = 30;

export function CeilingCountdown({ ceiling }: { ceiling: number }) {
  const enforcedAt = ceiling - LEEWAY;

  const [remaining, setRemaining] = useState(
    enforcedAt - Math.floor(Date.now() / 1000)
  );

  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining(enforcedAt - Math.floor(Date.now() / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [enforcedAt]);

  const status = remaining <= 0 ? "expired" : "active";

  const badgeClass =
    status === "active" ? "badge badge-green" : "badge badge-red";

  return (
    <>
      <div className="label">Ceiling (Unix seconds)</div>
      <div className="value">{ceiling}</div>

      <div className="label" style={{ marginTop: "0.75rem" }}>
        Ceiling (human-readable)
      </div>
      <div className="value">{new Date(ceiling * 1000).toLocaleString()}</div>

      <div className="label" style={{ marginTop: "0.75rem" }}>
        Time until enforcement (ceiling − 30s leeway)
      </div>
      <div
        className="value"
        style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
      >
        {remaining > 0 ? `${remaining}s` : "Enforced"}
        <span className={badgeClass}>
          {status === "active" ? "Active" : "Expired"}
        </span>
      </div>

      <p style={{ fontSize: "0.8rem", color: "#6b7280", marginTop: "0.75rem" }}>
        Hits 0 when <code>now &gt;= ceiling − 30s</code>. All session reads
        and token fetches are blocked from this point.
      </p>
    </>
  );
}
