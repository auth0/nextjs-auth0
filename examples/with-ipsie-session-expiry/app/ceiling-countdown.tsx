"use client";

import { useEffect, useState } from "react";

// The SDK enforces the ceiling 30s early (leeway for clock skew).
// Show time until enforcement, not time until the raw ceiling timestamp.
const LEEWAY = 30;

export function CeilingCountdown({ ceiling }: { ceiling: number }) {
  const enforcedAt = ceiling - LEEWAY;

  // Seed to null to avoid a server/client hydration mismatch on the first render.
  // The interval fires immediately and sets the real value on the client.
  const [remaining, setRemaining] = useState<number | null>(null);

  useEffect(() => {
    function tick() {
      setRemaining(enforcedAt - Math.floor(Date.now() / 1000));
    }
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [enforcedAt]);

  const status =
    remaining === null ? "loading" : remaining <= 0 ? "expired" : remaining <= 30 ? "warning" : "active";

  const badgeClass =
    status === "active"
      ? "badge badge-green"
      : status === "warning"
        ? "badge badge-yellow"
        : status === "expired"
          ? "badge badge-red"
          : "badge";

  const badgeLabel =
    status === "active"
      ? "Active"
      : status === "warning"
        ? "Expiring soon"
        : status === "expired"
          ? "Expired"
          : "…";

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
        {remaining === null ? "…" : remaining > 0 ? `${remaining}s` : "Enforced"}
        <span className={badgeClass}>{badgeLabel}</span>
      </div>

      <p style={{ fontSize: "0.8rem", color: "#6b7280", marginTop: "0.75rem" }}>
        Hits 0 when <code>now &gt;= ceiling − 30s</code>. All session reads
        and token fetches are blocked from this point.
      </p>
    </>
  );
}
