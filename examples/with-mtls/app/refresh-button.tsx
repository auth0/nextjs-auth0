"use client";

import { useState } from "react";

type RefreshResult = {
  token: string;
  expiresAt: number;
  payload: Record<string, unknown> | null;
  cnf: string | null;
};

export function RefreshButton({
  refreshAction,
}: {
  refreshAction: () => Promise<RefreshResult | { error: string }>;
}) {
  const [state, setState] = useState<
    | { status: "idle" }
    | { status: "loading" }
    | { status: "ok"; result: RefreshResult }
    | { status: "error"; error: string }
  >({ status: "idle" });

  async function handleClick() {
    setState({ status: "loading" });
    const res = await refreshAction();
    if ("error" in res) {
      setState({ status: "error", error: res.error });
    } else {
      setState({ status: "ok", result: res });
    }
  }

  return (
    <div>
      <button onClick={handleClick} disabled={state.status === "loading"}>
        {state.status === "loading" ? "Refreshing…" : "Force Refresh Token"}
      </button>

      {state.status === "error" && (
        <p style={{ color: "red", marginTop: "0.5rem" }}>Error: {state.error}</p>
      )}

      {state.status === "ok" && (
        <div style={{ marginTop: "1rem" }}>
          <p>
            <strong>cnf.x5t#S256:</strong>{" "}
            {state.result.cnf ? (
              <span style={{ color: "green" }}>✓ {state.result.cnf}</span>
            ) : (
              <span style={{ color: "red" }}>✗ not present</span>
            )}
          </p>
          <p><strong>Expires at:</strong> {new Date(state.result.expiresAt * 1000).toISOString()}</p>
          <p><strong>Payload:</strong></p>
          <pre style={{ overflowX: "auto" }}>
            {JSON.stringify(state.result.payload, null, 2)}
          </pre>
          <p><strong>Raw token:</strong></p>
          <pre style={{ wordBreak: "break-all" }}>{state.result.token}</pre>
          <button onClick={handleClick} style={{ marginTop: "0.5rem" }}>
            Refresh Again
          </button>
        </div>
      )}
    </div>
  );
}
