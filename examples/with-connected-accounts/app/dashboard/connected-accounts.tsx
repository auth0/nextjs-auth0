"use client";

import { useState } from "react";

const button =
  "rounded-lg px-3 py-2 text-sm font-medium text-white transition disabled:opacity-50";

export function ConnectedAccounts() {
  const [connection, setConnection] = useState("google-oauth2");
  const [loginHint, setLoginHint] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function run(request: () => Promise<Response>) {
    setBusy(true);
    const res = await request();
    setResult(await res.json());
    setBusy(false);
  }

  const query = `connection=${encodeURIComponent(connection)}`;

  return (
    <div className="space-y-4 rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
      <div className="grid grid-cols-2 gap-4">
        <label className="text-xs font-medium text-gray-600">
          Connection
          <input
            className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
            value={connection}
            onChange={(e) => setConnection(e.target.value)}
          />
        </label>
        <label className="text-xs font-medium text-gray-600">
          Login hint (optional, to pick an account)
          <input
            className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
            value={loginHint}
            onChange={(e) => setLoginHint(e.target.value)}
          />
        </label>
      </div>

      <div className="flex flex-wrap gap-3">
        {/* Starts the flow at the provider and returns here. */}
        <a
          className={`${button} bg-emerald-600 hover:bg-emerald-700`}
          href={`/auth/connect?${query}&returnTo=/dashboard`}
        >
          Connect
        </a>
        <button
          disabled={busy}
          className={`${button} bg-indigo-600 hover:bg-indigo-700`}
          onClick={() => run(() => fetch("/api/connected-accounts"))}
        >
          List accounts
        </button>
        <button
          disabled={busy}
          className={`${button} bg-violet-600 hover:bg-violet-700`}
          onClick={() =>
            run(() =>
              fetch("/api/connection-token", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ connection, loginHint }),
              })
            )
          }
        >
          Get connection token
        </button>
        <button
          disabled={busy}
          className={`${button} bg-red-600 hover:bg-red-700`}
          onClick={() => run(() => fetch(`/api/connected-accounts?${query}`, { method: "DELETE" }))}
        >
          Disconnect
        </button>
      </div>

      {result !== null && (
        <pre className="overflow-x-auto rounded-lg border border-gray-100 bg-gray-50 p-3 text-xs">
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}
