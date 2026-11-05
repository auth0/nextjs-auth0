"use client";

import { useState } from "react";

const CALLS = ["getPoppyContext", "getSession", "getAnonymousSession"] as const;
type Call = (typeof CALLS)[number];

export function Inspector() {
  const [running, setRunning] = useState<Call | null>(null);
  const [result, setResult] = useState<{ call: Call; body: string } | null>(
    null
  );

  async function run(call: Call) {
    setRunning(call);
    try {
      const response = await fetch(`/api/inspect?call=${call}`, {
        cache: "no-store"
      });
      const body = await response.json();
      setResult({ call, body: JSON.stringify(body, null, 2) });
    } catch (error) {
      setResult({
        call,
        body: `Request failed: ${error instanceof Error ? error.message : error}`
      });
    } finally {
      setRunning(null);
    }
  }

  return (
    <>
      <div className="methods">
        {CALLS.map((call) => (
          <button
            key={call}
            className="button button-secondary"
            disabled={running !== null}
            onClick={() => run(call)}
          >
            auth0.{call}()
          </button>
        ))}
      </div>

      {result && (
        <>
          <p className="result-title">auth0.{result.call}()</p>
          <pre>{result.body}</pre>
        </>
      )}
    </>
  );
}
