"use client";

import { useState } from "react";

export type Call = "getPoppyContext" | "getSession" | "getAnonymousSession";

// Buttons for the given SDK methods. Each result stays on the page, so two methods can be compared.
export function Inspector({ calls }: { calls: Call[] }) {
  const [running, setRunning] = useState<Call | null>(null);
  const [results, setResults] = useState<Partial<Record<Call, string>>>({});

  async function run(call: Call) {
    setRunning(call);
    let body: string;
    try {
      const response = await fetch(`/api/inspect?call=${call}`, {
        cache: "no-store"
      });
      body = JSON.stringify(await response.json(), null, 2);
    } catch (error) {
      body = `Request failed: ${error instanceof Error ? error.message : error}`;
    } finally {
      setRunning(null);
    }
    setResults((previous) => ({ ...previous, [call]: body }));
  }

  return (
    <>
      <div className="methods">
        {calls.map((call) => (
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

      {calls.map(
        (call) =>
          results[call] !== undefined && (
            <div key={call} data-call={call}>
              <p className="result-title">auth0.{call}()</p>
              <pre>{results[call]}</pre>
            </div>
          )
      )}
    </>
  );
}
