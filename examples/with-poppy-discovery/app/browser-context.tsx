"use client";

import { poppy } from "@auth0/nextjs-auth0";
import { useState } from "react";

// Calls the SDK's client-side poppy.getContext(), which reads the
// /auth/poppy-context route, and shows the result or the error code.
export function BrowserContext() {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    try {
      setResult(JSON.stringify(await poppy.getContext(), null, 2));
    } catch (error) {
      const code = (error as { code?: string }).code;
      const message = error instanceof Error ? error.message : String(error);
      setResult(`Error${code ? ` (${code})` : ""}: ${message}`);
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <div className="methods">
        <button
          className="button button-secondary"
          disabled={running}
          onClick={run}
        >
          poppy.getContext() in the browser
        </button>
      </div>

      {result !== null && (
        <div>
          <p className="result-title">poppy.getContext() in the browser</p>
          <pre>{result}</pre>
        </div>
      )}
    </>
  );
}
