"use client";

import { mfa } from "@auth0/nextjs-auth0";
import { useState } from "react";

// Exposes the client mfa singleton methods so Playwright can drive them.
export default function MfaPage() {
  const [result, setResult] = useState("");
  const [error, setError] = useState("");

  async function run(fn: () => Promise<unknown>) {
    setError("");
    setResult("");
    try {
      const res = await fn();
      setResult(JSON.stringify(res));
    } catch (e: any) {
      setError(e.message ?? String(e));
    }
  }

  return (
    <main>
      <p id="result">{result}</p>
      <p id="error">{error}</p>

      {/* challengeWithPopup — needs audience */}
      <button
        id="challenge-with-popup"
        onClick={() =>
          run(() =>
            mfa.challengeWithPopup({ audience: process.env.NEXT_PUBLIC_TEST_AUDIENCE ?? "" })
          )
        }
      >
        challengeWithPopup
      </button>

      {/* getAuthenticators — called server-side via the /auth/mfa/authenticators route */}
      <button
        id="get-authenticators-route"
        onClick={() =>
          run(async () => {
            const res = await fetch("/auth/mfa/authenticators");
            return res.json();
          })
        }
      >
        GET /auth/mfa/authenticators
      </button>

      {/* challenge — POST /auth/mfa/challenge */}
      <button
        id="mfa-challenge-route"
        onClick={() =>
          run(async () => {
            const res = await fetch("/auth/mfa/challenge", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ challenge_type: "otp" }),
            });
            return res.json();
          })
        }
      >
        POST /auth/mfa/challenge
      </button>

      {/* mfa.getAuthenticators() — client singleton */}
      <button
        id="mfa-get-authenticators"
        onClick={() =>
          run(() =>
            mfa.getAuthenticators({ mfaToken: "fake-mfa-token" })
          )
        }
      >
        mfa.getAuthenticators
      </button>

      {/* mfa.enroll() — client singleton */}
      <button
        id="mfa-enroll"
        onClick={() =>
          run(() =>
            mfa.enroll({ mfaToken: "fake-mfa-token", authenticatorTypes: ["otp"] })
          )
        }
      >
        mfa.enroll
      </button>

      {/* mfa.verify() — client singleton */}
      <button
        id="mfa-verify"
        onClick={() =>
          run(() =>
            mfa.verify({ mfaToken: "fake-mfa-token", otp: "000000" })
          )
        }
      >
        mfa.verify
      </button>
    </main>
  );
}
