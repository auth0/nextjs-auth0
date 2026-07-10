"use client";

import { passkey, serializeCredential } from "@auth0/nextjs-auth0";
import { useEffect, useState } from "react";

// Exposes passkey client methods and the serializeCredential utility for Playwright.
export default function PasskeyPage() {
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => { setHydrated(true); }, []);

  async function run(fn: () => Promise<unknown>) {
    setError("");
    setResult("");
    try {
      const res = await fn();
      setResult(JSON.stringify(res ?? "ok"));
    } catch (e: any) {
      setError(e.message ?? String(e));
    }
  }

  return (
    <main data-hydrated={hydrated ? "true" : undefined}>
      <p id="result">{result}</p>
      <p id="error">{error}</p>

      {/* CLIENT: passkey.signup() — fetches challenge, calls navigator.credentials.create, verifies */}
      <button
        id="passkey-signup"
        onClick={() =>
          run(() =>
            passkey.signup({
              email: process.env.NEXT_PUBLIC_TEST_PASSKEY_EMAIL ?? "noreply@example.com",
            })
          )
        }
      >
        passkey.signup
      </button>

      {/* CLIENT: passkey.login() — fetches challenge, calls navigator.credentials.get, verifies */}
      <button id="passkey-login" onClick={() => run(() => passkey.login())}>
        passkey.login
      </button>

      {/* CLIENT: enrollmentChallenge via /auth/passkey/enrollment-challenge */}
      <button
        id="passkey-enrollment-challenge"
        onClick={() =>
          run(async () => {
            const res = await fetch("/auth/passkey/enrollment-challenge", { method: "POST" });
            return res.json();
          })
        }
      >
        POST /auth/passkey/enrollment-challenge
      </button>

      {/* serializeCredential — exported utility, verify it is callable */}
      <button
        id="serialize-credential-check"
        onClick={() =>
          run(async () => {
            // serializeCredential takes a PublicKeyCredential — pass null to confirm export exists
            const type = typeof serializeCredential;
            return { type };
          })
        }
      >
        typeof serializeCredential
      </button>

      {/* passkey.enrollmentVerify() — client singleton with fake params */}
      <button
        id="passkey-enrollment-verify"
        onClick={() =>
          run(() =>
            passkey.enrollmentVerify({
              authenticationMethodId: "fake-method-id",
              authSession: "fake-auth-session",
              authResponse: {} as any,
            })
          )
        }
      >
        passkey.enrollmentVerify
      </button>
    </main>
  );
}
