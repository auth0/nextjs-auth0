"use client";

import { useState } from "react";

import { getAccessToken, mfa } from "@auth0/nextjs-auth0/client";
import { MfaRequiredError } from "@auth0/nextjs-auth0/errors";

type Step = "idle" | "otp";

export function StepUpButton() {
  const [step, setStep] = useState<Step>("idle");
  const [mfaToken, setMfaToken] = useState("");
  const [oobCode, setOobCode] = useState("");
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setStep("idle");
    setMfaToken("");
    setOobCode("");
    setOtp("");
    setError(null);
  }

  async function handleStepUp() {
    setLoading(true);
    setError(null);

    try {
      const token = await getAccessToken({
        audience: "https://api.example.com",
        scope: "read:users write:users"
      });
      alert(`Access token received — check the browser console.\n\n${token}`);
    } catch (err) {
      if (err instanceof MfaRequiredError) {
        try {
          const authenticators = await mfa.getAuthenticators({
            mfaToken: err.mfa_token
          });
          const active = authenticators.find(a => a.active);

          if (!active) {
            setError("No active MFA authenticator found. Please enroll a factor first.");
            setLoading(false);
            return;
          }

          const challengeRes = await mfa.challenge({
            mfaToken: err.mfa_token,
            challengeType: active.authenticatorType,
            authenticatorId: active.id
          });

          setMfaToken(err.mfa_token);
          if (challengeRes.oobCode) {
            setOobCode(challengeRes.oobCode);
          }
          setStep("otp");
        } catch (mfaErr: any) {
          setError(mfaErr?.error_description ?? "Failed to initiate MFA challenge.");
        }
      } else {
        const e = err as { error_description?: string; message?: string };
        setError(e.error_description ?? e.message ?? "Failed to get access token.");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (oobCode) {
        await mfa.verify({ mfaToken, oobCode, bindingCode: otp });
      } else {
        await mfa.verify({ mfaToken, otp });
      }

      // mfa.verify() caches the token in the session cookie and returns { success: true }.
      // Retrieve the access token from the session via getAccessToken().
      const token = await getAccessToken({
        audience: "https://api.example.com",
        scope: "read:users write:users"
      });
      console.log(`MFA complete — access token received.\n\n${token}`);
      reset();
    } catch (err: any) {
      setError(err?.error_description ?? err?.message ?? "Invalid code. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";

  if (step === "otp") {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-800">Two-factor authentication</h2>
          <p className="mt-1 text-sm text-gray-500">
            {oobCode
              ? "Enter the code sent to your phone."
              : "Enter the 6-digit code from your authenticator app."}
          </p>
        </div>

        <form onSubmit={handleVerify} className="space-y-4">
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            placeholder="000000"
            required
            autoFocus
            disabled={loading}
            className={inputClass + " text-center text-lg tracking-widest"}
          />

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || otp.length < 6}
            className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
          >
            {loading ? "Verifying…" : "Verify"}
          </button>
        </form>

        <button
          type="button"
          onClick={reset}
          className="w-full text-center text-sm text-gray-500 hover:text-gray-700"
        >
          ← Cancel
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <button
        type="button"
        onClick={handleStepUp}
        disabled={loading}
        className="w-full rounded-lg border border-orange-300 bg-orange-50 px-4 py-2 text-sm font-medium text-orange-700 transition hover:bg-orange-100 disabled:opacity-50"
      >
        {loading ? "Requesting…" : "Get token (read:users write:users)"}
      </button>
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {error}
        </div>
      )}
    </div>
  );
}
