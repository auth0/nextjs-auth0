"use client";

import { useState } from "react";

import { mfa, passkey } from "@auth0/nextjs-auth0/client";

import { QrCode } from "./qr-code";

type Mode = "login" | "signup";
type Step = "form" | "enroll" | "otp";

export function PasskeyForm() {
  const [mode, setMode] = useState<Mode>("login");
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [oobCode, setOobCode] = useState("");
  const [barcodeUri, setBarcodeUri] = useState("");
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function resetMfaState() {
    setMfaToken("");
    setOobCode("");
    setBarcodeUri("");
    setOtp("");
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (mode === "signup") {
        await passkey.signup({ email, name: displayName || email });
      } else {
        await passkey.login();
      }
      window.location.href = "/dashboard";
    } catch (err) {
      const e = err as { error?: string; error_description?: string; mfa_token?: string };

      if (e.error === "mfa_required" && e.mfa_token) {
        try {
          const authenticators = await mfa.getAuthenticators({ mfaToken: e.mfa_token });
          const active = authenticators.find(a => a.active);

          if (!active) {
            const enrollment = await mfa.enroll({
              mfaToken: e.mfa_token,
              authenticatorTypes: ["otp"]
            });
            if ("barcodeUri" in enrollment && enrollment.barcodeUri) {
              setBarcodeUri(enrollment.barcodeUri);
            }
            setMfaToken(e.mfa_token);
            setStep("enroll");
          } else {
            const challengeRes = await mfa.challenge({
              mfaToken: e.mfa_token,
              challengeType: active.authenticatorType,
              authenticatorId: active.id
            });
            setMfaToken(e.mfa_token);
            if (challengeRes.oobCode) {
              setOobCode(challengeRes.oobCode);
            }
            setStep("otp");
          }
        } catch (mfaErr: any) {
          setError(mfaErr?.error_description ?? "Failed to send MFA code. Please try again.");
        }
      } else if (e.error === "webauthn_error") {
        setError(
          e.error_description ??
            "Passkey operation was cancelled or not supported by this device."
        );
      } else if (e.error) {
        setError(e.error_description ?? "Something went wrong. Please try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleOtp(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (oobCode) {
        await mfa.verify({ mfaToken, oobCode, bindingCode: otp });
      } else {
        await mfa.verify({ mfaToken, otp });
      }
      window.location.href = "/dashboard";
    } catch (err) {
      const e = err as { error_description?: string };
      setOtp("");
      setError(e.error_description ?? "Invalid code. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60 flex items-center justify-center gap-2";

  if (step === "enroll") {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-800">Set up authenticator app</h2>
          <p className="mt-1 text-sm text-gray-500">
            Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.
          </p>
        </div>

        {barcodeUri && (
          <div className="flex justify-center rounded-lg border border-gray-200 bg-white p-4">
            <QrCode value={barcodeUri} />
          </div>
        )}

        <form onSubmit={handleOtp} className="space-y-4">
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

          <button type="submit" disabled={loading || otp.length < 6} className={btnPrimary}>
            {loading ? "Verifying…" : "Confirm & sign in"}
          </button>
        </form>

        <button
          type="button"
          onClick={() => { setStep("form"); resetMfaState(); setError(null); }}
          className="w-full text-center text-sm text-gray-500 hover:text-gray-700"
        >
          ← Back
        </button>
      </div>
    );
  }

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

        <form onSubmit={handleOtp} className="space-y-4">
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

          <button type="submit" disabled={loading || otp.length < 6} className={btnPrimary}>
            {loading ? "Verifying…" : "Verify"}
          </button>
        </form>

        <button
          type="button"
          onClick={() => { setStep("form"); resetMfaState(); setError(null); }}
          className="w-full text-center text-sm text-gray-500 hover:text-gray-700"
        >
          ← Back
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex rounded-lg border border-gray-200 p-1 text-sm">
        <button
          type="button"
          onClick={() => { setMode("login"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            mode === "login"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Sign in
        </button>
        <button
          type="button"
          onClick={() => { setMode("signup"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            mode === "signup"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Sign up
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {mode === "signup" && (
          <>
            <div>
              <label htmlFor="email" className="mb-1 block text-sm font-medium text-gray-700">
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
                className={inputClass}
              />
            </div>
            <div>
              <label htmlFor="displayName" className="mb-1 block text-sm font-medium text-gray-700">
                Display name{" "}
                <span className="font-normal text-gray-400">(optional)</span>
              </label>
              <input
                id="displayName"
                type="text"
                autoComplete="name"
                placeholder="Jane Smith"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                disabled={loading}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-gray-400">Shown in the browser passkey dialog.</p>
            </div>
          </>
        )}

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        <button type="submit" disabled={loading} className={btnPrimary}>
          <span>🔑</span>
          {loading
            ? mode === "signup" ? "Creating passkey…" : "Verifying passkey…"
            : mode === "signup" ? "Sign up with passkey" : "Sign in with passkey"}
        </button>
      </form>

      <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-200" />
        </div>
        <div className="relative flex justify-center">
          <span className="bg-gray-50 px-3 text-xs text-gray-400">or</span>
        </div>
      </div>

      <a
        href="/auth/login"
        className="block w-full rounded-lg border border-gray-300 px-4 py-2 text-center text-sm font-medium text-gray-700 transition hover:bg-gray-100"
      >
        Continue with Universal Login
      </a>

      <p className="text-center text-xs text-gray-400">
        Passkeys use your device biometrics or PIN — your credentials never leave your device.
      </p>
    </div>
  );
}
