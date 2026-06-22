"use client";

import { useState } from "react";

import { mfa, passwordless } from "@auth0/nextjs-auth0/client";

import { QrCode } from "./qr-code";

type ConnectionType = "email" | "sms" | "magic-link" | "universal-login";
type Step = "start" | "verify" | "link-sent" | "mfa-otp" | "mfa-enroll";

export function PasswordlessForm() {
  const [connection, setConnection] = useState<ConnectionType>("email");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<Step>("start");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA state
  const [mfaToken, setMfaToken] = useState("");
  const [oobCode, setOobCode] = useState("");
  const [barcodeUri, setBarcodeUri] = useState("");
  const [mfaCode, setMfaCode] = useState("");

  function resetMfaState() {
    setMfaToken("");
    setOobCode("");
    setBarcodeUri("");
    setMfaCode("");
  }

  async function handleStart(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (connection === "magic-link") {
        await passwordless.start({ connection: "email", email, send: "link" });
        setStep("link-sent");
        return;
      } else if (connection === "email") {
        await passwordless.start({ connection: "email", email, send: "code" });
      } else {
        await passwordless.start({ connection: "sms", phoneNumber: phone });
      }
      setStep("verify");
    } catch (err) {
      const e = err as { code?: string; error_description?: string };
      setError(
        e.code === "passwordless_start_error"
          ? (e.error_description ?? "Failed to send. Please try again.")
          : "An unexpected error occurred. Please try again."
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (connection === "email") {
        await passwordless.verify({ connection: "email", email, verificationCode: code });
      } else {
        await passwordless.verify({ connection: "sms", phoneNumber: phone, verificationCode: code });
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
            setStep("mfa-enroll");
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
            setStep("mfa-otp");
          }
        } catch (mfaErr: any) {
          setError(mfaErr?.error_description ?? "Failed to send MFA code. Please try again.");
        }
      } else {
        setError(
          e.error === "invalid_grant"
            ? "Invalid or expired code. Please check and try again."
            : (e.error_description ?? "Verification failed. Please try again.")
        );
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleMfaVerify(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (oobCode) {
        await mfa.verify({ mfaToken, oobCode, bindingCode: mfaCode });
      } else {
        await mfa.verify({ mfaToken, otp: mfaCode });
      }
      window.location.href = "/dashboard";
    } catch (err) {
      const e = err as { error_description?: string };
      setMfaCode("");
      setError(e.error_description ?? "Invalid code. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function handleBack() {
    setStep("start");
    setCode("");
    setError(null);
  }

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60";
  const btnSecondary =
    "w-full rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 transition hover:bg-gray-100 disabled:opacity-50";

  if (step === "mfa-enroll") {
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

        <form onSubmit={handleMfaVerify} className="space-y-4">
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
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

          <button type="submit" disabled={loading || mfaCode.length < 6} className={btnPrimary}>
            {loading ? "Verifying…" : "Confirm & sign in"}
          </button>
        </form>

        <button
          type="button"
          onClick={() => { setStep("start"); resetMfaState(); setCode(""); setError(null); }}
          className="w-full text-center text-sm text-gray-500 hover:text-gray-700"
        >
          ← Back
        </button>
      </div>
    );
  }

  if (step === "mfa-otp") {
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

        <form onSubmit={handleMfaVerify} className="space-y-4">
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
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

          <button type="submit" disabled={loading || mfaCode.length < 6} className={btnPrimary}>
            {loading ? "Verifying…" : "Verify"}
          </button>
        </form>

        <button
          type="button"
          onClick={() => { setStep("start"); resetMfaState(); setCode(""); setError(null); }}
          className="w-full text-center text-sm text-gray-500 hover:text-gray-700"
        >
          ← Back
        </button>
      </div>
    );
  }

  if (step === "link-sent") {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
          <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
          </svg>
        </div>
        <h2 className="text-lg font-semibold text-gray-900">Check your email</h2>
        <p className="text-sm text-gray-500">
          We sent a magic link to <span className="font-medium text-gray-900">{email}</span>. Click the link in the email to sign in.
        </p>
        <p className="text-xs text-gray-400">The link expires in 5 minutes. Check your spam folder if you don&apos;t see it.</p>
        <button
          type="button"
          onClick={() => { setStep("start"); setError(null); }}
          className="w-full text-center text-xs text-blue-600 underline hover:text-blue-800"
        >
          ← Use a different email
        </button>
      </div>
    );
  }

  if (step === "verify") {
    const hint =
      connection === "email"
        ? `We sent a 6-digit code to ${email}`
        : `We sent a 6-digit code to ${phone}`;

    return (
      <form onSubmit={handleVerify} className="space-y-4">
        <p className="text-sm text-gray-500">{hint}</p>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        <div>
          <label htmlFor="code" className="mb-1 block text-sm font-medium text-gray-700">
            Verification code
          </label>
          <input
            id="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            minLength={6}
            maxLength={6}
            disabled={loading}
            className={inputClass}
          />
        </div>

        <button type="submit" disabled={loading || code.length < 6} className={btnPrimary}>
          {loading ? "Verifying…" : "Sign in"}
        </button>

        <button type="button" onClick={handleBack} disabled={loading} className={btnSecondary}>
          ← Use a different {connection === "email" ? "email" : "phone number"}
        </button>

        <button
          type="button"
          onClick={() => { setCode(""); handleStart({ preventDefault: () => {} } as React.FormEvent); }}
          disabled={loading}
          className="w-full text-center text-xs text-blue-600 underline hover:text-blue-800 disabled:opacity-50"
        >
          Resend code
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handleStart} className="space-y-4">
      <div className="flex rounded-lg border border-gray-200 p-1 text-sm">
        <button
          type="button"
          onClick={() => { setConnection("email"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            connection === "email"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Email OTP
        </button>
        <button
          type="button"
          onClick={() => { setConnection("sms"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            connection === "sms"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          SMS OTP
        </button>
        <button
          type="button"
          onClick={() => { setConnection("magic-link"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            connection === "magic-link"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Magic Link
        </button>
        <button
          type="button"
          onClick={() => { setConnection("universal-login"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            connection === "universal-login"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Universal Login
        </button>
      </div>

      {connection === "universal-login" ? (
        <div className="space-y-3 pt-1">
          <p className="text-center text-sm text-gray-500">
            Auth0&apos;s Universal Login handles the full passwordless flow on a hosted page — no OTP code handling needed in your app.
          </p>
          <a
            href="/auth/login?connection=email"
            className="block w-full rounded-lg bg-blue-600 px-4 py-2 text-center text-sm font-semibold text-white transition hover:bg-blue-700"
          >
            Continue with email
          </a>
          <a
            href="/auth/login?connection=sms"
            className="block w-full rounded-lg border border-gray-300 px-4 py-2 text-center text-sm font-medium text-gray-700 transition hover:bg-gray-100"
          >
            Continue with SMS
          </a>
        </div>
      ) : (
        <>
          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          {connection === "email" || connection === "magic-link" ? (
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
              {connection === "magic-link" && (
                <p className="mt-1 text-xs text-gray-400">We&apos;ll email you a one-click sign-in link — no code to type.</p>
              )}
            </div>
          ) : (
            <div>
              <label htmlFor="phone" className="mb-1 block text-sm font-medium text-gray-700">
                Phone number
              </label>
              <input
                id="phone"
                type="tel"
                autoComplete="tel"
                placeholder="+14155550100"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                required
                disabled={loading}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-gray-400">E.164 format (e.g. +14155550100)</p>
            </div>
          )}

          <button type="submit" disabled={loading} className={btnPrimary}>
            {loading
              ? connection === "magic-link" ? "Sending link…" : "Sending code…"
              : connection === "magic-link" ? "Send magic link" : "Send code"}
          </button>

          <p className="text-center text-xs text-gray-400">
            Prefer a password?{" "}
            <a href="/auth/login" className="text-blue-600 underline hover:text-blue-800">
              Sign in with Auth0
            </a>
          </p>
        </>
      )}
    </form>
  );
}
