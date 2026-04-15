"use client";

import { useState } from "react";

import { passwordless } from "@auth0/nextjs-auth0/client";
import {
  PasswordlessStartError,
  PasswordlessVerifyError,
} from "@auth0/nextjs-auth0/errors";

type ConnectionType = "email" | "sms" | "magic-link";
type Step = "start" | "verify" | "link-sent";

export function PasswordlessForm() {
  const [connection, setConnection] = useState<ConnectionType>("email");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<Step>("start");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      if (err instanceof PasswordlessStartError) {
        setError(err.error_description);
      } else {
        setError("An unexpected error occurred. Please try again.");
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
      if (connection === "email") {
        await passwordless.verify({
          connection: "email",
          email,
          verificationCode: code,
        });
      } else {
        await passwordless.verify({
          connection: "sms",
          phoneNumber: phone,
          verificationCode: code,
        });
      }
      // Session cookie set — navigate to dashboard
      window.location.href = "/dashboard";
    } catch (err) {
      if (err instanceof PasswordlessVerifyError) {
        setError(
          err.error === "invalid_grant"
            ? "Invalid or expired code. Please check and try again."
            : err.error_description
        );
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  function handleBack() {
    setStep("start");
    setCode("");
    setError(null);
  }

  // Magic link "link sent" confirmation screen
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

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60";
  const btnSecondary =
    "w-full rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 transition hover:bg-gray-100 disabled:opacity-50";

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
          <label
            htmlFor="code"
            className="mb-1 block text-sm font-medium text-gray-700"
          >
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
            disabled={loading}
            className={inputClass}
          />
        </div>

        <button type="submit" disabled={loading || code.length < 4} className={btnPrimary}>
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
      {/* Connection toggle */}
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
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {error}
        </div>
      )}

      {connection === "email" || connection === "magic-link" ? (
        <div>
          <label
            htmlFor="email"
            className="mb-1 block text-sm font-medium text-gray-700"
          >
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
          <label
            htmlFor="phone"
            className="mb-1 block text-sm font-medium text-gray-700"
          >
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
    </form>
  );
}
