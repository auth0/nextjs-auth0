"use client";

import { useState } from "react";

import { mfa, passwordless } from "@auth0/nextjs-auth0/client";
import type {
  PasswordlessDbChallenge,
  PasswordlessDbChallengeEmailOptions,
  PasswordlessDbChallengePhoneOptions,
} from "@auth0/nextjs-auth0/types";

import { QrCode } from "./qr-code";

const CONNECTION = process.env.NEXT_PUBLIC_AUTH0_DB_CONNECTION ?? "Username-Password-Authentication";

type IdentifierType = "email" | "phone";
type Step = "identifier" | "otp" | "mfa-otp" | "mfa-enroll";

export function PasswordlessDbForm() {
  const [identifierType, setIdentifierType] = useState<IdentifierType>("email");
  const [identifier, setIdentifier] = useState("");
  const [otp, setOtp] = useState("");
  const [step, setStep] = useState<Step>("identifier");
  const [challenge, setChallenge] = useState<PasswordlessDbChallenge | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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

  async function handleSendOtp(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      let result: PasswordlessDbChallenge;

      if (identifierType === "email") {
        const opts: PasswordlessDbChallengeEmailOptions = {
          email: identifier,
          connection: CONNECTION,
          allowSignup: true,
        };
        result = await passwordless.challengeWithEmail(opts);
      } else {
        const opts: PasswordlessDbChallengePhoneOptions = {
          phoneNumber: identifier,
          connection: CONNECTION,
          deliveryMethod: "text",
          allowSignup: false,
        };
        result = await passwordless.challengeWithPhoneNumber(opts);
      }

      setChallenge(result);
      setStep("otp");
    } catch (err: unknown) {
      const e = err as { error_description?: string; message?: string };
      setError(e.error_description ?? e.message ?? "Failed to send OTP. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOtp(e: React.FormEvent) {
    e.preventDefault();
    if (!challenge) return;
    setError(null);
    setLoading(true);

    try {
      await passwordless.loginWithOtp({
        authSession: challenge.authSession,
        otp,
      });
      window.location.href = "/dashboard";
    } catch (err: unknown) {
      const e = err as { error?: string; error_description?: string; mfa_token?: string };

      if (e.error === "mfa_required" && e.mfa_token) {
        try {
          const authenticators = await mfa.getAuthenticators({ mfaToken: e.mfa_token });
          const active = authenticators.find(a => a.active);

          if (!active) {
            const enrollment = await mfa.enroll({
              mfaToken: e.mfa_token,
              authenticatorTypes: ["otp"],
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
              authenticatorId: active.id,
            });
            setMfaToken(e.mfa_token);
            if (challengeRes.oobCode) {
              setOobCode(challengeRes.oobCode);
            }
            setStep("mfa-otp");
          }
        } catch (mfaErr: unknown) {
          const me = mfaErr as { error_description?: string };
          setError(me.error_description ?? "Failed to initiate MFA. Please try again.");
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
    } catch (err: unknown) {
      const e = err as { error_description?: string };
      setMfaCode("");
      setError(e.error_description ?? "Invalid code. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function handleBack() {
    setStep("identifier");
    setChallenge(null);
    setOtp("");
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
          onClick={() => { setStep("identifier"); resetMfaState(); setOtp(""); setChallenge(null); setError(null); }}
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
          onClick={() => { setStep("identifier"); resetMfaState(); setOtp(""); setChallenge(null); setError(null); }}
          className="w-full text-center text-sm text-gray-500 hover:text-gray-700"
        >
          ← Back
        </button>
      </div>
    );
  }

  if (step === "otp") {
    return (
      <form onSubmit={handleVerifyOtp} className="space-y-4">
        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-1 text-base font-semibold text-gray-900">Enter your code</h2>
          <p className="mb-4 text-sm text-gray-500">
            We sent a one-time code to <span className="font-medium text-gray-700">{identifier}</span>.
          </p>

          <div className="space-y-3">
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
              className={inputClass + " text-center text-2xl font-mono tracking-widest"}
              required
              autoFocus
              disabled={loading}
            />

            {error && (
              <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
            )}

            <button
              type="submit"
              disabled={loading || otp.length < 6}
              className={btnPrimary}
            >
              {loading ? "Verifying…" : "Verify code"}
            </button>
          </div>
        </div>

        <button
          type="button"
          onClick={handleBack}
          className={btnSecondary}
        >
          ← Back
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handleSendOtp} className="space-y-4">
      <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-sm space-y-4">

        <div className="flex rounded-lg border border-gray-200 p-1">
          <button
            type="button"
            onClick={() => { setIdentifierType("email"); setIdentifier(""); setError(null); }}
            className={`flex-1 rounded-md py-1.5 text-sm font-medium transition ${
              identifierType === "email"
                ? "bg-white shadow text-gray-900"
                : "text-gray-500 hover:text-gray-700"
            }`}
          >
            Email
          </button>
          <button
            type="button"
            onClick={() => { setIdentifierType("phone"); setIdentifier(""); setError(null); }}
            className={`flex-1 rounded-md py-1.5 text-sm font-medium transition ${
              identifierType === "phone"
                ? "bg-white shadow text-gray-900"
                : "text-gray-500 hover:text-gray-700"
            }`}
          >
            Phone
          </button>
        </div>

        <div className="space-y-3">
          {identifierType === "email" ? (
            <input
              key="email"
              type="email"
              placeholder="you@example.com"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="email"
              className={inputClass}
              required
              autoFocus
            />
          ) : (
            <input
              key="phone"
              type="tel"
              placeholder="+14155550100"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="tel"
              className={inputClass}
              required
              autoFocus
            />
          )}

          {error && (
            <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading || !identifier}
            className={btnPrimary}
          >
            {loading ? "Sending…" : "Send code"}
          </button>
        </div>
      </div>

      <p className="text-center text-xs text-gray-400">
        A one-time code will be sent to your {identifierType === "email" ? "email address" : "phone number"}.
      </p>
    </form>
  );
}
