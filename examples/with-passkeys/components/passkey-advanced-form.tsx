"use client";

import { useState } from "react";

import { getLoginChallenge, getSignupChallenge, verifyPasskey } from "@/app/actions/passkey";
import { mfa, serializeCredential } from "@auth0/nextjs-auth0/client";
import type {
  PasskeyAuthResponse,
  PasskeyChallengeResponse,
  PasskeyCreationOptionsJSON,
  PasskeyDeliveryMethod,
  PasskeyRegisterResponse,
  PasskeyRequestOptionsJSON,
  PasskeyVerificationCodes,
  PasskeyVerificationIdentifier
} from "@auth0/nextjs-auth0/types";

import { QrCode } from "./qr-code";

type Mode = "login" | "signup";
type Step = "form" | "verify" | "ceremony" | "mfa";

const IDENTIFIER_LABELS: Record<PasskeyVerificationIdentifier, string> = {
  email: "Code sent to your email",
  phone: "Code sent to your phone"
};

// authnParamsPublicKey carries base64url fields. The SDK does not export a decoder.
function base64urlDecode(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (padded.length % 4)) % 4;
  const binary = atob(padded + "=".repeat(padding));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function decodeCreationOptions(raw: PasskeyCreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const opts = raw as any;
  return {
    ...opts,
    challenge: base64urlDecode(opts.challenge),
    user: { ...opts.user, id: base64urlDecode(opts.user.id) },
    excludeCredentials: (opts.excludeCredentials ?? []).map((c: any) => ({
      ...c,
      id: base64urlDecode(c.id)
    }))
  };
}

function decodeRequestOptions(raw: PasskeyRequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const opts = raw as any;
  return {
    ...opts,
    challenge: base64urlDecode(opts.challenge),
    allowCredentials: (opts.allowCredentials ?? []).map((c: any) => ({
      ...c,
      id: base64urlDecode(c.id)
    }))
  };
}

export function PasskeyAdvancedForm() {
  const [mode, setMode] = useState<Mode>("signup");
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  // How to send the phone code. "" lets Auth0 use the channel the connection supports.
  const [deliveryMethod, setDeliveryMethod] = useState<"" | PasskeyDeliveryMethod>("");
  const [challenge, setChallenge] = useState<PasskeyRegisterResponse | PasskeyChallengeResponse | null>(null);
  // Identifier verification: identifiers still needing a code, and the codes entered.
  const [pending, setPending] = useState<PasskeyVerificationIdentifier[]>([]);
  const [codes, setCodes] = useState<PasskeyVerificationCodes>({});
  // The serialized passkey, kept so a wrong code is retried without a second prompt.
  const [authResponse, setAuthResponse] = useState<PasskeyAuthResponse | null>(null);
  // MFA state
  const [mfaToken, setMfaToken] = useState("");
  const [oobCode, setOobCode] = useState("");
  const [barcodeUri, setBarcodeUri] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60 flex items-center justify-center gap-2";

  function reset(message: string | null = null) {
    setStep("form");
    setChallenge(null);
    setPending([]);
    setCodes({});
    setAuthResponse(null);
    setMfaToken("");
    setOobCode("");
    setBarcodeUri("");
    setMfaCode("");
    setError(message);
  }

  // Step 1 — Server Action: validate + get challenge
  async function handleGetChallenge(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const result =
        mode === "signup"
          ? await getSignupChallenge({
              // Pass the identifiers your connection accepts. Only those are verified.
              ...(email && { email }),
              ...(phoneNumber && { phoneNumber }),
              // Pass deliveryMethod only when the user picked one.
              ...(phoneNumber && deliveryMethod && { deliveryMethod }),
              name: displayName || email || phoneNumber
            })
          : await getLoginChallenge();

      if (!result.ok) {
        setError(
          result.error === "too_many_requests"
            ? "Too many attempts. Wait a moment and try again."
            : result.error_description
        );
        return;
      }

      setChallenge(result.challenge);
      const required =
        "verificationRequired" in result.challenge ? result.challenge.verificationRequired : undefined;
      if (required?.length) {
        // Collect the codes before creating the passkey.
        setPending(required);
        setCodes({});
        setStep("verify");
      } else {
        // Nothing to verify: go straight to the passkey prompt. The ceremony
        // step stays on screen as the retry point if the prompt is cancelled.
        setStep("ceremony");
        await handleCeremony(result.challenge);
      }
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  // Codes entered: go straight to the passkey prompt, or resubmit the kept
  // passkey after a wrong code. Submitting the code form is the user gesture
  // the browser needs, so no extra "Create passkey" click is required.
  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    await handleCeremony();
  }

  // Step 2 — Browser: run the WebAuthn ceremony
  // `current` is passed when the challenge was just fetched, because state
  // has not updated yet in the same handler.
  async function handleCeremony(current = challenge) {
    if (!current) return;
    if (authResponse) {
      // Already created (e.g. after a rate limit): resubmit, never prompt twice.
      await submit(authResponse, current);
      return;
    }
    setLoading(true);
    setError(null);

    let credential: PublicKeyCredential | null;
    try {
      if (mode === "signup") {
        credential = (await navigator.credentials.create({
          publicKey: decodeCreationOptions(current.authnParamsPublicKey as PasskeyCreationOptionsJSON)
        })) as PublicKeyCredential | null;
      } else {
        credential = (await navigator.credentials.get({
          publicKey: decodeRequestOptions(current.authnParamsPublicKey as PasskeyRequestOptionsJSON)
        })) as PublicKeyCredential | null;
      }
    } catch (err: any) {
      // NotAllowedError: the user cancelled or the prompt timed out.
      setError(err?.message ?? "Passkey operation was cancelled or not supported.");
      setLoading(false);
      return;
    }

    if (!credential) {
      setError("No credential returned. Try again.");
      setLoading(false);
      return;
    }

    const response = serializeCredential(credential);
    if (mode === "signup") setAuthResponse(response);
    await submit(response, current);
  }

  // Step 3 — Server Action: verify + create session
  async function submit(response: PasskeyAuthResponse, current = challenge) {
    if (!current) return;
    setLoading(true);
    setError(null);

    try {
      const result = await verifyPasskey(
        current.authSession,
        response,
        pending.length ? codes : undefined
      );

      if (result.ok) {
        window.location.href = "/dashboard";
      } else if (result.error === "mfa_required" && "mfaToken" in result) {
        await startMfa(result.mfaToken);
      } else if ("retryable" in result && result.retryable && result.verificationRequired?.length) {
        // A code was wrong. Keep the passkey; ask only for the identifiers still listed.
        setChallenge({ ...current, authSession: result.authSession ?? current.authSession });
        setPending(result.verificationRequired);
        setCodes({});
        setStep("verify");
        setError("That code was not right. Try again.");
      } else if (result.error === "too_many_requests") {
        // Keep the state so the user can resubmit after a pause.
        setError("Too many attempts. Wait a moment and try again.");
      } else {
        // Too many wrong codes, an expired session, or the passkey was rejected.
        reset(
          ("error_description" in result && result.error_description) ||
            "Could not complete the passkey flow. Please start again."
        );
      }
    } catch {
      // The Server Action failed unexpectedly. Keep the state so the user can retry.
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  // MFA after a passkey: no session exists yet. The client `mfa` helper calls
  // the SDK's /auth/mfa/* routes, and mfa.verify() creates the session.
  async function startMfa(token: string) {
    try {
      const authenticators = await mfa.getAuthenticators({ mfaToken: token });
      const active = authenticators.find((a) => a.active);
      if (!active) {
        const enrollment = await mfa.enroll({ mfaToken: token, authenticatorTypes: ["otp"] });
        if ("barcodeUri" in enrollment && enrollment.barcodeUri) {
          setBarcodeUri(enrollment.barcodeUri);
        }
      } else {
        const challengeRes = await mfa.challenge({
          mfaToken: token,
          challengeType: active.authenticatorType,
          authenticatorId: active.id
        });
        if (challengeRes.oobCode) setOobCode(challengeRes.oobCode);
      }
      setMfaToken(token);
      setStep("mfa");
    } catch (err: any) {
      reset(err?.error_description ?? "Failed to start MFA. Please try again.");
    }
  }

  async function handleMfa(e: React.FormEvent) {
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
    } catch (err: any) {
      setMfaCode("");
      setError(err?.error_description ?? "Invalid code. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  const errorBox = error && (
    <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
      {error}
    </div>
  );

  const backButton = (
    <button
      type="button"
      onClick={() => reset()}
      className="w-full text-center text-sm text-gray-400 hover:text-gray-600"
    >
      Back
    </button>
  );

  if (step === "verify") {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-800">
          <p className="font-medium">Verify your details</p>
          <p className="mt-1 text-blue-600">
            {authResponse
              ? "Enter the code again. Your passkey is kept, so you will not be prompted twice."
              : "Enter the one-time code we sent. You will create your passkey next."}
          </p>
        </div>

        <form onSubmit={handleVerify} className="space-y-4">
          {pending.map((identifier, i) => (
            <div key={identifier}>
              <label htmlFor={`adv-code-${identifier}`} className="mb-1 block text-sm font-medium text-gray-700">
                {IDENTIFIER_LABELS[identifier]}
              </label>
              <input
                id={`adv-code-${identifier}`}
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={codes[identifier] ?? ""}
                onChange={(e) => setCodes({ ...codes, [identifier]: e.target.value })}
                placeholder="000000"
                required
                autoFocus={i === 0}
                disabled={loading}
                className={inputClass + " text-center text-lg tracking-widest"}
              />
            </div>
          ))}

          {errorBox}

          <button type="submit" disabled={loading} className={btnPrimary}>
            {loading ? "Verifying…" : authResponse ? "Verify" : "Continue to passkey setup"}
          </button>
        </form>

        {backButton}
      </div>
    );
  }

  if (step === "mfa") {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-800">Two-factor authentication</h2>
          <p className="mt-1 text-sm text-gray-500">
            {barcodeUri
              ? "Scan this QR code with your authenticator app, then enter the 6-digit code."
              : oobCode
                ? "Enter the code sent to your phone."
                : "Enter the 6-digit code from your authenticator app."}
          </p>
        </div>

        {barcodeUri && (
          <div className="flex justify-center rounded-lg border border-gray-200 bg-white p-4">
            <QrCode value={barcodeUri} />
          </div>
        )}

        <form onSubmit={handleMfa} className="space-y-4">
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

          {errorBox}

          <button type="submit" disabled={loading || mfaCode.length < 6} className={btnPrimary}>
            {loading ? "Verifying…" : "Verify"}
          </button>
        </form>

        {backButton}
      </div>
    );
  }

  if (step === "ceremony") {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-800">
          <p className="font-medium">Challenge ready</p>
          <p className="mt-1 text-blue-600">
            Click below to trigger the browser passkey dialog.
          </p>
        </div>

        {errorBox}

        <button onClick={() => handleCeremony()} disabled={loading} className={btnPrimary}>
          <span>🔑</span>
          {loading ? "Waiting for device…" : mode === "signup" ? "Create passkey" : "Verify passkey"}
        </button>

        {backButton}
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
            mode === "login" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Sign in
        </button>
        <button
          type="button"
          onClick={() => { setMode("signup"); setError(null); }}
          className={`flex-1 rounded-md py-1.5 font-medium transition ${
            mode === "signup" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Sign up
        </button>
      </div>

      <form onSubmit={handleGetChallenge} className="space-y-4">
        {mode === "signup" && (
          <>
            <div>
              <label htmlFor="adv-email" className="mb-1 block text-sm font-medium text-gray-700">
                Email address
              </label>
              <input
                id="adv-email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required={!phoneNumber}
                disabled={loading}
                className={inputClass}
              />
            </div>
            <div>
              <label htmlFor="adv-name" className="mb-1 block text-sm font-medium text-gray-700">
                Display name{" "}
                <span className="font-normal text-gray-400">(optional)</span>
              </label>
              <input
                id="adv-name"
                type="text"
                autoComplete="name"
                placeholder="Jane Smith"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                disabled={loading}
                className={inputClass}
              />
            </div>
            <div>
              <label htmlFor="adv-phone" className="mb-1 block text-sm font-medium text-gray-700">
                Phone number
              </label>
              <input
                id="adv-phone"
                type="tel"
                autoComplete="tel"
                placeholder="+15551234567"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                required={!email}
                disabled={loading}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-gray-400">
                E.164 format. Enter it with or instead of an email, depending on your connection.
              </p>
            </div>
            {phoneNumber && (
              <div>
                <label htmlFor="adv-delivery" className="mb-1 block text-sm font-medium text-gray-700">
                  Send the code by
                </label>
                <select
                  id="adv-delivery"
                  value={deliveryMethod}
                  onChange={(e) => setDeliveryMethod(e.target.value as "" | PasskeyDeliveryMethod)}
                  disabled={loading}
                  className={inputClass}
                >
                  <option value="">Default</option>
                  <option value="text">Text message</option>
                  <option value="voice">Voice call</option>
                </select>
              </div>
            )}
          </>
        )}

        {errorBox}

        <button type="submit" disabled={loading} className={btnPrimary}>
          <span>🔑</span>
          {loading
            ? "Validating…"
            : mode === "signup"
              ? "Continue to passkey setup"
              : "Continue to passkey login"}
        </button>
      </form>

      <div className="rounded-lg border border-gray-100 bg-gray-50 px-3 py-2 text-xs text-gray-400">
        <p className="font-medium text-gray-500">Step-by-step flow</p>
        <ol className="mt-1 list-decimal pl-4 space-y-0.5">
          <li>Server validates inputs &amp; fetches challenge from Auth0</li>
          <li>Browser collects one-time codes, if the connection verifies email or phone</li>
          <li>Browser runs WebAuthn ceremony (biometric / PIN)</li>
          <li>Server verifies credential and codes &amp; creates session</li>
        </ol>
      </div>
    </div>
  );
}
