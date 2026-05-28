"use client";

import { useState } from "react";

import { getLoginChallenge, getSignupChallenge, verifyPasskey } from "@/app/actions/passkey";
import type { PasskeyChallengeResponse, PasskeyCreationOptionsJSON, PasskeyRequestOptionsJSON } from "@auth0/nextjs-auth0/types";

type Mode = "login" | "signup";
type Step = "form" | "ceremony" | "done";

function base64urlDecode(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (padded.length % 4)) % 4;
  const binary = atob(padded + "=".repeat(padding));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
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

function serializeCredential(credential: PublicKeyCredential) {
  const response = credential.response as any;
  return {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    type: "public-key" as const,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      ...(response.attestationObject !== undefined && {
        attestationObject: base64urlEncode(response.attestationObject)
      }),
      ...(response.authenticatorData !== undefined && {
        authenticatorData: base64urlEncode(response.authenticatorData)
      }),
      ...(response.signature !== undefined && {
        signature: base64urlEncode(response.signature)
      }),
      ...(response.userHandle !== undefined && {
        userHandle: response.userHandle ? base64urlEncode(response.userHandle) : null
      })
    },
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>
  };
}

export function PasskeyAdvancedForm() {
  const [mode, setMode] = useState<Mode>("signup");
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [challenge, setChallenge] = useState<PasskeyChallengeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60 flex items-center justify-center gap-2";

  // Step 1 — Server Action: validate + get challenge
  async function handleGetChallenge(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const result =
        mode === "signup"
          ? await getSignupChallenge({ email, name: displayName || email })
          : await getLoginChallenge();

      setChallenge(result);
      setStep("ceremony");
    } catch (err: any) {
      setError(err?.error_description ?? "Failed to get passkey challenge.");
    } finally {
      setLoading(false);
    }
  }

  // Step 2 — Browser: run the WebAuthn ceremony
  async function handleCeremony() {
    if (!challenge) return;
    setLoading(true);
    setError(null);

    let credential: PublicKeyCredential | null;
    try {
      if (mode === "signup") {
        credential = (await navigator.credentials.create({
          publicKey: decodeCreationOptions(challenge.authnParamsPublicKey as PasskeyCreationOptionsJSON)
        })) as PublicKeyCredential | null;
      } else {
        credential = (await navigator.credentials.get({
          publicKey: decodeRequestOptions(challenge.authnParamsPublicKey as PasskeyRequestOptionsJSON)
        })) as PublicKeyCredential | null;
      }
    } catch (err: any) {
      setError(err?.message ?? "Passkey operation was cancelled or not supported.");
      setLoading(false);
      return;
    }

    if (!credential) {
      setError("No credential returned. Try again.");
      setLoading(false);
      return;
    }

    // Step 3 — Server Action: verify + create session
    try {
      await verifyPasskey({
        authSession: challenge.authSession,
        authResponse: serializeCredential(credential)
      });
      setStep("done");
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(err?.error_description ?? "Verification failed. Please try again.");
    } finally {
      setLoading(false);
    }
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

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        <button onClick={handleCeremony} disabled={loading} className={btnPrimary}>
          <span>🔑</span>
          {loading ? "Waiting for device…" : mode === "signup" ? "Create passkey" : "Verify passkey"}
        </button>

        <button
          onClick={() => { setStep("form"); setChallenge(null); setError(null); }}
          className="w-full text-center text-sm text-gray-400 hover:text-gray-600"
        >
          Back
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
                required
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
          <li>Browser runs WebAuthn ceremony (biometric / PIN)</li>
          <li>Server verifies credential &amp; creates session</li>
        </ol>
      </div>
    </div>
  );
}
