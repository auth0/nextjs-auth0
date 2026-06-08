"use client";

import { useState } from "react";

// ---------------------------------------------------------------------------
// base64url helpers — ArrayBuffer ↔ string conversion for WebAuthn payloads
// ---------------------------------------------------------------------------

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlDecode(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (padded.length % 4)) % 4;
  const base64 = padded + "=".repeat(padding);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// Decode Auth0 enrollment challenge options for navigator.credentials.create()
// ---------------------------------------------------------------------------

function decodeCreationOptions(
  raw: Record<string, unknown>
): PublicKeyCredentialCreationOptions {
  const opts = raw as any;
  return {
    ...opts,
    challenge: base64urlDecode(opts.challenge),
    user: {
      ...opts.user,
      id: base64urlDecode(opts.user.id)
    },
    excludeCredentials: (opts.excludeCredentials ?? []).map((c: any) => ({
      ...c,
      id: base64urlDecode(c.id)
    }))
  };
}

// ---------------------------------------------------------------------------
// Serialise the attestation credential for the enrollment-verify request
// ---------------------------------------------------------------------------

function serializeCredential(credential: PublicKeyCredential): object {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    type: "public-key",
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      attestationObject: base64urlEncode(response.attestationObject)
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

// ---------------------------------------------------------------------------
// PasskeyEnrollForm — enrollment for already-authenticated users
// ---------------------------------------------------------------------------

type EnrollState = "idle" | "enrolling" | "success" | "error";

interface EnrolledPasskey {
  id: string;
  type: string;
  created_at?: string;
  key_id?: string;
}

export function PasskeyEnrollForm() {
  const [state, setState] = useState<EnrollState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [enrolled, setEnrolled] = useState<EnrolledPasskey | null>(null);

  async function handleEnroll() {
    setState("enrolling");
    setError(null);

    try {
      // Step 1 — get enrollment challenge from server
      const challengeRes = await fetch("/auth/passkey/enrollment-challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({})
      });

      if (!challengeRes.ok) {
        const err = await challengeRes.json().catch(() => ({}));
        throw new Error(
          err.error_description ?? "Failed to get enrollment challenge"
        );
      }

      const challenge = await challengeRes.json();
      const { authenticationMethodId, authSession, authnParamsPublicKey } =
        challenge;

      // Step 2 — browser WebAuthn ceremony (runs on device)
      const credential = (await navigator.credentials.create({
        publicKey: decodeCreationOptions(authnParamsPublicKey)
      })) as PublicKeyCredential | null;

      if (!credential) {
        throw new Error(
          "Passkey creation was cancelled or not supported by this device."
        );
      }

      // Step 3 — verify enrollment with server
      const verifyRes = await fetch("/auth/passkey/enrollment-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          authenticationMethodId,
          authSession,
          authResponse: serializeCredential(credential)
        })
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json().catch(() => ({}));
        throw new Error(
          err.error_description ?? "Failed to verify enrollment"
        );
      }

      const method = await verifyRes.json();
      setEnrolled(method);
      setState("success");
    } catch (err: any) {
      // User cancellation — DOMException name is "NotAllowedError"
      if (err?.name === "NotAllowedError") {
        setError("Passkey creation was cancelled.");
      } else {
        setError(err?.message ?? "An unexpected error occurred.");
      }
      setState("error");
    }
  }

  const btnPrimary =
    "w-full rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-green-700 disabled:opacity-60 flex items-center justify-center gap-2";

  if (state === "success" && enrolled) {
    return (
      <div className="rounded-lg border border-green-200 bg-green-50 p-4">
        <p className="mb-2 text-sm font-semibold text-green-800">
          Passkey enrolled successfully!
        </p>
        <dl className="space-y-1 text-xs text-green-700">
          <div className="flex justify-between">
            <dt className="font-medium">Method ID</dt>
            <dd className="max-w-[200px] truncate font-mono">{enrolled.id}</dd>
          </div>
          {enrolled.key_id && (
            <div className="flex justify-between">
              <dt className="font-medium">Key ID</dt>
              <dd className="max-w-[200px] truncate font-mono">
                {enrolled.key_id}
              </dd>
            </div>
          )}
          {enrolled.created_at && (
            <div className="flex justify-between">
              <dt className="font-medium">Created</dt>
              <dd>{new Date(enrolled.created_at).toLocaleString()}</dd>
            </div>
          )}
        </dl>
        <button
          type="button"
          onClick={() => {
            setState("idle");
            setEnrolled(null);
          }}
          className="mt-3 text-xs text-green-700 underline hover:text-green-900"
        >
          Enroll another passkey
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-600">
        Add another passkey to this account — useful for backup devices or
        shared computers.
      </p>

      {(state === "error" || error) && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {error}
        </div>
      )}

      <button
        type="button"
        onClick={handleEnroll}
        disabled={state === "enrolling"}
        className={btnPrimary}
      >
        <span>🔑</span>
        {state === "enrolling" ? "Enrolling…" : "Enroll a passkey"}
      </button>

      {state === "enrolling" && (
        <p className="text-center text-xs text-gray-400">
          Follow the browser prompt to register your passkey…
        </p>
      )}
    </div>
  );
}
