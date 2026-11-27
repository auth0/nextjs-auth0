"use client";

import { useRef, useState } from "react";
import { getAccessToken, mfa } from "@auth0/nextjs-auth0/client";
import type { Authenticator } from "@auth0/nextjs-auth0/types";

const button =
  "rounded-lg px-3 py-2 text-sm font-medium text-white transition disabled:opacity-50";
const input = "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm";

export function StepUp({ audience }: { audience: string }) {
  // The sealed token of an `mfa_required` answer: every MFA call below needs it.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [authenticators, setAuthenticators] = useState<Authenticator[]>([]);
  // The factor the user picked: "otp" or "oob". Null until its challenge is ready.
  const [challengeType, setChallengeType] = useState<"otp" | "oob" | null>(null);
  const [oobCode, setOobCode] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [bindingCode, setBindingCode] = useState("");
  const [message, setMessage] = useState("");
  const [pending, setPending] = useState(false);
  // Identifies the latest challenge request, so a slower earlier one cannot overwrite it.
  const challengeId = useRef(0);

  function resetChallenge() {
    challengeId.current++;
    setChallengeType(null);
    setOobCode(null);
    setCode("");
    setBindingCode("");
    setPending(false);
  }

  // 1. Ask for a token for the protected API. With MFA required, this throws `mfa_required`.
  async function requestToken() {
    try {
      await getAccessToken({ audience });
      setMfaToken(null);
      setMessage("Got the token for the API. No MFA was needed.");
    } catch (err: any) {
      if (err?.code !== "mfa_required") {
        setMessage(`${err?.code ?? "error"}: ${err?.message}`);
        return;
      }
      // A new `mfa_required` starts a new attempt: drop any state of the previous one.
      resetChallenge();
      setAuthenticators([]);
      setMfaToken(err.mfa_token);
      setMessage("MFA is required. Pick an authenticator.");
      // 2. List the authenticators the user can use.
      try {
        setAuthenticators(await mfa.getAuthenticators({ mfaToken: err.mfa_token }));
      } catch (listErr: any) {
        setMessage(`${listErr?.code ?? "error"}: ${listErr?.message}. Click "Get a token for the API" to retry.`);
      }
    }
  }

  // 3. Ask Auth0 to send or prepare the second factor (an OTP app needs nothing sent).
  async function challenge(authenticator: Authenticator) {
    const type = authenticator.authenticatorType === "oob" ? "oob" : "otp";
    resetChallenge();
    const id = challengeId.current;
    setPending(true);
    try {
      const result = await mfa.challenge({
        mfaToken: mfaToken!,
        challengeType: type,
        authenticatorId: authenticator.id,
      });
      if (id !== challengeId.current) return; // the user picked another authenticator meanwhile
      setChallengeType(type);
      setOobCode(result.oobCode ?? null);
      setMessage(type === "oob" ? "Enter the code you received." : "Enter the code from your app.");
    } catch (err: any) {
      if (id !== challengeId.current) return;
      setMessage(`${err?.code ?? "error"}: ${err?.message}. Pick an authenticator to try again.`);
    } finally {
      if (id === challengeId.current) setPending(false);
    }
  }

  // 4. Verify the code. The token for the API is saved in the session.
  async function verify() {
    try {
      await mfa.verify({
        mfaToken: mfaToken!,
        ...(challengeType === "oob" && oobCode ? { oobCode, bindingCode } : { otp: code }),
      });
      // 5. The token is cached now: asking again needs no MFA.
      await requestToken();
    } catch (err: any) {
      setMessage(`${err?.code ?? "error"}: ${err?.message}`);
    }
  }

  return (
    <div className="space-y-4 rounded-2xl border border-gray-200 bg-white p-6 shadow-sm">
      <p className="text-sm text-gray-600">
        API: <code>{audience || "(set NEXT_PUBLIC_AUTH0_AUDIENCE)"}</code>
      </p>
      <button className={`${button} bg-rose-600 hover:bg-rose-700`} onClick={requestToken}>
        Get a token for the API
      </button>

      {mfaToken && (
        <div className="space-y-3">
          <ul className="space-y-2">
            {authenticators.map((a) => (
              <li key={a.id} className="flex items-center justify-between rounded-lg border border-gray-200 px-3 py-2 text-sm">
                <span>
                  {a.name ?? a.authenticatorType} ({a.type ?? a.authenticatorType})
                </span>
                <button className={`${button} bg-indigo-600 hover:bg-indigo-700`} onClick={() => challenge(a)}>
                  Use
                </button>
              </li>
            ))}
          </ul>
          {challengeType === "otp" && (
            <input className={input} placeholder="Code" value={code} onChange={(e) => setCode(e.target.value)} />
          )}
          {challengeType === "oob" && (
            <input className={input} placeholder="Code you received (binding code)" value={bindingCode} onChange={(e) => setBindingCode(e.target.value)} />
          )}
          {challengeType && (
            <button disabled={pending} className={`${button} bg-teal-600 hover:bg-teal-700`} onClick={verify}>
              Verify
            </button>
          )}
        </div>
      )}

      {message && <p className="text-sm text-gray-700">{message}</p>}
    </div>
  );
}
