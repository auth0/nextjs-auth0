"use client";

import { passwordless } from "@auth0/nextjs-auth0";
import { useState } from "react";

// Exposes the passwordless singleton's route endpoints for Playwright.
export default function PasswordlessPage() {
  const [result, setResult] = useState("");
  const [error, setError] = useState("");

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
    <main>
      <p id="result">{result}</p>
      <p id="error">{error}</p>

      {/* start — POST /auth/passwordless/start */}
      <button
        id="passwordless-start"
        onClick={() =>
          run(() =>
            passwordless.start({
              connection: "email",
              email: "noreply@example.com",
              send: "code",
            })
          )
        }
      >
        passwordless.start
      </button>

      {/* verify — POST /auth/passwordless/verify */}
      <button
        id="passwordless-verify"
        onClick={() =>
          run(() =>
            passwordless.verify({
              connection: "email",
              email: "noreply@example.com",
              verificationCode: "000000",
            })
          )
        }
      >
        passwordless.verify
      </button>

      {/* challengeWithEmail — POST /auth/passwordless/otp/challenge */}
      <button
        id="passwordless-challenge-email"
        onClick={() =>
          run(() =>
            passwordless.challengeWithEmail({
              connection: process.env.NEXT_PUBLIC_TEST_PASSWORDLESS_CONNECTION ?? "email-otp-connection",
              email: process.env.NEXT_PUBLIC_TEST_PASSWORDLESS_EMAIL ?? "test@example.com",
            })
          )
        }
      >
        passwordless.challengeWithEmail
      </button>

      {/* loginWithOtp — POST /auth/passwordless/otp/token */}
      <button
        id="passwordless-login-otp"
        onClick={() =>
          run(() =>
            passwordless.loginWithOtp({
              authSession: "fake-auth-session",
              otp: "000000",
            })
          )
        }
      >
        passwordless.loginWithOtp
      </button>

      {/* challengeWithPhoneNumber — POST /auth/passwordless/otp/challenge */}
      <button
        id="passwordless-challenge-phone"
        onClick={() =>
          run(() =>
            passwordless.challengeWithPhoneNumber({
              connection: process.env.NEXT_PUBLIC_TEST_PASSWORDLESS_PHONE_CONNECTION ?? "sms-otp-connection",
              phoneNumber: process.env.NEXT_PUBLIC_TEST_PASSWORDLESS_PHONE ?? "+15550000000",
            })
          )
        }
      >
        passwordless.challengeWithPhoneNumber
      </button>
    </main>
  );
}
