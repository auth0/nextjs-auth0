"use client";

import { useState } from "react";

import { passkey } from "@auth0/nextjs-auth0/client";

type Mode = "login" | "signup";

export function PasskeyForm() {
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      const e = err as { error?: string; error_description?: string; message?: string };

      if (e.error === "webauthn_error") {
        // User cancelled the browser dialog or the device doesn't support passkeys
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

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200 disabled:opacity-50";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60 flex items-center justify-center gap-2";

  return (
    <div className="space-y-4">
      {/* Mode toggle */}
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
              {/* Email is required by default database connections. Connections
                  with custom attribute configuration may not require it — Auth0
                  will return an error if a required field is missing. */}
            </div>
            <div>
              <label
                htmlFor="displayName"
                className="mb-1 block text-sm font-medium text-gray-700"
              >
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
              <p className="mt-1 text-xs text-gray-400">
                Shown in the browser passkey dialog.
              </p>
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
            ? mode === "signup"
              ? "Creating passkey…"
              : "Verifying passkey…"
            : mode === "signup"
              ? "Sign up with passkey"
              : "Sign in with passkey"}
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
        Passkeys use your device biometrics or PIN — your credentials never
        leave your device.
      </p>
    </div>
  );
}
