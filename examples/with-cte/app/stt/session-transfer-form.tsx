"use client";

import { useEffect, useState } from "react";

type SttResult = {
  redirectUrl: string;
  expiresIn?: number;
};

type SttError = {
  code: string;
  message: string;
  cause?: { code: string; message: string };
};

const inputClass =
  "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 disabled:opacity-50";

const labelClass = "mb-1 block text-sm font-medium text-gray-700";

const TOKEN_TYPE_OPTIONS = [
  {
    label: "Custom (CTE profile)",
    value: "urn:acme:legacy-token"
  },
  {
    label: "ID Token",
    value: "urn:ietf:params:oauth:token-type:id_token"
  },
  {
    label: "Access Token",
    value: "urn:ietf:params:oauth:token-type:access_token"
  }
];

export function SessionTransferForm() {
  const [subjectToken, setSubjectToken] = useState("");
  const [subjectTokenType, setSubjectTokenType] = useState<string>(
    TOKEN_TYPE_OPTIONS[0].value
  );
  const [targetLoginUrl, setTargetLoginUrl] = useState("");
  const [reason, setReason] = useState("");
  const [organization, setOrganization] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [copied, setCopied] = useState(false);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SttResult | null>(null);
  const [error, setError] = useState<SttError | null>(null);

  // Default the target to this app's own login route (it both mints and redeems
  // in this example). Set on mount to avoid an SSR/CSR hydration mismatch, and
  // to avoid minting a wasted one-shot STT against a placeholder host.
  useEffect(() => {
    setTargetLoginUrl(`${window.location.origin}/auth/login`);
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);
    setCopied(false);

    const body: Record<string, string> = {
      subjectToken,
      subjectTokenType,
      targetLoginUrl
    };
    if (reason) body.reason = reason;
    if (organization) body.organization = organization;

    try {
      const res = await fetch("/api/stt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data as SttError);
      } else {
        setResult(data as SttResult);
      }
    } catch {
      setError({ code: "network_error", message: "Request failed." });
    } finally {
      setLoading(false);
    }
  }

  async function handleCopy() {
    if (!result?.redirectUrl) return;
    // Clipboard access can reject (insecure context / permission denied) — e.g.
    // plain http on localhost. Fail quietly rather than throwing an unhandled
    // rejection; the URL is still visible for manual copy.
    try {
      await navigator.clipboard.writeText(result.redirectUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // no-op: user can select and copy the URL shown on screen
    }
  }

  return (
    <div className="space-y-4">
      <form
        onSubmit={handleSubmit}
        className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm space-y-4"
      >
        {/* Subject token */}
        <div>
          <label htmlFor="subjectToken" className={labelClass}>
            Customer token <span className="text-red-500">*</span>
          </label>
          <textarea
            id="subjectToken"
            rows={3}
            value={subjectToken}
            onChange={(e) => setSubjectToken(e.target.value)}
            placeholder="eyJ... (the customer's ID token or access token)"
            required
            disabled={loading}
            className={inputClass + " font-mono text-xs resize-none"}
          />
        </div>

        {/* Subject token type */}
        <div>
          <label htmlFor="subjectTokenType" className={labelClass}>
            Token type <span className="text-red-500">*</span>
          </label>
          <input
            id="subjectTokenType"
            type="text"
            value={subjectTokenType}
            onChange={(e) => setSubjectTokenType(e.target.value)}
            placeholder="urn:acme:legacy-token"
            required
            disabled={loading}
            className={inputClass + " font-mono text-xs"}
            list="subjectTokenTypeOptions"
          />
          <datalist id="subjectTokenTypeOptions">
            {TOKEN_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </datalist>
          <p className="mt-1 text-xs text-gray-400">
            The <code className="rounded bg-gray-100 px-1">subject_token_type</code>{" "}
            must match a registered CTE profile (e.g.{" "}
            <code className="rounded bg-gray-100 px-1">urn:acme:legacy-token</code>).
          </p>
        </div>

        {/* Target login URL */}
        <div>
          <label htmlFor="targetLoginUrl" className={labelClass}>
            Target app login URL <span className="text-red-500">*</span>
          </label>
          <input
            id="targetLoginUrl"
            type="text"
            value={targetLoginUrl}
            onChange={(e) => setTargetLoginUrl(e.target.value)}
            placeholder="https://target-app.example.com/auth/login"
            required
            disabled={loading}
            className={inputClass}
          />
          <p className="mt-1 text-xs text-gray-400">
            The target app&apos;s login URL — must be a trusted, app-controlled
            value.
          </p>
        </div>

        {/* Advanced toggle */}
        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced((v) => !v)}
            className="text-sm text-indigo-600 hover:underline"
          >
            {showAdvanced ? "▾ Hide" : "▸ Show"} optional fields
          </button>
        </div>

        {showAdvanced && (
          <div className="space-y-4 rounded-lg border border-indigo-100 bg-indigo-50 p-4">
            <div>
              <label htmlFor="reason" className={labelClass}>
                Reason
              </label>
              <input
                id="reason"
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Investigating support ticket #1234"
                disabled={loading}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-indigo-600">
                Forwarded to Auth0 for audit logging.
              </p>
            </div>
            <div>
              <label htmlFor="organization" className={labelClass}>
                Organization
              </label>
              <input
                id="organization"
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                placeholder="org_abc123"
                disabled={loading}
                className={inputClass}
              />
            </div>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={loading || !subjectToken || !targetLoginUrl}
          className="w-full rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:opacity-60"
        >
          {loading ? "Requesting…" : "Request session transfer token"}
        </button>
      </form>

      {/* Error */}
      {error && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-6 shadow-sm">
          <h2 className="mb-2 text-sm font-semibold text-red-800">
            Request failed — <code>{error.code}</code>
          </h2>
          <p className="text-sm text-red-700">{error.message}</p>
          {error.cause && (
            <p className="mt-1 text-xs text-red-500">
              Cause: [{error.cause.code}] {error.cause.message}
            </p>
          )}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="rounded-2xl border border-green-200 bg-white p-8 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-green-800">
              STT ready{result.expiresIn !== undefined ? ` — expires in ${result.expiresIn}s` : ""}
            </h2>
            <span className="rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-800">
              one-shot · do not cache
            </span>
          </div>

          <div>
            <p className="mb-1 text-xs font-medium text-gray-500">
              Redirect URL (open in agent&apos;s browser tab)
            </p>
            <pre className="overflow-x-auto rounded-lg border border-gray-100 bg-gray-50 p-3 text-xs text-gray-700 whitespace-pre-wrap break-all">
              {result.redirectUrl}
            </pre>
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleCopy}
              className="flex-1 rounded-lg border border-gray-300 px-4 py-2 text-center text-sm font-medium text-gray-700 transition hover:bg-gray-100"
            >
              {copied ? "Copied!" : "Copy URL"}
            </button>
            <a
              href={result.redirectUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 rounded-lg bg-indigo-600 px-4 py-2 text-center text-sm font-medium text-white transition hover:bg-indigo-700"
            >
              Open in new tab →
            </a>
          </div>

          <p className="text-xs text-gray-400">
            Opening this URL establishes a session in the target app as the
            customer. The token is single-use — request a new one for each
            transfer.
          </p>
        </div>
      )}
    </div>
  );
}
