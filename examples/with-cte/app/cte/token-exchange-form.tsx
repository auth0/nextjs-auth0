"use client";

import { useState } from "react";

type ExchangeResult = {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn: number;
  scope?: string;
  act?: { sub: string; act?: unknown };
};

type ExchangeError = {
  code: string;
  message: string;
  cause?: { code: string; message: string };
};

const inputClass =
  "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 disabled:opacity-50";

const labelClass = "mb-1 block text-sm font-medium text-gray-700";

export function TokenExchangeForm() {
  const [subjectToken, setSubjectToken] = useState("");
  const [subjectTokenType, setSubjectTokenType] = useState(
    "urn:acme:legacy-token"
  );
  const [audience, setAudience] = useState("");
  const [scope, setScope] = useState("");
  const [actorToken, setActorToken] = useState("");
  const [actorTokenType, setActorTokenType] = useState("");
  const [showDelegation, setShowDelegation] = useState(false);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExchangeResult | null>(null);
  const [error, setError] = useState<ExchangeError | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);

    const body: Record<string, string> = {
      subjectToken,
      subjectTokenType,
    };
    if (audience) body.audience = audience;
    if (scope) body.scope = scope;
    if (showDelegation && actorToken) {
      body.actorToken = actorToken;
      body.actorTokenType = actorTokenType;
    }

    try {
      const res = await fetch("/api/cte", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data as ExchangeError);
      } else {
        setResult(data as ExchangeResult);
      }
    } catch {
      setError({ code: "network_error", message: "Request failed." });
    } finally {
      setLoading(false);
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
            Subject token <span className="text-red-500">*</span>
          </label>
          <textarea
            id="subjectToken"
            rows={3}
            value={subjectToken}
            onChange={(e) => setSubjectToken(e.target.value)}
            placeholder="eyJ... (JWT or opaque token to exchange)"
            required
            disabled={loading}
            className={inputClass + " font-mono text-xs resize-none"}
          />
        </div>

        {/* Subject token type */}
        <div>
          <label htmlFor="subjectTokenType" className={labelClass}>
            Subject token type <span className="text-red-500">*</span>
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
          />
          <p className="mt-1 text-xs text-gray-400">
            A URI (10–100 chars). Built-in:{" "}
            <code className="rounded bg-gray-100 px-1">
              urn:ietf:params:oauth:token-type:access_token
            </code>{" "}
            or{" "}
            <code className="rounded bg-gray-100 px-1">
              urn:ietf:params:oauth:token-type:id_token
            </code>
          </p>
        </div>

        {/* Audience */}
        <div>
          <label htmlFor="audience" className={labelClass}>
            Audience{" "}
            <span className="text-xs font-normal text-gray-400">(optional)</span>
          </label>
          <input
            id="audience"
            type="text"
            value={audience}
            onChange={(e) => setAudience(e.target.value)}
            placeholder="https://api.example.com"
            disabled={loading}
            className={inputClass}
          />
        </div>

        {/* Scope */}
        <div>
          <label htmlFor="scope" className={labelClass}>
            Scope{" "}
            <span className="text-xs font-normal text-gray-400">(optional)</span>
          </label>
          <input
            id="scope"
            type="text"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="read:data write:data"
            disabled={loading}
            className={inputClass}
          />
          <p className="mt-1 text-xs text-gray-400">
            Merged with defaults: openid profile email offline_access
          </p>
        </div>

        {/* Delegation toggle */}
        <div>
          <button
            type="button"
            onClick={() => setShowDelegation((v) => !v)}
            className="text-sm text-indigo-600 hover:underline"
          >
            {showDelegation ? "▾ Hide" : "▸ Add"} delegation / actor token
          </button>
        </div>

        {/* Actor token fields */}
        {showDelegation && (
          <div className="space-y-4 rounded-lg border border-indigo-100 bg-indigo-50 p-4">
            <p className="text-xs text-indigo-700">
              Actor token represents the entity acting on behalf of the subject
              (RFC 8693 §4.4). Auth0 must have the{" "}
              <code className="rounded bg-indigo-100 px-1">cte_actor_token</code>{" "}
              flag enabled and an Action calling{" "}
              <code className="rounded bg-indigo-100 px-1">
                api.authentication.setActor()
              </code>
              .
            </p>
            <div>
              <label htmlFor="actorToken" className={labelClass}>
                Actor token
              </label>
              <textarea
                id="actorToken"
                rows={2}
                value={actorToken}
                onChange={(e) => setActorToken(e.target.value)}
                placeholder="eyJ... (must be a valid RS256/PS256-signed JWT)"
                disabled={loading}
                className={inputClass + " font-mono text-xs resize-none"}
              />
            </div>
            <div>
              <label htmlFor="actorTokenType" className={labelClass}>
                Actor token type
              </label>
              <input
                id="actorTokenType"
                type="text"
                value={actorTokenType}
                onChange={(e) => setActorTokenType(e.target.value)}
                placeholder="http://corporate-idp/id-token"
                disabled={loading}
                className={inputClass + " font-mono text-xs"}
              />
            </div>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={loading || !subjectToken || !subjectTokenType}
          className="w-full rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:opacity-60"
        >
          {loading ? "Exchanging…" : "Exchange token"}
        </button>
      </form>

      {/* Error */}
      {error && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-6 shadow-sm">
          <h2 className="mb-2 text-sm font-semibold text-red-800">
            Exchange failed — <code>{error.code}</code>
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
          <h2 className="text-lg font-semibold text-green-800">
            Exchange successful
          </h2>

          <dl className="divide-y divide-gray-100 rounded-lg border border-gray-100 bg-gray-50 p-4 text-sm">
            <ResultRow label="Token type" value={result.tokenType} />
            <ResultRow label="Expires in" value={`${result.expiresIn}s`} />
            {result.scope && <ResultRow label="Scope" value={result.scope} />}
            {result.act && (
              <ResultRow
                label="act claim"
                value={JSON.stringify(result.act, null, 2)}
                mono
              />
            )}
            {result.refreshToken === undefined && (
              <div className="py-2 text-xs text-gray-400">
                No refresh token — suppressed by Auth0 when actor_token is
                present.
              </div>
            )}
          </dl>

          <div className="space-y-3">
            <TokenBlock label="Access token" value={result.accessToken} />
            {result.idToken && (
              <TokenBlock label="ID token" value={result.idToken} />
            )}
            {result.refreshToken && (
              <TokenBlock label="Refresh token" value={result.refreshToken} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ResultRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4 py-2">
      <dt className="font-medium text-gray-600 shrink-0">{label}</dt>
      <dd
        className={`text-right text-gray-900 break-all ${mono ? "font-mono text-xs text-indigo-700 whitespace-pre" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}

function TokenBlock({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="mb-1 text-xs font-medium text-gray-500">{label}</p>
      <pre className="overflow-x-auto rounded-lg border border-gray-100 bg-gray-50 p-3 text-xs text-gray-700 whitespace-pre-wrap break-all">
        {value}
      </pre>
    </div>
  );
}
