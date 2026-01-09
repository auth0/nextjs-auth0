"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

/**
 * MFA Demo Page
 *
 * Demonstrates the MFA step-up flow:
 * 1. User clicks "Call Protected API"
 * 2. Client fetches /api/protected
 * 3. If MFA required, receives 403 with mfa_token
 * 4. Client redirects to MFA completion page (or shows token details)
 */

// Inner component that uses useSearchParams
function MfaDemoContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Check if we have an mfa_token from a previous redirect
  const mfaToken = searchParams.get("token");

  async function callProtectedApi() {
    console.log("[MFA-Demo] Calling /api/protected...");
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("/api/protected");
      const data = await response.json();
      
      console.log("[MFA-Demo] Response:", { status: response.status, data });

      if (response.status === 403 && data.error === "mfa_required") {
        console.log("[MFA-Demo] MFA Required!", {
          mfa_token_length: data.mfa_token?.length,
          requirements: data.mfa_requirements
        });
        // MFA is required - in a real app, redirect to MFA UI
        setResult({
          type: "mfa_required",
          data,
        });

        // Example: redirect to MFA page with token
        // router.push(`/mfa?token=${encodeURIComponent(data.mfa_token)}`);
        return;
      }

      if (!response.ok) {
        console.log("[MFA-Demo] API Error:", response.status, data);
        setError(`API error: ${response.status} - ${data.error || "Unknown"}`);
        return;
      }

      console.log("[MFA-Demo] Success!");
      setResult({
        type: "success",
        data,
      });
    } catch (err) {
      console.error("[MFA-Demo] Network error:", err);
      setError(`Network error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: "2rem", maxWidth: "800px", margin: "0 auto" }}>
      <h1>MFA Step-up Demo</h1>

      <p style={{ marginBottom: "1rem", color: "#666" }}>
        This page demonstrates the MFA step-up authentication flow. When you
        call the protected API and MFA is required, the SDK returns an encrypted
        mfa_token that can be used to complete the MFA challenge.
      </p>

      {mfaToken && (
        <div
          style={{
            padding: "1rem",
            background: "#fff3cd",
            border: "1px solid #ffc107",
            borderRadius: "4px",
            marginBottom: "1rem",
          }}
        >
          <strong>MFA Token received:</strong>
          <pre
            style={{
              fontSize: "12px",
              wordBreak: "break-all",
              whiteSpace: "pre-wrap",
            }}
          >
            {mfaToken}
          </pre>
        </div>
      )}

      <button
        onClick={callProtectedApi}
        disabled={loading}
        className="btn btn-primary"
        style={{ marginBottom: "1rem" }}
      >
        {loading ? "Calling API..." : "Call Protected API"}
      </button>

      {error && (
        <div
          style={{
            padding: "1rem",
            background: "#ffebee",
            color: "#c62828",
            borderRadius: "4px",
          }}
        >
          {error}
        </div>
      )}

      {result && result.type === "success" && (
        <div
          style={{
            padding: "1rem",
            background: "#e8f5e9",
            borderRadius: "4px",
          }}
        >
          <h3 style={{ color: "#2e7d32", marginBottom: "0.5rem" }}>
            Success!
          </h3>
          <p>API Access Granted. Token verified.</p>
          <pre style={{ background: "#fff", padding: "0.5rem" }}>
            {JSON.stringify(result.data, null, 2)}
          </pre>
        </div>
      )}

      {result && result.type === "mfa_required" && (
        <div
          style={{
            padding: "1rem",
            background: "#e3f2fd",
            border: "1px solid #90caf9",
            borderRadius: "4px",
          }}
        >
          <h3 style={{ color: "#1565c0", marginBottom: "0.5rem" }}>
            MFA Required
          </h3>
          <p>
            The Server returned <code>mfa_required</code>. Use the{" "}
            <code>mfa_token</code> to challenge the user.
          </p>
          
          <div style={{ marginTop: "1rem" }}>
            <strong>Requirements:</strong>
            <pre style={{ background: "#fff", padding: "0.5rem" }}>
              {JSON.stringify(result.data.mfa_requirements, null, 2)}
            </pre>
          </div>

          <div style={{ marginTop: "1rem" }}>
            <strong>Action:</strong>
            <p>
              Redirect the user to your MFA page with this token, or trigger
              Auth0 hosted MFA page (if supported).
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// Main page component wrapping the content in Suspense
export default function MfaDemoPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <MfaDemoContent />
    </Suspense>
  );
}
