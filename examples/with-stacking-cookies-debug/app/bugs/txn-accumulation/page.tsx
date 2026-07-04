import Link from "next/link";
import TokenButton from "./TokenButton";

const LOGIN_LINKS = [
  { href: "/auth/login?returnTo=/app", label: "Go to Dashboard" },
  { href: "/auth/login?returnTo=/app", label: "View Reports"    },
  { href: "/auth/login?returnTo=/app", label: "Manage Billing"  },
  { href: "/auth/login?screen_hint=signup", label: "Create Account" },
];

export default function TxnAccumulationPage() {
  return (
    <div style={{ textAlign: "center" }}>
      <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6, color: "#111827" }}>__txn_* cookie accumulation</h1>
      <p style={{ fontSize: 13, color: "#6b7280", marginBottom: 32 }}>
        Each prefetched login link writes a <code>__txn_*</code> cookie that is never consumed.
      </p>

      <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: "#111827" }}>What happens when this page loads</h2>
      <ol style={{ fontSize: 13, color: "#374151", lineHeight: 1.9, paddingLeft: 20, marginBottom: 32, textAlign: "left" }}>
        <li>The {LOGIN_LINKS.length} buttons below all point directly to <code>/auth/login</code> with <code>prefetch&#123;true&#125;</code>.</li>
        <li>Next.js prefetches each link. <code>handleLogin</code> runs for each, generating a unique PKCE <code>state</code> and writing <code>__txn_&#123;state&#125;</code>.</li>
        <li>Prefetch responses are discarded. {LOGIN_LINKS.length} cookies are now in your browser — check DevTools → Application → Cookies. None will ever reach <code>handleCallback</code>.</li>
        <li>Reload. {LOGIN_LINKS.length} more cookies. Each lasts 1 hour. After enough reloads → <strong>431 Request Header Fields Too Large</strong>.</li>
      </ol>

      <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: "#111827" }}>Links (each one gets prefetched)</h2>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center", marginBottom: 40 }}>
        {LOGIN_LINKS.map((link, i) => (
          <Link
            key={i}
            href={link.href}
            prefetch={true}
            style={{
              background: "#2563eb", color: "white", borderRadius: 6,
              padding: "10px 20px", fontWeight: 500, fontSize: 14,
              textDecoration: "none", display: "inline-block",
            }}
          >
            {link.label}
          </Link>
        ))}
      </div>

      <TokenButton />

      <div style={{ borderTop: "1px solid #e5e7eb", paddingTop: 24, display: "flex", flexDirection: "column", gap: 8 }}>
        <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 4, color: "#111827" }}>Fixes applied</h2>
        {[
          { label: "Fix 1", desc: "Prefetch guard — returns 401 on non-navigational requests to /auth/login (sec-fetch-mode, fallback headers), preventing __txn_* creation. Controlled by dangerouslyAllowLoginPrefetch (default false)." },
          { label: "Fix 2", desc: "Value-prefix encoding + two-phase eviction — cookie values are encoded as \"p:{jwe}\" (prefetch, 60s TTL) or \"{ts}:{jwe}\" (real login). When accumulated size ≥ maxSizeBytes (default 4 KB): phase 1 evicts all \"p:\" cookies first (O(1), no crypto); phase 2 evicts oldest real logins by timestamp. Backward compatible with legacy \"{jwe}\" format." },
          { label: "Fix 3", desc: "Removed dormant early-return in single-transaction mode that Fix 2 would have awakened, causing silent login lock-out on upgrade." },
          { label: "Fix 4", desc: "Targeted callback cleanup — on successful login, sweeps all accumulated \"p:\" prefetch cookies and deletes only the completing __txn_{state} cookie. All other real in-flight login cookies (other tabs, prompt:login flows) are untouched." },
        ].map((f) => (
          <div key={f.label} style={{ display: "flex", gap: 10, fontSize: 13, textAlign: "left" }}>
            <span style={{ background: "#eff6ff", color: "#2563eb", fontFamily: "monospace", fontSize: 11, padding: "2px 7px", borderRadius: 4, flexShrink: 0, alignSelf: "flex-start", marginTop: 1 }}>{f.label}</span>
            <span style={{ color: "#374151" }}>{f.desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
