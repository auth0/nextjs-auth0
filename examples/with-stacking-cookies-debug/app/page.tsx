import Link from "next/link";

const BUGS = [
  {
    href: "/bugs/txn-accumulation",
    title: "__txn_* cookie accumulation",
    desc: "Every prefetched login link leaves an orphaned transaction cookie that is never cleaned up, eventually causing 431 Request Header Fields Too Large.",
  },
];

export default function Home() {
  return (
    <main style={{ maxWidth: 600, margin: "0 auto", padding: "48px 24px" }}>
      <h1 style={{ fontSize: 20, marginBottom: 8, color: "#111827" }}>nextjs-auth0 — Cookie Accumulation Debug</h1>
      <p style={{ color: "#6b7280", fontSize: 13, marginBottom: 32 }}>
        Reproduction app for transaction cookie accumulation bugs (GH #1917 / #2450).
      </p>

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {BUGS.map((b) => (
          <Link
            key={b.href}
            href={b.href}
            style={{
              display: "block", background: "#ffffff",
              border: "1px solid #e5e7eb", borderRadius: 8,
              padding: "16px 20px", textDecoration: "none",
            }}
          >
            <div style={{ fontWeight: 600, fontSize: 15, color: "#111827", marginBottom: 4 }}>{b.title}</div>
            <p style={{ color: "#6b7280", fontSize: 13, margin: 0 }}>{b.desc}</p>
          </Link>
        ))}
      </div>
    </main>
  );
}
