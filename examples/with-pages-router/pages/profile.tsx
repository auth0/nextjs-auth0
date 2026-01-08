import { auth0 } from "@/lib/auth0";
import { GetServerSideProps } from "next";

interface ProfileProps {
  session: {
    user: {
      name?: string;
      email?: string;
      sub: string;
      email_verified?: boolean;
    };
    tokenSet: {
      accessToken: string;
      idToken?: string;
      expiresAt: number;
    };
  };
}

export default function ProfilePage({ session }: ProfileProps) {
  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "2rem", maxWidth: "800px", margin: "0 auto" }}>
      <h1>👤 Your Profile</h1>

      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          backgroundColor: "#f0f9ff",
          borderRadius: "0.5rem"
        }}
      >
        <h2>User Information</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: "1rem" }}>
          <dt><strong>Name:</strong></dt>
          <dd>{session.user.name || "N/A"}</dd>

          <dt><strong>Email:</strong></dt>
          <dd>{session.user.email || "N/A"}</dd>

          <dt><strong>ID:</strong></dt>
          <dd><code>{session.user.sub}</code></dd>

          <dt><strong>Email Verified:</strong></dt>
          <dd>{session.user.email_verified ? "✅ Yes" : "❌ No"}</dd>
        </dl>
      </div>

      <div
        style={{
          marginTop: "2rem",
          padding: "1.5rem",
          backgroundColor: "#f5f5f5",
          borderRadius: "0.5rem"
        }}
      >
        <h2>Session Token Set</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: "1rem" }}>
          <dt><strong>Access Token:</strong></dt>
          <dd><code>{session.tokenSet.accessToken.substring(0, 30)}...</code></dd>

          <dt><strong>ID Token:</strong></dt>
          <dd><code>{session.tokenSet.idToken?.substring(0, 30)}...</code></dd>

          <dt><strong>Expires At:</strong></dt>
          <dd>{new Date(session.tokenSet.expiresAt * 1000).toLocaleString('en-US', {
            dateStyle: 'short',
            timeStyle: 'medium',
            hour12: false
          })}</dd>
        </dl>
      </div>

      <div style={{ marginTop: "2rem", display: "flex", gap: "1rem" }}>
        <a
          href="/"
          style={{
            padding: "0.75rem 1.5rem",
            backgroundColor: "#0070f3",
            color: "white",
            textDecoration: "none",
            borderRadius: "0.5rem"
          }}
        >
          ← Back to Home
        </a>
        <a
          href="/api/auth/logout"
          style={{
            padding: "0.75rem 1.5rem",
            backgroundColor: "#666",
            color: "white",
            textDecoration: "none",
            borderRadius: "0.5rem"
          }}
        >
          Log Out
        </a>
      </div>
    </main>
  );
}

export const getServerSideProps: GetServerSideProps<ProfileProps> = async (context) => {
  const session = await auth0.getSession(context.req, context.res);

  if (!session) {
    return {
      redirect: {
        destination: "/api/auth/login",
        permanent: false
      }
    };
  }

  return {
    props: {
      session: {
        user: {
          name: session.user.name,
          email: session.user.email,
          sub: session.user.sub,
          email_verified: session.user.email_verified
        },
        tokenSet: {
          accessToken: session.tokenSet.accessToken,
          idToken: session.tokenSet.idToken,
          expiresAt: session.tokenSet.expiresAt
        }
      }
    }
  };
};
