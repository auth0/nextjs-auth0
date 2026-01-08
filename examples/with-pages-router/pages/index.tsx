import { auth0 } from "@/lib/auth0";
import { GetServerSideProps } from "next";

interface HomeProps {
  session: {
    user: {
      name?: string;
      email?: string;
      sub: string;
    };
  } | null;
}

export default function Home({ session }: HomeProps) {
  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "2rem", maxWidth: "800px", margin: "0 auto" }}>
      <h1>🔐 Auth0 Next.js - Pages Router Example</h1>

      {!session ? (
        <div>
          <p>You are not logged in.</p>
          <p>
            This example uses the <strong>Pages Router</strong> with{" "}
            <strong>API routes</strong> for authentication.
          </p>
          <div style={{ marginTop: "2rem" }}>
            <a
              href="/api/auth/login"
              style={{
                padding: "0.75rem 1.5rem",
                backgroundColor: "#0070f3",
                color: "white",
                textDecoration: "none",
                borderRadius: "0.5rem",
                display: "inline-block"
              }}
            >
              Log In
            </a>
          </div>
        </div>
      ) : (
        <div>
          <p>
            Welcome, <strong>{session.user.name || session.user.email}</strong>!
          </p>
          <div style={{ marginTop: "1rem", display: "flex", gap: "1rem" }}>
            <a
              href="/profile"
              style={{
                padding: "0.75rem 1.5rem",
                backgroundColor: "#0070f3",
                color: "white",
                textDecoration: "none",
                borderRadius: "0.5rem"
              }}
            >
              View Profile
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
        </div>
      )}

      <div
        style={{
          marginTop: "3rem",
          padding: "1.5rem",
          backgroundColor: "#f5f5f5",
          borderRadius: "0.5rem"
        }}
      >
        <h2>How It Works</h2>
        <p>This example demonstrates:</p>
        <ul>
          <li>
            <strong>Pages Router:</strong> Traditional Next.js routing with
            <code>pages/</code> directory
          </li>
          <li>
            <strong>API Route Mounting:</strong> Auth routes are handled by
            <code>pages/api/[...auth0].ts</code>
          </li>
          <li>
            <strong>No Middleware:</strong> Authentication doesn&apos;t use middleware
          </li>
          <li>
            <strong>Server-Side Props:</strong> Session data fetched via
            <code>getServerSideProps</code>
          </li>
        </ul>
        <p>
          Check the <code>README.md</code> for more details!
        </p>
      </div>
    </main>
  );
}

export const getServerSideProps: GetServerSideProps<HomeProps> = async (context) => {
  const session = await auth0.getSession(context.req);

  return {
    props: {
      session: session ? {
        user: {
          name: session.user.name,
          email: session.user.email,
          sub: session.user.sub
        }
      } : null
    }
  };
};
