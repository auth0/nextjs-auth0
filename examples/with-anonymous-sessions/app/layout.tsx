import { Auth0Provider } from "@auth0/nextjs-auth0/client";

import { auth0 } from "@/lib/auth0";

import "./globals.css";

export default async function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  // Server-side anonymous session fetch for SSR seed (prevents loading flash)
  const anonymousSession = await auth0.getAnonymousSession();

  return (
    <html lang="en">
      <body>
        <Auth0Provider
          anonymousSession={anonymousSession}
          anonymousSessionRoute="/auth/anonymous-session"
        >
          {children}
        </Auth0Provider>
      </body>
    </html>
  );
}
