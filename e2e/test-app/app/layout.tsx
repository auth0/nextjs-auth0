import type { Metadata } from "next";
import { Auth0Provider } from "@auth0/nextjs-auth0";
import { auth0 } from "@/lib/auth0";

export const metadata: Metadata = {
  title: "nextjs-auth0 e2e test app",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth0.getSession();
  return (
    <html lang="en">
      <body>
        <Auth0Provider user={session?.user}>
          {children}
        </Auth0Provider>
      </body>
    </html>
  );
}
