import type { Metadata } from "next";
import { Auth0Provider } from "@auth0/nextjs-auth0";
import "./globals.css";

export const metadata: Metadata = {
  title: "MFA Testing App - Auth0 nextjs-auth0",
  description: "Comprehensive MFA step-up flow demonstration",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50">
        <Auth0Provider>
          {children}
        </Auth0Provider>
      </body>
    </html>
  );
}
