import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Connected Accounts — @auth0/nextjs-auth0",
  description:
    "Test app for connected accounts and connection tokens (Token Vault) with @auth0/nextjs-auth0",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 text-gray-900 antialiased">
        {children}
      </body>
    </html>
  );
}
