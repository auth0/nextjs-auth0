import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Auth0 mTLS Example",
  description: "Next.js + Auth0 with Mutual TLS (RFC 8705) client authentication"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
