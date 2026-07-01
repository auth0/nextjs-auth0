import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Custom Token Exchange — @auth0/nextjs-auth0",
  description:
    "Example of Custom Token Exchange (RFC 8693) with @auth0/nextjs-auth0",
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
