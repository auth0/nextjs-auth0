import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MFA step-up — @auth0/nextjs-auth0",
  description: "Example of MFA step-up with @auth0/nextjs-auth0",
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
