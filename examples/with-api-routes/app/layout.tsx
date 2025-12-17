import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Auth0 Next.js - API Routes Example",
  description: "Demonstrating API route mounting for authentication"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", padding: "2rem", maxWidth: "800px", margin: "0 auto" }}>
        {children}
      </body>
    </html>
  );
}
