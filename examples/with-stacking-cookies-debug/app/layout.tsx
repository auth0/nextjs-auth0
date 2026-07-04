import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Auth0 Cookie Debug",
  description: "Reproduction app for transaction cookie accumulation bugs",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
