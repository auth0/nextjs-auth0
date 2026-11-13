import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Poppy — Auth0 Next.js SDK",
  description: "Let personal AI agents shop on your site, and tell them apart from people."
};

export default function RootLayout({
  children
}: Readonly<{ children: React.ReactNode }>) {
  return (
    // Browser extensions can add attributes to <html> before React loads.
    <html lang="en" suppressHydrationWarning>
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
