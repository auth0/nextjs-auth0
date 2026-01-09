"use client";

import "./globals.css";
import { Auth0Provider, useUser } from "@auth0/nextjs-auth0";

function NavBar() {
  const { user, isLoading } = useUser();

  return (
    <nav className="navbar">
      <a href="/" className="navbar-brand">MFA Demo</a>
      <div className="navbar-links">
        {!isLoading && (
          user ? (
            <>
              <span className="user-email">{user.email}</span>
              <a href="/auth/logout" className="btn btn-secondary">Logout</a>
            </>
          ) : (
            <a href="/auth/login" className="btn btn-primary">Login</a>
          )
        )}
      </div>
    </nav>
  );
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <title>MFA Step-up Demo</title>
      </head>
      <body>
        <Auth0Provider>
          <NavBar />
          <main className="container">{children}</main>
        </Auth0Provider>
      </body>
    </html>
  );
}
