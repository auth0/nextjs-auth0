import React from 'react';
import './global.css';
import Header from '../components/header';
import { UserProvider } from '@auth0/nextjs-auth0/client';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <UserProvider>
        <body>
          <Header />
          <div className="container">{children}</div>
        </body>
      </UserProvider>
    </html>
  );
}
