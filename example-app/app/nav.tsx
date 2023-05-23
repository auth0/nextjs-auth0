'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useUser } from '@auth0/nextjs-auth0/client';

export default function Nav() {
  const { user } = useUser();
  const pathname = usePathname();
  const pageName = pathname?.split('/').pop();

  return (
    <>
      <div className={`header ${pageName}`}>
        <nav>
          <ul>
            <li>
              <Link href="/" legacyBehavior>
                <a className="active">App Router</a>
              </Link>
            </li>
            <li>
              <Link href="/page-router" legacyBehavior>
                <a>Page Router</a>
              </Link>
            </li>
          </ul>
        </nav>
      </div>
      <div className={`header ${pageName || 'home'} secondary`}>
        <nav>
          <ul>
            <li>
              <Link href="/" legacyBehavior>
                <a>Home</a>
              </Link>
            </li>
            <li>
              <Link href="/profile-csr" legacyBehavior>
                <a>Profile (CSR)</a>
              </Link>
            </li>{' '}
            <li>
              <Link href="/profile-ssr" legacyBehavior>
                <a>Profile (SSR)</a>
              </Link>
            </li>{' '}
            <li>
              <Link href="/profile-middleware" legacyBehavior>
                <a>Profile (Middleware)</a>
              </Link>
            </li>{' '}
            {user ? (
              <li>
                <a href="/api/auth/logout" data-testid="logout">
                  Logout
                </a>
              </li>
            ) : (
              <li>
                <a href="/api/auth/login" data-testid="login">
                  Login
                </a>
              </li>
            )}
          </ul>
        </nav>
      </div>
    </>
  );
}
