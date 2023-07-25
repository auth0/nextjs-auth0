import React from 'react';
import Link from 'next/link';
import { useUser } from '@auth0/nextjs-auth0/client';
import { useRouter } from 'next/router';

const Header = (): React.ReactElement => {
  const { user } = useUser();
  const { pathname } = useRouter();
  const pageName = pathname.split('/').pop();

  return (
    <>
      <div className={`header ${pageName}`}>
        <nav>
          <ul>
            <li>
              <Link href="/" legacyBehavior>
                <a>App Router</a>
              </Link>
            </li>
            <li>
              <Link href="/page-router" legacyBehavior>
                <a className="active">Page Router</a>
              </Link>
            </li>
          </ul>
        </nav>
      </div>
      <div className={`header ${pageName} secondary`}>
        <nav>
          <ul>
            <li>
              <Link href="/page-router" legacyBehavior>
                <a>Home</a>
              </Link>
            </li>
            <li>
              <Link href="/page-router/profile-csr" legacyBehavior>
                <a>Profile (CSR)</a>
              </Link>
            </li>{' '}
            <li>
              <Link href="/page-router/profile-ssr" legacyBehavior>
                <a>Profile (SSR)</a>
              </Link>
            </li>{' '}
            <li>
              <Link href="/page-router/profile-api" legacyBehavior>
                <a>Profile (API)</a>
              </Link>
            </li>{' '}
            <li>
              <Link href="/page-router/profile-middleware" legacyBehavior>
                <a>Profile (Middleware)</a>
              </Link>
            </li>{' '}
            {user ? (
              <li>
                <a href="/api/page-router-auth/logout" data-testid="logout">
                  Logout
                </a>
              </li>
            ) : (
              <li>
                <a href="/api/page-router-auth/login?returnTo=/page-router" data-testid="login">
                  Login
                </a>
              </li>
            )}
          </ul>
        </nav>
      </div>
      <style jsx>{`
        .header {
          padding: 0.2rem;
          color: #fff;
          background-color: #000;
        }
        .header.secondary {
          background-color: #333;
        }
        nav {
          max-width: 62rem;
          margin: 1.5rem auto;
        }
        ul {
          display: flex;
          list-style: none;
          margin-left: 0;
          padding-left: 0;
        }
        li {
          margin-right: 1rem;
        }
        .header.secondary li:nth-last-child(2) {
          margin-right: auto;
        }
        a {
          color: #fff;
          text-decoration: none;
        }
        .header.page-router a[href$='page-router'],
        .header.profile-csr a[href$='profile-csr'],
        .header.profile-ssr a[href$='profile-ssr'],
        .header.profile-api a[href$='profile-api'],
        .header.profile-middleware a[href$='profile-middleware'],
        a.active {
          color: #888;
        }
        .header.page-router a[data-testid='login'],
        .header.page-router a[data-testid='logout'] {
          color: #fff;
        }
        button {
          font-size: 1rem;
          color: #fff;
          cursor: pointer;
          border: none;
          background: none;
        }
      `}</style>
    </>
  );
};

export default Header;
