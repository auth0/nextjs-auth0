import Link from 'next/link';

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center">
      <h1 className="text-3xl font-bold mb-8">Auth0 Hooks POC</h1>
      <div className="space-x-4">
        <Link href="/api/auth/login" className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
          Login
        </Link>
        <Link href="/api/auth/logout" className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600">
          Logout
        </Link>
      </div>
      <div className="mt-4">
        <Link href="/api/auth/login?blockLogin=true" className="text-sm text-gray-600 hover:underline">
          Test Login Block (redirects to /login-blocked)
        </Link>
      </div>
    </div>
  );
}
