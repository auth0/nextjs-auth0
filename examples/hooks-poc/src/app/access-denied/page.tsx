import Link from 'next/link';

export default function AccessDeniedPage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center text-center px-4">
      <h1 className="text-3xl font-bold text-red-600 mb-4">Access Denied</h1>
      <p className="mb-2">
        Access was denied by the identity provider (e.g., you might have cancelled the login), 
        and this was caught by the <code>beforeCallback</code> hook.
      </p>
      <p className="mb-6">This page demonstrates short-circuiting from the `beforeCallback` hook based on IdP response.</p>
      <Link href="/" className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
        Go to Home Page
      </Link>
    </div>
  );
} 