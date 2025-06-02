import Link from 'next/link';

export default function LoginBlockedPage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center text-center px-4">
      <h1 className="text-3xl font-bold text-red-600 mb-4">Login Blocked</h1>
      <p className="mb-2">
        Your login attempt was intentionally blocked by the `beforeLogin` hook because the 
        <code>?blockLogin=true</code> query parameter was present.
      </p>
      <p className="mb-6">This demonstrates the short-circuiting capability of the hook.</p>
      <Link href="/" className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
        Go to Home Page
      </Link>
    </div>
  );
} 