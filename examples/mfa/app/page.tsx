import { auth0 } from '@/lib/auth0';
import Link from 'next/link';

export default async function Home() {
  const session = await auth0.getSession();
  const user = session?.user;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="max-w-2xl mx-auto p-8">
        <div className="bg-white rounded-2xl shadow-xl p-8 text-center">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            MFA Testing Application
          </h1>
          <p className="text-lg text-gray-600 mb-8">
            Demonstrating Auth0 Multi-Factor Authentication step-up flows
          </p>
          
          {!user ? (
            <>
              <p className="text-gray-700 mb-6">
                This application showcases how MFA is triggered only when accessing protected resources, not during initial login.
              </p>
              <a
                href="/auth/login"
                className="inline-block px-8 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
              >
                Login to Get Started
              </a>
            </>
          ) : (
            <>
              <p className="text-gray-700 mb-6">
                Welcome back, {user.name}! You are logged in.
              </p>
              <div className="flex gap-4 justify-center">
                <Link
                  href="/dashboard"
                  className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Go to Dashboard
                </Link>
                <a
                  href="/auth/logout"
                  className="px-6 py-3 bg-gray-600 text-white font-semibold rounded-lg hover:bg-gray-700 transition-colors"
                >
                  Logout
                </a>
              </div>
            </>
          )}

          <div className="mt-12 pt-8 border-t border-gray-200">
            <h2 className="text-xl font-semibold mb-4">Demo Flow</h2>
            <div className="text-left text-sm text-gray-600 space-y-2">
              <p>• <strong>Act 1:</strong> First-time enrollment (OTP, SMS, Email)</p>
              <p>• <strong>Act 2:</strong> Returning user fast path</p>
              <p>• <strong>Act 3:</strong> Factor management</p>
              <p>• <strong>Act 4:</strong> Error handling & recovery</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
