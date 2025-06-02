import { redirect } from 'next/navigation';
import {client} from '@/lib/auth0'
// Instantiate the client here. It should pick up config from environment variables.
// For a real app, you might want a shared instance or a helper function.

export default async function ProfilePageFromHook() {
  const session = await client.getSession();

  if (!session?.user) {
    // If no session, redirect to login. 
    // The login handler in route.ts should then use the beforeLogin hook.
    redirect('/api/auth/login?returnTo=/profile-from-hook');
    // It's important to return null or stop execution after redirect
    return null; 
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center">
      <h1 className="text-2xl font-bold mb-4">User Profile (from Hook)</h1>
      <p className="mb-2">This page should have been set as `returnTo` by the `beforeLogin` hook.</p>
      <p className="mb-4">If you see this, login was successful and the session is active.</p>
      <pre className="bg-gray-100 p-4 rounded text-sm overflow-x-auto w-full max-w-2xl">
        {JSON.stringify(session.user, null, 2)}
      </pre>
      <a href="/api/auth/logout" className="mt-6 px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600">
        Logout
      </a>
    </div>
  );
} 