'use client';

import Image from 'next/image';

interface UserInfoProps {
  user: any;
}

export function UserInfo({ user }: UserInfoProps) {
  return (
    <div className="bg-white border rounded-lg p-6 shadow-sm">
      <h2 className="text-xl font-semibold mb-4">User Information</h2>
      <div className="space-y-3">
        <div>
          <label className="text-sm text-gray-500">Email</label>
          <p className="font-medium">{user.email}</p>
        </div>
        <div>
          <label className="text-sm text-gray-500">Name</label>
          <p className="font-medium">{user.name}</p>
        </div>
        <div>
          <label className="text-sm text-gray-500">User ID</label>
          <p className="font-mono text-sm">{user.sub}</p>
        </div>
        {user.picture && (
          <div>
            <label className="text-sm text-gray-500 block mb-2">Avatar</label>
            <Image 
              src={user.picture} 
              alt={user.name || 'User avatar'} 
              width={64}
              height={64}
              className="rounded-full"
            />
          </div>
        )}
      </div>
    </div>
  );
}
