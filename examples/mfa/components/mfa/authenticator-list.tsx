'use client';

type Authenticator = {
  id: string;
  authenticator_type: 'otp' | 'oob' | 'recovery-code';
  oob_channel?: 'sms' | 'email';
  name?: string;
  created_at?: string;
};

interface AuthenticatorListProps {
  authenticators: Authenticator[];
  onSelect: (authenticator: Authenticator) => void;
  mode?: 'select' | 'manage';
  onDelete?: (id: string) => void;
}

export function AuthenticatorList({ 
  authenticators, 
  onSelect, 
  mode = 'select',
  onDelete 
}: AuthenticatorListProps) {
  const getAuthenticatorLabel = (auth: Authenticator) => {
    if (auth.authenticator_type === 'otp') return 'Authenticator App (OTP)';
    if (auth.authenticator_type === 'oob') {
      if (auth.oob_channel === 'sms') return 'SMS';
      if (auth.oob_channel === 'email') return 'Email';
    }
    if (auth.authenticator_type === 'recovery-code') return 'Recovery Code';
    return auth.authenticator_type;
  };

  const handleSelect = (auth: Authenticator) => {
    onSelect(auth);
  };

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this authenticator?')) {
      onDelete?.(id);
    }
  };

  if (authenticators.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        No authenticators enrolled
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {authenticators.map((auth) => (
        <div 
          key={auth.id}
          className="border rounded-lg p-4 hover:border-blue-500 transition-colors"
        >
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <h3 className="font-medium">{getAuthenticatorLabel(auth)}</h3>
              {auth.created_at && (
                <p className="text-sm text-gray-500">
                  Enrolled: {new Date(auth.created_at).toLocaleDateString()}
                </p>
              )}
            </div>
            <div className="flex gap-2">
              {mode === 'select' && (
                <button
                  onClick={() => handleSelect(auth)}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Use
                </button>
              )}
              {mode === 'manage' && onDelete && (
                <button
                  onClick={() => handleDelete(auth.id)}
                  className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
                >
                  Delete
                </button>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
