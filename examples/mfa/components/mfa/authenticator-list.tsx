'use client';

type Authenticator = {
  id: string;
  authenticatorType: 'otp' | 'oob' | 'recovery-code';
  oobChannel?: 'sms' | 'email';
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
  const getAuthenticatorIcon = (auth: Authenticator) => {
    if (auth.authenticatorType === 'otp') return '📱'; // TOTP app
    if (auth.oobChannel === 'sms') return '💬'; // SMS
    if (auth.oobChannel === 'email') return '📧'; // Email
    if (auth.authenticatorType === 'recovery-code') return '🔑'; // Recovery
    return '🔒';
  };

  const getAuthenticatorLabel = (auth: Authenticator) => {
    if (auth.authenticatorType === 'otp') return 'Authenticator App (OTP)';
    if (auth.authenticatorType === 'oob') {
      if (auth.oobChannel === 'sms') return 'SMS';
      if (auth.oobChannel === 'email') return 'Email';
    }
    if (auth.authenticatorType === 'recovery-code') return 'Recovery Code';
    return auth.authenticatorType;
  };

  const getAuthenticatorBadge = (auth: Authenticator) => {
    if (auth.authenticatorType === 'otp') {
      return <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded">TOTP - Direct Verify</span>;
    }
    if (auth.oobChannel === 'sms') {
      return <span className="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded">SMS - Send Code First</span>;
    }
    if (auth.oobChannel === 'email') {
      return <span className="px-2 py-1 text-xs font-medium bg-purple-100 text-purple-800 rounded">Email - Send Code First</span>;
    }
    if (auth.authenticatorType === 'recovery-code') {
      return <span className="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded">Recovery - Direct Verify</span>;
    }
    return null;
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
              <div className="flex items-center gap-2 mb-1">
                <span className="text-2xl">{getAuthenticatorIcon(auth)}</span>
                <h3 className="font-medium">{getAuthenticatorLabel(auth)}</h3>
              </div>
              <div className="mb-2">
                {getAuthenticatorBadge(auth)}
              </div>
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
