'use client';

import { useState } from 'react';
import { mfa } from '@auth0/nextjs-auth0/client';
import { ErrorDisplay } from './error-display';

interface EmailEnrollmentProps {
  mfaToken: string;
  onSuccess: (authenticator: any) => void;
  onCancel: () => void;
  userEmail?: string;
}

type EnrollmentState = 'idle' | 'enrolling' | 'awaiting-verification' | 'verifying' | 'success' | 'error';

export function EmailEnrollment({ mfaToken, onSuccess, onCancel, userEmail }: EmailEnrollmentProps) {
  const [state, setState] = useState<EnrollmentState>('idle');
  const [email, setEmail] = useState(userEmail || '');
  const [oobCode, setOobCode] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [error, setError] = useState<any>(null);

  const handleEnroll = async () => {
    if (!email || !email.includes('@')) {
      setError({ message: 'Please enter a valid email address', type: 'error' });
      return;
    }

    setState('enrolling');
    setError(null);

    try {
      const response = await mfa.enroll({
        mfaToken,
        authenticatorTypes: ['oob'],
        oobChannels: ['email'],
        email
      });

      
      if (response.authenticatorType === 'oob' && response.oobChannel === 'email') {
        // OOB enrollment sends code automatically
        setOobCode(response.oobCode || '');
        
        setState('awaiting-verification');
        setError({ message: '✓ Email sent! Check your inbox and enter the code below.', type: 'success' });
      } else {
        throw new Error('Unexpected response type from enrollment');
      }

    } catch (err: any) {
      setError(err);
      setState('error');
    }
  };

  const handleVerify = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      setError({ message: 'Please enter a 6-digit verification code', type: 'error' });
      return;
    }

    if (!oobCode) {
      setError({ message: 'Missing oobCode from enrollment response', type: 'error' });
      return;
    }

    setState('verifying');
    setError(null);

    try {
      await mfa.verify({
        mfaToken,
        oobCode,
        bindingCode: verificationCode
      });

      setState('success');
      setError({ message: '✓ Email enrolled successfully!', type: 'success' });

      // Fetch updated authenticators list
      setTimeout(async () => {
        try {
          const authenticators = await mfa.getAuthenticators({ mfaToken });
          const emailAuth = authenticators.find(a => 
            a.authenticatorType === 'oob' && a.oobChannel === 'email'
          );
          if (emailAuth) {
            onSuccess(emailAuth);
          } else {
            onSuccess({ id: 'new', authenticatorType: 'oob', oobChannel: 'email' } as any);
          }
        } catch {
          onSuccess({ id: 'new', authenticatorType: 'oob', oobChannel: 'email' } as any);
        }
      }, 1000);

    } catch (err: any) {
      setError(err);
      setState('error');
      setVerificationCode('');
    }
  };

  const handleCancel = () => {
    if (state === 'enrolling' || state === 'verifying') {
      return;
    }
    onCancel();
  };

  const handleReset = () => {
    setState('idle');
    setVerificationCode('');
    setOobCode('');
    setError(null);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">
            📧 Enroll Email
          </h2>
          <button
            onClick={handleCancel}
            disabled={state === 'enrolling' || state === 'verifying'}
            className="text-gray-400 hover:text-gray-600 disabled:opacity-50"
          >
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {state === 'success' ? (
          <div className="text-center py-8">
            <div className="text-6xl mb-4">✅</div>
            <p className="text-lg font-semibold text-green-600 mb-2">
              Email Enrolled Successfully!
            </p>
            <p className="text-sm text-gray-600">
              Your email is now registered for MFA.
            </p>
          </div>
        ) : state === 'idle' || state === 'enrolling' ? (
          <div>
            <p className="text-sm text-gray-600 mb-4">
              Enter your email address to receive verification codes for multi-factor authentication.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Email Address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  disabled={state === 'enrolling'}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                />
                <p className="text-xs text-gray-500 mt-1">
                  {userEmail ? 'Using your account email or enter a different one' : 'Enter email address'}
                </p>
              </div>

              {error && (
                <ErrorDisplay error={error} onDismiss={() => setError(null)} />
              )}

              <div className="flex gap-3">
                <button
                  onClick={handleCancel}
                  disabled={state === 'enrolling'}
                  className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleEnroll}
                  disabled={state === 'enrolling' || !email || !email.includes('@')}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {state === 'enrolling' ? 'Sending...' : 'Send Email'}
                </button>
              </div>
            </div>
          </div>
        ) : state === 'awaiting-verification' || state === 'verifying' ? (
          <div>
            <p className="text-sm text-gray-600 mb-4">
              We sent a 6-digit code to <strong>{email}</strong>. Check your inbox and enter it below.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Verification Code
                </label>
                <input
                  type="text"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                  disabled={state === 'verifying'}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg font-mono text-lg text-center"
                  autoFocus
                />
              </div>

              {error && (
                <ErrorDisplay error={error} onDismiss={() => setError(null)} />
              )}

              <div className="flex gap-3">
                <button
                  onClick={handleReset}
                  disabled={state === 'verifying'}
                  className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 disabled:opacity-50"
                >
                  Back
                </button>
                <button
                  onClick={handleVerify}
                  disabled={state === 'verifying' || verificationCode.length !== 6}
                  className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {state === 'verifying' ? 'Verifying...' : 'Verify'}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-8">
            <div className="text-6xl mb-4">❌</div>
            <p className="text-lg font-semibold text-red-600 mb-4">
              Enrollment Failed
            </p>
            {error && (
              <ErrorDisplay error={error} onDismiss={() => setError(null)} />
            )}
            <div className="flex gap-3 mt-4">
              <button
                onClick={handleCancel}
                className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Close
              </button>
              <button
                onClick={handleReset}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Try Again
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
