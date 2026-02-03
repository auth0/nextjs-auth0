'use client';

import { useState } from 'react';
import { mfa } from '@auth0/nextjs-auth0/client';
import { ErrorDisplay } from './error-display';
import { QrCodeDisplay } from './qr-code-display';

interface TotpEnrollmentProps {
  mfaToken: string;
  onSuccess: (authenticator: any) => void;
  onCancel: () => void;
}

type EnrollmentState = 'idle' | 'enrolling' | 'awaiting-verification' | 'verifying' | 'success' | 'error';

export function TotpEnrollment({ mfaToken, onSuccess, onCancel }: TotpEnrollmentProps) {
  const [state, setState] = useState<EnrollmentState>('idle');
  const [secret, setSecret] = useState('');
  const [barcodeUri, setBarcodeUri] = useState('');
  const [authenticatorId, setAuthenticatorId] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [error, setError] = useState<any>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  const handleEnroll = async () => {
    setState('enrolling');
    setError(null);

    try {
      console.log('[TOTP-ENROLLMENT] Enrolling TOTP authenticator');
      const response = await mfa.enroll({
        mfaToken,
        authenticatorTypes: ['otp']
      });

      console.log('[TOTP-ENROLLMENT] Enrollment response:', response);
      
      if (response.authenticatorType === 'otp') {
        setSecret(response.secret);
        setBarcodeUri(response.barcodeUri);
        setAuthenticatorId(response.id);
        setRecoveryCodes(response.recoveryCodes || []);
        
        setState('awaiting-verification');
        setError({ 
          message: '✓ Scan the QR code with your authenticator app and enter the 6-digit code.', 
          type: 'success' 
        });
      } else {
        throw new Error('Unexpected response type from enrollment');
      }

    } catch (err: any) {
      console.error('[TOTP-ENROLLMENT] Enrollment error:', err);
      setError(err);
      setState('error');
    }
  };

  const handleVerify = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      setError({ message: 'Please enter a 6-digit verification code', type: 'error' });
      return;
    }

    setState('verifying');
    setError(null);

    try {
      console.log('[TOTP-ENROLLMENT] Verifying TOTP code');

      await mfa.verify({
        mfaToken,
        otp: verificationCode
      });

      setState('success');
      setError({ message: '✓ Authenticator app enrolled successfully!', type: 'success' });

      // Fetch updated authenticators list
      setTimeout(async () => {
        try {
          const authenticators = await mfa.getAuthenticators({ mfaToken });
          const totpAuth = authenticators.find(a => 
            a.authenticatorType === 'otp'
          );
          if (totpAuth) {
            onSuccess(totpAuth);
          } else {
            onSuccess({ id: authenticatorId, authenticatorType: 'otp' } as any);
          }
        } catch (err) {
          console.error('[TOTP-ENROLLMENT] Error fetching authenticators:', err);
          onSuccess({ id: authenticatorId, authenticatorType: 'otp' } as any);
        }
      }, 1000);

    } catch (err: any) {
      console.error('[TOTP-ENROLLMENT] Verification error:', err);
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
    setSecret('');
    setBarcodeUri('');
    setAuthenticatorId('');
    setError(null);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">
            📱 Enroll Authenticator App
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
              Authenticator App Enrolled!
            </p>
            <p className="text-sm text-gray-600">
              Your authenticator app is now registered for MFA.
            </p>
          </div>
        ) : state === 'idle' ? (
          <div>
            <p className="text-sm text-gray-600 mb-4">
              Set up an authenticator app (like Google Authenticator, Authy, or 1Password) to generate verification codes.
            </p>

            <div className="space-y-4">
              <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <p className="text-sm text-blue-800">
                  <strong>💡 Tip:</strong> Download an authenticator app on your phone before proceeding.
                </p>
              </div>

              {error && (
                <ErrorDisplay error={error} onDismiss={() => setError(null)} />
              )}

              <div className="flex gap-3">
                <button
                  onClick={handleCancel}
                  className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleEnroll}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Continue
                </button>
              </div>
            </div>
          </div>
        ) : state === 'enrolling' ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Generating QR code...</p>
          </div>
        ) : state === 'awaiting-verification' || state === 'verifying' ? (
          <div>
            <p className="text-sm text-gray-600 mb-4">
              Scan the QR code with your authenticator app, then enter the 6-digit code it generates.
            </p>

            <div className="space-y-4">
              {barcodeUri && (
                <QrCodeDisplay barcodeUri={barcodeUri} secret={secret} />
              )}

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
