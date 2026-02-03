'use client';

import { useState } from 'react';
import { mfa } from '@auth0/nextjs-auth0/client';
import { ErrorDisplay } from './error-display';

interface PhoneEnrollmentProps {
  mfaToken: string;
  onSuccess: (authenticator: any) => void;
  onCancel: () => void;
}

type EnrollmentState = 'idle' | 'enrolling' | 'awaiting-verification' | 'verifying' | 'success' | 'error';

export function PhoneEnrollment({ mfaToken, onSuccess, onCancel }: PhoneEnrollmentProps) {
  const [state, setState] = useState<EnrollmentState>('idle');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [countryCode, setCountryCode] = useState('+1');
  const [oobCode, setOobCode] = useState('');
  const [bindingMethod, setBindingMethod] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [error, setError] = useState<any>(null);

  const handleEnroll = async () => {
    if (!phoneNumber || phoneNumber.length < 10) {
      setError({ message: 'Please enter a valid phone number (at least 10 digits)', type: 'error' });
      return;
    }

    setState('enrolling');
    setError(null);

    try {
      const fullPhoneNumber = `${countryCode}${phoneNumber}`;
      
      console.log('[PHONE-ENROLLMENT] Enrolling phone:', fullPhoneNumber);
      const response = await mfa.enroll({
        mfaToken,
        authenticatorTypes: ['oob'],
        oobChannels: ['sms'],
        phoneNumber: fullPhoneNumber
      });

      console.log('[PHONE-ENROLLMENT] Enrollment response:', response);
      
      if (response.authenticatorType === 'oob') {
        // OOB enrollment sends code automatically
        setOobCode(response.oobCode || '');
        setBindingMethod(response.bindingMethod || 'prompt');
        
        setState('awaiting-verification');
        setError({ message: '✓ SMS sent! Check your phone and enter the code below.', type: 'success' });
      } else {
        throw new Error('Unexpected response type from enrollment');
      }

    } catch (err: any) {
      console.error('[PHONE-ENROLLMENT] Enrollment error:', err);
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
      console.log('[PHONE-ENROLLMENT] Verifying with:', {
        oobCode: oobCode.substring(0, 20) + '...',
        bindingCode: verificationCode
      });

      await mfa.verify({
        mfaToken,
        oobCode,
        bindingCode: verificationCode
      });

      setState('success');
      setError({ message: '✓ Phone enrolled successfully!', type: 'success' });

      // Fetch updated authenticators list
      setTimeout(async () => {
        try {
          const authenticators = await mfa.getAuthenticators({ mfaToken });
          const phoneAuth = authenticators.find(a => 
            a.authenticatorType === 'oob' && a.oobChannel === 'sms'
          );
          if (phoneAuth) {
            onSuccess(phoneAuth);
          } else {
            // Just close if we can't find the new authenticator
            onSuccess({ id: 'new', authenticatorType: 'oob', oobChannel: 'sms' } as any);
          }
        } catch (err) {
          console.error('[PHONE-ENROLLMENT] Error fetching authenticators:', err);
          onSuccess({ id: 'new', authenticatorType: 'oob', oobChannel: 'sms' } as any);
        }
      }, 1000);

    } catch (err: any) {
      console.error('[PHONE-ENROLLMENT] Verification error:', err);
      setError(err);
      setState('error');
      setVerificationCode('');
    }
  };

  const handleCancel = () => {
    if (state === 'enrolling' || state === 'verifying') {
      return; // Don't allow cancel during API calls
    }
    onCancel();
  };

  const handleReset = () => {
    setState('idle');
    setPhoneNumber('');
    setVerificationCode('');
    setOobCode('');
    setBindingMethod('');
    setError(null);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">
            📱 Enroll Phone Number
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
              Phone Enrolled Successfully!
            </p>
            <p className="text-sm text-gray-600">
              Your phone number is now registered for MFA.
            </p>
          </div>
        ) : state === 'idle' || state === 'enrolling' ? (
          <div>
            <p className="text-sm text-gray-600 mb-4">
              Enter your phone number to receive SMS codes for multi-factor authentication.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Country Code
                </label>
                <select
                  value={countryCode}
                  onChange={(e) => setCountryCode(e.target.value)}
                  disabled={state === 'enrolling'}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                >
                  <option value="+1">+1 (US/Canada)</option>
                  <option value="+44">+44 (UK)</option>
                  <option value="+91">+91 (India)</option>
                  <option value="+61">+61 (Australia)</option>
                  <option value="+49">+49 (Germany)</option>
                  <option value="+33">+33 (France)</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Phone Number
                </label>
                <input
                  type="tel"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value.replace(/\D/g, ''))}
                  placeholder="5551234567"
                  disabled={state === 'enrolling'}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Enter phone number without country code
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
                  disabled={state === 'enrolling' || !phoneNumber || phoneNumber.length < 10}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {state === 'enrolling' ? 'Enrolling...' : 'Send SMS'}
                </button>
              </div>
            </div>
          </div>
        ) : state === 'awaiting-verification' || state === 'verifying' ? (
          <div>
            <p className="text-sm text-gray-600 mb-4">
              We sent a 6-digit code to <strong>{countryCode}{phoneNumber}</strong>. Enter it below to complete enrollment.
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
