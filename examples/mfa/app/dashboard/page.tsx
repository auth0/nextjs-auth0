'use client';

import { useState, useEffect } from 'react';
import { useUser } from '@auth0/nextjs-auth0';
import { UserInfo } from '@/components/user-info';
import { ProtectedData } from '@/components/protected-data';
import { ErrorDisplay } from '@/components/mfa/error-display';

export default function Dashboard() {
  const { user, isLoading } = useUser();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<any>(null);
  const [protectedData, setProtectedData] = useState<any>(null);
  const [mfaSuccess, setMfaSuccess] = useState<any>(null);
  
  // MFA inline flow states
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaRequirements, setMfaRequirements] = useState<any>(null);
  const [authenticators, setAuthenticators] = useState<any[]>([]);
  const [challengeData, setChallengeData] = useState<any>(null);
  const [otp, setOtp] = useState('');
  const [mfaStep, setMfaStep] = useState<'idle' | 'token' | 'authenticators' | 'enroll' | 'qr' | 'challenge' | 'verify'>('idle');
  const [enrollData, setEnrollData] = useState<any>(null);

  useEffect(() => {
    // Check for MFA success state
    const successData = sessionStorage.getItem('mfaSuccess');
    if (successData) {
      const parsed = JSON.parse(successData);
      setMfaSuccess(parsed);
      setProtectedData(parsed.protectedData?.data);
      sessionStorage.removeItem('mfaSuccess');
    }
  }, []);

  const handleAccessProtectedResource = async () => {
    setLoading(true);
    setError(null);
    setMfaStep('idle');

    try {
      // Step 1: Call protected API
      const response = await fetch('/api/protected');
      const data = await response.json();

      if (data.error === 'mfa_required') {
        // Step 2: Show MFA token received
        setMfaToken(data.mfaToken);
        setMfaRequirements(data.mfaRequirements);
        setMfaStep('token');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 3: Call getAuthenticators and display list
        const authResponse = await fetch(`/api/mfa/authenticators?mfa_token=${encodeURIComponent(data.mfaToken)}`);
        const authenticatorsList = await authResponse.json();
        
        if (authenticatorsList.error) {
          setError(authenticatorsList);
          setMfaStep('idle');
          setLoading(false);
          return;
        }
        
        setAuthenticators(authenticatorsList);
        setMfaStep('authenticators');

        if (authenticatorsList.length === 0) {
          await new Promise(resolve => setTimeout(resolve, 1500));
          setMfaStep('enroll');
          setLoading(false);
          return;
        }

        await new Promise(resolve => setTimeout(resolve, 1500));

        // Step 4: Call challenge - REQUIRED for all MFA flows
        const challengeResponse = await fetch('/api/mfa/challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mfaToken: data.mfaToken,
            challengeType: 'otp',
            authenticatorId: authenticatorsList[0].id, // Use first authenticator
          }),
        });

        const challenge = await challengeResponse.json();
        
        if (challenge.error) {
          setError(challenge);
          setMfaStep('idle');
          setLoading(false);
          return;
        }

        setChallengeData(challenge);
        setMfaStep('challenge');

        // Step 5: Wait for OTP (user input)
        // UI will show OTP input, verification happens in handleVerifyOtp

      } else if (data.error) {
        setError(data);
      } else {
        setProtectedData(data);
      }
    } catch (err: any) {
      setError(err);
      setMfaStep('idle');
    } finally {
      setLoading(false);
    }
  };

  const handleEnrollOtp = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/mfa/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaToken,
          authenticatorTypes: ['otp'],
        }),
      });

      const data = await response.json();

      if (data.error) {
        throw new Error(data.error_description || data.error);
      }

      setEnrollData(data);
      setMfaStep('qr');
    } catch (err: any) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleContinueFromQr = async () => {
    setLoading(true);
    setError(null);

    try {
      // Must call challenge API before OTP verification
      const challengeResponse = await fetch('/api/mfa/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaToken,
          challengeType: 'otp',
          authenticatorId: enrollData.id, // Use enrolled authenticator ID
        }),
      });

      const challenge = await challengeResponse.json();
      
      if (challenge.error) {
        setError(challenge);
        setMfaStep('qr');
        return;
      }

      setChallengeData(challenge);
      setMfaStep('challenge');
    } catch (err: any) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (otp.length !== 6) {
      setError({ message: 'Please enter a 6-digit code', type: 'error' });
      return;
    }

    setLoading(true);
    setError(null);
    setMfaStep('verify');

    try {
      const response = await fetch('/api/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaToken,
          otp,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error_description || errorData.error || 'Verification failed');
      }

      await response.json();

      setError({ message: '✓ Verification successful! Fetching protected data...', type: 'success' });
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Fetch protected data to verify token works
      const protectedResponse = await fetch('/api/protected');
      
      if (!protectedResponse.ok) {
        const errorData = await protectedResponse.json();
        setError({ message: `Token received but protected resource failed: ${errorData.error_description || errorData.error}`, type: 'error' });
        return;
      }

      const data = await protectedResponse.json();

      if (data.error) {
        setError({ message: `Protected resource returned: ${data.error_description || data.error}`, type: 'error' });
        return;
      }

      setProtectedData(data);
      setError({ message: '✓ Complete! Protected data retrieved successfully.', type: 'success' });
      
      // Reset MFA flow
      setMfaStep('idle');
      setMfaToken(null);
      setAuthenticators([]);
      setChallengeData(null);
      setEnrollData(null);
      setOtp('');

    } catch (err: any) {
      setError(err);
      setOtp('');
      setMfaStep('challenge');
    } finally {
      setLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <p className="text-gray-600 mb-4">Please login to continue</p>
          <a
            href="/auth/login"
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Login
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          <a
            href="/auth/logout"
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Logout
          </a>
        </div>

        <div className="space-y-6">
          <UserInfo user={user} />

          {mfaSuccess && (
            <div className="bg-green-50 border-2 border-green-500 rounded-lg p-6">
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">
                  <svg className="h-8 w-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-green-900 mb-3">
                    ✓ MFA Verification Complete
                  </h3>
                  <div className="space-y-2 text-sm text-green-800">
                    <p className="font-medium">Verified at: {new Date(mfaSuccess.timestamp).toLocaleString()}</p>
                    <div className="mt-3 space-y-1">
                      <p>✓ Access token received: <span className="font-mono">{mfaSuccess.verify.tokenType}</span></p>
                      <p>✓ Token expires in: <span className="font-semibold">{mfaSuccess.verify.expiresIn}s</span> (at {mfaSuccess.verify.expiresAt ? new Date(mfaSuccess.verify.expiresAt).toLocaleTimeString() : 'N/A'})</p>
                      {mfaSuccess.verify.scope && (
                        <p>✓ Scope: <span className="font-mono text-xs">{mfaSuccess.verify.scope}</span></p>
                      )}
                      <p>✓ Token cached in session: <span className="font-semibold">Yes</span></p>
                      <p>✓ Protected resource accessed: <span className="font-semibold">{mfaSuccess.protectedData.received ? 'Success' : 'Failed'}</span></p>
                    </div>
                  </div>
                  <button
                    onClick={() => setMfaSuccess(null)}
                    className="mt-4 px-4 py-2 bg-green-600 text-white text-sm rounded hover:bg-green-700"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            </div>
          )}

          {protectedData && (
            <ProtectedData data={protectedData} />
          )}

          <div className="bg-white border rounded-lg p-6 shadow-sm">
            <h2 className="text-xl font-semibold mb-4">Protected Resource Access</h2>
            <p className="text-gray-600 mb-4">
              Click the button below to access a protected API that requires MFA authentication.
              If you haven&apos;t enrolled in MFA yet, you&apos;ll be prompted to do so.
            </p>
            
            <button
              onClick={handleAccessProtectedResource}
              disabled={loading || mfaStep !== 'idle'}
              className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Processing...' : 'Access Protected API'}
            </button>

            {/* MFA Flow Visual Feedback */}
            {mfaStep === 'token' && (
              <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <div className="flex items-center gap-2">
                  <svg className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span className="font-semibold text-blue-900">Step 1/4: MFA Token Received</span>
                </div>
                <p className="text-sm text-blue-700 mt-2">Token length: {mfaToken?.length} characters</p>
                <p className="text-xs text-blue-600 mt-1">Requirements: {mfaRequirements?.challenge?.map((c: any) => c.type).join(', ')}</p>
              </div>
            )}

            {mfaStep === 'authenticators' && (
              <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
                <div className="flex items-center gap-2">
                  <svg className="h-5 w-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span className="font-semibold text-green-900">Step 2/4: Authenticators Retrieved</span>
                </div>
                <div className="mt-3 space-y-2">
                  {authenticators.map((auth: any, idx: number) => (
                    <div key={idx} className="text-sm text-green-700 flex items-center gap-2">
                      <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                      <span className="font-mono">{auth.authenticatorType}</span>
                      {auth.name && <span className="text-xs">({auth.name})</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {mfaStep === 'enroll' && (
              <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                <div className="flex items-center gap-2 mb-3">
                  <svg className="h-5 w-5 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <span className="font-semibold text-yellow-900">No Authenticators Found</span>
                </div>
                <p className="text-sm text-yellow-700 mb-3">You need to enroll an authenticator to continue. Click below to set up OTP authentication.</p>
                <button
                  onClick={handleEnrollOtp}
                  disabled={loading}
                  className="px-6 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {loading ? 'Enrolling...' : 'Enroll OTP Authenticator'}
                </button>
              </div>
            )}

            {mfaStep === 'qr' && enrollData && (
              <div className="mt-4 p-6 bg-white border-2 border-indigo-200 rounded-lg">
                <div className="flex items-center gap-2 mb-4">
                  <svg className="h-6 w-6 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
                  </svg>
                  <span className="font-semibold text-indigo-900">Scan QR Code</span>
                </div>
                
                <div className="bg-white p-4 rounded-lg border mb-4 flex justify-center">
                  <img 
                    src={enrollData.barcodeUri} 
                    alt="QR Code" 
                    className="w-48 h-48"
                  />
                </div>
                
                <div className="mb-4 p-3 bg-gray-50 rounded border">
                  <p className="text-xs text-gray-600 mb-1">Manual entry code:</p>
                  <p className="font-mono text-sm break-all">{enrollData.secret}</p>
                </div>

                {enrollData.recoveryCodes && enrollData.recoveryCodes.length > 0 && (
                  <div className="mb-4 p-3 bg-amber-50 rounded border border-amber-200">
                    <p className="text-xs text-amber-900 font-semibold mb-2">Recovery Codes (Save these!):</p>
                    <div className="grid grid-cols-2 gap-2">
                      {enrollData.recoveryCodes.map((code: string, idx: number) => (
                        <p key={idx} className="font-mono text-xs text-amber-800">{code}</p>
                      ))}
                    </div>
                  </div>
                )}
                
                <button
                  onClick={handleContinueFromQr}
                  className="w-full px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
                >
                  Continue to Verification
                </button>
              </div>
            )}

            {(mfaStep === 'challenge' || mfaStep === 'verify') && (
              <div className="mt-4 p-4 bg-purple-50 border border-purple-200 rounded-lg">
                <div className="flex items-center gap-2 mb-3">
                  <svg className="h-5 w-5 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span className="font-semibold text-purple-900">
                    {mfaStep === 'challenge' ? 'Step 4/5: Challenge Created - Enter Code' : 'Step 5/5: Verifying...'}
                  </span>
                </div>
                
                {mfaStep === 'challenge' && (
                  <>
                    <p className="text-sm text-purple-700 mb-1">Challenge created for authenticator:</p>
                    <p className="text-xs font-mono text-purple-600 mb-3">{challengeData?.challengeType || 'otp'}</p>
                    <p className="text-sm text-purple-700 mb-3">Enter your 6-digit code:</p>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        placeholder="000000"
                        maxLength={6}
                        className="flex-1 px-4 py-2 border border-purple-300 rounded-lg font-mono text-lg text-center"
                        autoFocus
                      />
                      <button
                        onClick={handleVerifyOtp}
                        disabled={otp.length !== 6 || loading}
                        className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                      >
                        Verify
                      </button>
                    </div>
                  </>
                )}

                {mfaStep === 'verify' && (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-600"></div>
                    <span className="text-sm text-purple-700">Verifying OTP and fetching access token...</span>
                  </div>
                )}
              </div>
            )}

            {error && (
              <div className="mt-4">
                <ErrorDisplay error={error} onDismiss={() => setError(null)} />
              </div>
            )}
          </div>

          {protectedData && (
            <ProtectedData data={protectedData} />
          )}
        </div>
      </div>
    </div>
  );
}
