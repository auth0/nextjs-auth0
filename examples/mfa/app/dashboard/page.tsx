'use client';

import { useState } from 'react';
import { useUser } from '@auth0/nextjs-auth0';
import { mfa } from '@auth0/nextjs-auth0/client';
import { EmailEnrollment } from '@/components/mfa/email-enrollment';
import { ErrorDisplay } from '@/components/mfa/error-display';
import { PhoneEnrollment } from '@/components/mfa/phone-enrollment';
import { TotpEnrollment } from '@/components/mfa/totp-enrollment';
import { ProtectedData } from '@/components/protected-data';
import { UserInfo } from '@/components/user-info';

export default function Dashboard() {
  const { user, isLoading } = useUser();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<any>(null);
  const [protectedData, setProtectedData] = useState<any>(null);
  
  // Simplified MFA flow states
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaRequirements, setMfaRequirements] = useState<any>(null);
  const [authenticators, setAuthenticators] = useState<any[]>([]);
  const [selectedAuthId, setSelectedAuthId] = useState<string>('');
  const [otp, setOtp] = useState('');
  const [enrollmentMode, setEnrollmentMode] = useState(false);
  const [enrollmentType, setEnrollmentType] = useState<'phone' | 'totp' | 'email'>('totp');
  const [challengeData, setChallengeData] = useState<{
    oobCode: string;
    bindingMethod: string;
  } | null>(null);

  const getAuthenticatorFlow = (auth: any) => {
    // TOTP: Direct verify (no challenge)
    if (auth.authenticatorType === 'otp' || auth.type === 'totp') {
      return 'direct';
    }
    
    // OOB (SMS/Email/Push): Challenge then verify
    if (auth.authenticatorType === 'oob' || auth.oobChannel) {
      return 'challenge';
    }
    
    // Recovery: Direct verify
    if (auth.authenticatorType === 'recovery-code') {
      return 'direct';
    }
    
    return 'direct';
  };

  const canEnroll = (type: string) => {
    if (!mfaRequirements) return false;
    
    // Must be in enroll list (or already have authenticators)
    const canEnrollType = mfaRequirements.enroll?.includes(type) || authenticators.length > 0;
    if (!canEnrollType) return false;
    
    // For OOB types (phone/email), must ALSO support oob challenges
    if (type === 'phone' || type === 'email') {
      const challengeTypes = (mfaRequirements.challenge || []).map((c: any) => c.type);
      return challengeTypes.includes('oob');
    }
    
    // For OTP, check if otp challenges supported
    if (type === 'otp') {
      const challengeTypes = (mfaRequirements.challenge || []).map((c: any) => c.type);
      return challengeTypes.includes('otp');
    }
    
    return true;
  };

  const handleReset = () => {
    setMfaToken(null);
    setAuthenticators([]);
    setSelectedAuthId('');
    setOtp('');
    setError(null);
    setChallengeData(null);
  };

  const handleSendChallenge = async (authenticatorId: string) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await mfa.challenge({
        mfaToken: mfaToken!,
        challengeType: 'oob',
        authenticatorId
      });
      
      setChallengeData({
        oobCode: response.oobCode || '',
        bindingMethod: response.bindingMethod || 'prompt'
      });
      
      setError({ 
        message: '✓ SMS sent! Enter the code below.', 
        type: 'success' 
      });
    } catch (err: any) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAccessProtectedResource = async () => {
    setLoading(true);
    setError(null);

    try {
      // Step 1: Call protected API - will trigger mfa_required
      const response = await fetch('/api/protected');
      const data = await response.json();

      if (data.error === 'mfa_required') {
        // Step 2: Store MFA token and requirements
        setMfaToken(data.mfaToken);
        setMfaRequirements(data.mfa_requirements || null);
        // Step 3: Fetch authenticators using the MFA token
        const authenticatorsList = await mfa.getAuthenticators({ mfaToken: data.mfaToken });
        
        // Filter to only active authenticators
        const activeAuthenticators = authenticatorsList.filter(a => a.active);
        
        setAuthenticators(activeAuthenticators);

        // Preselect first active authenticator
        if (activeAuthenticators.length > 0) {
          setSelectedAuthId(activeAuthenticators[0].id);
        } else if (authenticatorsList.length > 0) {
          // Fallback: show warning and use all authenticators
          // console.warn('[CLIENT] No active authenticators found, showing all');
          setAuthenticators(authenticatorsList);
          setSelectedAuthId(authenticatorsList[0].id);
        }
      } else if (data.error) {
        setError(data);
      } else {
        setProtectedData(data);
      }
    } catch (err: any) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (!otp || otp.length !== 6) {
      setError({ message: 'Please enter a 6-digit code', type: 'error' });
      return;
    }

    if (!mfaToken) {
      setError({ message: 'No MFA token available', type: 'error' });
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const selectedAuth = authenticators.find(a => a.id === selectedAuthId);
      const flow = getAuthenticatorFlow(selectedAuth);
      
      if (flow === 'challenge' && !challengeData) {
        setError({ 
          message: 'Please send SMS first by clicking "Send Code"', 
          type: 'error' 
        });
        setLoading(false);
        return;
      }
      
      // Verify based on flow type
      if (flow === 'direct') {
        // TOTP/Recovery: Direct verify
        await mfa.verify({
          mfaToken,
          otp,
          ...(selectedAuthId && { authenticatorId: selectedAuthId }),
        });
      } else {
        // OOB: Verify with oobCode from challenge
        await mfa.verify({
          mfaToken,
          oobCode: challengeData!.oobCode,
          bindingCode: otp, // User enters SMS code as binding code
        });
      }

      // Fetch protected data after successful verification
      const protectedResponse = await fetch('/api/protected');
      
      if (!protectedResponse.ok) {
        const errorData = await protectedResponse.json();
        setError({ message: `Protected resource failed: ${errorData.error_description || errorData.error}`, type: 'error' });
        return;
      }

      const data = await protectedResponse.json();

      if (data.error) {
        setError({ message: `Protected resource returned: ${data.error_description || data.error}`, type: 'error' });
        return;
      }

      setProtectedData(data);
      setError({ message: '✓ Complete! Protected data retrieved successfully.', type: 'success' });
      
      // Reset MFA flow state
      handleReset();

    } catch (err: any) {
      setError(err);
      setOtp('');
      setChallengeData(null);
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

          {protectedData && (
            <ProtectedData data={protectedData} />
          )}

          <div className="bg-white border rounded-lg p-6 shadow-sm">
            <h2 className="text-xl font-semibold mb-4">Protected Resource Access</h2>
            <p className="text-gray-600 mb-4">
              Click the button below to access a protected API that requires MFA authentication.
            </p>
            
            <button
              onClick={handleAccessProtectedResource}
              disabled={loading || (authenticators.length > 0 && !protectedData)}
              className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Processing...' : 'Access Protected API'}
            </button>

            {/* Show enrollment UI when mfa_requirements.enroll exists OR user wants to add factors */}
            {mfaToken && (mfaRequirements?.enroll?.length > 0 || authenticators.length > 0) && !protectedData && (
              <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                <h3 className="font-semibold text-yellow-900 mb-2">
                  📱 {authenticators.length === 0 ? 'Enroll Your First Authenticator' : 'Enroll Additional Authenticator'}
                </h3>
                <p className="text-sm text-yellow-700 mb-3">
                  {authenticators.length === 0 && mfaRequirements?.enroll?.length > 0 
                    ? 'You need at least one MFA factor to continue:' 
                    : 'You can enroll additional MFA factors:'}
                </p>
                
                <div className="flex gap-3">
                  {canEnroll('otp') && (
                    <button
                      onClick={() => {
                        setEnrollmentType('totp');
                        setEnrollmentMode(true);
                      }}
                      disabled={loading}
                      className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:bg-gray-400"
                    >
                      📱 Enroll Authenticator App
                    </button>
                  )}
                  {canEnroll('phone') && (
                    <button
                      onClick={() => {
                        setEnrollmentType('phone');
                        setEnrollmentMode(true);
                      }}
                      disabled={loading}
                      className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:bg-gray-400"
                    >
                      💬 Enroll Phone (SMS)
                    </button>
                  )}
                  {canEnroll('email') && (
                    <button
                      onClick={() => {
                        setEnrollmentType('email');
                        setEnrollmentMode(true);
                      }}
                      disabled={loading}
                      className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 disabled:bg-gray-400"
                    >
                      📧 Enroll Email
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* Enrollment modals */}
            {enrollmentMode && mfaToken && enrollmentType === 'phone' && (
              <PhoneEnrollment
                mfaToken={mfaToken}
                onSuccess={(auth) => {
                  setAuthenticators([...authenticators, auth]);
                  setEnrollmentMode(false);
                  setError({ message: '✓ Phone enrolled successfully!', type: 'success' });
                }}
                onCancel={() => setEnrollmentMode(false)}
              />
            )}
            {enrollmentMode && mfaToken && enrollmentType === 'totp' && (
              <TotpEnrollment
                mfaToken={mfaToken}
                onSuccess={(auth) => {
                  setAuthenticators([...authenticators, auth]);
                  setEnrollmentMode(false);
                  setError({ message: '✓ Authenticator app enrolled successfully!', type: 'success' });
                }}
                onCancel={() => setEnrollmentMode(false)}
              />
            )}
            {enrollmentMode && mfaToken && enrollmentType === 'email' && (
              <EmailEnrollment
                mfaToken={mfaToken}
                userEmail={user?.email}
                onSuccess={(auth) => {
                  setAuthenticators([...authenticators, auth]);
                  setEnrollmentMode(false);
                  setError({ message: '✓ Email enrolled successfully!', type: 'success' });
                }}
                onCancel={() => setEnrollmentMode(false)}
              />
            )}

            {/* Show authenticators selection */}
            {authenticators.length > 0 && !protectedData && (
              <div className="mt-4 p-4 bg-indigo-50 border border-indigo-200 rounded-lg">
                <div className="flex items-center gap-2 mb-3">
                  <svg className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                  <span className="font-semibold text-indigo-900">MFA Required - Select Authenticator</span>
                </div>
                
                <p className="text-sm text-indigo-700 mb-3">
                  Choose an authenticator and enter your code:
                </p>

                <div className="space-y-3 mb-4">
                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-2 block">Authenticator:</label>
                    <select
                      value={selectedAuthId}
                      onChange={(e) => {
                        setSelectedAuthId(e.target.value);
                        setChallengeData(null); // Reset challenge when switching
                        setOtp('');
                      }}
                      className="w-full px-3 py-2 border border-indigo-300 rounded-lg"
                    >
                      {authenticators.map((auth: any) => {
                        const flow = getAuthenticatorFlow(auth);
                        const icon = auth.authenticatorType === 'otp' ? '📱' : 
                                     auth.oobChannel === 'sms' ? '💬' : 
                                     auth.oobChannel === 'email' ? '📧' : '🔒';
                        const flowLabel = flow === 'direct' ? '(Direct)' : '(Send Code First)';
                        // Extract last part of ID for unique display
                        const idSuffix = auth.id.split('|')[1]?.substring(0, 8) || auth.id.substring(0, 8);
                        const activeLabel = auth.active ? '✓ Active' : '⚠️ Inactive';
                        return (
                          <option key={auth.id} value={auth.id}>
                            {icon} {auth.authenticatorType} [{idSuffix}] {auth.name ? `- ${auth.name}` : ''} {flowLabel} - {activeLabel}
                          </option>
                        );
                      })}
                    </select>
                  </div>

                  {/* Challenge button for OOB authenticators */}
                  {selectedAuthId && getAuthenticatorFlow(
                    authenticators.find(a => a.id === selectedAuthId)
                  ) === 'challenge' && (
                    challengeData ? (
                      <div className="p-3 bg-green-50 border border-green-200 rounded-lg text-sm text-green-700">
                        ✓ SMS sent! Enter the code below to verify.
                      </div>
                    ) : (
                      <button
                        onClick={() => handleSendChallenge(selectedAuthId)}
                        disabled={loading}
                        className="w-full px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:bg-gray-400"
                      >
                        {loading ? 'Sending...' : '💬 Send SMS Code'}
                      </button>
                    )
                  )}

                  <div>
                    <label className="text-sm font-medium text-gray-700 mb-2 block">
                      {challengeData ? 'Enter code from SMS:' : 'Enter authenticator code:'}
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        placeholder="000000"
                        maxLength={6}
                        className="flex-1 px-4 py-2 border border-indigo-300 rounded-lg font-mono text-lg text-center"
                        autoFocus
                      />
                      <button
                        onClick={handleVerifyOtp}
                        disabled={otp.length !== 6 || loading}
                        className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                      >
                        {loading ? 'Verifying...' : 'Verify'}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="flex-1 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                    <p className="text-xs text-blue-800">
                      <strong>💡 Tip:</strong> TOTP apps require direct verification. SMS/Email require sending a code first.
                    </p>
                  </div>
                  <button
                    onClick={handleReset}
                    disabled={loading}
                    className="px-4 py-2 bg-gray-600 text-white text-sm rounded-lg hover:bg-gray-700 disabled:bg-gray-400 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {error && (
              <div className="mt-4">
                <ErrorDisplay error={error} onDismiss={() => setError(null)} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
