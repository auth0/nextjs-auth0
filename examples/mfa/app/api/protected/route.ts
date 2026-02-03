import { NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function GET() {
  const audience = process.env.AUTH0_AUDIENCE;
  
  console.log('[/api/protected] Request received for audience:', audience);
  
  try {
    // This will trigger MFA step-up if user hasn't authenticated with MFA for this audience
    console.log('[/api/protected] Calling getAccessToken...');
    await auth0.getAccessToken({ audience });
    console.log('[/api/protected] Token retrieved successfully');

    // Simulate protected data
    const protectedData = {
      message: 'This is protected data that requires MFA',
      timestamp: new Date().toISOString(),
      data: {
        userId: 'user_123',
        sensitiveInfo: 'This data is only accessible after MFA verification',
      },
    };

    return NextResponse.json(protectedData);
  } catch (error: any) {
    console.error('[/api/protected] Error caught:', {
      code: error.code,
      error: error.error,
      message: error.message,
      error_description: error.error_description,
      status: error.status,
      cause: error.cause
    });
    
    // Check if it's an MFA required error
    if (error.code === 'mfa_required' || error.error === 'mfa_required') {
      // Validate mfa_token exists (empty string = re-auth required, not step-up)
      if (!error.mfa_token || error.mfa_token === '') {
        return NextResponse.json({
          error: 'mfa_reauthentication_required',
          error_description: 'MFA requires full re-authentication. Please log out and log in again.',
        }, { status: 401 });
      }
      
      // Extract types from SDK format: Array<{ type: string }> → string[]
      const mfaReqs = error.mfa_requirements || {};
      const enrollTypes = (mfaReqs.enroll || []).map((e: any) => e.type);
      const challengeTypes = (mfaReqs.challenge || []).map((c: any) => c.type);
      
      return NextResponse.json({
        error: 'mfa_required',
        error_description: error.error_description || 'Multi-factor authentication is required',
        mfaToken: error.mfa_token,
        mfa_requirements: {
          challenge: challengeTypes,
          enroll: enrollTypes,
          authenticators: error.authenticators || [],
        },
      });
    }

    // Other errors
    return NextResponse.json(
      {
        error: error.code || error.error || 'server_error',
        error_description: error.message || error.error_description || 'An error occurred',
      },
      { status: error.status || 500 }
    );
  }
}
