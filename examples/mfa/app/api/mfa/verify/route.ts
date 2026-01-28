import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { mfaToken, otp, recoveryCode, oobCode } = body;

    console.log('[API:MFA:Verify] Request received', { 
      hasOtp: !!otp,
      hasRecoveryCode: !!recoveryCode,
      hasOobCode: !!oobCode,
    });

    if (!mfaToken) {
      return NextResponse.json(
        { error: 'missing_mfa_token', error_description: 'MFA token is required' },
        { status: 400 }
      );
    }

    // App Router: SDK handles cookies internally via next/headers
    const verifyData = await auth0.mfa.verify({
      mfaToken,
      otp,
      recoveryCode,
      oobCode,
    });

    console.log('[API:MFA:Verify] Success - token cached in session');

    return NextResponse.json(verifyData);
  } catch (error: any) {
    console.error('[API:MFA:Verify] Failed:', error.code || error.error || 'unknown', error.message || error.error_description);
    
    return NextResponse.json(
      {
        error: error.code || error.error || 'verification_failed',
        error_description: error.message || error.error_description || 'Verification failed',
      },
      { status: error.status || 400 }
    );
  }
}
