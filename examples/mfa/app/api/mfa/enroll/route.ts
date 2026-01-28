import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { mfaToken, authenticatorTypes, oobChannels, phoneNumber, email } = body;

    console.log('[API:MFA:Enroll] Request received', { 
      authenticatorTypes, 
      oobChannels,
      hasPhoneNumber: !!phoneNumber,
      hasEmail: !!email,
    });

    if (!mfaToken) {
      return NextResponse.json(
        { error: 'missing_mfa_token', error_description: 'MFA token is required' },
        { status: 400 }
      );
    }

    // Call MFA enroll
    const enrollData = await auth0.mfa.enroll({
      mfaToken,
      authenticatorTypes,
      oobChannels,
      phoneNumber,
      email,
    });

    console.log('[API:MFA:Enroll] Success', { 
      authenticatorType: enrollData.authenticatorType,
      hasRecoveryCodes: !!enrollData.recoveryCodes,
    });

    return NextResponse.json(enrollData);
  } catch (error: any) {
    console.error('[API:MFA:Enroll] Failed:', error.code || error.error || 'unknown', error.message || error.error_description);
    
    return NextResponse.json(
      {
        error: error.code || error.error || 'enrollment_failed',
        error_description: error.message || error.error_description || 'Enrollment failed',
      },
      { status: error.status || 400 }
    );
  }
}
