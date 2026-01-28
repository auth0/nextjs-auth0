import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { mfaToken, challengeType, authenticatorId } = body;

    console.log('[API:MFA:Challenge] Request received', { 
      challengeType,
      hasAuthenticatorId: !!authenticatorId,
    });

    if (!mfaToken) {
      return NextResponse.json(
        { error: 'missing_mfa_token', error_description: 'MFA token is required' },
        { status: 400 }
      );
    }

    if (!challengeType) {
      return NextResponse.json(
        { error: 'missing_challenge_type', error_description: 'Challenge type is required' },
        { status: 400 }
      );
    }

    // Create MFA challenge
    const challengeData = await auth0.mfa.challenge({
      mfaToken,
      challengeType,
      authenticatorId,
    });

    console.log('[API:MFA:Challenge] Challenge created successfully', {
      challengeType,
      hasOobCode: !!challengeData.oobCode,
    });

    return NextResponse.json(challengeData);
  } catch (error: any) {
    console.error('[API:MFA:Challenge] Failed:', error.code || error.error || 'unknown', error.message || error.error_description);
    
    return NextResponse.json(
      {
        error: error.code || error.error || 'challenge_failed',
        error_description: error.message || error.error_description || 'Challenge creation failed',
      },
      { status: error.status || 400 }
    );
  }
}
