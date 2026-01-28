import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { mfaToken, authenticatorTypes, oobChannels, phoneNumber, email } = body;

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

    return NextResponse.json(enrollData);
  } catch (error: any) {
    
    return NextResponse.json(
      {
        error: error.code || error.error || 'enrollment_failed',
        error_description: error.message || error.error_description || 'Enrollment failed',
      },
      { status: error.status || 400 }
    );
  }
}
