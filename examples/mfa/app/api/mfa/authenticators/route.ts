import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function GET(request: NextRequest) {
  try {
    // Read mfaToken from query param (dashboard passes via URL)
    const mfaToken = request.nextUrl.searchParams.get('mfa_token');
    
    if (!mfaToken) {
      return NextResponse.json(
        { error: 'missing_mfa_token', error_description: 'MFA token required as ?mfa_token query parameter' },
        { status: 400 }
      );
    }

    // List all enrolled authenticators for the user
    const authenticators = await auth0.mfa.getAuthenticators({ mfaToken });

    return NextResponse.json(authenticators);
  } catch (error: any) {
    
    return NextResponse.json(
      {
        error: error.code || 'server_error',
        error_description: error.message || 'Failed to list authenticators',
      },
      { status: error.status || 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json();
    const { authenticatorId, mfaToken } = body;

    if (!authenticatorId) {
      return NextResponse.json(
        { error: 'missing_authenticator_id', error_description: 'Authenticator ID is required' },
        { status: 400 }
      );
    }

    if (!mfaToken) {
      return NextResponse.json(
        { error: 'missing_mfa_token', error_description: 'MFA token is required' },
        { status: 400 }
      );
    }

    // Delete authenticator
    await auth0.mfa.deleteAuthenticator({ mfaToken, authenticatorId });

    return new NextResponse(null, { status: 204 });
  } catch (error: any) {
    
    return NextResponse.json(
      {
        error: error.code || 'delete_failed',
        error_description: error.message || 'Failed to delete authenticator',
      },
      { status: error.status || 500 }
    );
  }
}
