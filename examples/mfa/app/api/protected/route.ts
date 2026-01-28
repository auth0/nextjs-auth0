import { NextResponse } from 'next/server';
import { auth0 } from '@/lib/auth0';

export async function GET() {
  const audience = process.env.AUTH0_AUDIENCE || 'resource-server-1';
  
  try {
    console.log('[API:Protected] Requesting access token', { audience });

    // This will trigger MFA step-up if user hasn't authenticated with MFA for this audience
    const { token } = await auth0.getAccessToken({ audience });

    console.log('[API:Protected] Access token obtained');

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
    console.error('[API:Protected] ═══════════════════════════════════════');
    console.error('[API:Protected] CAUGHT ERROR FROM SDK');
    console.error('[API:Protected] Error Type:', error.constructor?.name || 'Unknown');
    console.error('[API:Protected] Error Code:', error.code || error.error || 'none');
    console.error('[API:Protected] Error Message:', error.message || error.error_description || 'none');
    console.error('[API:Protected] Has mfa_token property:', 'mfa_token' in error);
    console.error('[API:Protected] Has mfa_requirements property:', 'mfa_requirements' in error);
    
    if (error.mfa_token) {
      console.error('[API:Protected] mfa_token (first 50 chars):', error.mfa_token.substring(0, 50) + '...');
      console.error('[API:Protected] mfa_token length:', error.mfa_token.length);
    }
    
    if (error.mfa_requirements) {
      console.error('[API:Protected] mfa_requirements:', JSON.stringify(error.mfa_requirements, null, 2));
    }
    console.error('[API:Protected] ═══════════════════════════════════════');

    // Check if it's an MFA required error
    if (error.code === 'mfa_required' || error.error === 'mfa_required') {
      console.log('[API:Protected] ✓ MFA STEP-UP REQUIRED');
      
      // Validate mfa_token exists (empty string = re-auth required, not step-up)
      if (!error.mfa_token || error.mfa_token === '') {
        console.error('[API:Protected] ✗ FATAL: No mfa_token - step-up not supported');
        console.error('[API:Protected] This means: action not configured OR API has no authorization policy');
        return NextResponse.json({
          error: 'mfa_reauthentication_required',
          error_description: 'MFA requires full re-authentication. Please log out and log in again.',
        }, { status: 401 });
      }
      
      console.log('[API:Protected] ✓ mfa_token present (encrypted)');
      
      // Extract types from SDK format: Array<{ type: string }> → string[]
      const mfaReqs = error.mfa_requirements || {};
      const enrollTypes = (mfaReqs.enroll || []).map((e: any) => e.type);
      const challengeTypes = (mfaReqs.challenge || []).map((c: any) => c.type);
      
      console.log('[API:Protected] Enroll types available:', enrollTypes.length > 0 ? enrollTypes : 'NONE');
      console.log('[API:Protected] Challenge types available:', challengeTypes.length > 0 ? challengeTypes : 'NONE');
      
      return NextResponse.json({
        error: 'mfa_required',
        error_description: error.error_description || 'Multi-factor authentication is required',
        mfaToken: error.mfa_token,
        mfaRequirements: {
          challenge: challengeTypes,
          enroll: enrollTypes,
          authenticators: error.authenticators || [],
        },
        // Debug info for UI
        _debug: {
          errorType: error.constructor?.name,
          mfaTokenPreview: error.mfa_token.substring(0, 50) + '...',
          mfaTokenLength: error.mfa_token.length,
        }
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
