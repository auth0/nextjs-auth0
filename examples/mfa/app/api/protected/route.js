import { NextResponse } from "next/server";
import { auth0 } from "../../../lib/auth0";
import { MfaRequiredError } from "@auth0/nextjs-auth0/server";

/**
 * MFA-protected API route demonstrating MfaRequiredError bubbling.
 *
 * When the API resource requires MFA step-up and the user hasn't completed it,
 * Auth0 returns a 403 with mfa_required. The SDK catches this and throws
 * MfaRequiredError with an encrypted mfa_token for the client to use.
 */
export async function GET() {
  try {
    // Request access token for protected audience
    // If MFA is required, SDK throws MfaRequiredError
    const { token } = await auth0.getAccessToken({
      audience: process.env.AUTH0_AUDIENCE,
      refresh: true,
    });

    // If we got here, MFA was not required or already satisfied
    return NextResponse.json({
      message: "Access token obtained successfully",
      tokenLength: token?.length,
    });
  } catch (error) {
    if (error instanceof MfaRequiredError) {
      // Return 403 with MFA details for client to handle
      return NextResponse.json(error.toJSON(), { status: 403 });
    }

    console.error("[API] Unexpected error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
