/**
 * Shared MFA test scenarios for flow tests.
 * Reduces duplication between client and server test suites.
 */

import type { MfaRequirements } from "../errors/index.js";
import type {
  Authenticator,
  ChallengeResponse,
  EnrollmentResponse,
  MfaVerifyResponse
} from "../types/index.js";

/**
 * Test scenario structure for black-box testing.
 */
export interface MfaTestScenario<TInput = any, TOutput = any> {
  /** Test case name */
  name: string;
  /** Input parameters */
  input: TInput;
  /** Expected output or validation function */
  expected?: TOutput | ((result: TOutput) => void);
  /** MSW response configuration */
  mswResponse?: {
    status: number;
    body: any;
  };
  /** Expected error validation */
  expectError?: (error: any) => void;
}

// ============================================================================
// getAuthenticators Scenarios
// ============================================================================

export const getAuthenticatorsScenarios: MfaTestScenario<
  { mfaToken: string; mfaRequirements?: MfaRequirements },
  Authenticator[]
>[] = [
  {
    name: "list all authenticators (3 types)",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: {
        challenge: [{ type: "otp" }, { type: "oob" }, { type: "recovery-code" }]
      }
    },
    mswResponse: {
      status: 200,
      body: [
        {
          id: "auth_123",
          authenticator_type: "otp",
          type: "otp",
          active: true,
          name: "Google Authenticator"
        },
        {
          id: "auth_456",
          authenticator_type: "oob",
          type: "oob",
          active: true,
          oob_channel: "sms",
          phone_number: "+1***5678"
        },
        {
          id: "auth_789",
          authenticator_type: "recovery-code",
          type: "recovery-code",
          active: true
        }
      ]
    },
    expected: (result: Authenticator[]) => {
      if (result.length !== 3) throw new Error("Expected 3 authenticators");
      if (result[0].type !== "otp") throw new Error("Expected otp first");
      if (result[1].type !== "oob") throw new Error("Expected oob second");
      if (result[2].type !== "recovery-code")
        throw new Error("Expected recovery-code third");
    }
  },
  {
    name: "filter by single challenge type (otp)",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 200,
      body: [
        {
          id: "auth_123",
          authenticator_type: "otp",
          type: "otp",
          active: true
        }
      ]
    },
    expected: (result: Authenticator[]) => {
      if (result.length !== 1) throw new Error("Expected 1 authenticator");
      if (result[0].type !== "otp") throw new Error("Expected otp only");
    }
  },
  {
    name: "empty authenticators array",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 200,
      body: []
    },
    expected: []
  },
  {
    name: "empty challenge types (no filtering - fallback)",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: { challenge: [] }
    },
    mswResponse: {
      status: 200,
      body: [
        {
          id: "auth_123",
          authenticator_type: "otp",
          type: "otp",
          active: true
        }
      ]
    },
    expected: (result: Authenticator[]) => {
      if (result.length !== 1)
        throw new Error("Expected 1 authenticator (fallback behavior)");
    }
  },
  {
    name: "missing challenge field (no filtering)",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: {}
    },
    mswResponse: {
      status: 200,
      body: [
        {
          id: "auth_123",
          authenticator_type: "otp",
          type: "otp",
          active: true
        }
      ]
    },
    expected: (result: Authenticator[]) => {
      if (result.length !== 1) throw new Error("Expected 1 authenticator");
    }
  },
  {
    name: "Auth0 400 error",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 400,
      body: {
        error: "invalid_grant",
        error_description: "Invalid MFA token"
      }
    },
    expectError: (error: any) => {
      if (error.code !== "invalid_grant")
        throw new Error("Expected invalid_grant");
    }
  },
  {
    name: "Auth0 500 error",
    input: {
      mfaToken: "encrypted-token",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 500,
      body: {
        error: "server_error",
        error_description: "Failed to list authenticators"
      }
    },
    expectError: (error: any) => {
      if (!error.message.includes("authenticators"))
        throw new Error("Expected error about authenticators");
    }
  }
];

// ============================================================================
// challenge Scenarios
// ============================================================================

export const challengeScenarios: MfaTestScenario<
  {
    mfaToken: string;
    challengeType: string;
    authenticatorId?: string;
    mfaRequirements?: MfaRequirements;
  },
  ChallengeResponse
>[] = [
  {
    name: "OTP challenge",
    input: {
      mfaToken: "encrypted-token",
      challengeType: "otp",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 200,
      body: {
        challenge_type: "otp",
        challengeType: "otp"
      }
    },
    expected: (result: ChallengeResponse) => {
      if (result.challengeType !== "otp")
        throw new Error("Expected challengeType=otp");
    }
  },
  {
    name: "OOB challenge",
    input: {
      mfaToken: "encrypted-token",
      challengeType: "oob",
      mfaRequirements: { challenge: [{ type: "oob" }] }
    },
    mswResponse: {
      status: 200,
      body: {
        challenge_type: "oob",
        challengeType: "oob",
        oob_code: "abc123",
        oobCode: "abc123",
        binding_method: "prompt",
        bindingMethod: "prompt"
      }
    },
    expected: (result: ChallengeResponse) => {
      if (result.challengeType !== "oob")
        throw new Error("Expected challengeType=oob");
      if (result.oobCode !== "abc123")
        throw new Error("Expected oobCode=abc123");
      if (result.bindingMethod !== "prompt")
        throw new Error("Expected bindingMethod=prompt");
    }
  },
  {
    name: "with authenticatorId",
    input: {
      mfaToken: "encrypted-token",
      challengeType: "otp",
      authenticatorId: "auth_123",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 200,
      body: {
        challenge_type: "otp",
        challengeType: "otp"
      }
    },
    expected: (result: ChallengeResponse) => {
      if (result.challengeType !== "otp") throw new Error("Expected otp");
    }
  },
  {
    name: "empty challenge types",
    input: {
      mfaToken: "encrypted-token",
      challengeType: "otp",
      mfaRequirements: { challenge: [] }
    },
    mswResponse: {
      status: 400,
      body: {
        error: "mfa_no_available_factors",
        error_description: "No challenge types available for MFA"
      }
    },
    expectError: (error: any) => {
      if (!error.message.includes("available"))
        throw new Error("Expected 'available' in error");
    }
  },
  {
    name: "Auth0 400 error",
    input: {
      mfaToken: "encrypted-token",
      challengeType: "invalid",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 400,
      body: {
        error: "invalid_request",
        error_description: "Invalid challenge type"
      }
    },
    expectError: (error: any) => {
      if (error.code !== "invalid_request")
        throw new Error("Expected invalid_request");
    }
  }
];

// ============================================================================
// verify Scenarios
// ============================================================================

export const verifyScenarios: MfaTestScenario<
  {
    mfaToken: string;
    otp?: string;
    oobCode?: string;
    bindingCode?: string;
    recoveryCode?: string;
    audience?: string;
    scope?: string;
    mfaRequirements?: MfaRequirements;
  },
  MfaVerifyResponse
>[] = [
  {
    name: "OTP verification success",
    input: {
      mfaToken: "encrypted-token",
      otp: "123456",
      audience: "https://api.example.com",
      scope: "openid profile"
    },
    mswResponse: {
      status: 200,
      body: {
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        token_type: "Bearer",
        expires_in: 3600
      }
    },
    expected: (result: MfaVerifyResponse) => {
      if (result.access_token !== "new-access-token")
        throw new Error("Expected access_token");
      if (result.token_type !== "Bearer")
        throw new Error("Expected token_type=Bearer");
    }
  },
  {
    name: "OOB verification success",
    input: {
      mfaToken: "encrypted-token",
      oobCode: "abc123",
      bindingCode: "456",
      audience: "https://api.example.com",
      scope: "openid profile"
    },
    mswResponse: {
      status: 200,
      body: {
        access_token: "new-access-token",
        token_type: "Bearer",
        expires_in: 3600
      }
    },
    expected: (result: MfaVerifyResponse) => {
      if (result.access_token !== "new-access-token")
        throw new Error("Expected access_token");
    }
  },
  {
    name: "Recovery code verification with new code",
    input: {
      mfaToken: "encrypted-token",
      recoveryCode: "abcd-efgh",
      audience: "https://api.example.com",
      scope: "openid profile"
    },
    mswResponse: {
      status: 200,
      body: {
        access_token: "new-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        recovery_code: "new-recovery-code"
      }
    },
    expected: (result: MfaVerifyResponse) => {
      if (result.access_token !== "new-access-token")
        throw new Error("Expected access_token");
      if (result.recovery_code !== "new-recovery-code")
        throw new Error("Expected recovery_code");
    }
  },
  {
    name: "Recovery code absent (tenant config)",
    input: {
      mfaToken: "encrypted-token",
      otp: "123456",
      audience: "https://api.example.com",
      scope: "openid profile"
    },
    mswResponse: {
      status: 200,
      body: {
        access_token: "new-access-token",
        token_type: "Bearer",
        expires_in: 3600
      }
    },
    expected: (result: MfaVerifyResponse) => {
      if (result.recovery_code !== undefined)
        throw new Error("Expected no recovery_code");
    }
  },
  {
    name: "Wrong OTP → chained MFA",
    input: {
      mfaToken: "encrypted-token",
      otp: "000000",
      audience: "https://api.example.com",
      scope: "openid profile",
      mfaRequirements: { challenge: [{ type: "otp" }] }
    },
    mswResponse: {
      status: 400,
      body: {
        error: "mfa_required",
        error_description: "Invalid OTP, retry required",
        mfa_token: "new-raw-mfa-token",
        mfa_requirements: {
          challenge: [{ type: "otp" }]
        }
      }
    },
    expectError: (error: any) => {
      if (error.code !== "mfa_required")
        throw new Error("Expected mfa_required");
      if (!error.mfa_token) throw new Error("Expected encrypted mfaToken");
      if (!error.mfa_requirements) throw new Error("Expected mfaRequirements");
    }
  },
  {
    name: "Wrong binding code",
    input: {
      mfaToken: "encrypted-token",
      oobCode: "abc123",
      bindingCode: "999",
      audience: "https://api.example.com",
      scope: "openid profile"
    },
    mswResponse: {
      status: 400,
      body: {
        error: "invalid_grant",
        error_description: "Invalid binding code"
      }
    },
    expectError: (error: any) => {
      if (error.code !== "invalid_grant")
        throw new Error("Expected invalid_grant");
    }
  },
  {
    name: "Rate limit (429)",
    input: {
      mfaToken: "encrypted-token",
      otp: "123456",
      audience: "https://api.example.com",
      scope: "openid profile"
    },
    mswResponse: {
      status: 429,
      body: {
        error: "too_many_attempts",
        error_description: "Too many attempts"
      }
    },
    expectError: (error: any) => {
      if (error.code !== "too_many_attempts")
        throw new Error("Expected too_many_attempts");
    }
  }
];

// ============================================================================
// enroll Scenarios
// ============================================================================

export const enrollScenarios: MfaTestScenario<
  {
    mfaToken: string;
    authenticatorTypes: string[];
    oobChannels?: string[];
    phoneNumber?: string;
    email?: string;
  },
  EnrollmentResponse
>[] = [
  {
    name: "OTP enrollment",
    input: {
      mfaToken: "encrypted-token",
      authenticatorTypes: ["otp"]
    },
    mswResponse: {
      status: 200,
      body: {
        authenticator_type: "otp",
        barcode_uri: "otpauth://totp/...",
        secret: "base32secret"
      }
    },
    expected: (result: EnrollmentResponse) => {
      if (result.authenticatorType !== "otp")
        throw new Error("Expected authenticatorType=otp");
      if (!result.barcodeUri) throw new Error("Expected barcodeUri");
      if (!result.secret) throw new Error("Expected secret");
    }
  },
  {
    name: "OOB SMS enrollment",
    input: {
      mfaToken: "encrypted-token",
      authenticatorTypes: ["oob"],
      oobChannels: ["sms"],
      phoneNumber: "+15551234567"
    },
    mswResponse: {
      status: 200,
      body: {
        authenticator_type: "oob",
        oob_channel: "sms",
        oob_code: "abc123"
      }
    },
    expected: (result: EnrollmentResponse) => {
      if (result.authenticatorType !== "oob")
        throw new Error("Expected authenticatorType=oob");
      if (result.oobChannel !== "sms")
        throw new Error("Expected oobChannel=sms");
    }
  },
  {
    name: "Email enrollment",
    input: {
      mfaToken: "encrypted-token",
      authenticatorTypes: ["oob"],
      oobChannels: ["email"],
      email: "user@example.com"
    },
    mswResponse: {
      status: 200,
      body: {
        id: "email|dev_abc123",
        authenticator_type: "oob",
        oob_channel: "email",
        oob_code: "email-code-123"
      }
    },
    expected: (result: EnrollmentResponse) => {
      if (result.authenticatorType !== "oob" || result.oobChannel !== "email")
        throw new Error("Expected authenticatorType=oob with oobChannel=email");
    }
  },
  {
    name: "Auth0 400 error",
    input: {
      mfaToken: "encrypted-token",
      authenticatorTypes: ["invalid"]
    },
    mswResponse: {
      status: 400,
      body: {
        error: "invalid_request",
        error_description: "Invalid authenticator type"
      }
    },
    expectError: (error: any) => {
      if (error.code !== "invalid_request")
        throw new Error("Expected invalid_request");
    }
  }
];
