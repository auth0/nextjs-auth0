import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from "vitest";

import {
  challengeScenarios,
  enrollScenarios,
  getAuthenticatorsScenarios,
  verifyScenarios
} from "../../test/mfa-scenarios-shared.js";
import { generateSecret } from "../../test/utils.js";
import type { MfaClient } from "../../types/index.js";
import { encryptMfaToken } from "../../utils/mfa-utils.js";

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  appBaseUrl: "http://localhost:3000",
  mfaToken: "raw-mfa-token-from-auth0"
};

// MSW server setup
const server = setupServer();

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });

  // Configure base URL for client routes via environment variables
  process.env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE = `${DEFAULT.appBaseUrl}/auth/mfa/authenticators`;
  process.env.NEXT_PUBLIC_MFA_CHALLENGE_ROUTE = `${DEFAULT.appBaseUrl}/auth/mfa/challenge`;
  process.env.NEXT_PUBLIC_MFA_VERIFY_ROUTE = `${DEFAULT.appBaseUrl}/auth/mfa/verify`;
  process.env.NEXT_PUBLIC_MFA_ENROLL_ROUTE = `${DEFAULT.appBaseUrl}/auth/mfa/enroll`;
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  delete process.env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE;
  delete process.env.NEXT_PUBLIC_MFA_CHALLENGE_ROUTE;
  delete process.env.NEXT_PUBLIC_MFA_VERIFY_ROUTE;
  delete process.env.NEXT_PUBLIC_MFA_ENROLL_ROUTE;
  server.close();
});

describe("ClientMfaClient", () => {
  let secret: string;
  let mfaClient: MfaClient;

  beforeEach(async () => {
    secret = await generateSecret(32);
    const { mfa } = await import("./index.js");
    mfaClient = mfa;
  });

  describe("getAuthenticators", () => {
    getAuthenticatorsScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        // Encrypt mfaToken with context
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          scenario.input.mfaRequirements?.challenge
            ? "https://api.example.com"
            : "",
          "openid profile",
          scenario.input.mfaRequirements,
          secret,
          300
        );

        // Setup MSW handler for SDK route
        if (scenario.mswResponse) {
          server.use(
            http.get(
              `${DEFAULT.appBaseUrl}/auth/mfa/authenticators`,
              ({ request }) => {
                // Verify query params
                const url = new URL(request.url);
                expect(url.searchParams.get("mfa_token")).toBe(encryptedToken);

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        // Execute test
        if (scenario.expectError) {
          try {
            await mfaClient.getAuthenticators({ mfaToken: encryptedToken });
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await mfaClient.getAuthenticators({
            mfaToken: encryptedToken
          });
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          } else {
            expect(result).toEqual(scenario.expected);
          }
        }
      });
    });

    it("should throw MfaGetAuthenticatorsError for network errors", async () => {
      const { MfaGetAuthenticatorsError } = await import(
        "../../errors/index.js"
      );

      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      // Simulate network failure
      server.use(
        http.get(`${DEFAULT.appBaseUrl}/auth/mfa/authenticators`, () => {
          return HttpResponse.error();
        })
      );

      try {
        await mfaClient.getAuthenticators({ mfaToken: encryptedToken });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaGetAuthenticatorsError);
        expect((error as any).code).toBe("client_error");
      }
    });
  });

  describe("challenge", () => {
    challengeScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        // Setup MSW handler for SDK route
        if (scenario.mswResponse) {
          server.use(
            http.post(
              `${DEFAULT.appBaseUrl}/auth/mfa/challenge`,
              async ({ request }) => {
                const body = (await request.json()) as any;
                expect(body?.mfaToken).toBeDefined();
                expect(body?.challengeType).toBeDefined();

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        // Encrypt mfaToken with context
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "https://api.example.com",
          "openid profile",
          scenario.input.mfaRequirements,
          secret,
          300
        );

        // Setup MSW handler for SDK route
        if (scenario.mswResponse) {
          server.use(
            http.post(
              `${DEFAULT.appBaseUrl}/auth/mfa/challenge`,
              async ({ request }) => {
                // Client sends via JSON body
                const body = (await request.json()) as any;
                expect(body.mfaToken).toBe(encryptedToken);
                expect(body.challengeType).toBe(scenario.input.challengeType);
                if (scenario.input.authenticatorId) {
                  expect(body.authenticatorId).toBe(
                    scenario.input.authenticatorId
                  );
                }

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        // Execute test
        if (scenario.expectError) {
          try {
            await mfaClient.challenge({
              mfaToken: encryptedToken,
              challengeType: scenario.input.challengeType,
              authenticatorId: scenario.input.authenticatorId
            });
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await mfaClient.challenge({
            mfaToken: encryptedToken,
            challengeType: scenario.input.challengeType,
            authenticatorId: scenario.input.authenticatorId
          });
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          } else {
            expect(result).toEqual(scenario.expected);
          }
        }
      });
    });

    it("should throw MfaChallengeError for network errors", async () => {
      const { MfaChallengeError } = await import("../../errors/index.js");

      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/challenge`, () => {
          return HttpResponse.error();
        })
      );

      try {
        await mfaClient.challenge({
          mfaToken: encryptedToken,
          challengeType: "otp"
        });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaChallengeError);
        expect((error as any).code).toBe("client_error");
      }
    });
  });

  describe("verify", () => {
    verifyScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        // Encrypt mfaToken with context
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          scenario.input.audience || "https://api.example.com",
          scenario.input.scope || "openid profile",
          scenario.input.mfaRequirements,
          secret,
          300
        );

        // Setup MSW handler for SDK route
        if (scenario.mswResponse) {
          server.use(
            http.post(
              `${DEFAULT.appBaseUrl}/auth/mfa/verify`,
              async ({ request }) => {
                const body = (await request.json()) as any;
                expect(body.mfaToken).toBe(encryptedToken);

                if (scenario.input.otp) {
                  expect(body.otp).toBe(scenario.input.otp);
                } else if (scenario.input.oobCode) {
                  expect(body.oobCode).toBe(scenario.input.oobCode);
                  expect(body.bindingCode).toBe(scenario.input.bindingCode);
                } else if (scenario.input.recoveryCode) {
                  expect(body.recoveryCode).toBe(scenario.input.recoveryCode);
                }

                return HttpResponse.json(scenario.mswResponse!.body, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        // Build verify options
        const verifyOptions: any = { mfaToken: encryptedToken };
        if (scenario.input.otp) verifyOptions.otp = scenario.input.otp;
        if (scenario.input.oobCode) {
          verifyOptions.oobCode = scenario.input.oobCode;
          verifyOptions.bindingCode = scenario.input.bindingCode;
        }
        if (scenario.input.recoveryCode)
          verifyOptions.recoveryCode = scenario.input.recoveryCode;

        // Execute test
        if (scenario.expectError) {
          try {
            await mfaClient.verify(verifyOptions);
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await mfaClient.verify(verifyOptions);
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          } else {
            expect(result).toEqual(scenario.expected);
          }
        }
      });
    });

    it("should throw MfaVerifyError for network errors", async () => {
      const { MfaVerifyError } = await import("../../errors/index.js");

      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/verify`, () => {
          return HttpResponse.error();
        })
      );

      try {
        await mfaClient.verify({ mfaToken: encryptedToken, otp: "123456" });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaVerifyError);
        expect((error as any).code).toBe("client_error");
      }
    });

    it("should parse MfaRequiredError for chained MFA", async () => {
      const { MfaRequiredError } = await import("../../errors/index.js");

      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      const newEncryptedToken = await encryptMfaToken(
        "new-raw-token",
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/verify`, () => {
          return HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Invalid OTP",
              mfa_token: newEncryptedToken,
              mfa_requirements: {
                challenge: [{ type: "otp" }]
              }
            },
            { status: 400 }
          );
        })
      );

      try {
        await mfaClient.verify({ mfaToken: encryptedToken, otp: "000000" });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaRequiredError);
        const mfaError = error as any;
        expect(mfaError.mfa_token).toBe(newEncryptedToken);
        expect(mfaError.mfa_requirements).toEqual({
          challenge: [{ type: "otp" }]
        });
      }
    });

    it("should preserve token_type from server response", async () => {
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "https://api.example.com",
        "openid profile",
        { challenge: [{ type: "otp" }] },
        secret,
        300
      );

      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/verify`, () => {
          return HttpResponse.json({
            access_token: "new-access-token",
            token_type: "Bearer",
            expires_in: 3600
          });
        })
      );

      const result = await mfaClient.verify({
        mfaToken: encryptedToken,
        otp: "123456"
      });
      expect(result.token_type).toBe("Bearer");
    });
  });

  describe("enroll", () => {
    // Shared scenarios (4 tests)
    enrollScenarios.forEach((scenario) => {
      it(scenario.name, async () => {
        const encryptedToken = await encryptMfaToken(
          DEFAULT.mfaToken,
          "",
          "openid profile",
          undefined,
          secret,
          300
        );

        if (scenario.mswResponse) {
          server.use(
            http.post(
              `${DEFAULT.appBaseUrl}/auth/mfa/enroll`,
              async ({ request }) => {
                const body = (await request.json()) as any;
                expect(body.mfaToken).toBe(encryptedToken);
                expect(body.authenticatorTypes).toEqual(
                  scenario.input.authenticatorTypes
                );

                // Server route returns transformed camelCase response
                const rawResponse = scenario.mswResponse!.body;
                const transformedResponse: any = {};

                if (rawResponse.authenticator_type)
                  transformedResponse.authenticatorType =
                    rawResponse.authenticator_type;
                if (rawResponse.barcode_uri)
                  transformedResponse.barcodeUri = rawResponse.barcode_uri;
                if (rawResponse.secret)
                  transformedResponse.secret = rawResponse.secret;
                if (rawResponse.oob_channel)
                  transformedResponse.oobChannel = rawResponse.oob_channel;
                if (rawResponse.oob_code)
                  transformedResponse.oobCode = rawResponse.oob_code;
                if (rawResponse.recovery_codes)
                  transformedResponse.recoveryCodes =
                    rawResponse.recovery_codes;
                if (rawResponse.error)
                  transformedResponse.error = rawResponse.error;
                if (rawResponse.error_description)
                  transformedResponse.error_description =
                    rawResponse.error_description;

                return HttpResponse.json(transformedResponse, {
                  status: scenario.mswResponse!.status
                });
              }
            )
          );
        }

        if (scenario.expectError) {
          try {
            await mfaClient.enroll({
              mfaToken: encryptedToken,
              authenticatorTypes: scenario.input.authenticatorTypes,
              ...(scenario.input.oobChannels && {
                oobChannels: scenario.input.oobChannels
              }),
              ...(scenario.input.phoneNumber && {
                phoneNumber: scenario.input.phoneNumber
              }),
              ...(scenario.input.email && { email: scenario.input.email })
            } as any);
            throw new Error("Expected error to be thrown");
          } catch (error) {
            scenario.expectError(error);
          }
        } else {
          const result = await mfaClient.enroll({
            mfaToken: encryptedToken,
            authenticatorTypes: scenario.input.authenticatorTypes,
            ...(scenario.input.oobChannels && {
              oobChannels: scenario.input.oobChannels
            }),
            ...(scenario.input.phoneNumber && {
              phoneNumber: scenario.input.phoneNumber
            }),
            ...(scenario.input.email && { email: scenario.input.email })
          } as any);
          if (typeof scenario.expected === "function") {
            scenario.expected(result);
          }
        }
      });
    });

    // Network errors (1 test)
    it("should throw MfaEnrollmentError for network errors", async () => {
      const { MfaEnrollmentError } = await import("../../errors/index.js");
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/enroll`, () => {
          return HttpResponse.error();
        })
      );

      try {
        await mfaClient.enroll({
          mfaToken: encryptedToken,
          authenticatorTypes: ["otp"]
        });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaEnrollmentError);
        expect((error as any).code).toBe("client_error");
      }
    });

    // Request format (1 test)
    it("should send POST with JSON body", async () => {
      const fetchSpy = vi.spyOn(global, "fetch");
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/enroll`, () => {
          return HttpResponse.json({
            authenticatorType: "otp",
            barcodeUri: "otpauth://...",
            secret: "SECRET"
          });
        })
      );

      await mfaClient.enroll({
        mfaToken: encryptedToken,
        authenticatorTypes: ["oob"],
        oobChannels: ["sms"],
        phoneNumber: "+15551234567"
      } as any);

      expect(fetchSpy).toHaveBeenCalledWith(
        expect.stringContaining("/auth/mfa/enroll"),
        expect.objectContaining({
          method: "POST",
          credentials: "omit",
          headers: expect.objectContaining({
            "Content-Type": "application/json"
          }),
          body: JSON.stringify({
            mfaToken: encryptedToken,
            authenticatorTypes: ["oob"],
            oobChannels: ["sms"],
            phoneNumber: "+15551234567"
          })
        })
      );
    });
  });

  describe("Credentials Policy", () => {
    it("stateless methods use credentials: omit, verify uses include", async () => {
      const fetchSpy = vi.spyOn(global, "fetch");
      const encryptedToken = await encryptMfaToken(
        DEFAULT.mfaToken,
        "",
        "openid profile",
        undefined,
        secret,
        300
      );

      // Test stateless: getAuthenticators
      server.use(
        http.get(`${DEFAULT.appBaseUrl}/auth/mfa/authenticators`, () => {
          return HttpResponse.json([]);
        })
      );
      await mfaClient.getAuthenticators({ mfaToken: encryptedToken });
      expect(fetchSpy).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ credentials: "omit" })
      );

      fetchSpy.mockClear();

      // Test stateful: verify (session caching)
      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/mfa/verify`, () => {
          return HttpResponse.json({
            access_token: "test",
            token_type: "Bearer",
            expires_in: 3600
          });
        })
      );
      await mfaClient.verify({ mfaToken: encryptedToken, otp: "123456" });
      expect(fetchSpy).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ credentials: "include" })
      );
    });
  });

  describe("getAuthenticators - query param validation", () => {
    it("should handle empty query param gracefully", async () => {
      const { MfaGetAuthenticatorsError } = await import(
        "../../errors/index.js"
      );

      // Server should reject empty mfa_token
      server.use(
        http.get(`${DEFAULT.appBaseUrl}/auth/mfa/authenticators`, () => {
          return HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Missing or invalid mfa_token"
            },
            { status: 400 }
          );
        })
      );

      try {
        await mfaClient.getAuthenticators({ mfaToken: "" });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaGetAuthenticatorsError);
      }
    });
  });
});
