/**
 * @vitest-environment jsdom
 */

import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { AccessTokenError, MfaRequiredError } from "../../errors/index.js";
import { getAccessToken } from "./get-access-token.js";

export const restHandlers = [
  http.get("/auth/access-token", ({ request }) => {
    const url = new URL(request.url);

    const audience = url.searchParams.get("audience");
    const scope = url.searchParams.get("scope");

    // This guard is there to ensure `includeFullResponse` doesn’t leak into the URL query string.
    if (url.searchParams.has("includeFullResponse")) {
      return HttpResponse.json(
        {
          error: {
            code: "invalid_request",
            message: "Unexpected includeFullResponse query param."
          }
        },
        { status: 400 }
      );
    }

    let token = "<access_token>";

    if (audience && scope) {
      token = `<access_token_for_${audience}_with_scope_${scope}>`;
    } else if (audience) {
      token = `<access_token_for_${audience}_without_scope>`;
    } else if (scope) {
      token = `<access_token_with_scope_${scope}>`;
    }

    if (audience === "trigger_json_error") {
      // Simulate a scenario where the response is not valid JSON
      return HttpResponse.text("Invalid JSON", { status: 400 });
    }

    if (audience === "trigger_not_ok_error") {
      // Simulate a scenario where the response is a valid error JSON
      return HttpResponse.json(
        {
          error: {
            code: "invalid_request",
            message: "The request is missing a required parameter."
          }
        },
        { status: 400 }
      );
    }

    if (audience === "with_full_response") {
      return HttpResponse.json({
        token,
        scope: "read:profile",
        expires_at: 123,
        expires_in: 60,
        token_type: "bearer"
      });
    }

    return HttpResponse.json({ token });
  })
];

const server = setupServer(...restHandlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

// Close server after all tests
afterAll(() => server.close());

// Reset handlers after each test for test isolation
afterEach(() => server.resetHandlers());

describe("getAccessToken", () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it("should work", async () => {
    const result = await getAccessToken();

    expect(result).toBe("<access_token>");
  });

  it("should pass audience and scope", async () => {
    const result = await getAccessToken({
      audience: "test_audience",
      scope: "read:bar"
    });

    expect(result).toBe("<access_token_for_test_audience_with_scope_read:bar>");
  });

  it("should pass only audience", async () => {
    const result = await getAccessToken({
      audience: "test_audience"
    });

    expect(result).toBe("<access_token_for_test_audience_without_scope>");
  });

  it("should pass only scope", async () => {
    const result = await getAccessToken({
      scope: "read:bar"
    });

    expect(result).toBe("<access_token_with_scope_read:bar>");
  });

  it("should return the full response when includeFullResponse is true", async () => {
    const result = await getAccessToken({
      audience: "with_full_response",
      includeFullResponse: true
    });

    expect(result).toEqual({
      token: "<access_token_for_with_full_response_without_scope>",
      scope: "read:profile",
      expires_at: 123,
      expires_in: 60,
      token_type: "bearer"
    });
  });

  it("should still return token only when includeFullResponse is false", async () => {
    const result = await getAccessToken({
      audience: "with_full_response",
      includeFullResponse: false
    });

    expect(result).toBe("<access_token_for_with_full_response_without_scope>");
  });

  it("should throw an error when json deserialization fails", async () => {
    await expect(() =>
      getAccessToken({
        audience: "trigger_json_error"
      })
    ).rejects.toThrowError(
      "An unexpected error occurred while trying to fetch the access token."
    );
  });

  it("should throw an error when response is not ok", async () => {
    await expect(() =>
      getAccessToken({
        audience: "trigger_not_ok_error"
      })
    ).rejects.toThrowError("The request is missing a required parameter.");
  });

  describe("mergeScopes", () => {
    it("should append mergeScopes=false to URL when mergeScopes is false", async () => {
      let capturedUrl: URL | undefined;
      server.use(
        http.get("/auth/access-token", ({ request }) => {
          capturedUrl = new URL(request.url);
          return HttpResponse.json({
            token: "<token>",
            scope: "read:data"
          });
        })
      );

      await getAccessToken({
        audience: "test_audience",
        scope: "read:data",
        mergeScopes: false
      });

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl!.searchParams.get("mergeScopes")).toBe("false");
    });

    it("should NOT append mergeScopes when mergeScopes is true", async () => {
      let capturedUrl: URL | undefined;
      server.use(
        http.get("/auth/access-token", ({ request }) => {
          capturedUrl = new URL(request.url);
          return HttpResponse.json({ token: "<token>" });
        })
      );

      await getAccessToken({
        audience: "test_audience",
        mergeScopes: true
      });

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl!.searchParams.has("mergeScopes")).toBe(false);
    });

    it("should NOT append mergeScopes when mergeScopes is undefined", async () => {
      let capturedUrl: URL | undefined;
      server.use(
        http.get("/auth/access-token", ({ request }) => {
          capturedUrl = new URL(request.url);
          return HttpResponse.json({ token: "<token>" });
        })
      );

      await getAccessToken({ audience: "test_audience" });

      expect(capturedUrl).toBeDefined();
      expect(capturedUrl!.searchParams.has("mergeScopes")).toBe(false);
    });
  });

  describe("MfaRequiredError reconstruction", () => {
    it("should throw MfaRequiredError for 403 mfa_required response", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Multifactor authentication required",
              mfa_token: "encrypted_mfa_token_value",
              mfa_requirements: { challenge: [{ type: "otp" }] }
            },
            { status: 403 }
          );
        })
      );

      try {
        await getAccessToken({ audience: "mfa_audience" });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaRequiredError);
        const mfaError = error as MfaRequiredError;
        expect(mfaError.message).toBe("Multifactor authentication required");
        expect(mfaError.mfa_token).toBe("encrypted_mfa_token_value");
        expect(mfaError.mfa_requirements).toEqual({
          challenge: [{ type: "otp" }]
        });
      }
    });

    it("should NOT throw MfaRequiredError for 403 without mfa_required error code", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(
            {
              error: { code: "forbidden", message: "Access forbidden" }
            },
            { status: 403 }
          );
        })
      );

      try {
        await getAccessToken({ audience: "forbidden_audience" });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(AccessTokenError);
        expect(error).not.toBeInstanceOf(MfaRequiredError);
      }
    });

    it("should use default message when error_description is missing", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(
            {
              error: "mfa_required",
              mfa_token: "token123"
            },
            { status: 403 }
          );
        })
      );

      try {
        await getAccessToken({ audience: "mfa_audience" });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(MfaRequiredError);
        const mfaError = error as MfaRequiredError;
        expect(mfaError.message).toBe(
          "Multi-factor authentication is required."
        );
      }
    });
  });
});
