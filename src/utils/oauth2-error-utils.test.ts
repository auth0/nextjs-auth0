import { describe, expect, it } from "vitest";

import { getOAuth2ErrorDetails } from "./oauth2-error-utils.js";

describe("getOAuth2ErrorDetails", () => {
  // Test 1: Null input
  it("should return undefined for null input", async () => {
    const result = await getOAuth2ErrorDetails(null);
    expect(result).toEqual({ error: undefined, error_description: undefined });
  });

  // Test 2: Undefined input
  it("should return undefined for undefined input", async () => {
    const result = await getOAuth2ErrorDetails(undefined);
    expect(result).toEqual({ error: undefined, error_description: undefined });
  });

  // Test 3: Empty object
  it("should return undefined for empty object", async () => {
    const result = await getOAuth2ErrorDetails({});
    expect(result).toEqual({ error: undefined, error_description: undefined });
  });

  // Test 4: Direct error properties (4xx ResponseBodyError)
  it("should extract direct error properties (4xx)", async () => {
    const error = {
      error: "invalid_grant",
      error_description: "Invalid credentials"
    };
    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: "invalid_grant",
      error_description: "Invalid credentials"
    });
  });

  // Test 5: Direct error only, no description (4xx)
  it("should extract direct error with no description (4xx)", async () => {
    const error = {
      error: "access_denied"
    };
    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: "access_denied",
      error_description: undefined
    });
  });

  // Test 6: Priority: Direct error over Response cause
  it("should extract direct error even with unused cause", async () => {
    // Create a mock Response
    const mockResponse = new Response(
      JSON.stringify({
        error: "wrong_error",
        error_description: "Wrong description"
      })
    );

    const error = {
      error: "invalid_scope",
      error_description: "Scope invalid",
      cause: mockResponse
    };

    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: "invalid_scope",
      error_description: "Scope invalid"
    });
    // Verify Response was not consumed (no Response.json() called)
    expect(mockResponse.bodyUsed).toBe(false);
  });

  // Test 7: Extract from 5xx Response cause (Valid JSON)
  it("should extract from Response cause (5xx with valid JSON)", async () => {
    const mockResponse = new Response(
      JSON.stringify({
        error: "access_denied",
        error_description: "Denied by Action"
      })
    );

    const error = {
      cause: mockResponse
    };

    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: "access_denied",
      error_description: "Denied by Action"
    });
  });

  // Test 8: 5xx Response with only error field
  it("should extract from Response cause with only error field", async () => {
    const mockResponse = new Response(
      JSON.stringify({
        error: "server_error"
      })
    );

    const error = {
      cause: mockResponse
    };

    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: "server_error",
      error_description: undefined
    });
  });

  // Test 9: 5xx Response with empty JSON
  it("should return undefined for Response with empty JSON", async () => {
    const mockResponse = new Response(JSON.stringify({}));

    const error = {
      cause: mockResponse
    };

    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: undefined,
      error_description: undefined
    });
  });

  // Test 10: 5xx Response with invalid JSON
  it("should return undefined for Response with invalid JSON", async () => {
    const mockResponse = new Response("not valid json");

    const error = {
      cause: mockResponse
    };

    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: undefined,
      error_description: undefined
    });
  });

  // Test 11: 5xx Response with empty body
  it("should return undefined for Response with empty body", async () => {
    const mockResponse = new Response("");

    const error = {
      cause: mockResponse
    };

    const result = await getOAuth2ErrorDetails(error);
    expect(result).toEqual({
      error: undefined,
      error_description: undefined
    });
  });

  // Test 12: Response.clone() safety (Multiple reads)
  it("should handle Response.clone() safety", async () => {
    const mockResponse = new Response(
      JSON.stringify({
        error: "access_denied",
        error_description: "Denied by Action"
      })
    );

    const error = {
      cause: mockResponse
    };

    // First call
    const result1 = await getOAuth2ErrorDetails(error);
    expect(result1).toEqual({
      error: "access_denied",
      error_description: "Denied by Action"
    });

    // Second call should not fail (clone prevents body already consumed)
    const result2 = await getOAuth2ErrorDetails(error);
    expect(result2).toEqual({
      error: "access_denied",
      error_description: "Denied by Action"
    });
  });

  // Test 13: Response not mutated by extraction
  it("should not mutate original Response", async () => {
    const mockResponse = new Response(
      JSON.stringify({
        error: "access_denied",
        error_description: "Denied by Action"
      })
    );

    const error = {
      cause: mockResponse
    };

    await getOAuth2ErrorDetails(error);

    // Original Response should not be consumed (clone was used)
    expect(mockResponse.bodyUsed).toBe(false);
  });
});
