import { describe, it, expect } from "vitest";
import { extractOAuthErrorDetails } from "./oauth-error-utils.js";

describe("extractOAuthErrorDetails", () => {
  it("returns empty object for null/undefined", async () => {
    expect(await extractOAuthErrorDetails(null)).toEqual({});
    expect(await extractOAuthErrorDetails(undefined)).toEqual({});
  });

  it("extracts error/error_description from ResponseBodyError (4xx)", async () => {
    const err = {
      error: "invalid_grant",
      error_description: "Invalid authorization code"
    };
    const result = await extractOAuthErrorDetails(err);
    expect(result).toEqual({
      error: "invalid_grant",
      error_description: "Invalid authorization code"
    });
  });

  it("extracts error details from OperationProcessingError with Response cause (5xx)", async () => {
    const responseBody = JSON.stringify({
      error: "access_denied",
      error_description: "Denied by Auth0 Action"
    });
    const response = new Response(responseBody, {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
    const err = { cause: response, message: "Response body error" };

    const result = await extractOAuthErrorDetails(err);
    expect(result).toEqual({
      error: "access_denied",
      error_description: "Denied by Auth0 Action"
    });
  });

  it("allows reading Response body multiple times (clones)", async () => {
    const responseBody = JSON.stringify({
      error: "server_error",
      error_description: "Something went wrong"
    });
    const response = new Response(responseBody, { status: 500 });
    const err = { cause: response };

    const result1 = await extractOAuthErrorDetails(err);
    const result2 = await extractOAuthErrorDetails(err);
    expect(result1).toEqual(result2);
    expect(result1.error).toBe("server_error");
  });

  it("returns empty object when Response body is not JSON", async () => {
    const response = new Response("Internal Server Error", { status: 500 });
    const err = { cause: response };

    const result = await extractOAuthErrorDetails(err);
    expect(result).toEqual({});
  });

  it("returns empty object when Response body JSON has no error fields", async () => {
    const response = new Response(JSON.stringify({ foo: "bar" }), { status: 500 });
    const err = { cause: response };

    const result = await extractOAuthErrorDetails(err);
    expect(result).toEqual({ error: undefined, error_description: undefined });
  });

  it("prefers direct error property over Response cause", async () => {
    // If error already has .error (ResponseBodyError), use it directly
    const response = new Response(
      JSON.stringify({ error: "from_response", error_description: "from response" }),
      { status: 500 }
    );
    const err = {
      error: "from_error_object",
      error_description: "from error object",
      cause: response
    };

    const result = await extractOAuthErrorDetails(err);
    expect(result.error).toBe("from_error_object");
    expect(result.error_description).toBe("from error object");
  });
});
