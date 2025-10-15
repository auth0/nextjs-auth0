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

import { getAccessToken } from "./get-access-token.js";

export const restHandlers = [
  http.get("/auth/access-token", ({ request }) => {
    const url = new URL(request.url);

    const audience = url.searchParams.get("audience");
    const scope = url.searchParams.get("scope");

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
});
