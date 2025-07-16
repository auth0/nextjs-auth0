import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";

import { Auth0Client } from "./client.js";

/**
 * Regression tests for https://github.com/auth0/nextjs-auth0/issues/2219
 * – "Headers.append: <fn> is an invalid header value".
 */

describe("#2219 – createRequestCookies header copying", () => {
  /**
   * Factory that creates an Auth0Client instance with minimal (fake) config
   * sufficient for creating the class without throwing configuration errors.
   */
  function makeClient() {
    return new Auth0Client({
      domain: "example.auth0.com",
      clientId: "client_id",
      clientSecret: "client_secret",
      secret: "0123456789abcdef0123456789abcdef",
      appBaseUrl: "http://localhost:3000"
    });
  }

  /**
   * Creates a bare-bones object that satisfies the subset of `IncomingMessage`
   * the private `createRequestCookies()` helper expects: a `headers` record.
   */
  function makePagesRouterReq(headers: Record<string, any>): IncomingMessage {
    return { headers } as unknown as IncomingMessage;
  }

  it("ignores function properties on req.headers (no throw)", () => {
    const client: any = makeClient();

    const req = makePagesRouterReq({
      cookie: "foo=bar",
      foo: "bar",
      append: () => {} // bogus enumerable function property that caused the crash
    });

    expect(() => client.createRequestCookies(req)).not.toThrow();
  });

  it("copies string and string[] values correctly", () => {
    const client: any = makeClient();

    const req = makePagesRouterReq({
      cookie: "foo=bar",
      "set-cookie": ["a=1", "b=2"]
    });

    const cookies = client.createRequestCookies(req);

    // Should parse the cookie header
    const foo = cookies.get("foo");
    expect(foo?.value).toBe("bar");

    // Still exposes at least one cookie object
    expect(cookies.getAll().length).toBeGreaterThanOrEqual(1);
  });
});
