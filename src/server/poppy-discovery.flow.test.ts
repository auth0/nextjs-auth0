import { NextRequest } from "next/server.js";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import type { PoppyConfig } from "../types/poppy.js";
import { Auth0Client } from "./client.js";

const domain = "auth.fernway.com";
const clientId = "my-client-id";
const clientSecret = "my-client-secret";
const secret =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const appBaseUrl = "https://fernway.com";

const poppyConfig: PoppyConfig = {
  protocolVersion: "0.3",
  domain: "fernway.com",
  issuer: "https://auth.fernway.com/",
  browserSessionEndpoint:
    "https://auth.fernway.com/poppy/my-client-id/browser-session",
  scopes: { "orders:write": "Place orders" }
};

// No handlers: serving the discovery files must not call Auth0.
const server = setupServer();

function request(path: string, method = "GET") {
  return new NextRequest(new URL(path, appBaseUrl), { method });
}

function createClient(options: { poppy?: { config: PoppyConfig } } = {}) {
  return new Auth0Client({
    domain,
    clientId,
    clientSecret,
    secret,
    appBaseUrl,
    ...options
  });
}

describe("Poppy discovery files", () => {
  beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  describe("when poppy is configured", () => {
    const auth0 = createClient({ poppy: { config: poppyConfig } });

    it("serves /.well-known/poppy.json", async () => {
      const res = await auth0.middleware(request("/.well-known/poppy.json"));

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("application/json");
      expect(await res.json()).toEqual({
        protocol_version: "0.3",
        organization: { domain: "fernway.com" },
        auth: {
          issuer: "https://auth.fernway.com/",
          scopes: { "orders:write": "Place orders" }
        },
        web: {
          browser_session_endpoint:
            "https://auth.fernway.com/poppy/my-client-id/browser-session"
        }
      });
    });

    it("serves /.well-known/oauth-protected-resource", async () => {
      const res = await auth0.middleware(
        request("/.well-known/oauth-protected-resource")
      );

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        resource: "https://fernway.com",
        authorization_servers: ["https://auth.fernway.com/"]
      });
    });

    it("sets no cookies on the discovery responses", async () => {
      const res = await auth0.middleware(request("/.well-known/poppy.json"));

      expect(res.headers.getSetCookie()).toEqual([]);
    });

    it("does not serve the files for other methods", async () => {
      const res = await auth0.middleware(
        request("/.well-known/poppy.json", "POST")
      );

      // Falls through to the app, like any path the SDK doesn't handle.
      expect(res.headers.get("x-middleware-next")).toBe("1");
    });

    it("leaves other /.well-known paths to the app", async () => {
      const res = await auth0.middleware(request("/.well-known/security.txt"));

      expect(res.headers.get("x-middleware-next")).toBe("1");
    });
  });

  describe("when poppy is not configured", () => {
    const auth0 = createClient();

    it.each([
      "/.well-known/poppy.json",
      "/.well-known/oauth-protected-resource"
    ])(
      "falls through on %s, so the app can serve its own file",
      async (path) => {
        const res = await auth0.middleware(request(path));

        expect(res.headers.get("x-middleware-next")).toBe("1");
      }
    );
  });

  it("throws InvalidConfigurationError at construction for an invalid config", () => {
    let error: unknown;
    try {
      createClient({
        poppy: {
          config: { ...poppyConfig, issuer: "https://auth.fernway.com" }
        }
      });
    } catch (e) {
      error = e;
    }

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as InvalidConfigurationError).code).toBe(
      "invalid_configuration"
    );
  });
});
