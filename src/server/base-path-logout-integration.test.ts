import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Auth0Client } from "./client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";

describe("Base path logout integration tests", () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should reproduce the bug scenario: cookies set with base path should be deleted with same path", async () => {
    // Set up environment with base path
    process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

    // Create Auth0Client which should auto-detect the base path
    const client = new Auth0Client({
      domain: "test.auth0.com",
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      appBaseUrl: "https://app.example.com/dashboard",
      secret: "test-secret-that-is-long-enough-for-jwt"
    });

    // Get the session store
    const sessionStore = (client as any).sessionStore as StatelessSessionStore;

    // Verify that the session store has the correct path configuration
    expect((sessionStore as any).cookieConfig.path).toBe("/dashboard");

    // Simulate cookie deletion during logout
    const mockResCookies = new ResponseCookies(new Headers());
    const mockReqCookies = new RequestCookies(new Headers()) as any;

    // Mock the get method to simulate an existing session cookie
    mockReqCookies.get = () => ({ value: "mock-session-value" });
    mockReqCookies.getAll = () => [];

    // Call delete method (this would be called during logout)
    await sessionStore.delete(mockReqCookies, mockResCookies);

    // Verify that the cookie deletion header includes the correct path
    const cookieHeader = mockResCookies.toString();

    // The cookie should be deleted with the same path it was set with
    expect(cookieHeader).toContain("Path=/dashboard");
    expect(cookieHeader).toContain("Max-Age=0");
  });

  it("should work correctly without base path (backward compatibility)", async () => {
    // No base path set
    delete process.env.NEXT_PUBLIC_BASE_PATH;

    const client = new Auth0Client({
      domain: "test.auth0.com",
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      appBaseUrl: "https://app.example.com",
      secret: "test-secret-that-is-long-enough-for-jwt"
    });

    const sessionStore = (client as any).sessionStore as StatelessSessionStore;

    // Should default to root path
    expect((sessionStore as any).cookieConfig.path).toBe("/");

    // Test deletion
    const mockResCookies = new ResponseCookies(new Headers());
    const mockReqCookies = new RequestCookies(new Headers()) as any;

    mockReqCookies.get = () => ({ value: "mock-session-value" });
    mockReqCookies.getAll = () => [];

    await sessionStore.delete(mockReqCookies, mockResCookies);

    const cookieHeader = mockResCookies.toString();

    // Should use root path or no path specified
    expect(cookieHeader).toContain("Max-Age=0");
  });

  it("should prioritize explicit cookie path over base path", async () => {
    process.env.NEXT_PUBLIC_BASE_PATH = "/dashboard";

    const client = new Auth0Client({
      domain: "test.auth0.com",
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      appBaseUrl: "https://app.example.com",
      secret: "test-secret-that-is-long-enough-for-jwt",
      session: {
        cookie: {
          path: "/custom-path"
        }
      }
    });

    const sessionStore = (client as any).sessionStore as StatelessSessionStore;

    // Should use the explicit path, not the base path
    expect((sessionStore as any).cookieConfig.path).toBe("/custom-path");
  });
});
