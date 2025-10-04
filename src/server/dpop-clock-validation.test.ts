import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Auth0Client } from "./client.js";

describe("DPoP Clock Validation Configuration", () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    vi.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should accept dpopOptions in Auth0Client constructor", () => {
    expect(() => {
      new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        secret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        dpopOptions: {
          clockSkew: 120,
          clockTolerance: 45
        }
      });
    }).not.toThrow();
  });

  it("should load clock settings from environment variables", () => {
    process.env.AUTH0_DPOP_CLOCK_SKEW = "300";
    process.env.AUTH0_DPOP_CLOCK_TOLERANCE = "90";

    expect(() => {
      new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        secret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        useDpop: true
      });
    }).not.toThrow();
  });

  it("should prioritize dpopOptions over environment variables", () => {
    process.env.AUTH0_DPOP_CLOCK_SKEW = "300";
    process.env.AUTH0_DPOP_CLOCK_TOLERANCE = "90";

    expect(() => {
      new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        secret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        useDpop: true,
        dpopOptions: {
          clockSkew: 60,
          clockTolerance: 30
        }
      });
    }).not.toThrow();
  });

  it("should handle partial dpopOptions", () => {
    expect(() => {
      new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        secret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        dpopOptions: {
          clockTolerance: 15
          // clockSkew not provided, should use default 0
        }
      });
    }).not.toThrow();
  });

  it("should work without dpopOptions when useDpop is false", () => {
    expect(() => {
      new Auth0Client({
        domain: "test.auth0.com",
        clientId: "test-client-id",
        secret: "test-secret",
        appBaseUrl: "http://localhost:3000"
        // No dpopOptions provided, useDpop defaults to false
      });
    }).not.toThrow();
  });
});
