import { describe, expect, it } from "vitest";

import { AuthClient } from "./auth-client.js";
import { Auth0Client } from "./client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const domain = "guabu.us.auth0.com";
const clientId = "my-client-id";
const clientSecret = "my-client-secret";
const secret =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

const defaultRoutes = {
  login: "/auth/login",
  logout: "/auth/logout",
  callback: "/auth/callback",
  profile: "/auth/profile",
  accessToken: "/auth/access-token",
  backChannelLogout: "/auth/backchannel-logout",
  connectAccount: "/auth/connect",
  mfaAuthenticators: "/auth/mfa/authenticators",
  mfaChallenge: "/auth/mfa/challenge",
  mfaVerify: "/auth/mfa/verify",
  mfaEnroll: "/auth/mfa/enroll"
};

describe("APP_BASE_URL Configuration", () => {
  describe("Auth0Client cookie security with dynamic mode", () => {
    it("should not set cookies to secure:true by default when appBaseUrl is undefined", () => {
      const client = new Auth0Client({
        domain,
        clientId,
        clientSecret,
        secret
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.secure).toBe(false);
    });

    it("should allow override of secure flag via session.cookie.secure option", () => {
      const client = new Auth0Client({
        domain,
        clientId,
        clientSecret,
        secret,
        session: {
          cookie: {
            secure: false
          }
        }
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.secure).toBe(false);
    });

    it("should set cookies to secure:true when static appBaseUrl uses HTTPS", () => {
      const client = new Auth0Client({
        domain,
        clientId,
        clientSecret,
        secret,
        appBaseUrl: "https://myapp.com"
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.secure).toBe(true);
    });

    it("should set cookies to secure:false when static appBaseUrl uses HTTP", () => {
      const client = new Auth0Client({
        domain,
        clientId,
        clientSecret,
        secret,
        appBaseUrl: "http://localhost:3000"
      });

      const sessionStore = (client as any).sessionStore;
      expect(sessionStore.cookieConfig.secure).not.toBe(true);
    });
  });

  describe("Array-based APP_BASE_URL configuration", () => {
    const transactionStore = new TransactionStore({
      secret,
      cookieOptions: {
        prefix: "__txn_",
        secure: false,
        sameSite: "lax",
        path: "/",
        maxAge: 3600
      }
    });

    const sessionStore = new StatelessSessionStore({
      secret,
      cookieOptions: {
        name: "__session",
        secure: false,
        sameSite: "lax",
        path: "/",
        transient: false
      }
    });

    it("should throw error if array is empty", () => {
      expect(() => {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain,
          clientId,
          clientSecret,
          secret,
          appBaseUrl: [],
          routes: defaultRoutes
        });
      }).toThrow(/APP_BASE_URL array configuration cannot be empty/);
    });

    it("should throw error if array contains invalid URLs", () => {
      expect(() => {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain,
          clientId,
          clientSecret,
          secret,
          appBaseUrl: ["https://valid.com", "not-a-url", "also-invalid"],
          routes: defaultRoutes
        });
      }).toThrow(/APP_BASE_URL array contains invalid URLs/);

      expect(() => {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain,
          clientId,
          clientSecret,
          secret,
          appBaseUrl: ["https://valid.com", "not-a-url"],
          routes: defaultRoutes
        });
      }).toThrow(/not-a-url/);
    });
  });
});
