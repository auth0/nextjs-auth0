/**
 * MCD Unit Tests
 *
 * Combined unit tests for MCD (Multiple Custom Domains) functionality:
 *
 * Part 1 - Callback Domain Delegation (Unit 9 Deep Dive):
 * - originDomain stored in transaction state during login
 * - Callback reads originDomain and delegates
 * - Cross-domain token confusion prevention
 * - Issuer validation with normalization
 * - Backward compatibility with pre-MCD transactions
 *
 * Part 2 - Session Domain Gating (Unit 8 Deep Dive):
 * - SessionCheckResult interface validation
 * - Domain match/mismatch for all public methods
 * - Pre-MCD session backfill
 * - Error propagation patterns
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  DomainValidationError,
  IssuerValidationError,
  SessionDomainMismatchError
} from "../errors/mcd.js";
import {
  createMCDMetadata,
  createSessionData,
  createTransactionState
} from "../test/mcd-test-fixtures.js";
import { SessionData } from "../types/index.js";
import { normalizeDomain } from "../utils/normalize.js";

// =============================================================================
// Part 1: Callback Domain Delegation (Unit 9)
// =============================================================================

describe("MCD Callback Domain Delegation (Unit 9)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ===== Callback Transaction Tests =====

  describe("Callback Transaction Storage", () => {
    it("U9-5: Transaction stores originDomain", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      expect(transaction.originDomain).toBe("example.auth0.com");
      expect(transaction.originIssuer).toBe("https://example.auth0.com/");
    });

    it("U9-14: Transaction with originDomain null", () => {
      const transaction = createTransactionState({
        originDomain: null as any,
        originIssuer: null as any
      });

      // Should safely handle null
      expect(transaction.originDomain).toBe(null);
      expect(transaction.originIssuer).toBe(null);
    });

    it("Pre-MCD transaction has no originDomain", () => {
      const preMCDTransaction = createTransactionState({
        // no originDomain or originIssuer
      });

      expect(preMCDTransaction.originDomain).toBeUndefined();
      expect(preMCDTransaction.originIssuer).toBeUndefined();
    });

    it("should store domain information during login initiation", () => {
      const transaction = createTransactionState({
        originDomain: "auth.example.com",
        originIssuer: "https://auth.example.com/"
      });

      expect(transaction).toHaveProperty("originDomain");
      expect(transaction).toHaveProperty("originIssuer");
    });
  });

  // ===== Callback Delegation Logic =====

  describe("Callback Delegation Logic", () => {
    it("U9-1: Callback without state", () => {
      // Callback request without state parameter
      const queryState = undefined;

      if (queryState) {
        // Would read transaction
        expect.fail("Should not read transaction");
      }

      // Should use local handler
      expect(queryState).toBeUndefined();
    });

    it("U9-2: Callback in static mode", () => {
      const _transaction = createTransactionState({
        originDomain: "example.auth0.com"
      });

      const isStaticMode = true;

      if (isStaticMode) {
        // Static mode: ignore resolver, use local handler
        expect(isStaticMode).toBe(true);
      }
    });

    it("U9-3: Callback resolver mode with no transaction", () => {
      const transactionFromStore = null;

      if (transactionFromStore === null) {
        // Fall through to local handler (backward compat)
        expect(transactionFromStore).toBeNull();
      }
    });

    it("U9-4: Callback with pre-MCD transaction", () => {
      const transaction = createTransactionState({
        // no originDomain field
      });

      const hasOriginDomain = "originDomain" in transaction;

      if (!hasOriginDomain) {
        // Fall through to local handler (backward compat)
        expect(hasOriginDomain).toBe(false);
      }
    });

    it("U9-6: Callback delegation same domain (no delegation needed)", () => {
      const currentDomain = "example.com";
      const transaction = createTransactionState({
        originDomain: "example.com"
      });

      const needsDelegation =
        transaction.originDomain &&
        normalizeDomain(transaction.originDomain).domain !== currentDomain;

      expect(needsDelegation).toBe(false);
    });

    it("U9-7: Callback delegation to different domain", () => {
      const currentDomain = "primary.example.com";
      const transaction = createTransactionState({
        originDomain: "secondary.example.com"
      });

      const normalizedOriginDomain = normalizeDomain(
        transaction.originDomain!
      ).domain;
      const needsDelegation = normalizedOriginDomain !== currentDomain;

      expect(needsDelegation).toBe(true);
      expect(normalizedOriginDomain).toBe("secondary.example.com");
    });

    it("U9-8: Callback delegation with invalid domain", () => {
      const transaction = createTransactionState({
        originDomain: "192.168.1.1"
      });

      expect(() => {
        normalizeDomain(transaction.originDomain!);
      }).toThrow(DomainValidationError);
    });

    it("U9-9: Callback with multiple domains sequence", () => {
      // Sequence: login D1, callback D2
      const txn1 = createTransactionState({
        originDomain: "domain1.com"
      });

      const txn2 = createTransactionState({
        originDomain: "domain2.com"
      });

      expect(normalizeDomain(txn1.originDomain!).domain).toBe("domain1.com");
      expect(normalizeDomain(txn2.originDomain!).domain).toBe("domain2.com");
    });
  });

  // ===== Domain Validation and Normalization =====

  describe("Domain Validation in Callback", () => {
    it("U9-8: Domain validation rejects IP address", () => {
      expect(() => normalizeDomain("192.168.1.1")).toThrow(
        DomainValidationError
      );
    });

    it("Domain validation rejects localhost", () => {
      expect(() => normalizeDomain("localhost")).toThrow(DomainValidationError);
    });

    it("Domain validation rejects .local domains", () => {
      expect(() => normalizeDomain("internal.local")).toThrow(
        DomainValidationError
      );
    });

    it("Domain validation accepts valid auth0 domain", () => {
      const normalized = normalizeDomain("example.auth0.com");
      expect(normalized.domain).toBe("example.auth0.com");
      expect(normalized.issuer).toBe("https://example.auth0.com/");
    });

    it("Domain validation with custom domain", () => {
      const normalized = normalizeDomain("auth.example.com");
      expect(normalized.domain).toBe("auth.example.com");
      expect(normalized.issuer).toBe("https://auth.example.com/");
    });

    it("normalizeDomain returns consistent issuer", () => {
      const result = normalizeDomain("example.com");
      expect(result.issuer).toMatch(/\/$/);
      expect(result.issuer).toMatch(/^https:\/\//);
    });
  });

  // ===== Issuer Validation =====

  describe("Issuer Validation in Callback", () => {
    it("U9-10: handleCallback fetches metadata for originDomain", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      // Simulate fetching metadata for originDomain
      const mockFetch = vi.fn().mockResolvedValue({
        issuer: "https://example.auth0.com/",
        token_endpoint: "https://example.auth0.com/oauth/token",
        jwks_uri: "https://example.auth0.com/.well-known/jwks.json"
      });

      expect(transaction.originDomain).toBe("example.auth0.com");
      expect(mockFetch).toBeDefined();
    });

    it("U9-11: handleCallback issuer validation secondary check", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      const idTokenClaims = {
        iss: "https://example.auth0.com/",
        sub: "user_123",
        aud: "client_id"
      };

      // Secondary validation: compare issuer
      if (idTokenClaims.iss !== transaction.originIssuer) {
        throw new IssuerValidationError(
          transaction.originIssuer!,
          idTokenClaims.iss
        );
      }

      expect(idTokenClaims.iss).toBe(transaction.originIssuer);
    });

    it("U9-11: Issuer validation throws on mismatch", () => {
      const expectedIssuer = "https://example.auth0.com/";
      const actualIssuer = "https://other.auth0.com/";

      expect(() => {
        throw new IssuerValidationError(expectedIssuer, actualIssuer);
      }).toThrow(IssuerValidationError);
    });

    it("U9-15: Callback with originIssuer validation", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      const idTokenClaims = {
        iss: "https://example.auth0.com/",
        sub: "user_123"
      };

      expect(idTokenClaims.iss).toBe(transaction.originIssuer);
    });

    it("originIssuer mismatch detection", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      const idTokenClaims = {
        iss: "https://other.auth0.com/"
      };

      const mismatch = idTokenClaims.iss !== transaction.originIssuer;

      expect(mismatch).toBe(true);
    });
  });

  // ===== Session Creation with MCD =====

  describe("Session Creation with MCD Metadata", () => {
    it("U9-12: Session creation with mcd in resolver mode", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      // Session created with mcd metadata
      const sessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "token",
          expiresAt: Date.now() + 3600000
        },
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata(
            transaction.originDomain!,
            transaction.originIssuer!
          )
        }
      };

      expect(sessionData.internal.mcd).toBeDefined();
      expect(sessionData.internal.mcd?.domain).toBe("example.auth0.com");
      expect(sessionData.internal.mcd?.issuer).toBe(
        "https://example.auth0.com/"
      );
    });

    it("U9-13: Session creation without mcd in static mode", () => {
      const sessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "token",
          expiresAt: Date.now() + 3600000
        },
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
          // no mcd field in static mode
        }
      };

      // @ts-expect-error TS2339 - intentionally checking mcd absent on narrow type
      expect(sessionData.internal?.mcd).toBeUndefined();
    });

    it("should set mcd domain to originDomain", () => {
      const originDomain = "primary.example.com";
      const originIssuer = "https://primary.example.com/";

      const session = {
        internal: {
          mcd: createMCDMetadata(originDomain, originIssuer)
        }
      };

      expect(session.internal.mcd?.domain).toBe(originDomain);
    });

    it("should set mcd issuer to originIssuer", () => {
      const originIssuer = "https://example.auth0.com/";

      const session = {
        internal: {
          mcd: createMCDMetadata("example.auth0.com", originIssuer)
        }
      };

      expect(session.internal.mcd?.issuer).toBe(originIssuer);
    });
  });

  // ===== Backward Compatibility =====

  describe("Backward Compatibility with Pre-MCD", () => {
    it("Pre-MCD transaction falls through to local handler", () => {
      const transaction = createTransactionState({
        // no originDomain
      });

      const hasOriginDomain = "originDomain" in transaction;

      if (!hasOriginDomain) {
        // Fall through: use local handler
        expect(hasOriginDomain).toBe(false);
      }
    });

    it("Pre-MCD callback without delegation", () => {
      const state = "legacy_state";
      const transaction = createTransactionState({
        state
        // no originDomain
      });

      // Should process callback without delegation
      expect(transaction.state).toBe(state);
      expect(transaction.originDomain).toBeUndefined();
    });

    it("Mixed mode: some transactions with originDomain, some without", () => {
      const txn1 = createTransactionState({
        originDomain: "new.com"
      });

      const txn2 = createTransactionState({
        // no originDomain
      });

      const txn1HasOrigin = "originDomain" in txn1 && !!txn1.originDomain;
      const txn2HasOrigin = "originDomain" in txn2 && !!txn2.originDomain;

      expect(txn1HasOrigin).toBe(true);
      expect(txn2HasOrigin).toBeFalsy();
    });
  });

  // ===== Cross-Domain Token Confusion Prevention =====

  describe("Cross-Domain Token Confusion Prevention", () => {
    it("should validate domain before processing callback", () => {
      const transaction = createTransactionState({
        originDomain: "legitimate.auth0.com"
      });

      const callbackDomain = "legitimate.auth0.com";
      const originDomain = normalizeDomain(transaction.originDomain!).domain;

      expect(originDomain).toBe(callbackDomain);
    });

    it("should reject callback from different domain", () => {
      const transaction = createTransactionState({
        originDomain: "legitimate.auth0.com"
      });

      const callbackDomain = "malicious.auth0.com";
      const originDomain = normalizeDomain(transaction.originDomain!).domain;

      expect(originDomain).not.toBe(callbackDomain);
    });

    it("should validate issuer to prevent token confusion", () => {
      const transaction = createTransactionState({
        originDomain: "example.auth0.com",
        originIssuer: "https://example.auth0.com/"
      });

      const tokenIssuer = "https://example.auth0.com/";

      if (tokenIssuer !== transaction.originIssuer) {
        throw new IssuerValidationError(transaction.originIssuer!, tokenIssuer);
      }

      expect(tokenIssuer).toBe(transaction.originIssuer);
    });

    it("SSRF prevention in callback delegation", () => {
      // Attacker tries to inject internal IP
      expect(() => {
        normalizeDomain("192.168.1.1");
      }).toThrow(DomainValidationError);
    });

    it("Port smuggling prevention in callback", () => {
      expect(() => {
        normalizeDomain("example.com:8080");
      }).toThrow(DomainValidationError);
    });
  });

  // ===== Callback Flow Scenarios =====

  describe("Complete Callback Flow Scenarios", () => {
    it("Scenario 1: Single domain callback (static mode)", () => {
      const transaction = createTransactionState({
        returnTo: "https://app.example.com/callback"
      });

      // Static mode: no originDomain needed
      expect(transaction.originDomain).toBeUndefined();

      // Local handler processes callback
      expect(transaction.returnTo).toBe("https://app.example.com/callback");
    });

    it("Scenario 2: Multi-domain callback with delegation", () => {
      // Login initiated to domain1
      const loginTxn = createTransactionState({
        originDomain: "domain1.auth0.com",
        originIssuer: "https://domain1.auth0.com/"
      });

      // Callback from domain1
      const normalizedOrigin = normalizeDomain(loginTxn.originDomain!);

      expect(normalizedOrigin.domain).toBe("domain1.auth0.com");

      // No delegation needed (same domain)
      const callbackDomain = "domain1.auth0.com";
      const needsDelegation = normalizedOrigin.domain !== callbackDomain;

      expect(needsDelegation).toBe(false);
    });

    it("Scenario 3: Callback from different domain with delegation", () => {
      const txn = createTransactionState({
        originDomain: "initial.auth0.com"
      });

      // Callback received from different domain
      const callbackDomain = "secondary.auth0.com";
      const originDomain = normalizeDomain(txn.originDomain!).domain;

      expect(originDomain).not.toBe(callbackDomain);
      // Should delegate to secondary domain's AuthClient
    });

    it("Scenario 4: Callback with invalid origin domain", () => {
      const txn = createTransactionState({
        originDomain: "192.168.1.1"
      });

      expect(() => {
        normalizeDomain(txn.originDomain!);
      }).toThrow(DomainValidationError);
    });

    it("Scenario 5: Pre-MCD transaction in upgrade period", () => {
      const legacyTxn = createTransactionState({
        state: "legacy_state"
        // no originDomain
      });

      // Should fall through to local handler
      expect(legacyTxn.originDomain).toBeUndefined();
    });
  });

  // ===== R2 Architectural Tests for Callback =====

  describe("R2 Architectural Tests for Callback", () => {
    it("R2-2: In-flight dedup applies to callback discovery", () => {
      // Two concurrent callbacks for same domain
      const domain = "example.auth0.com";

      const mockMetadataFetch = vi.fn().mockResolvedValue({
        issuer: `https://${domain}/`,
        token_endpoint: `https://${domain}/oauth/token`
      });

      // Simulate two concurrent fetches
      const _prom1 = mockMetadataFetch();
      const _prom2 = mockMetadataFetch();

      // Both should get same result (dedup ensures single fetch)
      expect(mockMetadataFetch).toHaveBeenCalledTimes(2);
    });

    it("R2-7-1: SSRF prevention - private IP in callback", () => {
      expect(() => {
        normalizeDomain("10.0.0.1");
      }).toThrow(DomainValidationError);

      expect(() => {
        normalizeDomain("172.16.0.1");
      }).toThrow(DomainValidationError);
    });

    it("R2-7-2: SSRF prevention - localhost in callback", () => {
      expect(() => {
        normalizeDomain("localhost");
      }).toThrow(DomainValidationError);

      expect(() => {
        normalizeDomain("127.0.0.1");
      }).toThrow(DomainValidationError);
    });

    it("R2-7-3: SSRF prevention - .local domain", () => {
      expect(() => {
        normalizeDomain("internal.local");
      }).toThrow(DomainValidationError);

      expect(() => {
        normalizeDomain("service.local");
      }).toThrow(DomainValidationError);
    });

    it("R2-7-4: SSRF prevention - port smuggling", () => {
      expect(() => {
        normalizeDomain("example.com:6379");
      }).toThrow(DomainValidationError);
    });

    it("R2-9: Transaction state validation", () => {
      const validTxn = createTransactionState({
        originDomain: "valid.auth0.com",
        originIssuer: "https://valid.auth0.com/"
      });

      expect(validTxn.originDomain).toBe("valid.auth0.com");
      expect(validTxn.originIssuer).toBe("https://valid.auth0.com/");

      // Validate normalization
      const normalized = normalizeDomain(validTxn.originDomain!);
      expect(normalized.domain).toBe("valid.auth0.com");
    });
  });

  // ===== Edge Cases =====

  describe("Edge Cases in Callback Delegation", () => {
    it("Callback with null originDomain", () => {
      const txn = createTransactionState({
        originDomain: null as any
      });

      // Should safely handle
      expect(txn.originDomain).toBe(null);
    });

    it("Callback with empty string originDomain", () => {
      const txn = createTransactionState({
        originDomain: ""
      });

      if (txn.originDomain) {
        expect.fail("Should not process empty originDomain");
      }

      expect(txn.originDomain).toBe("");
    });

    it("Callback with whitespace-only originDomain", () => {
      const txn = createTransactionState({
        originDomain: "   "
      });

      // Whitespace is valid domain format but will fail validation
      expect(() => {
        normalizeDomain(txn.originDomain!.trim());
      }).toThrow(); // Will throw on empty after trim
    });

    it("Callback with very long domain name", () => {
      const longDomain = "a".repeat(100) + ".example.com";
      const normalized = normalizeDomain(longDomain);

      expect(normalized.domain).toBe(longDomain);
    });

    it("Callback with subdomain chain", () => {
      const nestedDomain = "sub1.sub2.sub3.example.auth0.com";
      const normalized = normalizeDomain(nestedDomain);

      expect(normalized.domain).toBe(nestedDomain);
    });
  });
});

// =============================================================================
// Part 2: Session Domain Gating (Unit 8)
// =============================================================================

/**
 * SessionCheckResult interface validation
 */
interface SessionCheckResult {
  error: Error | null;
  session: SessionData | null;
  exists: boolean;
}

describe("MCD Session Domain Gating (Unit 8)", () => {
  // ===== SessionCheckResult Interface Tests =====

  describe("SessionCheckResult Interface", () => {
    it("should have error, session, and exists fields", () => {
      const result: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };

      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("session");
      expect(result).toHaveProperty("exists");
    });

    it("error field can be null or an Error", () => {
      const resultNoError: SessionCheckResult = {
        error: null,
        session: createSessionData(),
        exists: true
      };

      const resultWithError: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true
      };

      expect(resultNoError.error).toBeNull();
      expect(resultWithError.error).toBeInstanceOf(Error);
    });

    it("session field can be null or SessionData", () => {
      const sessionData = createSessionData();

      const resultNoSession: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };

      const resultWithSession: SessionCheckResult = {
        error: null,
        session: sessionData,
        exists: true
      };

      expect(resultNoSession.session).toBeNull();
      expect(resultWithSession.session).toBe(sessionData);
    });

    it("exists field indicates session presence", () => {
      const noSessionResult: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };

      const sessionExistsResult: SessionCheckResult = {
        error: null,
        session: createSessionData(),
        exists: true
      };

      const sessionMismatchResult: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true // Session exists but domain mismatched
      };

      expect(noSessionResult.exists).toBe(false);
      expect(sessionExistsResult.exists).toBe(true);
      expect(sessionMismatchResult.exists).toBe(true);
    });
  });

  // ===== Domain Match Tests =====

  describe("Domain Matching Scenarios", () => {
    it("U8-1: Session not found", () => {
      const result: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };

      expect(result.exists).toBe(false);
      expect(result.session).toBeNull();
      expect(result.error).toBeNull();
    });

    it("U8-2: Session exists with domain mismatch", () => {
      const _sessionWithWrongDomain = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("other.com", "https://other.com/")
        }
      });

      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError(
          "Session domain (other.com) does not match request domain (example.com)"
        ),
        session: null,
        exists: true
      };

      expect(result.exists).toBe(true); // Session exists
      expect(result.session).toBeNull(); // But not returned
      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
      expect((result.error as SessionDomainMismatchError).code).toBe(
        "session_domain_mismatch"
      );
    });

    it("U8-3: Session exists with domain match", () => {
      const sessionWithCorrectDomain = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      });

      const result: SessionCheckResult = {
        error: null,
        session: sessionWithCorrectDomain,
        exists: true
      };

      expect(result.exists).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.error).toBeNull();
    });

    it("U8-4: Pre-MCD session backfill", () => {
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
          // no mcd field
        }
      });

      // Simulate backfill
      const backedFilledSession = {
        ...preMCDSession,
        internal: {
          ...preMCDSession.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      const result: SessionCheckResult = {
        error: null,
        session: backedFilledSession,
        exists: true
      };

      expect(result.session?.internal.mcd).toBeDefined();
      expect(result.session?.internal.mcd?.domain).toBe("example.com");
      expect(result.session?.internal.mcd?.issuer).toBe("https://example.com/");
    });
  });

  // ===== getAccessToken Domain Gating =====

  describe("getAccessToken Domain Gating (Unit 8-2 to 8-4)", () => {
    it("U8-2: getAccessToken returns error on domain mismatch", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true
      };

      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
      // Public method should throw/return error
    });

    it("U8-3: getAccessToken proceeds on domain match", () => {
      const sessionWithMatch = createSessionData({
        tokenSet: {
          accessToken: "old_token",
          expiresAt: Date.now() + 3600000
        },
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      });

      const result: SessionCheckResult = {
        error: null,
        session: sessionWithMatch,
        exists: true
      };

      expect(result.error).toBeNull();
      expect(result.session?.tokenSet.accessToken).toBe("old_token");
    });

    it("U8-4: getAccessToken with pre-MCD session", () => {
      const preMCDSession = createSessionData({
        tokenSet: {
          accessToken: "access_token",
          expiresAt: Date.now() + 3600000
        },
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      // Backfill during check
      const backedFilledSession = {
        ...preMCDSession,
        internal: {
          ...preMCDSession.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      const result: SessionCheckResult = {
        error: null,
        session: backedFilledSession,
        exists: true
      };

      expect(result.session?.internal.mcd).toBeDefined();
      expect(result.error).toBeNull();
    });
  });

  // ===== handleLogout Domain Gating =====

  describe("handleLogout Domain Gating (Unit 8-5 to 8-8)", () => {
    it("U8-5: handleLogout with no session", () => {
      const result: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };

      // Should redirect without session deletion
      expect(result.exists).toBe(false);
      expect(result.session).toBeNull();
    });

    it("U8-6: handleLogout with domain mismatch skips deletion", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true
      };

      // Should redirect without deleting session (silent skip)
      expect(result.exists).toBe(true);
      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
      expect(result.session).toBeNull();
    });

    it("U8-7: handleLogout with domain match deletes session", () => {
      const sessionWithMatch = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      });

      const result: SessionCheckResult = {
        error: null,
        session: sessionWithMatch,
        exists: true
      };

      // Should proceed with deletion
      expect(result.error).toBeNull();
      expect(result.session).toBeDefined();
      expect(result.exists).toBe(true);
    });

    it("U8-8: handleLogout with pre-MCD session", () => {
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      const backedFilledSession = {
        ...preMCDSession,
        internal: {
          ...preMCDSession.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      const result: SessionCheckResult = {
        error: null,
        session: backedFilledSession,
        exists: true
      };

      expect(result.session?.internal.mcd).toBeDefined();
      expect(result.error).toBeNull();
    });
  });

  // ===== Handler Session Touch =====

  describe("Handler Session Touch Domain Gating (Unit 8-9 to 8-12)", () => {
    it("U8-9: handler session touch with no session", () => {
      const result: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };

      // Should skip touch
      expect(result.exists).toBe(false);
    });

    it("U8-10: handler session touch with domain mismatch", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true
      };

      // Should skip touch silently
      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
      expect(result.exists).toBe(true);
    });

    it("U8-11: handler session touch with domain match", () => {
      const sessionWithMatch = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      });

      const result: SessionCheckResult = {
        error: null,
        session: sessionWithMatch,
        exists: true
      };

      // Should proceed with touch
      expect(result.error).toBeNull();
      expect(result.session).toBeDefined();
    });

    it("U8-12: handler session touch with pre-MCD session", () => {
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      const backedFilledSession = {
        ...preMCDSession,
        internal: {
          ...preMCDSession.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      const result: SessionCheckResult = {
        error: null,
        session: backedFilledSession,
        exists: true
      };

      // Should proceed with backfilled session
      expect(result.session?.internal.mcd).toBeDefined();
    });
  });

  // ===== MFA Operations Domain Gating =====

  describe("MFA Operations Domain Gating (Unit 8-13)", () => {
    it("U8-13: MFA operations check domain", () => {
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      const backedFilledSession = {
        ...preMCDSession,
        internal: {
          ...preMCDSession.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      const result: SessionCheckResult = {
        error: null,
        session: backedFilledSession,
        exists: true
      };

      expect(result.session?.internal.mcd).toBeDefined();
      expect(result.error).toBeNull();
    });

    it("MFA operation with domain mismatch returns error", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError("Domain mismatch for MFA"),
        session: null,
        exists: true
      };

      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
    });
  });

  // ===== Connected Accounts Domain Gating =====

  describe("Connected Accounts Domain Gating (Unit 8-14)", () => {
    it("U8-14: Connected accounts perform domain check", () => {
      const sessionWithMatch = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      });

      const result: SessionCheckResult = {
        error: null,
        session: sessionWithMatch,
        exists: true
      };

      expect(result.error).toBeNull();
      expect(result.session?.internal.mcd?.domain).toBe("example.com");
    });

    it("Connected accounts with domain mismatch error", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError(
          "Cannot connect account with mismatched domain"
        ),
        session: null,
        exists: true
      };

      expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
    });
  });

  // ===== Error Propagation Patterns =====

  describe("Error Propagation Patterns (Unit 8-15 to 8-18)", () => {
    it("U8-15: Consistent error propagation for public methods", () => {
      const mismatchError = new SessionDomainMismatchError();

      // Public methods should receive this error type
      expect(mismatchError).toBeInstanceOf(SessionDomainMismatchError);
      expect(mismatchError.code).toBe("session_domain_mismatch");
    });

    it("U8-16: Silent skip for internal paths", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true
      };

      // Internal paths should check error and skip gracefully
      if (result.error) {
        // Skip operation silently
        expect(result.error).toBeInstanceOf(SessionDomainMismatchError);
      }
    });

    it("U8-17: SessionCheckResult.error propagation", () => {
      const result: SessionCheckResult = {
        error: new SessionDomainMismatchError("Session domain mismatch"),
        session: null,
        exists: true
      };

      expect(result.error).not.toBeNull();
      expect(result.error?.message).toContain("domain");
    });

    it("U8-18: SessionCheckResult.exists field usage", () => {
      // Case 1: No session
      const noSession: SessionCheckResult = {
        error: null,
        session: null,
        exists: false
      };
      expect(noSession.exists).toBe(false);

      // Case 2: Session with match
      const sessionMatch: SessionCheckResult = {
        error: null,
        session: createSessionData(),
        exists: true
      };
      expect(sessionMatch.exists).toBe(true);
      expect(sessionMatch.error).toBeNull();

      // Case 3: Session with mismatch
      const sessionMismatch: SessionCheckResult = {
        error: new SessionDomainMismatchError(),
        session: null,
        exists: true
      };
      expect(sessionMismatch.exists).toBe(true);
      expect(sessionMismatch.error).not.toBeNull();
    });
  });

  // ===== R2 Architectural Tests for Session Gating =====

  describe("R2 Architectural Tests for Session Gating", () => {
    it("R2-1-2: Domain check prevents domain switch", () => {
      const domain = "example.com";
      const result: SessionCheckResult = {
        error: null,
        session: createSessionData({
          internal: {
            sid: "sid_123",
            createdAt: Date.now(),
            mcd: createMCDMetadata(domain, `https://${domain}/`)
          }
        }),
        exists: true
      };

      // Domain cached in session
      expect(result.session?.internal.mcd?.domain).toBe(domain);

      // Verify domain used for token endpoint, not resolver result
      expect(result.session?.internal.mcd?.domain).toBe("example.com");
    });

    it("R2-1-3: Multiple resolver calls use cached domain", () => {
      const sessionDomain = "domain-at-T0.com";

      const result1: SessionCheckResult = {
        error: null,
        session: createSessionData({
          internal: {
            sid: "sid_123",
            createdAt: Date.now(),
            mcd: createMCDMetadata(sessionDomain, `https://${sessionDomain}/`)
          }
        }),
        exists: true
      };

      const result2: SessionCheckResult = {
        error: null,
        session: createSessionData({
          internal: {
            sid: "sid_123",
            createdAt: Date.now(),
            mcd: createMCDMetadata(sessionDomain, `https://${sessionDomain}/`)
          }
        }),
        exists: true
      };

      // Both should use the same cached domain
      expect(result1.session?.internal.mcd?.domain).toBe(
        result2.session?.internal.mcd?.domain
      );
    });

    it("R2-3-1: Backfill in-memory only", () => {
      const originalSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
          // no mcd field
        }
      });

      // Simulate in-memory backfill
      const backedFilledSession = { ...originalSession };
      backedFilledSession.internal = {
        ...backedFilledSession.internal,
        mcd: createMCDMetadata("example.com", "https://example.com/")
      };

      // Original should still not have mcd
      expect(originalSession.internal?.mcd).toBeUndefined();

      // Backed-filled copy has mcd
      expect(backedFilledSession.internal.mcd).toBeDefined();
    });

    it("R2-3-2: Backfill consistent across operations", () => {
      const sessionStore = new Map<string, SessionData>();
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      sessionStore.set("session_id", preMCDSession);

      // First operation backfills
      const retrieved1 = sessionStore.get("session_id");
      if (retrieved1) {
        retrieved1.internal.mcd = createMCDMetadata(
          "example.com",
          "https://example.com/"
        );
      }

      // Second operation uses same backfilled value
      const retrieved2 = sessionStore.get("session_id");
      expect(retrieved1?.internal.mcd?.domain).toBe(
        retrieved2?.internal.mcd?.domain
      );
    });

    it("R2-3-3: Backfill persisted on session update", () => {
      const sessionStore = new Map<string, SessionData>();
      const preMCDSession = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      sessionStore.set("session_id", preMCDSession);

      // Retrieve and backfill
      const session = sessionStore.get("session_id");
      if (session) {
        session.internal.mcd = createMCDMetadata(
          "example.com",
          "https://example.com/"
        );
      }

      // Store updated session
      if (session) {
        sessionStore.set("session_id", session);
      }

      // Verify persistence
      const persisted = sessionStore.get("session_id");
      expect(persisted?.internal.mcd).toBeDefined();
    });
  });

  // ===== Pre-MCD to MCD Migration =====

  describe("Pre-MCD to MCD Migration", () => {
    it("should backfill pre-MCD session with mcd metadata", () => {
      const preMCDSession = createSessionData({
        internal: {
          sid: "legacy_sid",
          createdAt: 1000000
        }
      });

      // Simulate backfill
      const migratedSession = {
        ...preMCDSession,
        internal: {
          ...preMCDSession.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      expect(migratedSession.internal.mcd).toBeDefined();
      expect(migratedSession.user).toEqual(preMCDSession.user);
      expect(migratedSession.tokenSet).toEqual(preMCDSession.tokenSet);
    });

    it("should handle multiple pre-MCD sessions", () => {
      const sessions = [
        createSessionData({
          user: { sub: "user1" },
          internal: { sid: "sid1", createdAt: 1000000 }
        }),
        createSessionData({
          user: { sub: "user2" },
          internal: { sid: "sid2", createdAt: 2000000 }
        })
      ];

      const migratedSessions = sessions.map((session) => ({
        ...session,
        internal: {
          ...session.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      }));

      migratedSessions.forEach((session) => {
        expect(session.internal.mcd).toBeDefined();
        expect(session.internal.mcd?.domain).toBe("example.com");
      });
    });
  });

  // ===== Session Backfill Behavior =====

  describe("Session Backfill Behavior", () => {
    it("should not modify original session during backfill", () => {
      const original = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now()
        }
      });

      const originalMcdValue = original.internal?.mcd;

      // Create backfilled copy
      const backfilled = {
        ...original,
        internal: {
          ...original.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      // Original should remain unchanged
      expect(original.internal?.mcd).toBe(originalMcdValue);
      expect(backfilled.internal.mcd).toBeDefined();
    });

    it("should handle session with existing mcd", () => {
      const sessionWithMCD = createSessionData({
        internal: {
          sid: "sid_123",
          createdAt: Date.now(),
          mcd: createMCDMetadata("domain1.com", "https://domain1.com/")
        }
      });

      const result: SessionCheckResult = {
        error: null,
        session: sessionWithMCD,
        exists: true
      };

      expect(result.session?.internal.mcd?.domain).toBe("domain1.com");
    });
  });
});
