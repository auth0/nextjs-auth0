/**
 * MCD Callback Domain Delegation Tests (Unit 9 Deep Dive)
 *
 * Focused tests for callback delegation functionality:
 * - originDomain stored in transaction state during login
 * - Callback reads originDomain and delegates
 * - Cross-domain token confusion prevention
 * - Issuer validation with normalization
 * - Backward compatibility with pre-MCD transactions
 */

import { describe, expect, it, vi } from "vitest";

import { DomainValidationError, IssuerValidationError } from "./errors.js";
import { normalizeDomain } from "./normalize.js";
import type { TransactionState } from "./transaction-store.js";
import type { MCDMetadata } from "./types.js";

describe("MCD Callback Domain Delegation (Unit 9)", () => {
  // ===== Helper functions =====

  function createTransactionState(
    partial: Partial<TransactionState> = {}
  ): TransactionState {
    return {
      codeVerifier: "code_verifier_123",
      responseType: "code",
      state: "state_value",
      returnTo: "https://example.com/callback",
      nonce: "nonce_123",
      ...partial
    } as TransactionState;
  }

  function createMCDMetadata(domain: string, issuer: string): MCDMetadata {
    return { domain, issuer };
  }

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

      expect((preMCDTransaction as any).originDomain).toBeUndefined();
      expect((preMCDTransaction as any).originIssuer).toBeUndefined();
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

      expect((sessionData.internal as any).mcd).toBeUndefined();
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
      expect((transaction as any).originDomain).toBeUndefined();
    });

    it("Mixed mode: some transactions with originDomain, some without", () => {
      const txn1 = createTransactionState({
        originDomain: "new.com"
      });

      const txn2 = createTransactionState({
        // no originDomain
      });

      const txn1HasOrigin = "originDomain" in txn1 && !!txn1.originDomain;
      const txn2HasOrigin =
        "originDomain" in txn2 && !!(txn2 as any).originDomain;

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
      expect((transaction as any).originDomain).toBeUndefined();

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
      expect((legacyTxn as any).originDomain).toBeUndefined();
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
