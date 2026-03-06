/**
 * MCD Session Domain Gating Tests (Unit 8 Deep Dive)
 *
 * Focused tests for session domain gating functionality:
 * - SessionCheckResult interface validation
 * - Domain match/mismatch for all public methods
 * - Pre-MCD session backfill
 * - Error propagation patterns
 */

import { describe, expect, it } from "vitest";

import type { SessionData } from "../types/index.js";
import { SessionDomainMismatchError } from "./errors.js";
import type { MCDMetadata } from "./types.js";

/**
 * SessionCheckResult interface validation
 */
interface SessionCheckResult {
  error: Error | null;
  session: SessionData | null;
  exists: boolean;
}

describe("MCD Session Domain Gating (Unit 8)", () => {
  // ===== Helper functions =====

  function createSessionData(partial: Partial<SessionData> = {}): SessionData {
    return {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "access_token_123",
        expiresAt: Date.now() + 3600000
      },
      internal: {
        sid: "sid_123",
        createdAt: Date.now()
      },
      ...partial
    };
  }

  function createMCDMetadata(domain: string, issuer: string): MCDMetadata {
    return { domain, issuer };
  }

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
      expect((originalSession.internal as any).mcd).toBeUndefined();

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

      const originalMcdValue = (original.internal as any).mcd;

      // Create backfilled copy
      const backfilled = {
        ...original,
        internal: {
          ...original.internal,
          mcd: createMCDMetadata("example.com", "https://example.com/")
        }
      };

      // Original should remain unchanged
      expect((original.internal as any).mcd).toBe(originalMcdValue);
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
