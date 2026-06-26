import { describe, expect, it } from "vitest";

import { AccessTokenErrorCode } from "../errors/oauth-errors.js";
import { getSessionChangesAfterGetAccessToken } from "../utils/session-changes-helpers.js";
import {
  buildSessionFromCallback,
  isSessionCeilingInPast,
  isSessionCeilingReached
} from "../utils/session-helpers.js";

// ---------------------------------------------------------------------------
// isSessionCeilingReached
//
// Validates Req 2 (treat session as expired at ceiling) and Req 3 (skip
// refresh past ceiling). The guard in getTokenSet and getSessionWithDomainCheck
// both delegate to this helper, so correctness here covers both enforcement points.
// ---------------------------------------------------------------------------

describe("isSessionCeilingReached", () => {
  const now = Math.floor(Date.now() / 1000);

  it("returns false when sessionExpiresAt is undefined — no ceiling, existing behavior unchanged", () => {
    expect(isSessionCeilingReached(undefined)).toBe(false);
  });

  it("returns false when sessionExpiresAt is null — safe default, never treated as expired", () => {
    expect(isSessionCeilingReached(null as unknown as number)).toBe(false);
  });

  it("returns false for a ceiling comfortably in the future (beyond leeway)", () => {
    expect(isSessionCeilingReached(now + 3600)).toBe(false);
  });

  it("returns true for a ceiling in the past", () => {
    expect(isSessionCeilingReached(now - 60)).toBe(true);
  });

  it("returns true for a ceiling within the 30s leeway window (now + 10)", () => {
    // The SDK treats the session as expired slightly before the wall-clock ceiling
    expect(isSessionCeilingReached(now + 10)).toBe(true);
  });

  it("returns false for a ceiling comfortably beyond the leeway (now + 60)", () => {
    // Use 60s rather than 31s to avoid a race where Date.now() ticks 1 second
    // between `now` capture and the internal clock read inside the helper.
    expect(isSessionCeilingReached(now + 60)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isSessionCeilingInPast
//
// Validates Req 1 at-login guard: if session_expiry <= iat at login, the
// session must be rejected before being persisted. The comparison uses iat
// (not wall-clock now) so a session that arrives late over the network is
// not incorrectly rejected.
// ---------------------------------------------------------------------------

describe("isSessionCeilingInPast", () => {
  const iat = 1_893_456_000; // a fixed future timestamp for determinism

  it("returns false when sessionExpiresAt is undefined — no ceiling present", () => {
    expect(isSessionCeilingInPast(undefined, iat)).toBe(false);
    expect(isSessionCeilingInPast(undefined, undefined)).toBe(false);
  });

  it("returns false when sessionExpiresAt is null — safe default", () => {
    expect(isSessionCeilingInPast(null as unknown as number, iat)).toBe(false);
  });

  it("returns true when ceiling is well before iat — session already lapsed at login", () => {
    expect(isSessionCeilingInPast(iat - 3600, iat)).toBe(true);
  });

  it("returns true when ceiling equals iat — exactly at issue time, within leeway", () => {
    // session_expiry == iat satisfies session_expiry <= iat requirement
    expect(isSessionCeilingInPast(iat, iat)).toBe(true);
  });

  it("returns false when ceiling is comfortably after iat (iat + 3600)", () => {
    expect(isSessionCeilingInPast(iat + 3600, iat)).toBe(false);
  });

  it("returns true when ceiling is exactly at the leeway boundary (iat + 30)", () => {
    expect(isSessionCeilingInPast(iat + 30, iat)).toBe(true);
  });

  it("returns false when ceiling is one second beyond the leeway (iat + 31)", () => {
    expect(isSessionCeilingInPast(iat + 31, iat)).toBe(false);
  });

  it("falls back to wall-clock now when iat is absent", () => {
    const past = Math.floor(Date.now() / 1000) - 100;
    expect(isSessionCeilingInPast(past, undefined)).toBe(true);
  });

  it("falls back to wall-clock now when iat is a non-number", () => {
    const past = Math.floor(Date.now() / 1000) - 100;
    expect(isSessionCeilingInPast(past, "not-a-number")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildSessionFromCallback — Req 1: read and persist the claim
//
// Validates that session_expiry from ID token claims is stamped onto
// session.internal.sessionExpiresAt (the SDK-side persisted field), and that
// absence or non-number values are handled safely without breaking existing
// sessions.
// ---------------------------------------------------------------------------

describe("buildSessionFromCallback — session_expiry stamping", () => {
  const fakeOidcRes = {
    access_token: "at",
    id_token: "idt",
    scope: "openid profile",
    refresh_token: "rt",
    expires_in: 3600
  } as any;

  const fakeTxnState = {
    scope: "openid profile",
    audience: undefined,
    responseType: "code",
    state: "state",
    returnTo: "/"
  } as any;

  it("stamps sessionExpiresAt when session_expiry is a valid integer in the ID token", () => {
    const ceiling = Math.floor(Date.now() / 1000) + 7200;
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: ceiling } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBe(ceiling);
  });

  it("stamps sessionExpiresAt even when session_expiry is already in the past — rejection is the caller's job (handleCallback)", () => {
    // buildSessionFromCallback stamps the value unconditionally; it is
    // handleCallback in auth-client.ts that calls isSessionCeilingInPast
    // and rejects before persisting. This test confirms the helper does not
    // swallow the past value before the caller can evaluate it.
    const pastCeiling = Math.floor(Date.now() / 1000) - 3600;
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: pastCeiling } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBe(pastCeiling);
  });

  it("leaves sessionExpiresAt absent when session_expiry is not present in the ID token", () => {
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s" } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("leaves sessionExpiresAt absent when session_expiry is a non-number (string date)", () => {
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: "2099-01-01" } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("leaves sessionExpiresAt absent when session_expiry is null", () => {
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: null } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("leaves sessionExpiresAt absent when session_expiry is a millisecond timestamp (>= 10_000_000_000) — common Action mistake", () => {
    // Date.now() returns ms (13 digits). The guard rejects values >= 10_000_000_000
    // so a year-57000 ceiling that would never fire is not silently stamped.
    const msTimestamp = Date.now(); // e.g. 1_700_000_000_000
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: msTimestamp } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("leaves sessionExpiresAt absent when session_expiry is NaN — typeof NaN === 'number' but NaN < guard fails", () => {
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: NaN } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("leaves sessionExpiresAt absent when session_expiry is Infinity", () => {
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: Infinity } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("leaves sessionExpiresAt absent when session_expiry is a boolean", () => {
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: true } as any,
      fakeOidcRes,
      fakeTxnState
    );
    expect(session.internal.sessionExpiresAt).toBeUndefined();
  });

  it("ceiling is preserved independently of tokenSet fields — refresh grants do not overwrite it", () => {
    // session.internal is a separate field from session.tokenSet.
    // A token refresh updates tokenSet but never touches internal, so
    // sessionExpiresAt survives the refresh unchanged (Req 3 invariant).
    const ceiling = Math.floor(Date.now() / 1000) + 7200;
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: ceiling } as any,
      fakeOidcRes,
      fakeTxnState
    );
    // Simulate what a refresh does: update only tokenSet
    session.tokenSet = {
      ...session.tokenSet,
      accessToken: "refreshed_at",
      expiresAt: ceiling + 100
    };
    // sessionExpiresAt must still be the original ceiling
    expect(session.internal.sessionExpiresAt).toBe(ceiling);
  });
});

// ---------------------------------------------------------------------------
// Ceiling preservation through getSessionChangesAfterGetAccessToken (Req 3)
//
// #updateSessionAfterTokenRetrieval spreads sessionChanges over the session.
// sessionChanges only ever contains tokenSet / accessTokens — never internal.
// This test confirms that spreading changes does NOT erase sessionExpiresAt,
// mirroring the explicit internal-preservation code in Python's update_state_data.
// ---------------------------------------------------------------------------

describe("ceiling preserved through getSessionChangesAfterGetAccessToken", () => {
  it("sessionExpiresAt survives a global-audience token refresh", () => {
    const ceiling = Math.floor(Date.now() / 1000) + 7200;
    const session = buildSessionFromCallback(
      { sub: "u", sid: "s", session_expiry: ceiling } as any,
      {
        access_token: "old_at",
        id_token: "idt",
        scope: "openid profile",
        refresh_token: "rt",
        expires_in: 3600
      } as any,
      {
        scope: "openid profile",
        audience: undefined,
        responseType: "code",
        state: "s",
        returnTo: "/"
      } as any
    );

    const refreshedTokenSet = {
      accessToken: "new_at",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      scope: "openid profile",
      requestedScope: "openid profile",
      refreshToken: "new_rt"
    };

    const changes = getSessionChangesAfterGetAccessToken(
      session,
      refreshedTokenSet,
      {
        scope: "openid profile",
        audience: undefined
      }
    );

    // Spread changes the way #updateSessionAfterTokenRetrieval does
    const updated = changes ? { ...session, ...changes } : session;

    // The ceiling must survive — internal is never part of sessionChanges
    expect(updated.internal.sessionExpiresAt).toBe(ceiling);
    // And the token was actually refreshed
    expect(updated.tokenSet.accessToken).toBe("new_at");
  });
});

// ---------------------------------------------------------------------------
// AccessTokenErrorCode.SESSION_EXPIRED — Req 3 error signal
//
// The code surfaced to callers on getTokenSet once the ceiling passes.
// ---------------------------------------------------------------------------

describe("AccessTokenErrorCode.SESSION_EXPIRED", () => {
  it("has the correct string value 'session_expired'", () => {
    expect(AccessTokenErrorCode.SESSION_EXPIRED).toBe("session_expired");
  });
});
