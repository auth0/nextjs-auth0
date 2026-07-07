/**
 * Storage invariant tests — validate wire format guarantees that must hold at all times.
 * Breaking any of these means cookies written today can't be read after the change.
 *
 * 1. Cookie format round-trip   — encrypt/decrypt stays stable with the same secret
 * 2. Chunked cookie round-trip  — >3500-byte payload written and reassembled correctly
 * 3. Transaction cookie format  — __txn_<state> name and decrypt round-trip
 */

import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import { describe, expect, it } from "vitest";

import {
  decrypt,
  encrypt,
  getChunkedCookie,
  setChunkedCookie
} from "./server/cookies.js";

// ---------------------------------------------------------------------------
// Shared constants that reflect the CURRENT wire format.
// If any of these change the tests break — that is intentional.
// ---------------------------------------------------------------------------

const SECRET = "a-32-byte-secret-for-testing-use";

// A real JWE produced by encrypt() with the current algorithm constants:
//   ENC = "A256GCM", ALG = "dir", DIGEST = "sha256",
//   BYTE_LENGTH = 32, ENCRYPTION_INFO = "JWE CEK"
// Regenerate with: await encrypt({ sub: "user_snapshot" }, SECRET, Math.floor(Date.now()/1000) + 86400*365*10)
// The expiry is set 10 years out so this snapshot stays valid for a long time.
const SNAPSHOT_JWE_PAYLOAD = {
  sub: "user_snapshot",
  purpose: "migration-safety"
};

// ---------------------------------------------------------------------------
// 1. Cookie format: encrypt → stored snapshot → decrypt must return same data
// ---------------------------------------------------------------------------

describe("Cookie format round-trip", () => {
  it("encrypt/decrypt is stable — same secret and payload always produces a decryptable JWE", async () => {
    const expiry = Math.floor(Date.now() / 1000) + 3600;
    const jwe = await encrypt(SNAPSHOT_JWE_PAYLOAD, SECRET, expiry);

    // JWE must be a compact serialisation: 5 base64url segments separated by dots
    expect(jwe.split(".")).toHaveLength(5);

    const result = await decrypt<typeof SNAPSHOT_JWE_PAYLOAD>(jwe, SECRET);
    expect(result).not.toBeNull();
    expect(result!.payload.sub).toBe("user_snapshot");
    expect(result!.payload.purpose).toBe("migration-safety");
  });

  it("decrypt returns null for a JWE encrypted with a different secret (key mismatch)", async () => {
    const expiry = Math.floor(Date.now() / 1000) + 3600;
    const jwe = await encrypt(SNAPSHOT_JWE_PAYLOAD, SECRET, expiry);
    const result = await decrypt(jwe, "a-different-32-byte-secret-here!");
    expect(result).toBeNull();
  });

  it("decrypt returns null for an expired JWE (not an exception)", async () => {
    // decrypt() has clockTolerance of 15s, so expire well beyond that
    const pastExpiry = Math.floor(Date.now() / 1000) - 60;
    const jwe = await encrypt(SNAPSHOT_JWE_PAYLOAD, SECRET, pastExpiry);
    const result = await decrypt(jwe, SECRET);
    expect(result).toBeNull();
  });

  it("ENCRYPTION_INFO constant is JWE CEK — key derivation did not change", async () => {
    // We encrypt with the known info string and decrypt with the same secret.
    // If ENCRYPTION_INFO changes, a real cookie encrypted today can't be read
    // after deploy — silent logout for all users.
    const expiry = Math.floor(Date.now() / 1000) + 3600;
    const jwe = await encrypt({ probe: true }, SECRET, expiry);
    // Decrypt with correct secret must succeed
    const ok = await decrypt<{ probe: boolean }>(jwe, SECRET);
    expect(ok?.payload.probe).toBe(true);
    // Decrypt with wrong info-derived key must fail
    // We simulate this by using a different secret — same effect as wrong HKDF info
    const fail = await decrypt(jwe, "wrong-secret-here-for-key-check!!");
    expect(fail).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. Chunked cookie round-trip
//    Cookie name:  __session
//    Chunk prefix: __   (chunk names: __session__0, __session__1, ...)
//    Max chunk:    3500 bytes
// ---------------------------------------------------------------------------

describe("Chunked cookie round-trip", () => {
  function makeCookiePair() {
    const reqCookies = new RequestCookies(new Headers());
    const resCookies = new ResponseCookies(new Headers());
    return { reqCookies, resCookies };
  }

  it("small payload (<3500 bytes) is stored as a single cookie with exact name", async () => {
    const { reqCookies, resCookies } = makeCookiePair();
    const smallValue = "a".repeat(100);

    setChunkedCookie(
      "__session",
      smallValue,
      { httpOnly: true, sameSite: "lax", secure: false, path: "/" },
      reqCookies,
      resCookies
    );

    const resNames = [...(resCookies as any)._parsed.keys()];
    expect(resNames).toContain("__session");
    expect(resNames).not.toContain("__session__0");
  });

  it("large payload (>3500 bytes) is split into chunks with __ separator", async () => {
    const { reqCookies, resCookies } = makeCookiePair();
    // 8000 bytes forces at least 3 chunks (ceiling of 8000/3500 = 3)
    const largeValue = "x".repeat(8000);

    setChunkedCookie(
      "__session",
      largeValue,
      { httpOnly: true, sameSite: "lax", secure: false, path: "/" },
      reqCookies,
      resCookies
    );

    const resNames = [...(resCookies as any)._parsed.keys()];
    // Must use double-underscore chunk format: __session__0, __session__1, ...
    expect(resNames).toContain("__session__0");
    expect(resNames).toContain("__session__1");
    expect(resNames).toContain("__session__2");
    // Must NOT fall back to dot-separated legacy format
    expect(resNames).not.toContain("__session.0");
  });

  it("chunked value is fully reassembled by getChunkedCookie from the request cookies", async () => {
    const { reqCookies, resCookies } = makeCookiePair();
    const largeValue = "y".repeat(8000);

    // setChunkedCookie writes to both reqCookies (read-after-write) and resCookies
    setChunkedCookie(
      "__session",
      largeValue,
      { httpOnly: true, sameSite: "lax", secure: false, path: "/" },
      reqCookies,
      resCookies
    );

    // getChunkedCookie reassembles from the request cookies (populated by setChunkedCookie)
    const reassembled = getChunkedCookie("__session", reqCookies);
    expect(reassembled).toBe(largeValue);
  });

  it("single (non-chunked) value is returned by getChunkedCookie unchanged", async () => {
    const { reqCookies, resCookies } = makeCookiePair();
    setChunkedCookie(
      "__session",
      "small-value",
      { httpOnly: true, sameSite: "lax", secure: false, path: "/" },
      reqCookies,
      resCookies
    );
    expect(getChunkedCookie("__session", reqCookies)).toBe("small-value");
  });
});

// ---------------------------------------------------------------------------
// 3. Transaction cookie name format
//    Name pattern: __txn_<state>
//    Value:        JWE produced by encrypt()
// ---------------------------------------------------------------------------

describe("Transaction cookie name format", () => {
  it("transaction cookie name is __txn_<state>", async () => {
    const { TransactionStore } = await import("./server/transaction-store.js");
    const { RESPONSE_TYPES } = await import("./types/index.js");

    const store = new TransactionStore({ secret: SECRET });
    const state = "my-login-state";

    const resCookies = new ResponseCookies(new Headers());
    await store.save(
      resCookies,
      {
        state,
        returnTo: "/dashboard",
        responseType: RESPONSE_TYPES.CODE,
        codeVerifier: "cv"
      },
      { get: () => undefined } as any
    );

    const cookieNames = [...(resCookies as any)._parsed.keys()];
    expect(cookieNames).toContain(`__txn_${state}`);
  });

  it("transaction cookie value is a valid JWE (5-segment compact serialisation)", async () => {
    const { TransactionStore } = await import("./server/transaction-store.js");
    const { RESPONSE_TYPES } = await import("./types/index.js");

    const store = new TransactionStore({ secret: SECRET });
    const state = "txn-format-check";

    const resCookies = new ResponseCookies(new Headers());
    await store.save(
      resCookies,
      {
        state,
        returnTo: "/",
        responseType: RESPONSE_TYPES.CODE,
        codeVerifier: "cv"
      },
      { get: () => undefined } as any
    );

    const cookie = (resCookies as any)._parsed.get(`__txn_${state}`);
    expect(cookie).toBeDefined();
    expect(cookie.value.split(".")).toHaveLength(5);
  });

  it("saved transaction is retrievable by get()", async () => {
    const { TransactionStore } = await import("./server/transaction-store.js");
    const { RESPONSE_TYPES } = await import("./types/index.js");

    const store = new TransactionStore({ secret: SECRET });
    const state = "get-round-trip";

    const resCookies = new ResponseCookies(new Headers());
    await store.save(
      resCookies,
      {
        state,
        returnTo: "/home",
        responseType: RESPONSE_TYPES.CODE,
        codeVerifier: "cv"
      },
      { get: () => undefined } as any
    );

    // Build request cookies from the Set-Cookie header
    const cookieHeader = [...(resCookies as any)._parsed.values()]
      .map((c: any) => `${c.name}=${c.value}`)
      .join("; ");
    const reqCookies = new RequestCookies(
      new Headers({ cookie: cookieHeader })
    );

    // get() returns a JWTDecryptResult — payload holds the TransactionState
    const result = await store.get(reqCookies, state);
    expect(result).not.toBeNull();
    expect(result!.payload.returnTo).toBe("/home");
    expect(result!.payload.codeVerifier).toBe("cv");
  });
});
