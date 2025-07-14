import { NextResponse } from "next/server.js";
import * as jose from "jose";
import { describe, expect, it } from "vitest";

import { generateSecret } from "../test/utils.js";
import { addCacheControlHeadersForSession, decrypt, encrypt } from "./cookies.js";

describe("encrypt/decrypt", async () => {
  const secret = await generateSecret(32);
  const incorrectSecret = await generateSecret(32);

  it("should encrypt/decrypt a payload with the correct secret", async () => {
    const payload = { key: "value" };
    const maxAge = 60 * 60; // 1 hour in seconds
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encrypted = await encrypt(payload, secret, expiration);
    const decrypted = await decrypt(encrypted, secret) as jose.JWTDecryptResult;

    expect(decrypted!.payload).toEqual(expect.objectContaining(payload));
  });

  it("should fail to decrypt a payload with the incorrect secret", async () => {
    const payload = { key: "value" };
    const maxAge = 60 * 60; // 1 hour in seconds
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encrypted = await encrypt(payload, secret, expiration);
    await expect(() =>
      decrypt(encrypted, incorrectSecret)
    ).rejects.toThrowError();
  });

  it("should fail to decrypt when expired", async () => {
    const payload = { key: "value" };
    const expiration = Math.floor(Date.now() / 1000 - 60); // 60 seconds in the past
    const encrypted = await encrypt(payload, secret, expiration);
    const decrypted = await decrypt(encrypted, secret);
    expect(decrypted).toBeNull();
  });

  it("should fail to encrypt if a secret is not provided", async () => {
    const payload = { key: "value" };
    const maxAge = 60 * 60; // 1 hour in seconds
    const expiration = Math.floor(Date.now() / 1000 + maxAge);

    await expect(() => encrypt(payload, "", expiration)).rejects.toThrowError();
  });

  it("should fail to decrypt if a secret is not provided", async () => {
    const payload = { key: "value" };
    const maxAge = 60 * 60; // 1 hour in seconds
    const expiration = Math.floor(Date.now() / 1000 + maxAge);

    const encrypted = await encrypt(payload, secret, expiration);
    await expect(() => decrypt(encrypted, "")).rejects.toThrowError();
  });
});

describe("addCacheControlHeadersForSession", () => {
  it("unconditionally adds strict cache headers", () => {
    const res = NextResponse.next();

    addCacheControlHeadersForSession(res);

    expect(res.headers.get("Cache-Control")).toBe(
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
    expect(res.headers.get("Pragma")).toBe("no-cache");
    expect(res.headers.get("Expires")).toBe("0");
  });
});
