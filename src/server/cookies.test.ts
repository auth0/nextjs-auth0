import { NextResponse } from "next/server";
import { describe, expect, it } from "vitest";

import { generateSecret } from "../test/utils";
import { addCacheControlHeadersForSession, decrypt, encrypt } from "./cookies";

describe("encrypt/decrypt", async () => {
  const secret = await generateSecret(32);
  const incorrectSecret = await generateSecret(32);

  it("should encrypt/decrypt a payload with the correct secret", async () => {
    const payload = { key: "value" };
    const maxAge = 60 * 60; // 1 hour in seconds
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const encrypted = await encrypt(payload, secret, expiration);
    const decrypted = await decrypt(encrypted, secret);

    expect(decrypted.payload).toEqual(expect.objectContaining(payload));
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
    await expect(() => decrypt(encrypted, secret)).rejects.toThrowError(
      `"exp" claim timestamp check failed`
    );
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
  it("adds cache headers if __session cookie has a future Date expiry", () => {
    const res = NextResponse.next();
    const futureDate = new Date(Date.now() + 60_000); // 1 minute in the future

    res.cookies.set("__session", "dummy", { expires: futureDate });
    addCacheControlHeadersForSession(res);

    expect(res.headers.get("Cache-Control")).toBe(
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
    expect(res.headers.get("Pragma")).toBe("no-cache");
    expect(res.headers.get("Expires")).toBe("0");
  });

  it("does NOT add headers if __session cookie is missing", () => {
    const res = NextResponse.next();

    addCacheControlHeadersForSession(res);
    expect(res.headers.get("Cache-Control")).toBeNull();
    expect(res.headers.get("Pragma")).toBeNull();
    expect(res.headers.get("Expires")).toBeNull();
  });

  it("does NOT add headers if __session cookie is expired", () => {
    const res = NextResponse.next();
    const pastDate = new Date(Date.now() - 60_000); // 1 minute in the past

    res.cookies.set("__session", "dummy", { expires: pastDate });
    addCacheControlHeadersForSession(res);

    expect(res.headers.get("Cache-Control")).toBeNull();
  });

  it("does NOT add headers if __session cookie has no value", () => {
    const res = NextResponse.next();
    const futureDate = new Date(Date.now() + 60_000);

    // setting an empty value simulates a session cookie being cleared
    res.cookies.set("__session", "", { expires: futureDate });
    addCacheControlHeadersForSession(res);

    expect(res.headers.get("Cache-Control")).toBeNull();
  });

  it("does NOT add headers if __session cookie has no expires field", () => {
    const res = NextResponse.next();

    res.cookies.set("__session", "dummy"); // no `expires`
    addCacheControlHeadersForSession(res);

    expect(res.headers.get("Cache-Control")).toBeNull();
  });
});
