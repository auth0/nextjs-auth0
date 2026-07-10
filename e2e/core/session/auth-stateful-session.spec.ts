import { expect, test } from "@playwright/test";
import { loginWithStatefulAuth0, logoutStateful, injectSession, EMAIL } from "../../helpers";

// Serial: the in-memory SQLite DB is shared across the test-app process — parallel workers
// would race on clearStore/login/delete operations and corrupt each other's state.
test.describe.configure({ mode: "serial" });

// These tests do their own login via the stateful route; clear the inherited storageState.
test.use({ storageState: { cookies: [], origins: [] } });

// Helpers — all stateful routes use auth0Stateful (SQLite-backed Auth0Client)

async function injectStatefulSession(
  context: Parameters<typeof injectSession>[0],
  opts: Parameters<typeof injectSession>[1] = {}
) {
  return injectSession(context, {
    ...opts,
    apiPath: "/app-router/api/stateful/inject-session",
  });
}

async function getStoreRecords(context: Parameters<typeof injectSession>[0]) {
  const res = await context.request.get("/app-router/api/stateful/store-debug");
  const body = await res.json();
  return body.sessions as { id: string; data: string }[];
}

async function deleteStoreRecord(
  context: Parameters<typeof injectSession>[0],
  id: string
) {
  await context.request.delete(`/app-router/api/stateful/store-debug?id=${id}`);
}

async function clearStore(context: Parameters<typeof injectSession>[0]) {
  await context.request.delete("/app-router/api/stateful/store-debug");
}

// ─── Cookie shape ─────────────────────────────────────────────────────────────

test.describe("stateful session — cookie contains only opaque session ID", () => {
  test.beforeEach(async ({ context }) => clearStore(context));

  test("login creates a record in the DB; cookie holds only an opaque ID", async ({
    page,
    context,
  }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");

    // DB should have exactly one record after login
    const records = await getStoreRecords(context);
    expect(records.length).toBe(1);

    // Cookie value should be an encrypted JWE — not a readable session payload
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((c) => c.name === "__session_stateful");
    expect(sessionCookie).toBeDefined();
    // JWE tokens start with "ey" (base64url header)
    expect(sessionCookie!.value).toMatch(/^ey/);
    // The raw cookie value should NOT contain the user email
    expect(sessionCookie!.value).not.toContain(EMAIL);
  });
});

// ─── getSession() reads from DB ───────────────────────────────────────────────

test.describe("stateful session — getSession() reads from DB", () => {
  test.beforeEach(async ({ context }) => clearStore(context));

  test("getSession() returns session data from DB when cookie is valid", async ({
    page,
    context,
  }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");
    const res = await context.request.get("/app-router/api/stateful/get-session");
    expect(res.status()).toBe(200);
    const session = await res.json();
    expect(session.user.email).toBe(EMAIL);
  });

  test("getSession() returns null when DB record is missing even with valid cookie", async ({
    page,
    context,
  }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");

    // Verify session works before revocation
    const before = await context.request.get("/app-router/api/stateful/get-session");
    expect(before.status()).toBe(200);

    // Server-side revocation: delete the DB record directly
    const records = await getStoreRecords(context);
    expect(records.length).toBeGreaterThan(0);
    await deleteStoreRecord(context, records[0].id);

    // Cookie is still present, but DB record is gone — should be 401
    const after = await context.request.get("/app-router/api/stateful/get-session");
    expect(after.status()).toBe(401);
  });
});

// ─── Logout ───────────────────────────────────────────────────────────────────

test.describe("stateful session — logout deletes DB record", () => {
  test.beforeEach(async ({ context }) => clearStore(context));

  test("logout deletes the session record from the DB", async ({ page, context }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");

    const recordsBefore = await getStoreRecords(context);
    expect(recordsBefore.length).toBe(1);

    await logoutStateful(page);

    const recordsAfter = await getStoreRecords(context);
    expect(recordsAfter.length).toBe(0);
  });

  test("getSession() returns null after logout", async ({ page, context }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");
    await logoutStateful(page);

    const res = await context.request.get("/app-router/api/stateful/get-session");
    expect(res.status()).toBe(401);
  });

  test("logout state propagates — old cookie is rejected even if replayed", async ({
    page,
    context,
  }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");

    // Capture the session cookie before logout
    const cookiesBefore = await context.cookies();
    const oldCookie = cookiesBefore.find((c) => c.name === "__session_stateful")!;
    expect(oldCookie).toBeDefined();

    // Verify session is valid right now
    const beforeLogout = await context.request.get("/app-router/api/stateful/get-session");
    expect(beforeLogout.status()).toBe(200);

    // Logout — deletes the DB record
    await logoutStateful(page);

    // Re-inject the old cookie value (simulates a second browser tab or stolen cookie)
    await context.addCookies([{
      name: "__session_stateful",
      value: oldCookie.value,
      domain: "localhost",
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
    }]);

    // DB record is gone — the replayed cookie should be rejected
    const afterReplay = await context.request.get("/app-router/api/stateful/get-session");
    expect(afterReplay.status()).toBe(401);

    // DB is still empty — session was not recreated
    const records = await getStoreRecords(context);
    expect(records.length).toBe(0);
  });
});

// ─── updateSession() ─────────────────────────────────────────────────────────

test.describe("stateful session — updateSession() writes to DB", () => {
  test.beforeEach(async ({ context }) => clearStore(context));

  test("updateSession() persists changes in the DB record", async ({ page, context }) => {
    const before = Date.now();
    await loginWithStatefulAuth0(page, "/app-router/server");

    const updateRes = await context.request.post("/app-router/api/stateful/update-session");
    expect(updateRes.status()).toBe(200);

    // Read back via stateful get-session — should reflect the update
    const sessionRes = await context.request.get("/app-router/api/stateful/get-session");
    const session = await sessionRes.json();
    expect(session.user.updatedAt).toBeGreaterThan(before);

    // DB record should contain the updated data
    const records = await getStoreRecords(context);
    const stored = JSON.parse(records[0].data);
    expect(stored.user.updatedAt).toBeGreaterThan(before);
  });

  test("session cookie is still present after updateSession() (only DB record changes)", async ({
    page,
    context,
  }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");

    await context.request.post("/app-router/api/stateful/update-session");

    // Cookie must still exist after the update — stateful store updates the DB, not the cookie value.
    // (JWE re-encryption on rolling sessions produces a different ciphertext for the same session ID,
    // so we assert presence rather than strict value equality.)
    const cookiesAfter = await context.cookies();
    const sessionAfter = cookiesAfter.find((c) => c.name === "__session_stateful");
    expect(sessionAfter).toBeDefined();
    expect(sessionAfter!.value).toMatch(/^ey/);

    // And the session is still readable after the update
    const res = await context.request.get("/app-router/api/stateful/get-session");
    expect(res.status()).toBe(200);
  });
});

// ─── Session injection ────────────────────────────────────────────────────────

test.describe("stateful session — session injection via stateful endpoint", () => {
  test.beforeEach(async ({ context }) => clearStore(context));

  test("injected stateless session is not readable by stateful client", async ({ context }) => {
    // Standard inject writes a full stateless JWE — stateful client expects a session ID pointer
    await injectSession(context, {
      user: { sub: "stateless|001", email: "stateless@example.com" },
    });
    // Stateful client tries to decrypt and look up the ID — should return 401
    const res = await context.request.get("/app-router/api/stateful/get-session");
    expect(res.status()).toBe(401);
  });
});

// ─── Concurrent logout race guard ────────────────────────────────────────────

test.describe("stateful session — rolling update respects revocation", () => {
  test.beforeEach(async ({ context }) => clearStore(context));

  test("update after server-side revocation does not recreate the session", async ({
    page,
    context,
  }) => {
    await loginWithStatefulAuth0(page, "/app-router/server");

    // Revoke server-side
    const records = await getStoreRecords(context);
    await deleteStoreRecord(context, records[0].id);

    // Attempt to updateSession — store.update() returns false (no row), session not recreated
    const updateRes = await context.request.post("/app-router/api/stateful/update-session");
    expect(updateRes.status()).toBe(401);

    // DB should still be empty
    const recordsAfter = await getStoreRecords(context);
    expect(recordsAfter.length).toBe(0);
  });
});
