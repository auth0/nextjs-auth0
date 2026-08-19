import { type APIRequestContext } from "@playwright/test";

/**
 * Set the mock scenario for E2E_ANON_MOCK server.
 */
export async function setScenario(
  request: APIRequestContext,
  scenario: string
): Promise<void> {
  const res = await request.post("/api/test/mock-scenario", {
    data: { scenario }
  });
  if (!res.ok()) {
    throw new Error(
      `Failed to set scenario: ${res.status()} ${await res.text()}`
    );
  }
}

/**
 * Create an anonymous session via POST /api/anon/create.
 * Returns the raw Response for caller to assert status/json.
 */
export async function createAnon(
  request: APIRequestContext,
  opts?: { metadata?: any }
) {
  return request.post("/api/anon/create", {
    data: opts?.metadata ? { metadata: opts.metadata } : {}
  });
}

/**
 * Read the current anonymous session via GET /auth/anonymous-session.
 * Returns { status, json } where json is null on 204.
 */
export async function readAnon(
  request: APIRequestContext
): Promise<{ status: number; json: any }> {
  const res = await request.get("/auth/anonymous-session");
  const status = res.status();
  let json = null;
  if (status !== 204) {
    try {
      json = await res.json();
    } catch {
      // ignore parse failures
    }
  }
  return { status, json };
}
