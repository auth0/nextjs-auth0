/**
 * TEST-ONLY — DO NOT COPY TO PRODUCTION.
 *
 * Part of the offline e2e mock harness (playwright.offline.config.ts, E2E_ANON_MOCK=1).
 * This file mocks Auth0 network calls and injects test scenarios. It must never run in a
 * real deployment. Delete lib/mock/ before using this example in production.
 *
 * Simulates Auth0 anonymous session endpoints (/anonymous/token, /anonymous/logout)
 * with scenario control for error injection. All values are synthetic.
 */

let currentScenario: string = "success";
let counter = 0;

export function setScenario(s: string): void {
  currentScenario = s;
}

export function getScenario(): string {
  return currentScenario;
}

function id(): string {
  return "e2e" + (++counter).toString(16).padStart(8, "0");
}

function makeAnonJwt(sub: string): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub,
    iat: nowSec,
    exp: nowSec + 3600
  };

  const b64url = (obj: object): string =>
    Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  return `${b64url(header)}.${b64url(payload)}.sig`;
}

function errResp(status: number, code: string): Response {
  return new Response(
    JSON.stringify({ error: code, error_description: `mock: ${code}` }),
    { status, headers: { "content-type": "application/json" } }
  );
}

function successResp(status: number, payload: object): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

export const mockAnonFetch: typeof fetch = async (input, init) => {
  let url: string;
  if (typeof input === "string") {
    url = input;
  } else if (input instanceof URL) {
    url = input.href;
  } else {
    url = (input as Request).url;
  }

  if (url.includes("/anonymous/token")) {
    const body = init?.body ? JSON.parse(String(init.body)) : {};

    // RENEW: body has session_token
    if (body.session_token) {
      const renewSub = "anon@" + id();
      return successResp(200, {
        token_type: "Bearer",
        access_token: makeAnonJwt(renewSub),
        expires_in: 3600
      });
    }

    // CREATE: switch on scenario
    switch (currentScenario) {
      case "success":
        return successResp(201, {
          token_type: "Bearer",
          session_token: "anon_sesstok_" + id(),
          access_token: makeAnonJwt("anon@" + id()),
          expires_in: 3600,
          ...(body.scope && { scope: body.scope }),
          ...(body.metadata && { metadata: body.metadata })
        });

      case "expired":
        return successResp(201, {
          token_type: "Bearer",
          session_token: "anon_sesstok_" + id(),
          access_token: makeAnonJwt("anon@" + id()),
          expires_in: -10,
          ...(body.scope && { scope: body.scope }),
          ...(body.metadata && { metadata: body.metadata })
        });

      case "feature_not_enabled":
        return errResp(403, "feature_not_enabled");

      case "unauthorized_client":
        return errResp(403, "unauthorized_client");

      case "invalid_target":
        return errResp(400, "invalid_target");

      case "invalid_scope":
        return errResp(400, "invalid_scope");

      case "server_error":
        return errResp(500, "server_error");

      case "invalid_client":
        return errResp(401, "invalid_client");

      default:
        return errResp(400, "invalid_request");
    }
  }

  if (url.includes("/anonymous/logout")) {
    return successResp(200, {});
  }

  // Passthrough for all other requests
  return fetch(input as any, init);
};
