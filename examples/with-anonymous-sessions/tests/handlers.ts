/**
 * MSW handlers for anonymous sessions API
 * Mocks POST /anonymous/token and POST /anonymous/logout per WIRE-CONTRACT-LIVE.md
 */
import { http, HttpResponse } from "msw";

import {
  SYNTHETIC_DOMAIN,
  WIRE_CREATE_RESPONSE,
  WIRE_CREATE_WITH_METADATA_RESPONSE,
  WIRE_LOGOUT_WITH_SESSION_TOKEN_ERROR,
  WIRE_RENEW_RESPONSE,
  WIRE_RENEW_WITH_METADATA_ERROR
} from "./fixtures/synthetic-tokens";

export const handlers = [
  // POST /anonymous/token
  http.post(`${SYNTHETIC_DOMAIN}/anonymous/token`, async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    const hasSessionToken = "session_token" in body;
    const hasMetadata = "metadata" in body;

    // RENEW + metadata → 400 invalid_request
    if (hasSessionToken && hasMetadata) {
      return HttpResponse.json(WIRE_RENEW_WITH_METADATA_ERROR, {
        status: 400
      });
    }

    // RENEW (session_token only) → 200, no session_token reissue
    if (hasSessionToken) {
      return HttpResponse.json(WIRE_RENEW_RESPONSE, { status: 200 });
    }

    // CREATE with metadata → 200
    if (hasMetadata) {
      return HttpResponse.json(WIRE_CREATE_WITH_METADATA_RESPONSE, {
        status: 200
      });
    }

    // CREATE (no session_token, no metadata) → 200
    return HttpResponse.json(WIRE_CREATE_RESPONSE, { status: 200 });
  }),

  // POST /anonymous/logout
  http.post(`${SYNTHETIC_DOMAIN}/anonymous/logout`, async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    const hasSessionToken = "session_token" in body;

    // LOGOUT with session_token in body → 400 invalid_request
    if (hasSessionToken) {
      return HttpResponse.json(WIRE_LOGOUT_WITH_SESSION_TOKEN_ERROR, {
        status: 400
      });
    }

    // LOGOUT (client_id or empty) → 204 No Content
    return new HttpResponse(null, { status: 204 });
  })
];
