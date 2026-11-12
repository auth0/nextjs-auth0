import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { PoppyError, PoppyErrorCode } from "../errors/index.js";
import {
  createAuthorizationServerMetadata,
  setupMswLifecycle
} from "../test/defaults.js";
import type { AnonymousCookiePayload } from "../types/anonymous-session.js";
import type { PoppyConfig } from "../types/poppy.js";
import { Auth0Client, type Auth0ClientOptions } from "./client.js";
import { encrypt } from "./cookies.js";

// Black-box: requests go through auth0.middleware, MSW stands in for Auth0.

const domain = "auth.fernway.test";
const issuer = `https://${domain}/`;
const appBaseUrl = "https://fernway.test";
const clientId = "fernway-web";
const clientSecret = "fernway-web-secret";
const secret =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

const poppyConfig: PoppyConfig = {
  protocolVersion: "0.3",
  domain: "fernway.test",
  issuer,
  browserSessionEndpoint: `${issuer}poppy/${clientId}/browser-session`
};

let keyPair: jose.GenerateKeyPairResult;
let tokenResponse: Record<string, unknown> = {};
let anonymousTokenRequests = 0;

const server = setupServer(
  http.get(`${issuer}.well-known/openid-configuration`, () =>
    HttpResponse.json(createAuthorizationServerMetadata(domain, { issuer }))
  ),
  http.get(`${issuer}.well-known/jwks.json`, async () =>
    HttpResponse.json({
      keys: [
        {
          ...(await jose.exportJWK(keyPair.publicKey)),
          kid: "k1",
          alg: "RS256",
          use: "sig"
        }
      ]
    })
  ),
  http.post(`${issuer}oauth/token`, () => HttpResponse.json(tokenResponse)),
  http.post(`${issuer}anonymous/token`, () => {
    anonymousTokenRequests++;
    return HttpResponse.json({ error: "unexpected" }, { status: 500 });
  })
);
setupMswLifecycle(server);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair("RS256");
});

beforeEach(() => {
  anonymousTokenRequests = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const epoch = () => Math.floor(Date.now() / 1000);

// The act Auth0's browser join puts in the web app's tokens (auth0-server
// poppy-browser-session-spike): the agent's client metadata URL plus the two
// Poppy IDs, and poppy_agent_id only when the agent sent one.
const agentClientId = "https://muse.example/agent.json";
const agentAct = (overrides: Record<string, unknown> = {}) => ({
  sub: agentClientId,
  poppy_sid: "s_8Hq2",
  poppy_user_id: "u_Q7c1",
  ...overrides
});

// The sub_profile on a guest join's tokens.
const anonymousSubProfile = "user urn:auth0:anonymous_user";

/** A browser: keeps the cookies the app sets and sends them back. */
class Browser {
  private jar = new Map<string, string>();

  absorb(res: NextResponse) {
    for (const cookie of res.cookies.getAll()) {
      if (cookie.value === "" || cookie.maxAge === 0) {
        this.jar.delete(cookie.name);
      } else {
        this.jar.set(cookie.name, cookie.value);
      }
    }
  }

  set(name: string, value: string) {
    this.jar.set(name, value);
  }

  has(name: string) {
    return this.jar.has(name);
  }

  request(path: string) {
    const headers = new Headers();
    if (this.jar.size) {
      headers.set(
        "cookie",
        [...this.jar].map(([name, value]) => `${name}=${value}`).join("; ")
      );
    }
    return new NextRequest(new URL(path, appBaseUrl), { headers });
  }
}

function createClient(options: Partial<Auth0ClientOptions> = {}) {
  return new Auth0Client({
    domain,
    clientId,
    clientSecret,
    secret,
    appBaseUrl,
    poppy: { config: poppyConfig },
    ...options
  });
}

async function signIdToken(claims: Record<string, unknown>, nonce: string) {
  return (
    new jose.SignJWT({ sid: "auth0-sid", nonce, ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setIssuedAt()
      // Auth0 caps join tokens at 2 hours; a test can pass its own exp.
      .setExpirationTime(typeof claims.exp === "number" ? claims.exp : "2h")
      .sign(keyPair.privateKey)
  );
}

/** /auth/login, then the authorize URL the browser was sent to. */
async function startLogin(auth0: Auth0Client, browser: Browser, path: string) {
  const res = await auth0.middleware(browser.request(path));
  browser.absorb(res);
  const authorizeUrl = new URL(res.headers.get("location")!);
  return {
    authorizeUrl,
    state: authorizeUrl.searchParams.get("state")!,
    nonce: authorizeUrl.searchParams.get("nonce")!
  };
}

/** A full login: /auth/login → Auth0 (mocked) → /auth/callback. */
async function login(
  auth0: Auth0Client,
  browser: Browser,
  idTokenClaims: Record<string, unknown>,
  {
    path = "/auth/login",
    scope = "openid profile orders:write"
  }: { path?: string; scope?: string } = {}
) {
  const { state, nonce } = await startLogin(auth0, browser, path);
  tokenResponse = {
    access_token: "at_123",
    token_type: "Bearer",
    expires_in: 36000,
    scope,
    id_token: await signIdToken(idTokenClaims, nonce)
  };
  const res = await auth0.middleware(
    browser.request(`/auth/callback?code=code_123&state=${state}`)
  );
  browser.absorb(res);
  return res;
}

async function plainAnonymousCookie(): Promise<string> {
  const payload: AnonymousCookiePayload = {
    session_token: "st_plain",
    access_token: "anon.at.123",
    expires_at: epoch() + 3600
  };
  return encrypt(payload, secret, epoch() + 3600);
}

describe("Poppy: third-party-initiated login", () => {
  it("lands on target_link_uri and forwards neither parameter to /authorize", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    const query = new URLSearchParams({
      iss: issuer,
      target_link_uri: `${appBaseUrl}/checkout?step=2`
    });

    const { authorizeUrl } = await startLogin(
      auth0,
      browser,
      `/auth/login?${query}`
    );
    expect(authorizeUrl.searchParams.has("iss")).toBe(false);
    expect(authorizeUrl.searchParams.has("target_link_uri")).toBe(false);

    const res = await login(
      auth0,
      browser,
      { sub: "auth0|ana" },
      {
        path: `/auth/login?${query}`
      }
    );
    expect(new URL(res.headers.get("location")!).pathname).toBe("/checkout");
    expect(new URL(res.headers.get("location")!).search).toBe("?step=2");
  });

  it("ignores a cross-origin target_link_uri", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = new Browser();
    const query = new URLSearchParams({
      iss: issuer,
      target_link_uri: "https://evil.example/phish"
    });

    const res = await login(
      auth0,
      browser,
      { sub: "auth0|ana" },
      {
        path: `/auth/login?${query}`
      }
    );

    const location = new URL(res.headers.get("location")!);
    expect(location.origin).toBe(appBaseUrl);
    expect(location.pathname).toBe("/");
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("not on this app's origin")
    );
  });

  it("ignores target_link_uri when iss is not the configured issuer", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = new Browser();
    const query = new URLSearchParams({
      iss: "https://attacker.example/",
      target_link_uri: `${appBaseUrl}/account/email`
    });

    const { authorizeUrl } = await startLogin(
      auth0,
      browser,
      `/auth/login?${query}`
    );
    expect(authorizeUrl.searchParams.has("iss")).toBe(false);
    expect(authorizeUrl.searchParams.has("target_link_uri")).toBe(false);

    const res = await login(
      auth0,
      browser,
      { sub: "auth0|ana" },
      {
        path: `/auth/login?${query}`
      }
    );
    expect(new URL(res.headers.get("location")!).pathname).toBe("/");
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("iss does not match")
    );
  });

  it("without the poppy option, still forwards both parameters as before", async () => {
    const auth0 = createClient({ poppy: undefined });
    const query = new URLSearchParams({
      iss: issuer,
      target_link_uri: `${appBaseUrl}/checkout`
    });

    const { authorizeUrl } = await startLogin(
      auth0,
      new Browser(),
      `/auth/login?${query}`
    );
    expect(authorizeUrl.searchParams.get("iss")).toBe(issuer);
    expect(authorizeUrl.searchParams.get("target_link_uri")).toBe(
      `${appBaseUrl}/checkout`
    );
  });
});

describe("Poppy: signed-in agent", () => {
  const agentClaims = () => ({
    sub: "auth0|ana",
    name: "Ana García",
    sub_profile: "user",
    client_profile: "web",
    act: agentAct(),
    unrelated_claim: "dropped"
  });

  it("keeps the agent claims and reports a signed-in agent", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, agentClaims());

    const session = await auth0.getSession(browser.request("/"));
    expect(session?.user).toEqual({
      sub: "auth0|ana",
      name: "Ana García",
      sub_profile: "user",
      client_profile: "web",
      act: {
        sub: agentClientId,
        poppy_sid: "s_8Hq2",
        poppy_user_id: "u_Q7c1"
      }
    });

    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "agent",
      state: "signed_in",
      agent: { clientId: agentClientId },
      sub: agentClientId,
      poppy_sid: "s_8Hq2",
      poppy_user_id: "u_Q7c1",
      scopes: ["openid", "profile", "orders:write"]
    });
  });

  it("caps the session cookie at the ID token's exp", async () => {
    const auth0 = createClient();
    const res = await login(auth0, new Browser(), {
      ...agentClaims(),
      exp: epoch() + 600
    });

    const maxAge = res.cookies.get("__session")?.maxAge;
    expect(maxAge).toBeGreaterThan(590);
    expect(maxAge).toBeLessThanOrEqual(600);
  });

  it("never rolls the session past the cap", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      ...agentClaims(),
      exp: epoch() + 600
    });

    // Any non-SDK path rolls the session.
    const res = await auth0.middleware(browser.request("/products"));
    const maxAge = res.cookies.get("__session")?.maxAge;
    expect(maxAge).toBeDefined();
    expect(maxAge).toBeLessThanOrEqual(600);
  });

  it("ends the session once the join's tokens expire", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      ...agentClaims(),
      exp: epoch() + 120
    });
    expect(await auth0.getSession(browser.request("/"))).not.toBeNull();

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 121 * 1000);

    expect(await auth0.getSession(browser.request("/"))).toBeNull();
    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });

  it("rejects a login whose tokens are about to expire", async () => {
    const auth0 = createClient();
    const res = await login(auth0, new Browser(), {
      ...agentClaims(),
      exp: epoch() + 5
    });

    expect(res.status).toBe(500);
    expect(res.cookies.get("__session")).toBeUndefined();
  });

  it("still reports the agent when beforeSessionSaved strips act and every claim", async () => {
    const auth0 = createClient({
      beforeSessionSaved: async (session) => ({
        ...session,
        user: { sub: session.user.sub },
        // An app may also try to drop internal state; the SDK restores it.
        internal: { sid: "x", createdAt: 0 }
      })
    });
    const browser = new Browser();
    await login(auth0, browser, agentClaims());

    const session = await auth0.getSession(browser.request("/"));
    expect(session?.user).toEqual({ sub: "auth0|ana" });
    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      kind: "agent",
      state: "signed_in",
      agent: { clientId: agentClientId }
    });
  });

  it("reads the Poppy IDs only from inside act, under their own names", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      sub: "auth0|ana",
      act: agentAct({ poppy_uid: "u_old_name" }),
      // Top-level copies are not where the join puts them, so they are ignored.
      poppy_sid: "s_top",
      poppy_user_id: "u_top"
    });

    const context = await auth0.poppy.getContext(browser.request("/"));
    expect(context).toMatchObject({
      poppy_sid: "s_8Hq2",
      poppy_user_id: "u_Q7c1"
    });
    expect(context).not.toHaveProperty("sessionId");
    expect(context).not.toHaveProperty("userId");
  });

  it("exposes poppy_agent_id when the agent sent one", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      sub: "auth0|ana",
      act: agentAct({ poppy_agent_id: "travel_agent" })
    });

    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      kind: "agent",
      poppy_agent_id: "travel_agent"
    });
  });
});

describe("Poppy: people", () => {
  it("reports a person for an ordinary login", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    const res = await login(auth0, browser, { sub: "auth0|ana" });

    expect(res.cookies.get("__session")?.maxAge).toBe(86400);
    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });

  it("reports a person for an impersonation actor (no Poppy IDs in act)", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      sub: "auth0|ana",
      act: { sub: "auth0|support-rep" }
    });

    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });

  it("reports a person with no session at all", async () => {
    const auth0 = createClient();
    expect(await auth0.poppy.getContext(new Browser().request("/"))).toEqual({
      kind: "human"
    });
  });

  it("reports a person when act has only some of the Poppy IDs", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      sub: "auth0|ana",
      act: { sub: agentClientId, poppy_sid: "s_8Hq2" }
    });

    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });
});

describe("Poppy: without the poppy option", () => {
  it("treats an agent login exactly as before", async () => {
    const auth0 = createClient({ poppy: undefined });
    const browser = new Browser();
    const res = await login(auth0, browser, {
      sub: "auth0|ana",
      sub_profile: "user",
      act: agentAct(),
      exp: epoch() + 600
    });

    // No cap, no extra claims, no agent state.
    expect(res.cookies.get("__session")?.maxAge).toBe(86400);
    const session = await auth0.getSession(browser.request("/"));
    expect(session?.user).toEqual({
      sub: "auth0|ana",
      act: expect.objectContaining({ sub: agentClientId })
    });
    expect(session?.internal.poppy).toBeUndefined();
    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });

  it("stores a guest-shaped login as an ordinary user session, as before", async () => {
    const auth0 = createClient({ poppy: undefined });
    const browser = new Browser();
    await login(auth0, browser, {
      sub: "anon_poppy@7c2e5a1d",
      sub_profile: anonymousSubProfile,
      act: agentAct()
    });

    expect(browser.has("__session")).toBe(true);
    expect(browser.has("auth0_anon")).toBe(false);
  });
});

describe("Poppy: agent guest", () => {
  const guestClaims = () => ({
    sub: "anon_poppy@7c2e5a1d",
    sub_profile: anonymousSubProfile,
    act: agentAct(),
    exp: epoch() + 900
  });

  it("stores the guest as an anonymous session, never a user session", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    const res = await login(auth0, browser, guestClaims(), {
      path: `/auth/login?${new URLSearchParams({ iss: issuer, target_link_uri: `${appBaseUrl}/cart` })}`
    });

    expect(res.status).toBe(307);
    expect(new URL(res.headers.get("location")!).pathname).toBe("/cart");
    expect(res.cookies.get("__session")).toBeUndefined();

    const guestCookie = res.cookies.get("auth0_anon");
    expect(guestCookie?.maxAge).toBeGreaterThan(890);
    expect(guestCookie?.maxAge).toBeLessThanOrEqual(900);

    expect(await auth0.getSession(browser.request("/"))).toBeNull();
    // Works without anonymousSession.enabled: the guest comes from the join.
    expect(await auth0.getAnonymousSession(browser.request("/"))).toEqual({
      id: "anon_poppy@7c2e5a1d",
      accessToken: "at_123",
      expiresAt: expect.any(Number)
    });
    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "agent",
      state: "guest",
      agent: { clientId: agentClientId },
      sub: agentClientId,
      poppy_sid: "s_8Hq2",
      poppy_user_id: "u_Q7c1",
      scopes: []
    });
  });

  it("skips the app's onCallback and beforeSessionSaved hooks for a guest", async () => {
    const onCallback = vi.fn(async () => NextResponse.redirect(appBaseUrl));
    const beforeSessionSaved = vi.fn(async (session) => session);
    const auth0 = createClient({ onCallback, beforeSessionSaved });
    const browser = new Browser();

    await login(auth0, browser, guestClaims());

    expect(onCallback).not.toHaveBeenCalled();
    expect(beforeSessionSaved).not.toHaveBeenCalled();
    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      state: "guest"
    });
  });

  it.each([
    [
      "an act that is not a Poppy actor",
      {
        sub: "anon_poppy@7c2e5a1d",
        sub_profile: anonymousSubProfile,
        act: { sub: "auth0|support-rep" }
      }
    ],
    [
      "an anon_poppy@ subject without the anonymous sub_profile",
      { sub: "anon_poppy@7c2e5a1d", act: agentAct() }
    ],
    [
      "an anonymous sub_profile without the anon_poppy@ subject",
      {
        sub: "auth0|someone",
        sub_profile: anonymousSubProfile,
        act: agentAct()
      }
    ]
  ])("refuses %s, storing nothing", async (_case, claims) => {
    const auth0 = createClient();
    const browser = new Browser();
    const res = await login(auth0, browser, claims);

    expect(res.status).toBe(500);
    expect(browser.has("__session")).toBe(false);
    expect(browser.has("auth0_anon")).toBe(false);
  });

  it("passes a PoppyError to onCallback, naming the failing check", async () => {
    const received: unknown[] = [];
    const onCallback = vi.fn(async (error: unknown) => {
      received.push(error);
      return new NextResponse("refused", { status: 500 });
    });
    const auth0 = createClient({ onCallback });

    await login(auth0, new Browser(), {
      sub: "anon_poppy@7c2e5a1d",
      sub_profile: anonymousSubProfile,
      act: { sub: agentClientId }
    });

    expect(received).toHaveLength(1);
    const error = received[0] as PoppyError;
    expect(error).toBeInstanceOf(PoppyError);
    expect(error.code).toBe(PoppyErrorCode.INVALID_GUEST);
    expect(error.message).toContain(
      'Reason: act.poppy_sid is missing or not a string ("act" has: sub)'
    );
  });

  it("ends the guest when the join's tokens expire", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      ...guestClaims(),
      exp: epoch() + 120
    });
    expect((await auth0.poppy.getContext(browser.request("/"))).kind).toBe(
      "agent"
    );

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 121 * 1000);

    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
    expect(await auth0.getAnonymousSession(browser.request("/"))).toBeNull();
  });

  it("ends an agent's earlier sign-in in this browser (signed-out rejoin)", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana", act: agentAct() });
    expect(browser.has("__session")).toBe(true);

    await login(auth0, browser, guestClaims());

    expect(browser.has("__session")).toBe(false);
    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      state: "guest"
    });
  });

  it("keeps a person's own login in this browser, but reports the agent", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana" });

    await login(auth0, browser, guestClaims());

    // A join without an access token keeps the browser's own login (spec §6)...
    expect(browser.has("__session")).toBe(true);
    expect((await auth0.getSession(browser.request("/")))?.user.sub).toBe(
      "auth0|ana"
    );
    // ...but while the browser carries the guest, the agent is driving.
    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      kind: "agent",
      state: "guest",
      poppy_sid: "s_8Hq2",
      scopes: []
    });
  });

  it("reports the person again once the guest has ended", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana" });
    await login(auth0, browser, { ...guestClaims(), exp: epoch() + 120 });

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 121 * 1000);

    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });

  it("refuses a person's login while the guest is in the browser", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, guestClaims());

    const res = await auth0.middleware(browser.request("/auth/login"));

    expect(res.status).toBe(403);
    expect(browser.has("auth0_anon")).toBe(true);
    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      state: "guest"
    });
  });

  it("refuses a guest login in a popup", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    const res = await login(auth0, browser, guestClaims(), {
      path: "/auth/login?challengeMode=popup"
    });

    expect(await res.text()).toContain("poppy_guest_not_supported");
    expect(browser.has("__session")).toBe(false);
    expect(browser.has("auth0_anon")).toBe(false);
  });
});

describe("Poppy: rejoin as the customer", () => {
  const guestClaims = {
    sub: "anon_poppy@7c2e5a1d",
    sub_profile: anonymousSubProfile,
    act: agentAct()
  };

  it("replaces the guest with the customer's session and keeps the Session ID", async () => {
    const auth0 = createClient({
      anonymousSession: { enabled: true, clearAnonymousSessionOnLogin: false }
    });
    const browser = new Browser();
    await login(auth0, browser, guestClaims);
    expect(browser.has("auth0_anon")).toBe(true);

    // The rejoin's /auth/login must not mint an anonymous transfer ticket from
    // the guest cookie (no /anonymous/token call, no ticket on /authorize).
    const join = `/auth/login?${new URLSearchParams({ iss: issuer })}`;
    const { authorizeUrl } = await startLogin(auth0, browser, join);
    expect(authorizeUrl.searchParams.has("anon_transfer_token")).toBe(false);
    expect(anonymousTokenRequests).toBe(0);

    await login(
      auth0,
      browser,
      { sub: "auth0|ana", act: agentAct() },
      { path: join }
    );

    // Deleted even though clearAnonymousSessionOnLogin is false.
    expect(browser.has("auth0_anon")).toBe(false);
    expect(await auth0.poppy.getContext(browser.request("/"))).toMatchObject({
      kind: "agent",
      state: "signed_in",
      poppy_sid: "s_8Hq2"
    });
  });

  it("leaves an ordinary anonymous session alone when clearAnonymousSessionOnLogin is false", async () => {
    const auth0 = createClient({
      anonymousSession: { enabled: true, clearAnonymousSessionOnLogin: false }
    });
    const browser = new Browser();
    browser.set("auth0_anon", await plainAnonymousCookie());

    // A plain anonymous session mints a transfer ticket at login; that is the
    // existing behaviour and is not under test here, so answer it.
    server.use(
      http.post(`${issuer}anonymous/token`, () =>
        HttpResponse.json({
          token_type: "N_A",
          anon_transfer_token: "ticket",
          expires_in: 60
        })
      )
    );

    await login(auth0, browser, { sub: "auth0|ana", act: agentAct() });

    expect(browser.has("auth0_anon")).toBe(true);
  });
});

describe("Poppy: logout", () => {
  const guestClaims = () => ({
    sub: "anon_poppy@7c2e5a1d",
    sub_profile: anonymousSubProfile,
    act: agentAct()
  });

  async function logout(
    auth0: Auth0Client,
    browser: Browser,
    path = "/auth/logout"
  ) {
    const res = await auth0.middleware(browser.request(path));
    browser.absorb(res);
    return res;
  }

  it("logs a guest out through Auth0 and deletes the guest cookie", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, guestClaims());
    expect(browser.has("auth0_anon")).toBe(true);

    const res = await logout(auth0, browser, "/auth/logout?returnTo=%2Fbye");

    // Auth0's logout ends the guest's anonymous Auth0 session as well.
    const location = new URL(res.headers.get("location")!);
    expect(location.host).toBe(domain);
    expect(
      location.searchParams.get("returnTo") ??
        location.searchParams.get("post_logout_redirect_uri")
    ).toBe("/bye");
    expect(browser.has("auth0_anon")).toBe(false);
    expect(await auth0.poppy.getContext(browser.request("/"))).toEqual({
      kind: "human"
    });
  });

  it("logs out a guest that has already ended the same way", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { ...guestClaims(), exp: epoch() + 120 });

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 121 * 1000);

    const res = await logout(auth0, browser);
    expect(new URL(res.headers.get("location")!).host).toBe(domain);
    expect(browser.has("auth0_anon")).toBe(false);
  });

  it("clears a guest left behind when a person logs out", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana" });
    await login(auth0, browser, guestClaims());
    expect(browser.has("__session")).toBe(true);
    expect(browser.has("auth0_anon")).toBe(true);

    const res = await logout(auth0, browser);

    // The person's session is Auth0's to end, so this logout still goes there.
    expect(new URL(res.headers.get("location")!).host).toBe(domain);
    expect(browser.has("__session")).toBe(false);
    expect(browser.has("auth0_anon")).toBe(false);
  });

  it("clears the guest when logout can't reach Auth0", async () => {
    const browser = new Browser();
    const auth0 = createClient();
    await login(auth0, browser, { sub: "auth0|ana" });
    await login(auth0, browser, guestClaims());

    // A new client has no cached discovery, so the failure below is hit.
    server.use(
      http.get(`${issuer}.well-known/openid-configuration`, () =>
        HttpResponse.json({ error: "down" }, { status: 500 })
      )
    );
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await logout(createClient(), browser);

    expect(res.status).toBe(500);
    expect(browser.has("__session")).toBe(false);
    expect(browser.has("auth0_anon")).toBe(false);
  });

  it("leaves an ordinary anonymous session to Auth0's logout, as before", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = new Browser();
    browser.set("auth0_anon", await plainAnonymousCookie());

    const res = await logout(auth0, browser);

    expect(new URL(res.headers.get("location")!).host).toBe(domain);
    expect(browser.has("auth0_anon")).toBe(true);
  });
});

describe("Poppy: context route", () => {
  async function getContextRoute(
    auth0: Auth0Client,
    browser: Browser,
    path = "/auth/poppy-context"
  ) {
    return auth0.middleware(browser.request(path));
  }

  it("returns a person", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana" });

    const res = await getContextRoute(auth0, browser);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toContain("no-store");
    expect(await res.json()).toEqual({ kind: "human" });
  });

  it("returns a guest, the same as the server", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, {
      sub: "anon_poppy@7c2e5a1d",
      sub_profile: anonymousSubProfile,
      act: agentAct()
    });

    const res = await getContextRoute(auth0, browser);
    expect(await res.json()).toEqual(
      await auth0.poppy.getContext(browser.request("/"))
    );
  });

  it("returns a signed-in agent with its scopes, and no tokens", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana", act: agentAct() });

    const res = await getContextRoute(auth0, browser);
    const body = await res.json();
    expect(body).toEqual({
      kind: "agent",
      state: "signed_in",
      agent: { clientId: agentClientId },
      sub: agentClientId,
      poppy_sid: "s_8Hq2",
      poppy_user_id: "u_Q7c1",
      scopes: ["openid", "profile", "orders:write"]
    });
    expect(JSON.stringify(body)).not.toContain("at_123");
  });

  it("answers 404 without the poppy option", async () => {
    const auth0 = createClient({ poppy: undefined });
    const res = await getContextRoute(auth0, new Browser());
    expect(res.status).toBe(404);
  });

  it("can be mounted on a custom path", async () => {
    const auth0 = createClient({ routes: { poppyContext: "/api/who" } });
    const res = await getContextRoute(auth0, new Browser(), "/api/who");
    expect(await res.json()).toEqual({ kind: "human" });
  });
});

describe("Poppy: login while an agent guest is in the browser", () => {
  const guestClaims = {
    sub: "anon_poppy@7c2e5a1d",
    sub_profile: anonymousSubProfile,
    act: agentAct()
  };

  async function guestBrowser(auth0: Auth0Client) {
    const browser = new Browser();
    await login(auth0, browser, guestClaims);
    expect(browser.has("auth0_anon")).toBe(true);
    return browser;
  }

  it.each([
    ["a plain login", "/auth/login"],
    ["a login with returnTo", "/auth/login?returnTo=%2Faccount"],
    ["a popup login", "/auth/login?challengeMode=popup"]
  ])("refuses %s with 403 and the reason", async (_case, path) => {
    const auth0 = createClient();
    const browser = await guestBrowser(auth0);

    const res = await auth0.middleware(browser.request(path));

    expect(res.status).toBe(403);
    expect(res.headers.get("location")).toBeNull();
    expect(await res.text()).toContain(
      "A Personal Agent is browsing as a guest"
    );
    // No login transaction was started.
    expect(
      res.cookies.getAll().some((cookie) => cookie.name.startsWith("__txn"))
    ).toBe(false);
  });

  it("refuses a third-party-initiated login whose iss is not the issuer", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const auth0 = createClient();
    const browser = await guestBrowser(auth0);

    const res = await auth0.middleware(
      browser.request(
        `/auth/login?${new URLSearchParams({ iss: "https://attacker.example/" })}`
      )
    );

    expect(res.status).toBe(403);
  });

  it("lets the agent's join through", async () => {
    const auth0 = createClient();
    const browser = await guestBrowser(auth0);

    const res = await auth0.middleware(
      browser.request(`/auth/login?${new URLSearchParams({ iss: issuer })}`)
    );

    expect(res.status).toBe(307);
    expect(new URL(res.headers.get("location")!).host).toBe(domain);
  });

  it("throws a PoppyError from auth0.startInteractiveLogin()", async () => {
    const auth0 = createClient();
    const browser = await guestBrowser(auth0);

    const error = await auth0
      .startInteractiveLogin({}, browser.request("/"))
      .then(
        () => undefined,
        (e: unknown) => e
      );

    expect(error).toBeInstanceOf(PoppyError);
    expect((error as PoppyError).code).toBe(PoppyErrorCode.LOGIN_NOT_ALLOWED);
  });

  it("allows a login once the guest has logged out", async () => {
    const auth0 = createClient();
    const browser = await guestBrowser(auth0);
    browser.absorb(await auth0.middleware(browser.request("/auth/logout")));

    const res = await auth0.middleware(browser.request("/auth/login"));

    expect(res.status).toBe(307);
    expect(new URL(res.headers.get("location")!).host).toBe(domain);
  });

  it("doesn't refuse a login for a signed-in agent", async () => {
    const auth0 = createClient();
    const browser = new Browser();
    await login(auth0, browser, { sub: "auth0|ana", act: agentAct() });

    const res = await auth0.middleware(browser.request("/auth/login"));

    expect(res.status).toBe(307);
  });

  it("doesn't refuse a login without the poppy option", async () => {
    const browser = await guestBrowser(createClient());

    const res = await createClient({ poppy: undefined }).middleware(
      browser.request("/auth/login")
    );

    expect(res.status).toBe(307);
  });
});
