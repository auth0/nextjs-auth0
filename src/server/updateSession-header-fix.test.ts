import { beforeEach, describe, expect, it, vi } from "vitest";

import { Auth0Client } from "./client.js";

describe("UpdateSession Header Copying Fix", () => {
  let client: Auth0Client;
  let mockPagesRouterReq: any;
  let mockPagesRouterRes: any;
  let mockSession: any;

  beforeEach(() => {
    // Create a mock session that matches SessionData structure
    mockSession = {
      user: { sub: "test_user", nickname: "test" },
      tokenSet: {
        accessToken: "test_token",
        expiresAt: Date.now() / 1000 + 3600
      },
      internal: { sid: "test_session_id", createdAt: Date.now() / 1000 }
    };

    client = new Auth0Client({
      domain: "test.auth0.com",
      clientId: "test_client_id",
      clientSecret: "test_client_secret",
      appBaseUrl: "http://localhost:3000",
      secret: "test_secret_key_must_be_long_enough_for_hs256"
    });

    mockPagesRouterReq = {
      headers: {
        cookie: "appSession=mock_session_cookie"
      }
    };

    mockPagesRouterRes = {
      headers: {},
      setHeader: vi.fn((key: string, value: any) => {
        mockPagesRouterRes.headers[key] = value;
      }),
      getHeaders: () => mockPagesRouterRes.headers
    };

    // Mock the session store to return a valid session
    vi.spyOn(client["sessionStore"], "get").mockResolvedValue(mockSession);

    // Mock the session store to simulate setting multiple cookies
    vi.spyOn(client["sessionStore"], "set").mockImplementation(
      async (_reqCookies, resCookies) => {
        // Simulate StatelessSessionStore setting multiple cookies
        resCookies.set("appSession", "updated_session_value");
        resCookies.set("appSession.1", "chunk_data_here");
      }
    );
  });

  it("should handle multiple set-cookie headers correctly in Pages Router", async () => {
    await client.updateSession(mockPagesRouterReq, mockPagesRouterRes, {
      ...mockSession,
      user: { ...mockSession.user, nickname: "updated_user" }
    });

    // Verify setHeader was called properly
    expect(mockPagesRouterRes.setHeader).toHaveBeenCalled();

    // Check that the set-cookie header was set as an array
    const setCookieHeader = mockPagesRouterRes.headers["set-cookie"];
    expect(setCookieHeader).toBeDefined();
    expect(Array.isArray(setCookieHeader)).toBe(true);

    // Verify we have multiple cookies
    expect(setCookieHeader.length).toBeGreaterThan(1);

    // Verify the cookies contain expected values
    const cookieStrings = setCookieHeader.join(" ");
    expect(cookieStrings).toContain("appSession=");
    expect(cookieStrings).toContain("appSession.1=");
  });

  it("should preserve all cookies including legacy deletion cookies", async () => {
    // Mock session store to definitely include legacy cookie deletion
    vi.spyOn(client["sessionStore"], "set").mockImplementation(
      async (_reqCookies, resCookies) => {
        // All cookies should have consistent path from cookieConfig (default: "/")
        resCookies.set("appSession", "new_session_value", { path: "/" });
        resCookies.set("appSession.1", "chunk_1", { path: "/" });
        resCookies.set("appSession.2", "chunk_2", { path: "/" });
        resCookies.set("__session", "", { maxAge: 0, path: "/" }); // Legacy cookie deletion
      }
    );

    await client.updateSession(mockPagesRouterReq, mockPagesRouterRes, {
      ...mockSession,
      user: { ...mockSession.user, nickname: "test_user_updated" }
    });

    const setCookieHeader = mockPagesRouterRes.headers["set-cookie"];
    expect(Array.isArray(setCookieHeader)).toBe(true);
    expect(setCookieHeader.length).toBe(4); // All 4 cookies should be preserved

    // Verify specific cookies
    const cookieString = setCookieHeader.join(" | ");
    expect(cookieString).toContain("appSession=new_session_value; Path=/");
    expect(cookieString).toContain("appSession.1=chunk_1; Path=/");
    expect(cookieString).toContain("appSession.2=chunk_2; Path=/");
    // __session=; Path=/; Max-Age=0
    expect(cookieString).toContain("__session=; Path=/; Max-Age=0"); // Legacy deletion
  });

  it("should not call setHeader for set-cookie if no cookies are set", async () => {
    // Mock session store to set no cookies
    vi.spyOn(client["sessionStore"], "set").mockImplementation(async () => {
      // Don't set any cookies
    });

    await client.updateSession(mockPagesRouterReq, mockPagesRouterRes, {
      ...mockSession,
      user: { ...mockSession.user, nickname: "test_user" }
    });

    // Should not have set any set-cookie header
    expect(mockPagesRouterRes.headers["set-cookie"]).toBeUndefined();
  });

  it("should handle non-cookie headers normally", async () => {
    // Mock session store to set both cookies and other headers
    vi.spyOn(client["sessionStore"], "set").mockImplementation(
      async (_reqCookies, resCookies) => {
        resCookies.set("appSession", "test_value");
        // Simulate setting a custom header (this wouldn't normally happen in StatelessSessionStore, but test the logic)
        const headers = (resCookies as any).headers || new Headers();
        headers.set("X-Custom-Header", "test-value");
      }
    );

    await client.updateSession(mockPagesRouterReq, mockPagesRouterRes, {
      ...mockSession,
      user: { ...mockSession.user, nickname: "test_user" }
    });

    // Should have both the cookie array and the custom header
    expect(Array.isArray(mockPagesRouterRes.headers["set-cookie"])).toBe(true);
    expect(mockPagesRouterRes.headers["set-cookie"].length).toBe(1);
  });
});
