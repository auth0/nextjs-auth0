/**
 * @vitest-environment jsdom
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance
} from "vitest";

import { startEnterpriseLogin } from "./start-enterprise-login.js";

/** A discovery-route JSON response with the given `isFederated` flag. */
function federatedResponse(isFederated: boolean) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ isFederated })
  } as unknown as Response;
}

/** The URL passed to the last window.location.assign call, parsed. */
function lastNavigatedUrl(): URL {
  const assign = window.location.assign as unknown as MockInstance<
    typeof window.location.assign
  >;
  return new URL(assign.mock.calls.at(-1)![0] as string, "https://app.test");
}

describe("startEnterpriseLogin (client helper)", () => {
  let fetchSpy: MockInstance<typeof fetch>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(global, "fetch");
    Object.defineProperty(window, "location", {
      writable: true,
      value: { assign: vi.fn(), toString: () => "https://app.test" }
    });
    delete process.env.NEXT_PUBLIC_FEDERATED_DOMAIN_ROUTE;
    delete process.env.NEXT_PUBLIC_LOGIN_ROUTE;
    delete process.env.NEXT_PUBLIC_BASE_PATH;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("posts the email to the discovery route and, when federated, navigates to /auth/login with login_hint", async () => {
    fetchSpy.mockResolvedValue(federatedResponse(true));

    const result = await startEnterpriseLogin({ email: "jane@acme.com" });

    expect(result).toBe(true);

    // Discovery: POSTs the email to the default federated-domain route.
    expect(fetchSpy).toHaveBeenCalledWith(
      "/auth/federated-domain",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "jane@acme.com" })
      })
    );

    // Navigation: browser is sent to /auth/login carrying the email as login_hint.
    const url = lastNavigatedUrl();
    expect(url.pathname).toBe("/auth/login");
    expect(url.searchParams.get("login_hint")).toBe("jane@acme.com");
  });

  it("forwards authorizationParameters and returnTo onto the login query string", async () => {
    fetchSpy.mockResolvedValue(federatedResponse(true));

    await startEnterpriseLogin({
      email: "jane@acme.com",
      authorizationParameters: {
        organization: "org_123",
        connection: "acme-saml"
      },
      returnTo: "/dashboard"
    });

    const url = lastNavigatedUrl();
    expect(url.searchParams.get("organization")).toBe("org_123");
    expect(url.searchParams.get("connection")).toBe("acme-saml");
    expect(url.searchParams.get("returnTo")).toBe("/dashboard");
    expect(url.searchParams.get("login_hint")).toBe("jane@acme.com");
  });

  it("uses email for login_hint even when authorizationParameters supplies one", async () => {
    fetchSpy.mockResolvedValue(federatedResponse(true));

    await startEnterpriseLogin({
      email: "jane@acme.com",
      authorizationParameters: { login_hint: "someone-else@acme.com" }
    });

    expect(lastNavigatedUrl().searchParams.get("login_hint")).toBe(
      "jane@acme.com"
    );
  });

  it("returns false and does not navigate when the domain is not federated", async () => {
    fetchSpy.mockResolvedValue(federatedResponse(false));

    const result = await startEnterpriseLogin({ email: "jane@gmail.com" });

    expect(result).toBe(false);
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("throws and does not navigate when the discovery route responds not-ok", async () => {
    fetchSpy.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({})
    } as unknown as Response);

    await expect(
      startEnterpriseLogin({ email: "jane@acme.com" })
    ).rejects.toThrow(/checking the email domain/);
    expect(window.location.assign).not.toHaveBeenCalled();
  });

  it("honours federatedDomainRoute and loginRoute overrides", async () => {
    fetchSpy.mockResolvedValue(federatedResponse(true));

    await startEnterpriseLogin({
      email: "jane@acme.com",
      federatedDomainRoute: "/custom/discover",
      loginRoute: "/custom/login"
    });

    expect(fetchSpy.mock.calls[0][0]).toBe("/custom/discover");
    expect(lastNavigatedUrl().pathname).toBe("/custom/login");
  });

  it("resolves routes from NEXT_PUBLIC env vars when no option is passed", async () => {
    process.env.NEXT_PUBLIC_FEDERATED_DOMAIN_ROUTE = "/env/discover";
    process.env.NEXT_PUBLIC_LOGIN_ROUTE = "/env/login";
    fetchSpy.mockResolvedValue(federatedResponse(true));

    await startEnterpriseLogin({ email: "jane@acme.com" });

    expect(fetchSpy.mock.calls[0][0]).toBe("/env/discover");
    expect(lastNavigatedUrl().pathname).toBe("/env/login");
  });

  it("prefixes routes with NEXT_PUBLIC_BASE_PATH", async () => {
    process.env.NEXT_PUBLIC_BASE_PATH = "/docs";
    fetchSpy.mockResolvedValue(federatedResponse(true));

    await startEnterpriseLogin({ email: "jane@acme.com" });

    expect(fetchSpy.mock.calls[0][0]).toBe("/docs/auth/federated-domain");
    expect(lastNavigatedUrl().pathname).toBe("/docs/auth/login");
  });
});
