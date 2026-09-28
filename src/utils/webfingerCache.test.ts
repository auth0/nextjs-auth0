import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance
} from "vitest";

import {
  _clearWebFingerCacheForTesting,
  isFederatedDomain,
  type IsFederatedDomainOptions
} from "./webfingerCache.js";

const AUTH0_DOMAIN = "test-tenant.auth0.com";
const OIDC_REL = "http://openid.net/specs/connect/1.0/issuer";

/** A WebFinger 200 body advertising the OIDC issuer link. */
function managedBody(domain = "acmecorp.com") {
  return {
    subject: `urn:auth0:discovery:domain:${domain}`,
    links: [{ rel: OIDC_REL, href: `https://${AUTH0_DOMAIN}/` }]
  };
}

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body
  } as unknown as Response;
}

describe("isFederatedDomain", () => {
  let fetchSpy: MockInstance<typeof fetch>;

  beforeEach(() => {
    _clearWebFingerCacheForTesting();
    fetchSpy = vi.spyOn(global, "fetch");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    _clearWebFingerCacheForTesting();
  });

  describe("request shape", () => {
    it("queries the WebFinger endpoint with the discovery resource and OIDC rel", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(200, managedBody()));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toBe(
        `https://${AUTH0_DOMAIN}/.well-known/webfinger` +
          `?resource=urn:auth0:discovery:domain:acmecorp.com` +
          `&rel=${OIDC_REL}`
      );
    });

    it("percent-encodes the email domain in the resource parameter", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(404, {}));

      await isFederatedDomain(AUTH0_DOMAIN, "acme corp.com");

      const url = fetchSpy.mock.calls[0][0] as string;
      expect(url).toContain("urn:auth0:discovery:domain:acme%20corp.com");
    });
  });

  describe("responses", () => {
    it("returns true for a 200 advertising the OIDC rel", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(200, managedBody()));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(true);
    });

    it("returns false for a 404 (domain not managed)", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(404, {}));

      await expect(isFederatedDomain(AUTH0_DOMAIN, "gmail.com")).resolves.toBe(
        false
      );
    });

    it("returns false for a 403 (endpoint disabled on the tenant)", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(403, {}));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(false);
    });

    it("returns false and warns for a 429 (rate limited)", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      fetchSpy.mockResolvedValue(jsonResponse(429, {}));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(false);

      expect(warn).toHaveBeenCalledOnce();
      expect(warn.mock.calls[0][0]).toContain("rate limit hit (429)");
    });

    it("returns false for a 500", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(500, {}));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(false);
    });

    it("returns false when fetch rejects", async () => {
      fetchSpy.mockRejectedValue(new TypeError("network failure"));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(false);
    });
  });

  describe("caching", () => {
    it("serves a repeat lookup from cache without a second request", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(200, managedBody()));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");

      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it("re-fetches a true result after its 60s TTL expires", async () => {
      vi.useFakeTimers();
      fetchSpy.mockResolvedValue(jsonResponse(200, managedBody()));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      expect(fetchSpy).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(59_000);
      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      expect(fetchSpy).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(2_000);
      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it("re-fetches a false result after its shorter 15s TTL expires", async () => {
      vi.useFakeTimers();
      fetchSpy.mockResolvedValue(jsonResponse(404, {}));

      await isFederatedDomain(AUTH0_DOMAIN, "newcustomer.com");
      expect(fetchSpy).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(14_000);
      await isFederatedDomain(AUTH0_DOMAIN, "newcustomer.com");
      expect(fetchSpy).toHaveBeenCalledTimes(1);

      vi.advanceTimersByTime(2_000);
      await isFederatedDomain(AUTH0_DOMAIN, "newcustomer.com");
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it("picks up a domain that becomes federated once the negative TTL lapses", async () => {
      vi.useFakeTimers();
      fetchSpy.mockResolvedValueOnce(jsonResponse(404, {}));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "newcustomer.com")
      ).resolves.toBe(false);

      fetchSpy.mockResolvedValueOnce(
        jsonResponse(200, managedBody("newcustomer.com"))
      );
      vi.advanceTimersByTime(16_000);

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "newcustomer.com")
      ).resolves.toBe(true);
    });

    it("does not cache a 403, so enabling the endpoint takes effect immediately", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(403, {}));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");

      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it("does not cache a 429, so the limit window is not extended", async () => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      fetchSpy.mockResolvedValue(jsonResponse(429, {}));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");

      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it("does not cache a network error", async () => {
      fetchSpy.mockRejectedValue(new TypeError("network failure"));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");
      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com");

      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe("cache keys", () => {
    it("treats email domains case-insensitively, sharing one cache entry", async () => {
      fetchSpy.mockResolvedValue(jsonResponse(200, managedBody()));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "AcmeCorp.com")
      ).resolves.toBe(true);
      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(true);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      // The request itself is normalized too.
      expect(fetchSpy.mock.calls[0][0]).toContain(
        "urn:auth0:discovery:domain:acmecorp.com"
      );
    });

    it("keeps separate entries per email domain", async () => {
      fetchSpy
        .mockResolvedValueOnce(jsonResponse(200, managedBody("acmecorp.com")))
        .mockResolvedValueOnce(jsonResponse(404, {}));

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com")
      ).resolves.toBe(true);
      await expect(isFederatedDomain(AUTH0_DOMAIN, "gmail.com")).resolves.toBe(
        false
      );
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it("keeps separate entries per Auth0 domain", async () => {
      fetchSpy
        .mockResolvedValueOnce(jsonResponse(200, managedBody()))
        .mockResolvedValueOnce(jsonResponse(404, {}));

      await expect(
        isFederatedDomain("tenant-a.auth0.com", "acmecorp.com")
      ).resolves.toBe(true);
      await expect(
        isFederatedDomain("tenant-b.auth0.com", "acmecorp.com")
      ).resolves.toBe(false);
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });
  });

  describe("options", () => {
    it("uses customFetch instead of global fetch when provided", async () => {
      const customFetch = vi
        .fn()
        .mockResolvedValue(jsonResponse(200, managedBody()));
      const opts: IsFederatedDomainOptions = { customFetch };

      await expect(
        isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com", opts)
      ).resolves.toBe(true);

      expect(customFetch).toHaveBeenCalledTimes(1);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("forwards the WebFinger URL to customFetch unchanged", async () => {
      const customFetch = vi
        .fn()
        .mockResolvedValue(jsonResponse(200, managedBody()));

      await isFederatedDomain(AUTH0_DOMAIN, "acmecorp.com", { customFetch });

      const url = customFetch.mock.calls[0][0] as string;
      expect(url).toBe(
        `https://${AUTH0_DOMAIN}/.well-known/webfinger` +
          `?resource=urn:auth0:discovery:domain:acmecorp.com` +
          `&rel=${OIDC_REL}`
      );
    });
  });
});
