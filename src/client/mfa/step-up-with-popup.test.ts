/**
 * @vitest-environment jsdom
 */

import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { AccessTokenError } from "../../errors/index.js";
import {
  ExecutionContextError,
  PopupBlockedError,
  PopupInProgressError
} from "../../errors/popup-errors.js";

// Token response for MSW
const DEFAULT_TOKEN_RESPONSE = {
  token: "eyJ-access-token",
  scope: "openid profile email",
  expires_at: Math.floor(Date.now() / 1000) + 86400,
  expires_in: 86400,
  token_type: "Bearer"
};

// MSW server
const server = setupServer();

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
});

afterAll(() => {
  server.close();
});

/**
 * Helper: Simulate successful popup flow.
 * Opens popup → fires auth_complete postMessage → returns.
 *
 * Must be called AFTER the stepUpWithPopup promise is created
 * but BEFORE it resolves.
 */
function simulatePopupSuccess(
  user?: { sub: string; email: string },
  delay = 0
) {
  setTimeout(() => {
    const messageEvent = new MessageEvent("message", {
      data: {
        type: "auth_complete",
        success: true,
        ...(user && { user })
      },
      origin: window.location.origin
    });
    window.dispatchEvent(messageEvent);
  }, delay);
}

function simulatePopupError(
  error: { code: string; message: string },
  delay = 0
) {
  setTimeout(() => {
    const messageEvent = new MessageEvent("message", {
      data: {
        type: "auth_complete",
        success: false,
        error
      },
      origin: window.location.origin
    });
    window.dispatchEvent(messageEvent);
  }, delay);
}

describe("stepUpWithPopup", () => {
  let windowOpenSpy: any;

  beforeEach(() => {
    // Default: window.open succeeds
    windowOpenSpy = vi.spyOn(window, "open").mockReturnValue({
      closed: false,
      close: vi.fn()
    } as unknown as Window);
  });

  /**
   * We re-import to get a fresh module for each test, avoiding singleton state
   * (activePopup) leaking between tests.
   */
  async function getStepUpWithPopup() {
    // Dynamic import to get fresh module (activePopup singleton reset)
    const mod = await import("./index.js");
    return mod.mfa.stepUpWithPopup.bind(mod.mfa);
  }

  describe("execution context guard", () => {
    it("should throw ExecutionContextError in server context", async () => {
      const stepUpWithPopup = await getStepUpWithPopup();

      // Simulate SSR by temporarily making window undefined
      const originalWindow = globalThis.window;
      // @ts-expect-error - intentionally deleting window for SSR simulation
      delete globalThis.window;

      try {
        await expect(
          stepUpWithPopup({ audience: "https://api.example.com" })
        ).rejects.toBeInstanceOf(ExecutionContextError);
      } finally {
        globalThis.window = originalWindow;
      }
    });
  });

  describe("popup blocked", () => {
    it("should throw PopupBlockedError when window.open returns null", async () => {
      windowOpenSpy.mockReturnValue(null);
      const stepUpWithPopup = await getStepUpWithPopup();

      await expect(
        stepUpWithPopup({ audience: "https://api.example.com" })
      ).rejects.toBeInstanceOf(PopupBlockedError);
    });
  });

  describe("concurrent popup guard", () => {
    it("should throw PopupInProgressError on second concurrent call", async () => {
      // Setup MSW handler for access token (for the first call)
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );

      const stepUpWithPopup = await getStepUpWithPopup();

      // First call: will wait for postMessage
      const firstPromise = stepUpWithPopup({
        audience: "https://api.example.com"
      });

      // Second call: should throw PopupInProgressError immediately
      await expect(
        stepUpWithPopup({ audience: "https://api.other.com" })
      ).rejects.toBeInstanceOf(PopupInProgressError);

      // Clean up: resolve the first call
      simulatePopupSuccess();
      await firstPromise;
    });
  });

  describe("URL construction", () => {
    it("should construct correct login URL with required params", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise;

      const openUrl = windowOpenSpy.mock.calls[0][0] as string;
      const url = new URL(openUrl, window.location.origin);

      expect(url.pathname).toBe("/auth/login");
      expect(url.searchParams.get("returnTo")).toBe("/");
      // prompt should NOT be present by default (lets Auth0 skip to MFA challenge)
      expect(url.searchParams.has("prompt")).toBe(false);
      expect(url.searchParams.get("acr_values")).toBe(
        "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
      );
      expect(url.searchParams.get("audience")).toBe("https://api.example.com");
      expect(url.searchParams.get("returnStrategy")).toBe("postMessage");
      // Scope should NOT be present when not provided
      expect(url.searchParams.has("scope")).toBe(false);
    });

    it("should include prompt when explicitly provided", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com",
        prompt: "login"
      });
      simulatePopupSuccess();
      await promise;

      const openUrl = windowOpenSpy.mock.calls[0][0] as string;
      const url = new URL(openUrl, window.location.origin);
      expect(url.searchParams.get("prompt")).toBe("login");
    });

    it("should include scope when explicitly provided", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com",
        scope: "openid profile email read:data"
      });
      simulatePopupSuccess();
      await promise;

      const openUrl = windowOpenSpy.mock.calls[0][0] as string;
      const url = new URL(openUrl, window.location.origin);
      expect(url.searchParams.get("scope")).toBe(
        "openid profile email read:data"
      );
    });

    it("should use custom acr_values when provided", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com",
        acr_values: "custom:acr:value"
      });
      simulatePopupSuccess();
      await promise;

      const openUrl = windowOpenSpy.mock.calls[0][0] as string;
      const url = new URL(openUrl, window.location.origin);
      expect(url.searchParams.get("acr_values")).toBe("custom:acr:value");
    });

    it("should use custom returnTo when provided", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com",
        returnTo: "/dashboard"
      });
      simulatePopupSuccess();
      await promise;

      const openUrl = windowOpenSpy.mock.calls[0][0] as string;
      const url = new URL(openUrl, window.location.origin);
      expect(url.searchParams.get("returnTo")).toBe("/dashboard");
    });
  });

  describe("popup dimensions", () => {
    it("should use default dimensions (400x600)", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise;

      const features = windowOpenSpy.mock.calls[0][2] as string;
      expect(features).toContain("width=400");
      expect(features).toContain("height=600");
    });

    it("should use custom dimensions when provided", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com",
        popupWidth: 500,
        popupHeight: 700
      });
      simulatePopupSuccess();
      await promise;

      const features = windowOpenSpy.mock.calls[0][2] as string;
      expect(features).toContain("width=500");
      expect(features).toContain("height=700");
    });
  });

  describe("happy path - token retrieval", () => {
    it("should return AccessTokenResponse on success", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess({
        sub: "auth0|123",
        email: "test@example.com"
      });

      const result = await promise;
      expect(result).toEqual(DEFAULT_TOKEN_RESPONSE);
    });

    it("should pass audience to getAccessToken", async () => {
      server.use(
        http.get("/auth/access-token", ({ request }) => {
          const url = new URL(request.url);
          expect(url.searchParams.get("audience")).toBe(
            "https://api.example.com"
          );
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise;
    });

    it("should pass scope and mergeScopes=false when scope is provided", async () => {
      server.use(
        http.get("/auth/access-token", ({ request }) => {
          const url = new URL(request.url);
          expect(url.searchParams.get("scope")).toBe("read:data");
          expect(url.searchParams.get("mergeScopes")).toBe("false");
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com",
        scope: "read:data"
      });
      simulatePopupSuccess();
      await promise;
    });

    it("should NOT pass scope or mergeScopes when scope is not provided", async () => {
      server.use(
        http.get("/auth/access-token", ({ request }) => {
          const url = new URL(request.url);
          expect(url.searchParams.has("scope")).toBe(false);
          expect(url.searchParams.has("mergeScopes")).toBe(false);
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise;
    });
  });

  describe("postMessage error handling", () => {
    it("should throw AccessTokenError on auth_complete with error", async () => {
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupError({
        code: "access_denied",
        message: "User denied authentication"
      });

      await expect(promise).rejects.toBeInstanceOf(AccessTokenError);
      await expect(promise).rejects.toThrow("User denied authentication");
    });

    it("should throw AccessTokenError for unknown error codes from postMessage", async () => {
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupError({
        code: "server_error",
        message: "Internal server error"
      });

      await expect(promise).rejects.toBeInstanceOf(AccessTokenError);
    });
  });

  describe("token retrieval error handling", () => {
    it("should throw AccessTokenError when /auth/access-token returns error", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(
            {
              error: {
                code: "missing_refresh_token",
                message: "No access token found."
              }
            },
            { status: 400 }
          );
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      const promise = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();

      await expect(promise).rejects.toBeInstanceOf(AccessTokenError);
    });
  });

  describe("cleanup", () => {
    it("should reset activePopup after successful flow", async () => {
      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );
      const stepUpWithPopup = await getStepUpWithPopup();

      // First call succeeds
      const promise1 = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise1;

      // Second call should NOT throw PopupInProgressError
      // (activePopup was cleaned up)
      const promise2 = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise2;
    });

    it("should reset activePopup after error", async () => {
      const stepUpWithPopup = await getStepUpWithPopup();

      // First call errors
      const promise1 = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupError({
        code: "access_denied",
        message: "denied"
      });
      try {
        await promise1;
      } catch {
        // expected
      }

      server.use(
        http.get("/auth/access-token", () => {
          return HttpResponse.json(DEFAULT_TOKEN_RESPONSE);
        })
      );

      // Second call should work
      const promise2 = stepUpWithPopup({
        audience: "https://api.example.com"
      });
      simulatePopupSuccess();
      await promise2;
    });
  });
});
