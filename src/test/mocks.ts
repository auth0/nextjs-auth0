import * as oauth from "oauth4webapi";
import { vi } from "vitest";

import { RequestCookies } from "../server/cookies.js";

/**
 * Creates a mock factory for next/headers.js
 *
 * Usage in test files:
 *   vi.mock("next/headers.js", () => createNextHeadersMock());
 *
 * Options:
 *   - cookies: whether to mock the cookies function (default: true)
 */
export async function createNextHeadersMock(options?: { cookies?: boolean }) {
  const actual =
    await vi.importActual<typeof import("next/headers.js")>("next/headers.js");

  const mock: Record<string, any> = {
    ...actual,
    headers: vi.fn().mockImplementation(() => {
      return new Headers();
    })
  };

  if (options?.cookies !== false) {
    mock.cookies = vi.fn().mockImplementation(async () => {
      return new RequestCookies(new Headers());
    });
  }

  return mock;
}

/**
 * Creates a mock factory for oauth4webapi with DPoP support
 *
 * Usage in test files:
 *   vi.mock("oauth4webapi", () => createOAuth4WebapiDPopMock());
 *
 * Mocks:
 *   - protectedResourceRequest: vi.fn()
 *   - isDPoPNonceError: vi.fn()
 *   - DPoP: vi.fn((client, keyPair) => ({ client, keyPair }))
 *   - generateKeyPair: vi.fn() returning mock CryptoKey objects
 *   - discoveryRequest: vi.fn()
 *   - processDiscoveryResponse: vi.fn()
 *   - customFetch: Symbol("customFetch")
 *   - allowInsecureRequests: Symbol("allowInsecureRequests")
 */
export async function createOAuth4WebapiDPopMock() {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");

  return {
    ...actual,
    protectedResourceRequest: vi.fn(),
    isDPoPNonceError: vi.fn(),
    DPoP: vi.fn((client, keyPair) => ({ client, keyPair })),
    generateKeyPair: vi.fn(async () => ({
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    })),
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    customFetch: Symbol("customFetch"),
    allowInsecureRequests: Symbol("allowInsecureRequests")
  };
}

/**
 * Creates a minimal mock factory for oauth4webapi
 *
 * Usage in test files:
 *   vi.mock("oauth4webapi", () => createOAuth4WebapiMock());
 *
 * Mocks only essential functions:
 *   - protectedResourceRequest: vi.fn()
 *   - isDPoPNonceError: vi.fn()
 *   - DPoP: vi.fn()
 */
export async function createOAuth4WebapiMock() {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");

  return {
    ...actual,
    protectedResourceRequest: vi.fn(),
    isDPoPNonceError: vi.fn(),
    DPoP: vi.fn()
  };
}
