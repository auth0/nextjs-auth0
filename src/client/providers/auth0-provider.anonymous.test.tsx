/**
 * @vitest-environment jsdom
 */

import React from "react";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { SWRConfig } from "swr";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AnonymousSession } from "../../types/index.js";
import { useAnonymousSession } from "../hooks/use-anonymous-session.js";
import { Auth0Provider } from "./auth0-provider.js";

describe("M5 BLOCKER: FR-8 Auth0Provider anonymousSession prop", () => {
  const mockSession: AnonymousSession = {
    id: "anon@uuid-seeded",
    accessToken: "bearer-token-seeded",
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
    metadata: { cart: { qty: 10 } }
  };

  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  afterEach(() => {
    // Clean up React components and SWR cache after each test
    cleanup();
  });

  describe("Provider anonymousSession prop seeds SWR fallback", () => {
    it("M5: Provider with anonymousSession={seed} → hook gets seeded value with NO loading flash", async () => {
      // Mock fetch — should NOT be called because SWR uses fallback
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockSession
      });

      // Render hook inside provider with seeded anonymousSession and isolated SWR cache
      const wrapper = ({ children }: { children: React.ReactNode }) => (
        <SWRConfig
          value={{
            provider: () => new Map(),
            revalidateOnMount: false,
            revalidateIfStale: false
          }}
        >
          <Auth0Provider anonymousSession={mockSession}>
            {children}
          </Auth0Provider>
        </SWRConfig>
      );

      const { result } = renderHook(() => useAnonymousSession(), { wrapper });

      // CRITICAL ASSERTION: NO loading flash (isLoading false on first render)
      expect(result.current.isLoading).toBe(false);
      expect(result.current.anonymous).toEqual(mockSession);
      expect(result.current.error).toBeNull();

      // Verify fetch was NOT called (SWR used fallback, revalidation disabled)
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it("M5: Provider with anonymousSession={null} → hook gets null with NO loading flash", async () => {
      global.fetch = vi.fn();

      const wrapper = ({ children }: { children: React.ReactNode }) => (
        <SWRConfig value={{ provider: () => new Map() }}>
          <Auth0Provider anonymousSession={null}>{children}</Auth0Provider>
        </SWRConfig>
      );

      const { result } = renderHook(() => useAnonymousSession(), { wrapper });

      // NO loading flash, immediate null
      expect(result.current.isLoading).toBe(false);
      expect(result.current.anonymous).toBeNull();
      expect(result.current.error).toBeNull();

      // Fetch not called (fallback present)
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it("M5: Provider WITHOUT anonymousSession prop → hook fetches normally (loading flash present)", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockSession
      });

      // Provider WITHOUT anonymousSession prop
      const wrapper = ({ children }: { children: React.ReactNode }) => (
        <SWRConfig value={{ provider: () => new Map() }}>
          <Auth0Provider>{children}</Auth0Provider>
        </SWRConfig>
      );

      const { result } = renderHook(() => useAnonymousSession(), { wrapper });

      // Initial state: loading true (NO fallback, normal fetch)
      expect(result.current.isLoading).toBe(true);
      expect(result.current.anonymous).toBeNull();

      // Wait for fetch to complete
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // After fetch: data present
      expect(result.current.anonymous).toEqual(mockSession);
      expect(global.fetch).toHaveBeenCalled();
    });

    it("M5: Seeded value matches hook return exactly", async () => {
      const customSession: AnonymousSession = {
        id: "anon@custom-seed",
        accessToken: "custom-token",
        expiresAt: Math.floor(Date.now() / 1000) + 7200,
        metadata: { preferences: { theme: "dark" } }
      };

      global.fetch = vi.fn();

      const customRoute = "/test/custom-seed";
      const wrapper = ({ children }: { children: React.ReactNode }) => (
        <SWRConfig value={{ provider: () => new Map() }}>
          <Auth0Provider
            anonymousSession={customSession}
            anonymousSessionRoute={customRoute}
          >
            {children}
          </Auth0Provider>
        </SWRConfig>
      );

      const { result } = renderHook(
        () => useAnonymousSession({ route: customRoute }),
        { wrapper }
      );

      // EXACT match (not just shape)
      expect(result.current.anonymous?.id).toBe("anon@custom-seed");
      expect(result.current.anonymous?.metadata).toEqual({
        preferences: { theme: "dark" }
      });
    });

    it("M5: Custom anonymousSessionRoute works with seeded value", async () => {
      global.fetch = vi.fn();

      const wrapper = ({ children }: { children: React.ReactNode }) => (
        <SWRConfig value={{ provider: () => new Map() }}>
          <Auth0Provider
            anonymousSession={mockSession}
            anonymousSessionRoute="/custom/anon"
          >
            {children}
          </Auth0Provider>
        </SWRConfig>
      );

      const { result } = renderHook(
        () => useAnonymousSession({ route: "/custom/anon" }),
        { wrapper }
      );

      // Seeded value present, no fetch
      expect(result.current.isLoading).toBe(false);
      expect(result.current.anonymous).toEqual(mockSession);
      expect(global.fetch).not.toHaveBeenCalled();
    });
  });
});
