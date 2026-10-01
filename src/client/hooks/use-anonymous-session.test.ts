/**
 * @vitest-environment jsdom
 */

import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AnonymousSession } from "../../types/index.js";
import { useAnonymousSession } from "./use-anonymous-session.js";

describe("M4 BLOCKER: FR-3 useAnonymousSession Hook REAL execution", () => {
  const mockSession: AnonymousSession = {
    id: "anon@uuid-1234",
    accessToken: "bearer-token-xyz",
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
    metadata: { cart: { qty: 5 } }
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // Clear global fetch mock before each test
    global.fetch = vi.fn();
  });

  afterEach(() => {
    // Clean up React components and SWR cache after each test
    cleanup();
  });

  describe("Hook with REAL SWR execution", () => {
    it("M4: Hook returns 200 → {anonymous: session, isLoading: false}", async () => {
      // Mock fetch to return 200 with session
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockSession
      });

      // Use unique route per test to avoid SWR cache collision
      const { result } = renderHook(() =>
        useAnonymousSession({ route: "/test/anon-200" })
      );

      // Wait for SWR to fetch (SWR may skip loading state if data arrives fast)
      await waitFor(() => {
        expect(result.current.anonymous).toEqual(mockSession);
      });

      // ASSERT: session loaded
      expect(result.current.error).toBeNull();
      expect(global.fetch).toHaveBeenCalled();
    });

    it("M4: Hook returns 204 → {anonymous: null, isLoading: false}", async () => {
      // Mock fetch to return 204 (no session)
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 204
      });

      const { result } = renderHook(() =>
        useAnonymousSession({ route: "/test/anon-204" })
      );

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // ASSERT: no session (null)
      expect(result.current.anonymous).toBeNull();
      expect(result.current.error).toBeNull();
    });

    it("M4: Hook fetch error → {error: Error, anonymous: null, isLoading: false}", async () => {
      // Mock fetch to return error
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      });

      const { result } = renderHook(() =>
        useAnonymousSession({ route: "/test/anon-error" })
      );

      await waitFor(
        () => {
          expect(result.current.error).toBeTruthy();
        },
        { timeout: 3000 }
      );

      // ASSERT: error state
      expect(result.current.error).toBeInstanceOf(Error);
      expect(result.current.anonymous).toBeNull();
      expect(result.current.isLoading).toBe(false);
    });

    it("M4: isLoading false after data loads", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockSession
      });

      const { result } = renderHook(() =>
        useAnonymousSession({ route: "/test/anon-loading" })
      );

      // Wait for load to complete
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.anonymous).toEqual(mockSession);
    });

    it("M4: invalidate() triggers SWR revalidation", async () => {
      let callCount = 0;
      global.fetch = vi.fn().mockImplementation(async () => {
        callCount++;
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ...mockSession,
            id: `anon@call-${callCount}`
          })
        };
      });

      const { result } = renderHook(() =>
        useAnonymousSession({ route: "/test/anon-invalidate" })
      );

      // Wait for initial fetch
      await waitFor(() => {
        expect(callCount).toBeGreaterThanOrEqual(1);
      });

      const firstId = result.current.anonymous?.id;

      // Call invalidate to trigger refetch
      await act(async () => {
        result.current.invalidate();
      });

      // Wait for ID to change (React render commit)
      await waitFor(() => {
        expect(result.current.anonymous?.id).not.toBe(firstId);
      });

      // Verify refetch happened
      expect(callCount).toBeGreaterThanOrEqual(2);
    });

    it("M4: Hook uses custom route from options", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockSession
      });

      renderHook(() => useAnonymousSession({ route: "/custom/anon-route" }));

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalled();
      });

      // Verify fetch was called with custom route
      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[0]).toContain("/custom/anon-route");
    });

    it("M4: Hook returns correct shape {anonymous, isLoading, error, invalidate}", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockSession
      });

      const { result } = renderHook(() => useAnonymousSession());

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      // ASSERT: shape matches contract
      expect(result.current).toHaveProperty("anonymous");
      expect(result.current).toHaveProperty("isLoading");
      expect(result.current).toHaveProperty("error");
      expect(result.current).toHaveProperty("invalidate");
      expect(typeof result.current.invalidate).toBe("function");
    });
  });
});
