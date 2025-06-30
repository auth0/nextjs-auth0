/**
 * @vitest-environment jsdom
 */

import React from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import * as swrModule from "swr";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance
} from "vitest";

import type { User } from "../../types/index.js";
import { useUser } from "./use-user.js";

// New test suite for integration testing with fetch and SWR cache
describe("useUser Integration with SWR Cache", () => {
  const initialUser: User = {
    sub: "initial_user_123",
    name: "Initial User",
    email: "initial@example.com"
  };
  const updatedUser: User = {
    sub: "updated_user_456",
    name: "Updated User",
    email: "updated@example.com"
  };

  // Explicitly type fetchSpy using MockInstance and the global fetch signature
  let fetchSpy: MockInstance<
    (
      input: RequestInfo | URL,
      init?: RequestInit | undefined
    ) => Promise<Response>
  >;

  beforeEach(() => {
    // Mock the global fetch
    fetchSpy = vi.spyOn(global, "fetch");
  });

  afterEach(() => {
    vi.restoreAllMocks(); // Restore original fetch implementation
  });

  it("should fetch initial user data and update after invalidate", async () => {
    // Mock fetch to return initial data first
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(initialUser), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );

    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <swrModule.SWRConfig value={{ provider: () => new Map() }}>
        {children}
      </swrModule.SWRConfig>
    );

    const { result } = renderHook(() => useUser(), { wrapper });

    // Wait for the initial data to load
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    // Assert initial state
    expect(result.current.user).toEqual(initialUser);
    expect(result.current.error).toBe(null);

    // Mock fetch to return updated data for the next call
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(updatedUser), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );

    // Call invalidate to trigger re-fetch
    await act(async () => {
      result.current.invalidate();
    });

    // Wait for the hook to reflect the updated data
    await waitFor(() => expect(result.current.user).toEqual(updatedUser));

    // Assert updated state
    expect(result.current.user).toEqual(updatedUser);
    expect(result.current.error).toBe(null);
    expect(result.current.isLoading).toBe(false);

    // Verify fetch was called twice (initial load + invalidate)
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(fetchSpy).toHaveBeenCalledWith("/auth/profile");
  });

  it("should handle fetch error during invalidation", async () => {
    // Mock fetch to return initial data first
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(initialUser), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );

    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <swrModule.SWRConfig
        value={{
          provider: () => new Map(),
          shouldRetryOnError: false,
          dedupingInterval: 0
        }}
      >
        {children}
      </swrModule.SWRConfig>
    );

    const { result } = renderHook(() => useUser(), { wrapper });

    // Wait for the initial data to load
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.user).toEqual(initialUser);

    // Mock fetch to return an error for the next call
    const fetchError = new Error("Network Error");
    fetchSpy.mockRejectedValueOnce(fetchError);

    // Call invalidate to trigger re-fetch
    await act(async () => {
      result.current.invalidate();
    });

    // Wait for the hook to reflect the error state, user should still be the initial one before error
    await waitFor(() => expect(result.current.error).not.toBeNull());

    // Assert error state - SWR catches the rejection from fetch itself.
    // Check for the message of the error we explicitly rejected with.
    expect(result.current.user).toBeNull(); // Expect null now, not stale data
    expect(result.current.error?.message).toBe(fetchError.message); // Correct assertion
    expect(result.current.isLoading).toBe(false);

    // Verify fetch was called twice
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("should handle unauthenticated requests to the profile endpoint", async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(null, {
        status: 204
      })
    );

    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <swrModule.SWRConfig value={{ provider: () => new Map() }}>
        {children}
      </swrModule.SWRConfig>
    );

    const { result } = renderHook(() => useUser(), { wrapper });

    // Wait for the initial data to load
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.user).toEqual(null);
    expect(result.current.error).toBe(undefined);
    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(fetchSpy).toHaveBeenCalledWith("/auth/profile");
  });
});
