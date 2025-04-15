/**
 * @vitest-environment jsdom
 */

import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import * as swrModule from "swr";

import type { User } from "../../types/index.js";
import { useUser } from "./use-user.js";

// Define mockMutate outside the mock factory so it can be referenced in tests
const mockMutate = vi.fn();

// Mock the SWR module, preserving original exports like SWRConfig
// vi.mock("swr", async (importActual) => {
//   const actual = await importActual<typeof swrModule>();
//   return {
//     ...actual,
//     default: vi.fn(() => ({ // Mock the default export (useSWR hook)
//       data: undefined,
//       error: undefined,
//       isLoading: true,
//       isValidating: false,
//       mutate: mockMutate
//     }))
//   };
// });

describe("useUser", () => {
  const mockUser: User = {
    sub: "user_123",
    name: "Test User",
    email: "test@example.com"
  };

  // No need to mock swrModule.default here anymore, done globally

  beforeEach(() => {
    // Clear mocks before each test
    vi.clearAllMocks();
    mockMutate.mockClear();
  });

  afterEach(() => {
    // restoreAllMocks handles spies and mocks
    vi.restoreAllMocks();
  });

  it("should return isLoading when no data or error", () => {
    // Reset the global mock implementation for this specific test
    vi.mocked(swrModule.default).mockImplementation(() => ({
      data: undefined,
      error: undefined,
      isLoading: true,
      isValidating: false,
      mutate: mockMutate
    }));
    const result = useUser();

    expect(result.isLoading).toBe(true);
    expect(result.user).toBe(undefined);
    expect(result.error).toBe(undefined);
    expect(typeof result.invalidate).toBe("function");
  });

  it("should return user data when data is available", () => {
    // Mock SWR default export (useSWR hook) to return user data for this test
    vi.mocked(swrModule.default).mockImplementationOnce(() => ({
      data: mockUser,
      error: undefined,
      isLoading: false,
      isValidating: false,
      mutate: mockMutate
    }));

    const result = useUser();

    expect(result.isLoading).toBe(false);
    expect(result.user).toBe(mockUser);
    expect(result.error).toBe(null);
    expect(typeof result.invalidate).toBe("function");
  });

  it("should return error when fetch fails", () => {
    const mockError = new Error("Unauthorized");
    // Mock SWR default export (useSWR hook) to return error for this test
    vi.mocked(swrModule.default).mockImplementationOnce(() => ({
      data: undefined,
      error: mockError,
      isLoading: false,
      isValidating: false,
      mutate: mockMutate
    }));

    const result = useUser();

    expect(result.isLoading).toBe(false);
    expect(result.user).toBe(null);
    expect(result.error).toBe(mockError);
    expect(typeof result.invalidate).toBe("function");
  });

  it("should call mutate when invalidate is called", () => {
    // Mock SWR default export (useSWR hook) with mockMutate for invalidate testing
    vi.mocked(swrModule.default).mockImplementationOnce(() => ({
      data: mockUser,
      error: undefined,
      isLoading: false,
      isValidating: false,
      mutate: mockMutate
    }));

    const result = useUser();

    // Call invalidate function
    result.invalidate();

    // Verify mutate was called
    expect(mockMutate).toHaveBeenCalledTimes(1);
  });
});

// New test suite for integration testing with fetch and SWR cache
describe.only("useUser Integration with SWR Cache", () => {
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
    (input: RequestInfo | URL, init?: RequestInit | undefined) => Promise<Response>
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
      <swrModule.SWRConfig value={{ provider: () => new Map() }}>{children}</swrModule.SWRConfig>
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
    expect(result.current.user).toEqual(initialUser); // SWR might keep stale data upon rejection
    expect(result.current.error?.message).toBe(fetchError.message); // Correct assertion
    expect(result.current.isLoading).toBe(false);

    // Verify fetch was called twice
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});
