import React from "react";
// Import the mocked SWR module
import swr, { SWRConfig } from "swr";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { User } from "../../types/index.js";
import { useUser } from "./use-user.js";

// Create a mock for SWR that we can control in our tests
vi.mock("swr", () => {
  const mockMutate = vi.fn();
  return {
    __esModule: true,
    default: vi.fn(() => ({
      data: undefined,
      error: undefined,
      isLoading: true,
      isValidating: false,
      mutate: mockMutate
    }))
  };
});

describe("useUser", () => {
  const mockUser: User = {
    sub: "user_123",
    name: "Test User",
    email: "test@example.com"
  };

  // Get a reference to the mocked SWR default function
  const mockSWR = vi.mocked(swr);

  // Get a reference to the mockMutate function inside the mock
  const mockMutate = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset the default mock implementation
    mockSWR.mockImplementation(() => ({
      data: undefined,
      error: undefined,
      isLoading: true,
      isValidating: false,
      mutate: mockMutate
    }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should return isLoading when no data or error", () => {
    // The default mock implementation has isLoading=true
    const result = useUser();

    expect(result.isLoading).toBe(true);
    expect(result.user).toBe(undefined);
    expect(result.error).toBe(undefined);
    expect(typeof result.invalidate).toBe("function");
  });

  it("should return user data when data is available", () => {
    // Mock SWR to return user data
    mockSWR.mockImplementationOnce(() => ({
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

    // Mock SWR to return error
    mockSWR.mockImplementationOnce(() => ({
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
    // Mock SWR with mockMutate for invalidate testing
    mockSWR.mockImplementationOnce(() => ({
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
