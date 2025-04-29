import * as swrModule from "swr";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { User } from "../../types/index.js";
import { useUser } from "./use-user.js";

// Define mockMutate outside the mock factory so it can be referenced in tests
const mockMutate = vi.fn();

// Mock the SWR module, preserving original exports like SWRConfig
vi.mock("swr", async (importActual) => {
  const actual = await importActual<typeof swrModule>();
  return {
    ...actual,
    default: vi.fn(() => ({
      // Mock the default export (useSWR hook)
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
