import { describe, expect, it, vi } from "vitest";

import { createFetcher } from "./index.js";

describe("createFetcher standalone function", () => {
  it("should create a fetcher using Auth0Client.createFetcher method", () => {
    const mockCreateFetcher = vi.fn().mockReturnValue({
      fetchWithAuth: vi.fn()
    });

    const mockAuth0Client = {
      createFetcher: mockCreateFetcher
    };

    const config = { baseUrl: "https://api.example.com" };
    const fetcher = createFetcher(mockAuth0Client, config);

    expect(mockCreateFetcher).toHaveBeenCalledWith(config);
    expect(fetcher).toBeDefined();
    expect(typeof fetcher.fetchWithAuth).toBe("function");
  });

  it("should work with empty config", () => {
    const mockCreateFetcher = vi.fn().mockReturnValue({
      fetchWithAuth: vi.fn()
    });

    const mockAuth0Client = {
      createFetcher: mockCreateFetcher
    };

    const fetcher = createFetcher(mockAuth0Client);

    expect(mockCreateFetcher).toHaveBeenCalledWith({});
    expect(fetcher).toBeDefined();
  });
});
