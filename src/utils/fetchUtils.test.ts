import { describe, expect, it, vi } from "vitest";

import { createSizeLimitedFetch } from "./fetchUtils.js";

const MAX_SIZE = 1024; // 1 KB for tests

describe("createSizeLimitedFetch", () => {
  it("passes through responses within size limit", async () => {
    const body = "hello";
    const baseFetch = vi.fn().mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: { "content-length": String(body.length) }
      })
    );

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    const response = await wrappedFetch("https://example.com");

    expect(response.status).toEqual(200);
    expect(await response.text()).toEqual(body);
    expect(baseFetch).toHaveBeenCalledOnce();
  });

  it("rejects when Content-Length exceeds limit", async () => {
    const baseFetch = vi.fn().mockResolvedValue(
      new Response("x", {
        headers: { "content-length": String(MAX_SIZE + 1) }
      })
    );

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    await expect(wrappedFetch("https://example.com")).rejects.toThrow(
      /Response body too large.*exceeds.*byte limit/
    );
  });

  it("allows response when Content-Length equals limit exactly", async () => {
    const body = "x".repeat(MAX_SIZE);
    const baseFetch = vi.fn().mockResolvedValue(
      new Response(body, {
        headers: { "content-length": String(MAX_SIZE) }
      })
    );

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    const response = await wrappedFetch("https://example.com");
    expect(await response.text()).toEqual(body);
  });

  it("rejects chunked response exceeding limit during streaming", async () => {
    const oversizedBody = "x".repeat(MAX_SIZE + 1);
    const baseFetch = vi.fn().mockResolvedValue(
      new Response(oversizedBody) // No content-length header
    );

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    const response = await wrappedFetch("https://example.com");
    await expect(response.text()).rejects.toThrow(
      /Response body too large.*exceeded.*byte limit/
    );
  });

  it("passes through response without body", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    const response = await wrappedFetch("https://example.com");
    expect(response.status).toEqual(204);
  });

  it("preserves response status and headers through streaming wrapper", async () => {
    const baseFetch = vi.fn().mockResolvedValue(
      new Response("ok", {
        status: 201,
        statusText: "Created",
        headers: { "x-custom": "value" }
      })
    );

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    const response = await wrappedFetch("https://example.com");
    expect(response.status).toEqual(201);
    expect(response.headers.get("x-custom")).toEqual("value");
  });

  it("forwards input and init to base fetch", async () => {
    const baseFetch = vi.fn().mockResolvedValue(new Response("ok"));
    const init = { method: "POST", body: "data" };

    const wrappedFetch = createSizeLimitedFetch(baseFetch, MAX_SIZE);
    await wrappedFetch("https://example.com/api", init);

    expect(baseFetch).toHaveBeenCalledWith("https://example.com/api", init);
  });
});
