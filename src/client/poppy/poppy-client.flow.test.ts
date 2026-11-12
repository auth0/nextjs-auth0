// @vitest-environment jsdom
// @vitest-environment-options {"url": "http://localhost:3000"}
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { PoppyError, PoppyErrorCode } from "../../errors/index.js";
import type { PoppyContext } from "../../types/index.js";
import { poppy } from "./index.js";

const CONTEXT_URL = "http://localhost:3000/auth/poppy-context";

const guest: PoppyContext = {
  kind: "agent",
  state: "guest",
  agent: { clientId: "https://muse.example/agent.json" },
  sub: "https://muse.example/agent.json",
  poppy_sid: "s_8Hq2",
  poppy_user_id: "u_Q7c1",
  scopes: []
};

const server = setupServer();

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
  vi.unstubAllEnvs();
});

afterAll(() => {
  server.close();
});

async function rejection(promise: Promise<unknown>): Promise<PoppyError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(PoppyError);
  return error as PoppyError;
}

describe("poppy.getContext", () => {
  it("returns the context from the route", async () => {
    server.use(http.get(CONTEXT_URL, () => HttpResponse.json(guest)));
    expect(await poppy.getContext()).toEqual(guest);
  });

  it("returns a person", async () => {
    server.use(
      http.get(CONTEXT_URL, () => HttpResponse.json({ kind: "human" }))
    );
    expect(await poppy.getContext()).toEqual({ kind: "human" });
  });

  it("uses NEXT_PUBLIC_POPPY_CONTEXT_ROUTE", async () => {
    vi.stubEnv("NEXT_PUBLIC_POPPY_CONTEXT_ROUTE", "/api/who");
    server.use(
      http.get("http://localhost:3000/api/who", () => HttpResponse.json(guest))
    );
    expect(await poppy.getContext()).toEqual(guest);
  });

  it("says Poppy isn't enabled when the route answers 404", async () => {
    server.use(
      http.get(
        CONTEXT_URL,
        () => new HttpResponse("Not found", { status: 404 })
      )
    );
    const error = await rejection(poppy.getContext());
    expect(error.code).toBe(PoppyErrorCode.NOT_ENABLED);
    expect(error.message).toContain("`poppy` option");
  });

  it("reports any other failure as unavailable, with the status", async () => {
    server.use(
      http.get(CONTEXT_URL, () => new HttpResponse(null, { status: 401 }))
    );
    const error = await rejection(poppy.getContext());
    expect(error.code).toBe(PoppyErrorCode.CONTEXT_UNAVAILABLE);
    expect(error.message).toContain("HTTP 401");
  });

  it("reports a network error as unavailable", async () => {
    server.use(http.get(CONTEXT_URL, () => HttpResponse.error()));
    const error = await rejection(poppy.getContext());
    expect(error.code).toBe(PoppyErrorCode.CONTEXT_UNAVAILABLE);
  });

  it("reports a body that isn't JSON as unavailable", async () => {
    server.use(
      http.get(CONTEXT_URL, () => new HttpResponse("<html>", { status: 200 }))
    );
    const error = await rejection(poppy.getContext());
    expect(error.code).toBe(PoppyErrorCode.CONTEXT_UNAVAILABLE);
  });
});
