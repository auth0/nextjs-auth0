import { describe, expect, it } from "vitest";

import { TokenRequestCache } from "./token-request-cache.js";

describe("Token Request Cache", () => {
  it("should cache when audience and scope provided", async () => {
    const cache = new TokenRequestCache();
    const options = {
      options: { audience: "test-audience", scope: "read:messages" },
      authorizationParameters: {
        audience: "test-audience",
        scope: "read:messages"
      }
    };
    const requestHandler = () =>
      Promise.resolve({ token: "token_1", expiresAt: 1, scope: "" });
    const requestHandler2 = () =>
      Promise.resolve({ token: "token_2", expiresAt: 1, scope: "" });

    const execute1 = cache.execute(requestHandler, options);
    const execute2 = cache.execute(requestHandler2, options);

    const [res1, res2] = await Promise.all([execute1, execute2]);

    expect(res1.token).toBe("token_1");
    expect(res2.token).toBe("token_1");
  });

  it("should cache when only global scope and audience provided", async () => {
    const cache = new TokenRequestCache();
    const options = {
      options: {},
      authorizationParameters: {
        audience: "test-audience",
        scope: "read:messages"
      }
    };
    const requestHandler = () =>
      Promise.resolve({ token: "token_1", expiresAt: 1, scope: "" });
    const requestHandler2 = () =>
      Promise.resolve({ token: "token_2", expiresAt: 1, scope: "" });

    const execute1 = cache.execute(requestHandler, options);
    const execute2 = cache.execute(requestHandler2, options);

    const [res1, res2] = await Promise.all([execute1, execute2]);

    expect(res1.token).toBe("token_1");
    expect(res2.token).toBe("token_1");
  });

  it("should not cache when same audience and different scope provided", async () => {
    const cache = new TokenRequestCache();
    const options = {
      options: { audience: "test-audience", scope: "read:messages" },
      authorizationParameters: {
        audience: "test-audience",
        scope: "read:messages"
      }
    };
    const options2 = {
      options: { audience: "test-audience", scope: "write:messages" },
      authorizationParameters: {
        audience: "test-audience",
        scope: "read:messages"
      }
    };
    const requestHandler = () =>
      Promise.resolve({ token: "token_1", expiresAt: 1, scope: "" });
    const requestHandler2 = () =>
      Promise.resolve({ token: "token_2", expiresAt: 1, scope: "" });

    const execute1 = cache.execute(requestHandler, options);
    const execute2 = cache.execute(requestHandler2, options2);

    const [res1, res2] = await Promise.all([execute1, execute2]);

    expect(res1.token).toBe("token_1");
    expect(res2.token).toBe("token_2");
  });

  it("should not cache when different audience and same scope provided", async () => {
    const cache = new TokenRequestCache();
    const options = {
      options: { audience: "test-audience", scope: "read:messages" },
      authorizationParameters: {
        audience: "test-audience",
        scope: "read:messages"
      }
    };
    const options2 = {
      options: { audience: "test-audience-2", scope: "read:messages" },
      authorizationParameters: {
        audience: "test-audience",
        scope: "read:messages"
      }
    };
    const requestHandler = () =>
      Promise.resolve({ token: "token_1", expiresAt: 1, scope: "" });
    const requestHandler2 = () =>
      Promise.resolve({ token: "token_2", expiresAt: 1, scope: "" });

    const execute1 = cache.execute(requestHandler, options);
    const execute2 = cache.execute(requestHandler2, options2);

    const [res1, res2] = await Promise.all([execute1, execute2]);

    expect(res1.token).toBe("token_1");
    expect(res2.token).toBe("token_2");
  });
});
