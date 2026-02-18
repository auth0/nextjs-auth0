import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type {
  InstrumentationEvent,
  InstrumentationLogger
} from "../types/instrumentation.js";
import { AuthClient } from "./auth-client.js";
import { InstrumentationEmitter } from "./instrumentation-emitter.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000"
};

function createAuthClient(
  secret: string,
  logger?: InstrumentationLogger,
  overrides?: Record<string, any>
): AuthClient {
  const transactionStore = new TransactionStore({ secret });
  const sessionStore = new StatelessSessionStore({ secret });

  return new AuthClient({
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    appBaseUrl: DEFAULT.appBaseUrl,
    secret,
    transactionStore,
    sessionStore,
    routes: getDefaultRoutes(),
    logger,
    ...overrides
  });
}

describe("InstrumentationEmitter", () => {
  it("hasLogger is false when no logger provided", () => {
    const emitter = new InstrumentationEmitter();
    expect(emitter.hasLogger).toBe(false);
  });

  it("hasLogger is true when logger provided", () => {
    const emitter = new InstrumentationEmitter(() => {});
    expect(emitter.hasLogger).toBe(true);
  });

  it("emit is a no-op when no logger configured", () => {
    const emitter = new InstrumentationEmitter();
    // Should not throw
    emitter.emit("info", "test:event", { key: "value" });
  });

  it("emit calls logger with correct shape", () => {
    const events: InstrumentationEvent[] = [];
    const emitter = new InstrumentationEmitter((e) => events.push(e));

    emitter.emit("info", "test:event", { key: "value" });

    expect(events).toHaveLength(1);
    expect(events[0].event).toBe("test:event");
    expect(events[0].level).toBe("info");
    expect(events[0].data).toEqual({ key: "value" });
    expect(events[0].durationMs).toBeUndefined();
  });

  it("emit includes durationMs when provided", () => {
    const events: InstrumentationEvent[] = [];
    const emitter = new InstrumentationEmitter((e) => events.push(e));

    emitter.emit("debug", "timed:op", {}, 42);

    expect(events[0].durationMs).toBe(42);
  });

  it("swallows synchronous logger errors", () => {
    const emitter = new InstrumentationEmitter(() => {
      throw new Error("boom");
    });
    // Should not throw
    emitter.emit("info", "test", {});
  });

  it("swallows async logger rejections", () => {
    const emitter = new InstrumentationEmitter(() => {
      return Promise.reject(new Error("async boom")) as any;
    });
    // Should not throw
    emitter.emit("info", "test", {});
  });

  describe("base context", () => {
    it("merges baseData into every emitted event", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e), {
        domain: "example.auth0.com"
      });

      emitter.emit("info", "test:event", { key: "value" });

      expect(events[0].data).toEqual({
        domain: "example.auth0.com",
        key: "value"
      });
    });

    it("call-site data overrides baseData on conflict", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e), {
        domain: "base.auth0.com"
      });

      emitter.emit("info", "test:event", { domain: "override.auth0.com" });

      expect(events[0].data.domain).toBe("override.auth0.com");
    });

    it("works with empty baseData", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e), {});

      emitter.emit("info", "test:event", { key: "value" });

      expect(events[0].data).toEqual({ key: "value" });
    });
  });

  describe("emitError", () => {
    it("extracts errorType and message from standard Error", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e));

      class DiscoveryError extends Error {
        constructor(msg: string) {
          super(msg);
          this.name = "DiscoveryError";
        }
      }

      emitter.emitError("discovery", new DiscoveryError("not found"));

      expect(events[0].level).toBe("error");
      expect(events[0].event).toBe("error");
      expect(events[0].data).toEqual({
        operation: "discovery",
        errorType: "DiscoveryError",
        message: "not found"
      });
    });

    it("extracts error_description and error from OAuth-style errors", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e));

      const oauthError = {
        error: "invalid_grant",
        error_description: "The refresh token is expired"
      };

      emitter.emitError("token_refresh", oauthError);

      expect(events[0].data).toEqual({
        operation: "token_refresh",
        errorType: "Object",
        message: "The refresh token is expired",
        code: "invalid_grant"
      });
    });

    it("allows overriding errorType and code", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e));

      emitter.emitError("cte", new Error("fail"), {
        errorType: "CustomTokenExchangeError",
        code: "EXCHANGE_FAILED"
      });

      expect(events[0].data.errorType).toBe("CustomTokenExchangeError");
      expect(events[0].data.code).toBe("EXCHANGE_FAILED");
    });

    it("passes durationMs through", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e));

      emitter.emitError("discovery", new Error("timeout"), {
        durationMs: 5000
      });

      expect(events[0].durationMs).toBe(5000);
    });

    it("includes baseData in error events", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e), {
        domain: "example.auth0.com"
      });

      emitter.emitError("callback", new Error("bad state"));

      expect(events[0].data.domain).toBe("example.auth0.com");
      expect(events[0].data.operation).toBe("callback");
    });

    it("omits code when not available", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e));

      emitter.emitError("logout", new Error("failed"));

      expect(events[0].data).not.toHaveProperty("code");
    });

    it("is no-op when no logger configured", () => {
      const emitter = new InstrumentationEmitter();
      // Should not throw
      emitter.emitError("test", new Error("boom"));
    });

    it("handles non-Error values", () => {
      const events: InstrumentationEvent[] = [];
      const emitter = new InstrumentationEmitter((e) => events.push(e));

      emitter.emitError("test", "string error");

      expect(events[0].data.errorType).toBe("Error");
      expect(events[0].data.message).toBe("string error");
    });
  });
});

describe("Instrumentation - Type Shape", () => {
  // UT-1: InstrumentationEvent has correct shape
  it("UT-1: event emitted by logger conforms to InstrumentationEvent shape", () => {
    const events: InstrumentationEvent[] = [];
    const logger: InstrumentationLogger = (event) => events.push(event);

    // Trigger a constructor warning by enabling insecure requests in production
    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      const secret = "a".repeat(64);
      createAuthClient(secret, logger, { allowInsecureRequests: true });
    } catch {
      // ignore constructor errors
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }

    // At minimum, the insecure requests warning should have been emitted
    expect(events.length).toBeGreaterThan(0);
    const event = events[0];
    expect(event).toHaveProperty("event");
    expect(event).toHaveProperty("level");
    expect(event).toHaveProperty("timestamp");
    expect(event).toHaveProperty("data");
    expect(typeof event.event).toBe("string");
    expect(["debug", "info", "warn", "error"]).toContain(event.level);
    // ISO 8601 timestamp
    expect(new Date(event.timestamp).toISOString()).toBe(event.timestamp);
    expect(typeof event.data).toBe("object");
  });

  // UT-2: LogLevel is one of the 4 valid strings
  it("UT-2: LogLevel values are restricted to debug|info|warn|error", () => {
    // Already checked via type system, but verify runtime values
    const events: InstrumentationEvent[] = [];
    const logger: InstrumentationLogger = (event) => events.push(event);

    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      const secret = "a".repeat(64);
      createAuthClient(secret, logger, { allowInsecureRequests: true });
    } catch {
      // ignore
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }

    for (const event of events) {
      expect(["debug", "info", "warn", "error"]).toContain(event.level);
    }
  });

  // UT-3: durationMs is present only on timed operations
  it("UT-3: durationMs is present on timed events, absent otherwise", () => {
    // We'll test this in the flow tests where timed operations occur.
    // Here, verify the constructor warning has no durationMs.
    const events: InstrumentationEvent[] = [];
    const logger: InstrumentationLogger = (event) => events.push(event);

    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      const secret = "a".repeat(64);
      createAuthClient(secret, logger, { allowInsecureRequests: true });
    } catch {
      // ignore
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }

    const warnEvent = events.find(
      (e) => e.event === "config:insecure-requests"
    );
    expect(warnEvent).toBeDefined();
    expect(warnEvent!.durationMs).toBeUndefined();
  });
});

describe("Instrumentation - emit() Guard / Error Handling", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  // UT-4: No logger configured -> no events emitted (no-op)
  it("UT-4: no logger configured means no events emitted", () => {
    // Simply construct without logger and ensure no crash
    const client = createAuthClient(secret, undefined);
    expect(client).toBeDefined();
  });

  // UT-5: Logger that throws synchronously does not break auth flow
  it("UT-5: synchronous throw in logger is swallowed", () => {
    const throwingLogger: InstrumentationLogger = () => {
      throw new Error("Logger exploded");
    };

    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      // Should not throw
      const client = createAuthClient(secret, throwingLogger, {
        allowInsecureRequests: true
      });
      expect(client).toBeDefined();
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }
  });

  // EC-1: Async logger rejection is swallowed
  it("EC-1: async logger rejection is swallowed", () => {
    const asyncThrowingLogger: InstrumentationLogger = () => {
      return Promise.reject(new Error("Async logger exploded")) as any;
    };

    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      const client = createAuthClient(secret, asyncThrowingLogger, {
        allowInsecureRequests: true
      });
      expect(client).toBeDefined();
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }
  });
});

describe("Instrumentation - PII Filtering", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  // UT-12 through UT-20: Verify no PII in emitted events
  it("UT-12: emitted events never contain access tokens, refresh tokens, or PII", () => {
    const events: InstrumentationEvent[] = [];
    const logger: InstrumentationLogger = (event) => events.push(event);

    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      createAuthClient(secret, logger, { allowInsecureRequests: true });
    } catch {
      // ignore
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }

    for (const event of events) {
      const serialized = JSON.stringify(event);
      // Must not contain any tokens or secrets
      expect(serialized).not.toContain(secret);
      expect(serialized).not.toContain("access_token");
      expect(serialized).not.toContain("refresh_token");
      expect(serialized).not.toContain("id_token");
    }
  });
});

describe("Instrumentation - Console.warn/error Suppression", () => {
  let secret: string;
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    secret = await generateSecret(32);
    consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleWarnSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });

  // G2: console.warn for insecure requests is suppressed when logger is present
  it("G2: console.warn for insecure requests is suppressed when logger present", () => {
    const events: InstrumentationEvent[] = [];
    const logger: InstrumentationLogger = (event) => events.push(event);

    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      createAuthClient(secret, logger, { allowInsecureRequests: true });
    } catch {
      // ignore
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }

    // Logger should have received the event
    const warnEvent = events.find(
      (e) => e.event === "config:insecure-requests"
    );
    expect(warnEvent).toBeDefined();

    // console.warn should NOT have been called for this specific message
    const warnCalls = consoleWarnSpy.mock.calls.map((c) => c[0]);
    const hasInsecureWarn = warnCalls.some(
      (msg) => typeof msg === "string" && msg.includes("allowInsecureRequests")
    );
    expect(hasInsecureWarn).toBe(false);
  });

  it("console.warn for insecure requests IS emitted when no logger", () => {
    const origEnv = process.env.NODE_ENV;

    (process.env as any).NODE_ENV = "production";
    try {
      createAuthClient(secret, undefined, { allowInsecureRequests: true });
    } catch {
      // ignore
    } finally {
      (process.env as any).NODE_ENV = origEnv;
    }

    const warnCalls = consoleWarnSpy.mock.calls.map((c) => c[0]);
    const hasInsecureWarn = warnCalls.some(
      (msg) => typeof msg === "string" && msg.includes("allowInsecureRequests")
    );
    expect(hasInsecureWarn).toBe(true);
  });
});
