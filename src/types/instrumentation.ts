/**
 * Severity/category of an instrumentation event.
 *
 * - `'debug'`: Verbose, dev-only. Includes discovery details, session reads, MFA steps.
 * - `'info'`: General operational events. Auth flow start/complete, session create/delete.
 * - `'warn'`: Unexpected but recoverable situations.
 * - `'error'`: Failures that affect the auth flow.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * A single instrumentation event emitted by the SDK.
 * All fields are PII-filtered by the SDK before emission.
 *
 * @example
 * ```typescript
 * {
 *   event: 'auth:login:start',
 *   level: 'info',
 *   timestamp: '2026-02-18T12:00:00.000Z',
 *   data: { domain: 'example.auth0.com', scope: 'openid profile' }
 * }
 * ```
 */
export interface InstrumentationEvent {
  /** Event name, namespaced: 'auth:login:start', 'discovery:start', etc. */
  event: string;

  /** Severity / category */
  level: LogLevel;

  /** ISO 8601 timestamp of when the event was emitted */
  timestamp: string;

  /** PII-filtered event data. Shape varies per event type. */
  data: Record<string, unknown>;

  /** Duration in ms for timed operations (present on 'complete' events) */
  durationMs?: number;
}

/**
 * Logger callback provided by the consumer.
 * The SDK calls this synchronously at each instrumentation point.
 * If the logger throws, the error is silently swallowed.
 * If the logger returns a Promise, it is not awaited.
 *
 * @example
 * ```typescript
 * const logger: InstrumentationLogger = (event) => {
 *   console.log(`[${event.level}] ${event.event}`, event.data);
 * };
 * ```
 */
export type InstrumentationLogger = (event: InstrumentationEvent) => void;
