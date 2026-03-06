import type {
  InstrumentationLogger,
  LogLevel
} from "../types/instrumentation.js";

/**
 * Numeric severity for log level comparison.
 * Higher value = more severe.
 */
const LOG_LEVEL_SEVERITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

const VALID_LOG_LEVELS = new Set<string>(["debug", "info", "warn", "error"]);
const VALID_LOG_TARGETS = new Set<string>(["console"]);

/**
 * Resolve an InstrumentationLogger from environment variables.
 *
 * - `AUTH0_LOGGING_TARGET`: Logging target. Currently only `"console"` is supported.
 *   If unset or invalid, returns `undefined` (no logging).
 * - `AUTH0_LOGGING_LEVEL`: Minimum log level to emit. One of `"debug"`, `"info"`,
 *   `"warn"`, `"error"`. Defaults to `"info"` when a target is configured.
 *
 * @returns An InstrumentationLogger or undefined if env-based logging is not configured.
 */
export function resolveLoggerFromEnvironment():
  | InstrumentationLogger
  | undefined {
  const target = process.env.AUTH0_LOGGING_TARGET?.toLowerCase();
  if (!target || !VALID_LOG_TARGETS.has(target)) {
    return undefined;
  }

  const levelEnv = process.env.AUTH0_LOGGING_LEVEL?.toLowerCase();
  const minLevel: LogLevel =
    levelEnv && VALID_LOG_LEVELS.has(levelEnv)
      ? (levelEnv as LogLevel)
      : "info";
  const minSeverity = LOG_LEVEL_SEVERITY[minLevel];

  return (event) => {
    if (LOG_LEVEL_SEVERITY[event.level] < minSeverity) {
      return;
    }

    const method =
      event.level === "error"
        ? "error"
        : event.level === "warn"
          ? "warn"
          : "log";

    const parts: unknown[] = [
      `[auth0/${event.level}]`,
      event.event,
      event.data
    ];
    if (event.durationMs !== undefined) {
      parts.push(`(${event.durationMs}ms)`);
    }
    // eslint-disable-next-line no-console
    console[method](...parts);
  };
}

/**
 * Encapsulates all instrumentation emission logic.
 * Constructed with an optional logger and optional base context data
 * that is automatically merged into every emitted event.
 * No-op when logger is absent. Never lets logger errors propagate to auth flows.
 */
export class InstrumentationEmitter {
  /** Whether a logger was configured. Used to gate console.warn/error suppression. */
  readonly hasLogger: boolean;

  private logger?: InstrumentationLogger;
  private baseData: Record<string, unknown>;

  constructor(
    logger?: InstrumentationLogger,
    baseData: Record<string, unknown> = {}
  ) {
    this.logger = logger;
    this.hasLogger = !!logger;
    this.baseData = baseData;
  }

  /**
   * Emit an instrumentation event to the configured logger.
   * Base context data is merged under call-site data (call-site wins on conflict).
   * No-op when logger is not configured. Swallows all logger errors.
   */
  emit(
    level: LogLevel,
    event: string,
    data: Record<string, unknown>,
    durationMs?: number
  ): void {
    if (!this.logger) {
      return;
    }

    try {
      const result: any = this.logger({
        event,
        level,
        timestamp: new Date().toISOString(),
        data: { ...this.baseData, ...data },
        ...(durationMs !== undefined ? { durationMs } : {})
      });
      // Prevent unhandled rejection if logger is async
      if (result && typeof result.catch === "function") {
        result.catch(() => {});
      }
    } catch {
      // Swallow - never let logger errors break auth flows
    }
  }

  /**
   * Emit an error-level instrumentation event, extracting fields from the error object.
   *
   * Extracts from the error:
   * - `errorType`: from `error.constructor.name` (overridable via options)
   * - `message`: from `error.error_description` (OAuth) → `error.message` → `String(error)`
   * - `code`: from `options.code` → `error.code` → `error.error` (OAuth)
   */
  emitError(
    operation: string,
    error: unknown,
    options?: {
      code?: string | number;
      errorType?: string;
      durationMs?: number;
    }
  ): void {
    if (!this.logger) {
      return;
    }

    const isErrorLike = error !== null && typeof error === "object";
    const err = error as Record<string, any>;

    const errorType =
      options?.errorType ??
      (isErrorLike && err.constructor?.name ? err.constructor.name : "Error");
    const message = isErrorLike
      ? (err.error_description ?? err.message ?? String(error))
      : String(error);
    const code =
      options?.code ?? (isErrorLike ? (err.code ?? err.error) : undefined);

    this.emit(
      "error",
      "error",
      {
        operation,
        errorType,
        message,
        ...(code !== undefined ? { code } : {})
      },
      options?.durationMs
    );
  }
}
