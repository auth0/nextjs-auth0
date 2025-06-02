import { NextRequest, NextResponse } from "next/server";

import type { SessionData, StartInteractiveLoginOptions } from "../types";
import type { TransactionState } from "./transaction-store";

export interface LoginOptions extends StartInteractiveLoginOptions {}

/**
 * Hook executed before the login process begins.
 * It can short-circuit the login by returning a `NextResponse`.
 * @param request The incoming Next.js request.
 * @param options The initial login options.
 * @returns A `Promise` that resolves to `NextResponse` to short-circuit, or `void` to continue.
 */
export type BeforeLoginHook = (
  request: NextRequest,
  options: LoginOptions
) => Promise<NextResponse | void>;

/**
 * Hook executed after the login process completes.
 * It can modify the `NextResponse` or return a new one.
 * If it returns `void`, the (potentially mutated) response passed to it will be used.
 * @param request The incoming Next.js request.
 * @param response The `NextResponse` from the login process. This response object can be mutated by the hook if it returns `void`.
 * @param options The login options used.
 * @returns A `Promise` that resolves to `NextResponse` to replace the original, or `void` to use the (potentially modified) original response.
 */
export type AfterLoginHook = (
  request: NextRequest,
  response: NextResponse,
  options: LoginOptions
) => Promise<NextResponse | void>;

/**
 * Options for the logout process.
 */
export interface LogoutOptions {
  /** The URL to return to after logout. */
  returnTo?: string;
}

/**
 * Hook executed before the logout process begins.
 * It can short-circuit the logout by returning a `NextResponse`.
 * @param request The incoming Next.js request.
 * @param options The initial logout options.
 * @param session The current session data, or `null` if no session exists.
 * @returns A `Promise` that resolves to `NextResponse` to short-circuit, or `void` to continue.
 */
export type BeforeLogoutHook = (
  request: NextRequest,
  options: LogoutOptions,
  session: SessionData | null
) => Promise<NextResponse | void>;

/**
 * Hook executed after the logout process completes.
 * It can modify the `NextResponse` or return a new one.
 * If it returns `void`, the (potentially mutated) response passed to it will be used.
 * @param request The incoming Next.js request.
 * @param response The `NextResponse` from the logout process. This response object can be mutated by the hook if it returns `void`.
 * @param options The logout options used.
 * @returns A `Promise` that resolves to `NextResponse` to replace the original, or `void` to use the (potentially modified) original response.
 */
export type AfterLogoutHook = (
  request: NextRequest,
  response: NextResponse,
  options: LogoutOptions
) => Promise<NextResponse | void>;

/**
 * Hook executed before the callback handling process begins.
 * It can short-circuit the callback handling by returning a `NextResponse`.
 * @param request The incoming Next.js request.
 * @param transactionState The state associated with the transaction, or `null` if missing or invalid.
 * @returns A `Promise` that resolves to `NextResponse` to short-circuit, or `void` to continue.
 */
export type BeforeCallbackHook = (
  request: NextRequest,
  transactionState: TransactionState | null // null if state is missing or invalid early on
) => Promise<NextResponse | void>;

type GenericAfterHook<T_Options> = (
  request: NextRequest,
  response: NextResponse,
  options: T_Options
) => Promise<NextResponse | void>;

async function executeAfterHook<T_Options>(
  hook: GenericAfterHook<T_Options> | undefined,
  request: NextRequest,
  response: NextResponse,
  options: T_Options
): Promise<NextResponse> {
  if (!hook) {
    return response;
  }
  const result = await hook(request, response, options);
  // mutations to `response` will be reflected even if void is returned
  return result instanceof NextResponse ? result : response;
}

/**
 * Processes a `BeforeLoginHook`.
 * @param hook The `BeforeLoginHook` to process, or undefined.
 * @param request The incoming Next.js request.
 * @param initialOptions The initial `LoginOptions`. These options can be mutated by the hook.
 * @returns A `Promise` resolving to a `NextResponse` if the hook short-circuits, or `undefined` to proceed.
 */
export async function processBeforeLoginHook(
  hook: BeforeLoginHook | undefined,
  request: NextRequest,
  initialOptions: LoginOptions // This object is mutated by the hook if it returns void
): Promise<NextResponse | undefined> {
  if (!hook) {
    return undefined; // Proceed, no hook to run
  }
  const shortCircuitResponse = await hook(request, initialOptions);

  if (shortCircuitResponse instanceof NextResponse) {
    return shortCircuitResponse;
  }
  // If hook returned void, it means proceed with potentially mutated initialOptions.
  return undefined;
}

/**
 * Processes a `BeforeLogoutHook`.
 * @param hook The `BeforeLogoutHook` to process, or undefined.
 * @param request The incoming Next.js request.
 * @param initialOptions The initial `LogoutOptions`. These options can be mutated by the hook.
 * @param session The current `SessionData`, or null.
 * @returns A `Promise` resolving to a `NextResponse` if the hook short-circuits, or `undefined` to proceed.
 */
export async function processBeforeLogoutHook(
  hook: BeforeLogoutHook | undefined,
  request: NextRequest,
  initialOptions: LogoutOptions, // This object is mutated by the hook if it returns void
  session: SessionData | null
): Promise<NextResponse | undefined> {
  if (!hook) {
    return undefined; // Proceed, no hook to run
  }
  const shortCircuitResponse = await hook(request, initialOptions, session);

  if (shortCircuitResponse instanceof NextResponse) {
    return shortCircuitResponse;
  }
  // If hook returned void, it means proceed with potentially mutated initialOptions.
  return undefined;
}

/**
 * Processes a `BeforeCallbackHook`.
 * @param hook The `BeforeCallbackHook` to process, or undefined.
 * @param request The incoming Next.js request.
 * @param transactionState The `TransactionState`, or null.
 * @returns A `Promise` resolving to a `NextResponse` if the hook short-circuits, or `undefined` otherwise.
 */
export async function processBeforeCallbackHook(
  hook: BeforeCallbackHook | undefined,
  request: NextRequest,
  transactionState: TransactionState | null
): Promise<NextResponse | undefined> {
  if (!hook) {
    return undefined;
  }
  const result = await hook(request, transactionState);
  return result instanceof NextResponse ? result : undefined;
}

/**
 * Processes an `AfterLoginHook`.
 * @param hook The `AfterLoginHook` to process, or undefined.
 *
 *   The incoming Next.js request.
 * @param response The `NextResponse` from the login process.
 * @param options The `LoginOptions` used.
 * @returns A `Promise` resolving to the final `NextResponse`.
 */
export async function processAfterLoginHook(
  hook: AfterLoginHook | undefined,
  request: NextRequest,
  response: NextResponse,
  options: LoginOptions
): Promise<NextResponse> {
  return executeAfterHook(hook, request, response, options);
}

/**
 * Processes an `AfterLogoutHook`.
 * @param hook The `AfterLogoutHook` to process, or undefined.
 * @param request The incoming Next.js request.
 * @param response The `NextResponse` from the logout process.
 * @param options The `LogoutOptions` used.
 * @returns A `Promise` resolving to the final `NextResponse`.
 */
export async function processAfterLogoutHook(
  hook: AfterLogoutHook | undefined,
  request: NextRequest,
  response: NextResponse,
  options: LogoutOptions
): Promise<NextResponse> {
  return executeAfterHook(hook, request, response, options);
}
