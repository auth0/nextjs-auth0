import { NextRequest, NextResponse } from "next/server";

import type { SessionData, StartInteractiveLoginOptions } from "../types";
import type { TransactionState } from "./transaction-store";

// New Hook-related type definitions
export interface LoginOptions extends StartInteractiveLoginOptions {}

export type BeforeLoginHook = (
  request: NextRequest,
  options: LoginOptions
) => Promise<LoginOptions | NextResponse | void>;

export type AfterLoginHook = (
  request: NextRequest,
  response: NextResponse,
  options: LoginOptions
) => Promise<NextResponse | void>;

export interface LogoutOptions {
  returnTo?: string;
  // Potentially other logout-specific options in the future
}

export type BeforeLogoutHook = (
  request: NextRequest,
  options: LogoutOptions,
  session: SessionData | null
) => Promise<LogoutOptions | NextResponse | void>;

export type AfterLogoutHook = (
  request: NextRequest,
  response: NextResponse,
  options: LogoutOptions
) => Promise<NextResponse | void>;

export type BeforeCallbackHook = (
  request: NextRequest,
  transactionState: TransactionState | null // null if state is missing or invalid early on
) => Promise<NextResponse | void>;

// Hook Processing Logic

// Private helper to process the result of a "before" hook
function _processBeforeHookResult<T_Options>(
  hookResult: T_Options | NextResponse | void, // The actual resolved result from the hook
  initialOptions: T_Options
): { finalOptions: T_Options; shortCircuit?: NextResponse } {
  if (hookResult instanceof NextResponse) {
    // Hook returned a NextResponse: short-circuit, use initial options as a fallback for finalOptions type consistency.
    return { finalOptions: initialOptions, shortCircuit: hookResult };
  }
  if (hookResult) {
    // Hook returned modified options (T_Options).
    return { finalOptions: hookResult as T_Options, shortCircuit: undefined };
  }
  // Hook returned void or undefined: use initial options, no short-circuit.
  return { finalOptions: initialOptions, shortCircuit: undefined };
}

// PRIVATE Generic helper for "after" hooks that can modify a response or short-circuit
async function _processAfterHook<T_Options>(
  hook:
    | ((
        request: NextRequest,
        response: NextResponse,
        options: T_Options
      ) => Promise<NextResponse | void>)
    | undefined,
  request: NextRequest,
  response: NextResponse,
  options: T_Options
): Promise<NextResponse> {
  if (!hook) {
    return response;
  }
  const result = await hook(request, response, options);
  return result instanceof NextResponse ? result : response;
}

export async function processBeforeLoginHook(
  hook: BeforeLoginHook | undefined,
  request: NextRequest,
  initialOptions: LoginOptions
): Promise<{ finalOptions: LoginOptions; shortCircuit?: NextResponse }> {
  if (!hook) {
    return { finalOptions: initialOptions, shortCircuit: undefined };
  }
  const result = await hook(request, initialOptions);
  return _processBeforeHookResult(result, initialOptions);
}

export async function processAfterLoginHook(
  hook: AfterLoginHook | undefined,
  request: NextRequest,
  response: NextResponse, // This response can be modified in-place by the hook
  options: LoginOptions
): Promise<NextResponse> {
  return _processAfterHook(hook, request, response, options);
}

export async function processBeforeLogoutHook(
  hook: BeforeLogoutHook | undefined,
  request: NextRequest,
  initialOptions: LogoutOptions,
  session: SessionData | null
): Promise<{ finalOptions: LogoutOptions; shortCircuit?: NextResponse }> {
  if (!hook) {
    return { finalOptions: initialOptions, shortCircuit: undefined };
  }
  const result = await hook(request, initialOptions, session);
  return _processBeforeHookResult(result, initialOptions);
}

export async function processAfterLogoutHook(
  hook: AfterLogoutHook | undefined,
  request: NextRequest,
  response: NextResponse, // Can be modified in-place
  options: LogoutOptions
): Promise<NextResponse> {
  return _processAfterHook(hook, request, response, options);
}

export async function processBeforeCallbackHook(
  hook: BeforeCallbackHook | undefined,
  request: NextRequest,
  transactionState: TransactionState | null
): Promise<NextResponse | undefined> {
  // Returns NextResponse if short-circuiting
  if (!hook) {
    return undefined;
  }
  const result = await hook(request, transactionState);
  return result instanceof NextResponse ? result : undefined;
}
