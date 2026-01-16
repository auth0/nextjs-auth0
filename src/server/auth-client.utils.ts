/**
 * This file is a first step to cleaning out auth-client.ts by moving out the
 * utility methods into this file.
 *
 * This isn't a complete extraction, just a start.
 */

import { NextResponse } from "next/server.js";

import {
  Auth0NextApiResponse,
  Auth0NextResponse,
  Auth0Response
} from "./http/index.js";

/**
 * Unwraps an Auth0NextResponse by extracting the underlying NextResponse.
 *
 * @param handler A function that returns a Promise resolving to an Auth0NextResponse.
 * @returns A Promise that resolves to a NextResponse.
 */
export async function unwrapHandler(
  handler: () => Promise<Auth0NextResponse>
): Promise<NextResponse>;

/**
 * Unwraps an Auth0NextApiResponse by calling `.end()` on the underlying NextApiResponse if needed, and returning void.
 * @param handler A function that returns a Promise resolving to an Auth0NextApiResponse.
 * @returns A Promise that's void'.
 */
export async function unwrapHandler(
  handler: () => Promise<Auth0NextApiResponse>
): Promise<void>;

/**
 * Unwraps an Auth0Response by extracting the underlying NextResponse, or calling `.end()` on the underlying NextApiResponse if needed, and returning void.
 * @param handler A function that returns a Promise resolving to an Auth0Response.
 * @returns A Promise that resolves to a NextResponse or void (in case of Pages Router usage).
 */
export async function unwrapHandler(
  handler: () => Promise<Auth0Response>
): Promise<NextResponse | void>;

/**
 * Unwraps an Auth0Response by extracting the underlying NextResponse, or calling `.end()` on the underlying NextApiResponse.
 * This utility simplifies the pattern of awaiting handler calls and accessing .res
 *
 * @param handler A function that returns a Promise resolving to an Auth0Response.
 * @returns A Promise that resolves to a NextResponse or void (in case of Pages Router usage).
 */
export async function unwrapHandler(
  handler: () => Promise<Auth0Response>
): Promise<NextResponse | void> {
  const auth0Response = await handler();
  const response = auth0Response.res;
  const canEndRequest =
    response && "end" in response && typeof response.end === "function";

  // When the underlying response supports .end(), call it to finalize the response without returning the NextApiResponse instance.
  // NextResponse does not have .end(), instead we return the NextResponse instance.
  if (canEndRequest && !response.headersSent) {
    response.end();
  } else {
    return response as NextResponse;
  }
}
