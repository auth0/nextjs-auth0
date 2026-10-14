import type { NextResponse } from "next/server.js";

import type { SdkError } from "../../errors/index.js";
import type { CompleteConnectAccountResponse } from "../../types/connected-accounts.js";
import type { RESPONSE_TYPES, SessionData } from "../../types/index.js";

export type BeforeSessionSavedHook = (
  session: SessionData,
  idToken: string | null
) => Promise<SessionData>;

export type OnCallbackContext = {
  /**
   * The type of response expected from the authorization server.
   * One of {@link RESPONSE_TYPES}
   */
  responseType?: RESPONSE_TYPES;
  /**
   * The resolved base URL for the current request, used to build safe redirects.
   */
  appBaseUrl?: string;
  /**
   * The URL or path the user should be redirected to after completing the transaction.
   */
  returnTo?: string;
  /**
   * The connected account information when the responseType is {@link RESPONSE_TYPES.CONNECT_CODE}
   */
  connectedAccount?: CompleteConnectAccountResponse;
  /**
   * The return strategy for this callback flow.
   * - 'redirect' (default): Standard OAuth redirect flow
   * - 'popup': Popup flow returning via window.postMessage
   * Hook authors can use this to detect popup flows and adapt behavior.
   */
  challengeMode?: "redirect" | "popup";
  /**
   * True if an active anonymous session was linked at login time (digest-bound cookie matched at callback).
   * False if a link was attempted but the anonymous cookie was missing or failed digest verification (session-fixation check).
   * When false, the app SHOULD NOT treat the anonymous session as successfully linked.
   * When true, onCallback hook can trigger migration logic (e.g., move cart to authenticated user).
   */
  anonymousSessionLinked?: boolean;
};

export type OnCallbackHook = (
  error: SdkError | null,
  ctx: OnCallbackContext,
  session: SessionData | null
) => Promise<NextResponse>;
