import type { StartEnterpriseLoginOptions } from "../../types/authorize.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

/**
 * Options for the client-side {@link startEnterpriseLogin} helper.
 *
 * Extends the server {@link StartEnterpriseLoginOptions} (so `email`,
 * `authorizationParameters`, and `returnTo` behave identically to the server
 * flavour) and adds the two client-only route overrides the browser needs to
 * reach the SDK's mounted routes.
 */
export interface StartEnterpriseLoginClientOptions extends StartEnterpriseLoginOptions {
  /**
   * Override the domain-discovery route. Defaults to the
   * `NEXT_PUBLIC_FEDERATED_DOMAIN_ROUTE` env var or `/auth/federated-domain`.
   */
  federatedDomainRoute?: string;
  /**
   * Override the login route. Defaults to the `NEXT_PUBLIC_LOGIN_ROUTE` env var
   * or `/auth/login`.
   */
  loginRoute?: string;
}

/**
 * Client component counterpart to the server `startEnterpriseLogin`.
 *
 * Asks the SDK's mounted `/auth/federated-domain` route whether the email domain
 * is federated and, when it is, navigates the browser to `/auth/login` with the
 * email as `login_hint`. Discovery runs on the server so the browser never calls
 * WebFinger directly, which would let anyone enumerate the tenant's customer
 * domains.
 *
 * @param options - Login options. `email` is required and drives discovery.
 * @returns `true` when the domain is federated and the browser was navigated to
 * Auth0; `false` when it is not, so the caller can fall back to its own
 * non-enterprise login.
 *
 * @example
 * ```tsx
 * "use client";
 * import { startEnterpriseLogin } from "@auth0/nextjs-auth0";
 *
 * async function onSubmit(email: string) {
 *   const redirected = await startEnterpriseLogin({ email, returnTo: "/dashboard" });
 *   if (!redirected) await yourExistingLogin(email); // not a federated domain
 * }
 * ```
 *
 * @see [Enterprise Connect](https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#enterprise-connect-b2b-integration) for the full flow.
 */
export async function startEnterpriseLogin(
  options: StartEnterpriseLoginClientOptions
): Promise<boolean> {
  const { email, authorizationParameters } = options;

  const federatedDomainRoute = normalizeWithBasePath(
    options.federatedDomainRoute ||
      process.env.NEXT_PUBLIC_FEDERATED_DOMAIN_ROUTE ||
      "/auth/federated-domain"
  );

  const res = await fetch(federatedDomainRoute, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  });

  if (!res.ok) {
    throw new Error(
      "An unexpected error occurred while checking the email domain."
    );
  }

  const { isFederated } = (await res.json()) as { isFederated?: boolean };
  if (!isFederated) {
    return false;
  }

  const loginRoute = normalizeWithBasePath(
    options.loginRoute || process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login"
  );

  // Forward any caller-supplied authorization parameters onto the /auth/login
  // query string (the same transport the login route already reads them from),
  // then set login_hint from email last so it wins.
  const merged = { ...authorizationParameters, login_hint: email };
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(merged)) {
    if (value != null) {
      params.set(key, String(value));
    }
  }
  if (options.returnTo) {
    params.set("returnTo", options.returnTo);
  }

  window.location.assign(`${loginRoute}?${params.toString()}`);
  return true;
}
