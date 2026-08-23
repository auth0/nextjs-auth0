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
 * Client-side Enterprise Connect login initiation, for use from client
 * components. It asks the server whether the email domain is federated (via the
 * SDK's mounted `/auth/federated-domain` route) and, when it is, navigates the
 * browser to `/auth/login` with the email as `login_hint`. Home Realm Discovery
 * resolves the connection and organization from the domain.
 *
 * Domain discovery runs on the server so the browser never calls WebFinger
 * directly, which would expose the tenant's customer domains to enumeration.
 *
 * @returns `true` when the domain is federated and the browser was navigated to
 * Auth0; `false` when the domain is not federated, so the caller can route to
 * its own non-enterprise login.
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
