import { NextRequest, NextResponse } from "next/server.js";

import { isFederatedDomain } from "../../utils/webfingerCache.js";
import { middlewareContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";

/**
 * Route: POST /auth/federated-domain (Enterprise Connect only). Reads `{ email }` and answers
 * `{ isFederated }`, so the browser never calls WebFinger itself (which would expose the tenant's
 * customer domains).
 */
export async function handleFederatedDomain(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  let email: unknown;
  try {
    ({ email } = await req.json());
  } catch {
    return NextResponse.json(
      { error: "invalid request body" },
      { status: 400 }
    );
  }

  if (
    typeof email !== "string" ||
    /\s/.test(email) ||
    email.indexOf("@") <= 0 ||
    email.indexOf("@") !== email.lastIndexOf("@") ||
    email.endsWith("@")
  ) {
    return NextResponse.json({ error: "invalid email" }, { status: 400 });
  }

  const emailDomain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
  const domain = await setup.currentDomain(
    middlewareContext(req, NextResponse.next())
  );
  const isFederated = await isFederatedDomain(domain, emailDomain, {
    customFetch: setup.fetch
  });

  return NextResponse.json({ isFederated });
}
