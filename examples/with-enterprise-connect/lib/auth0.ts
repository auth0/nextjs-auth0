import { Auth0Client } from "@auth0/nextjs-auth0/server";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export interface AppSession {
  sub: string;
  email: string;
  orgId: string;
  name?: string;
}

// Session is stored as base64 JSON in a cookie — no server-side store needed for this demo.
// In production use a signed/encrypted cookie or a database-backed session.
export async function getAppSession(): Promise<AppSession | null> {
  const cookieStore = await cookies();
  const raw = cookieStore.get("app_session")?.value;
  if (!raw) return null;
  try {
    return JSON.parse(Buffer.from(raw, "base64").toString("utf-8")) as AppSession;
  } catch {
    return null;
  }
}

export const auth0 = new Auth0Client({
  enterpriseConnect: true,
  authorizationParameters: {
    scope: "openid profile email" // no offline_access — EC has no refresh token
    // No static organization — it is resolved per login via HRD from login_hint
  },

  async onCallback(error, ctx, session) {
    if (error) throw error;

    if (!session?.user) return;

    const user = session.user;
    const orgId = user["org_id"] as string;

    // In production, validate orgId against your database before trusting the login.
    // The check below only verifies the claim exists — replace with a real lookup:
    // e.g. const isKnown = await db.orgs.exists(orgId); if (!isKnown) throw new Error(...)
    if (!orgId) {
      throw new Error("org_id missing from token");
    }

    const appSession: AppSession = {
      sub: user.sub,
      email: user.email as string,
      orgId,
      name: user.name as string | undefined
    };

    const encoded = Buffer.from(JSON.stringify(appSession)).toString("base64");
    const returnTo = ctx.returnTo ?? "/dashboard";
    const res = NextResponse.redirect(new URL(returnTo, process.env.APP_BASE_URL));
    res.cookies.set("app_session", encoded, {
      httpOnly: true,
      sameSite: "lax",
      path: "/"
    });
    return res;
  }
});
