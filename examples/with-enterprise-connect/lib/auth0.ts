import { Auth0Client } from "@auth0/nextjs-auth0/server";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export interface AppSession {
  sub: string;
  email: string;
  orgId: string;
  name?: string;
}

// The signed payload carries an absolute expiry (`exp`, epoch seconds) on top of
// the session fields. EC has no refresh token, so the session lives for a fixed
// window and the user re-authenticates when it lapses.
interface SignedSession extends AppSession {
  exp: number;
}

// Session lifetime. Kept in one place so the cookie maxAge and the server-side
// `exp` check stay in sync.
const SESSION_TTL_SECONDS = 60 * 60 * 24; // 24h

// This is a minimal, secure default. In production, replace this with whatever session mechanism your app already has.
// Signs the cookie with the native Web Crypto API (no extra package) so the payload can't be forged.
const enc = new TextEncoder();
const key = () =>
  crypto.subtle.importKey(
    "raw",
    enc.encode(process.env.AUTH0_SECRET!),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

export async function getAppSession(): Promise<AppSession | null> {
  const raw = (await cookies()).get("app_session")?.value;
  if (!raw) return null;
  const [body, signature] = raw.split(".");
  if (!body || !signature) return null;
  try {
    // Verify the signature before trusting the payload; reject if tampered.
    const valid = await crypto.subtle.verify(
      "HMAC",
      await key(),
      Buffer.from(signature, "base64url"),
      enc.encode(body)
    );
    if (!valid) return null;

    // Signature is authentic; now enforce expiry. A valid signature alone would
    // let a leaked cookie replay forever, so a server-checked `exp` bounds it.
    const payload = JSON.parse(Buffer.from(body, "base64url").toString()) as SignedSession;
    if (typeof payload.exp !== "number" || Date.now() >= payload.exp * 1000) {
      return null;
    }
    const { exp: _exp, ...session } = payload;
    return session;
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

    if (!session?.user) {
      const loginUrl = new URL("/login", process.env.APP_BASE_URL);
      loginUrl.searchParams.set("error", "no-session");
      return NextResponse.redirect(loginUrl);
    }

    const user = session.user;
    const orgId = user["org_id"] as string;

    if (!orgId) {
      throw new Error("org_id missing from token");
    }

    // session.user holds the OIDC claims; keep only the fields you need.
    // `exp` bounds the session server-side; the cookie maxAge below mirrors it.
    const signedSession: SignedSession = {
      sub: user.sub,
      email: user.email as string,
      orgId,
      name: user.name as string | undefined,
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
    };

    // Sign the payload so the cookie can't be forged: "<body>.<signature>".
    const body = Buffer.from(JSON.stringify(signedSession)).toString("base64url");
    const signature = Buffer.from(
      await crypto.subtle.sign("HMAC", await key(), enc.encode(body))
    ).toString("base64url");

    const returnTo = ctx.returnTo ?? "/dashboard";
    const res = NextResponse.redirect(new URL(returnTo, process.env.APP_BASE_URL));
    res.cookies.set("app_session", `${body}.${signature}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      // Mirror the signed `exp`: expire the cookie client-side too, so the
      // browser stops sending it once the session lapses.
      maxAge: SESSION_TTL_SECONDS
    });
    return res;
  }
});
