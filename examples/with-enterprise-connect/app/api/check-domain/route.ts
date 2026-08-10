import { isFederatedDomain } from "@auth0/nextjs-auth0/server";
import { getEnterpriseConfig } from "@/lib/auth0";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  const { email } = await req.json();

  if (!email || !email.includes("@")) {
    return NextResponse.json({ error: "invalid email" }, { status: 400 });
  }

  const emailDomain = email.split("@")[1].toLowerCase();
  const isFederated = await isFederatedDomain(
    process.env.AUTH0_DOMAIN!,
    emailDomain
  );

  if (!isFederated) {
    return NextResponse.json({ isFederated, emailDomain });
  }

  // Look up the enterprise config for this domain from your database.
  // Each enterprise customer has their own Auth0 connection and org_id.
  const config = await getEnterpriseConfig(emailDomain);
  if (!config) {
    return NextResponse.json({ isFederated: false, emailDomain });
  }

  return NextResponse.json({
    isFederated,
    emailDomain,
    connection: config.connection,
    orgId: config.orgId
  });
}
