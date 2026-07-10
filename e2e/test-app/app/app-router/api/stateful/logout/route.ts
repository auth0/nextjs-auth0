import { NextRequest } from "next/server";
import { auth0Stateful } from "@/lib/auth0-stateful";

export async function GET(req: NextRequest) {
  return auth0Stateful.middleware(req);
}
