import { NextRequest } from "next/server";
import { auth0Stateful } from "@/lib/auth0-stateful";

async function handler(req: NextRequest) {
  return auth0Stateful.middleware(req);
}

export const GET = handler;
export const POST = handler;
