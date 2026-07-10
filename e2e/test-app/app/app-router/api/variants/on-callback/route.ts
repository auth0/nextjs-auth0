import { NextRequest } from "next/server";
import { auth0OnCallback } from "@/lib/auth0-config-variants";

export async function GET(req: NextRequest) {
  return auth0OnCallback.middleware(req);
}
