/**
 * TEST-ONLY — DO NOT COPY TO PRODUCTION.
 *
 * Part of the offline e2e mock harness (playwright.offline.config.ts, E2E_ANON_MOCK=1).
 * This route injects test scenarios to control mock Auth0 responses. It must never run in a
 * real deployment. Delete app/api/test/ before using this example in production.
 */
import { NextResponse } from "next/server";

import { getScenario, setScenario } from "@/lib/mock/anon-mock-fetch";

export async function POST(req: Request) {
  if (process.env.E2E_ANON_MOCK !== "1") {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  const { scenario } = await req.json();
  setScenario(scenario);
  return NextResponse.json({ ok: true, scenario });
}

export async function GET() {
  if (process.env.E2E_ANON_MOCK !== "1") {
    return NextResponse.json({ error: "not_found" }, { status: 404 });
  }

  return NextResponse.json({ scenario: getScenario() });
}
