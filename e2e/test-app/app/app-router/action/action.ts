"use server"

import { auth0 } from "@/lib/auth0"

export async function testServerAction() {
  const session = await auth0.getSession()

  if (!session) {
    return { status: "unauthenticated" }
  }

  return {
    status: "authenticated",
  }
}
