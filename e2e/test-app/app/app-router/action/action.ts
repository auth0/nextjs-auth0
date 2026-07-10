"use server";

import { auth0 } from "@/lib/auth0";

export async function getSessionAction() {
  const session = await auth0.getSession();
  if (!session) return { status: "unauthenticated", email: null };
  return { status: "authenticated", email: session.user.email };
}

export async function updateSessionAction() {
  const session = await auth0.getSession();
  if (!session) return { status: "unauthenticated" };
  await auth0.updateSession({ ...session, user: { ...session.user, updatedAt: Date.now() } });
  return { status: "updated" };
}
