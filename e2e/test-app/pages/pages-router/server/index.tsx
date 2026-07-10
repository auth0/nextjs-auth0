import type { GetServerSideProps, InferGetServerSidePropsType } from "next";
import { auth0 } from "@/lib/auth0";

export const getServerSideProps = (async (ctx) => {
  const session = await auth0.getSession(ctx.req);
  if (!session) return { props: { user: null, updatedAt: null } };
  return {
    props: {
      user: { email: session.user.email!, sub: session.user.sub },
      updatedAt: session.user.updatedAt ? String(session.user.updatedAt) : null,
    },
  };
}) satisfies GetServerSideProps<{ user: { email: string; sub: string } | null; updatedAt: string | null }>;

export default function ServerPage({
  user,
  updatedAt,
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  if (!user) {
    return (
      <main>
        <h1 id="status">unauthenticated</h1>
        <a href="/auth/login?returnTo=/pages-router/server">Log in</a>
      </main>
    );
  }
  return (
    <main>
      <h1 id="status">authenticated</h1>
      <p id="email">{user.email}</p>
      <p id="sub">{user.sub}</p>
      <p id="updated-at">{updatedAt ?? ""}</p>
    </main>
  );
}
