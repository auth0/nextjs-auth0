import type { GetServerSideProps } from "next";
import { auth0 } from "@/lib/auth0";

type Props = { email: string };

export const getServerSideProps: GetServerSideProps<Props> = auth0.withPageAuthRequired({
  returnTo: "/pages-router/protected",
  async getServerSideProps(ctx) {
    const session = await auth0.getSession(ctx.req);
    return { props: { email: session?.user.email ?? "" } };
  },
});

export default function ProtectedPage({ email }: Props) {
  return (
    <main>
      <h1 id="status">authenticated</h1>
      <p id="email">{email}</p>
    </main>
  );
}
