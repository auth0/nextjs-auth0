import { redirect } from "next/navigation";
import { getAppSession } from "@/lib/auth0";

export const dynamic = "force-dynamic";

export default async function Home() {
  const session = await getAppSession();
  redirect(session ? "/dashboard" : "/login");
}
