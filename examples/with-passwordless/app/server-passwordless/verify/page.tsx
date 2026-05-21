import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { PasswordlessVerifyError } from "@auth0/nextjs-auth0/errors";
import { auth0 } from "@/lib/auth0";

// Same name as in page.tsx — keeps both files in sync.
const PL_COOKIE = "pl_pending";

export default async function ServerPasswordlessVerifyPage({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const session = await auth0.getSession();
  if (session) redirect("/dashboard");

  // Read the identifier from the HttpOnly cookie set by the start action.
  const cookieStore = await cookies();
  const raw = cookieStore.get(PL_COOKIE)?.value;
  const pending = raw
    ? (JSON.parse(raw) as { connection: "email" | "sms"; email?: string; phone?: string })
    : null;

  if (
    !pending ||
    (pending.connection === "email" && !pending.email) ||
    (pending.connection === "sms" && !pending.phone)
  ) {
    redirect("/server-passwordless");
  }

  const { connection, email = "", phone = "" } = pending!;
  const params = await searchParams;
  const error = params.error ?? null;
  const hint =
    connection === "email"
      ? `We sent a 6-digit code to ${email}`
      : `We sent a 6-digit code to ${phone}`;

  async function verifyOtp(formData: FormData) {
    "use server";
    const code = formData.get("code") as string;

    // Re-read inside the action — Server Actions have their own execution context.
    const actionCookies = await cookies();
    const actionRaw = actionCookies.get(PL_COOKIE)?.value;
    const actionPending = actionRaw
      ? (JSON.parse(actionRaw) as { connection: "email" | "sms"; email?: string; phone?: string })
      : null;

    if (!actionPending) redirect("/server-passwordless");

    if (actionPending!.connection === "email") {
      console.log("[server-passwordless] email OTP verify");
      try {
        // passwordless.verify exchanges the OTP for tokens and writes the session
        // cookie via next/headers — the same mechanism as auth0.passwordless.start.
        // After this call the user is signed in.
        await auth0.passwordless.verify({
          connection: "email",
          email: actionPending!.email!,
          verificationCode: code
        });
        console.log("[server-passwordless] email OTP verify success — session created");
      } catch (err) {
        const message = err instanceof PasswordlessVerifyError
          ? err.error_description ?? err.message
          : (err instanceof Error ? err.message : "Invalid or expired code");
        console.error(`[server-passwordless] email OTP verify failed — ${message}`);
        redirect(`/server-passwordless/verify?error=${encodeURIComponent(message)}`);
      }
    } else {
      console.log("[server-passwordless] SMS OTP verify");
      try {
        await auth0.passwordless.verify({
          connection: "sms",
          phoneNumber: actionPending!.phone!,
          verificationCode: code
        });
        console.log("[server-passwordless] SMS OTP verify success — session created");
      } catch (err) {
        const message = err instanceof PasswordlessVerifyError
          ? err.error_description ?? err.message
          : (err instanceof Error ? err.message : "Invalid or expired code");
        console.error(`[server-passwordless] SMS OTP verify failed — ${message}`);
        redirect(`/server-passwordless/verify?error=${encodeURIComponent(message)}`);
      }
    }

    // Clear the pending cookie — it's consumed once the session is created.
    actionCookies.delete(PL_COOKIE);
    redirect("/dashboard");
  }

  const backHref =
    connection === "email"
      ? `/server-passwordless?tab=email`
      : `/server-passwordless?tab=sms`;

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold tracking-tight">Enter your code</h1>
          <p className="mt-2 text-sm text-gray-500">{hint}</p>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        <form action={verifyOtp} className="space-y-4">
          <div>
            <label htmlFor="code" className="mb-1 block text-sm font-medium text-gray-700">
              Verification code
            </label>
            <input
              id="code"
              name="code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              required
              minLength={6}
              maxLength={6}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
            />
          </div>

          <button
            type="submit"
            className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
          >
            Sign in
          </button>
        </form>

        <a
          href={backHref}
          className="mt-4 block text-center text-xs text-gray-500 underline hover:text-gray-700"
        >
          ← Use a different {connection === "email" ? "email" : "phone number"}
        </a>
      </div>
    </main>
  );
}
