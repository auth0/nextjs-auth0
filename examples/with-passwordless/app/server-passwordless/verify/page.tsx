import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

export default async function ServerPasswordlessVerifyPage({
  searchParams
}: {
  searchParams: Promise<{
    connection?: string;
    email?: string;
    phone?: string;
    error?: string;
  }>;
}) {
  const session = await auth0.getSession();
  if (session) redirect("/dashboard");

  const params = await searchParams;
  const raw = params.connection;
  const connection: "email" | "sms" | undefined =
    raw === "email" || raw === "sms" ? raw : undefined;
  const email = params.email ?? "";
  const phone = params.phone ?? "";
  const error = params.error ?? null;

  if (!connection || (connection === "email" && !email) || (connection === "sms" && !phone)) {
    redirect("/server-passwordless");
  }

  const hint =
    connection === "email"
      ? `We sent a 6-digit code to ${email}`
      : `We sent a 6-digit code to ${phone}`;

  async function verifyOtp(formData: FormData) {
    "use server";
    const code = formData.get("code") as string;

    if (connection === "email") {
      console.log("[server-passwordless] email OTP verify");
      try {
        // passwordless.verify exchanges the OTP for tokens and writes the
        // session cookie to next/headers — the user is signed in after this call.
        await auth0.passwordless.verify({
          connection: "email",
          email,
          verificationCode: code
        });
        console.log("[server-passwordless] email OTP verify success — session created");
      } catch (err) {
        const e = err as { error?: string; error_description?: string };
        console.error(`[server-passwordless] email OTP verify failed — ${e.error}: ${e.error_description}`);
        redirect(
          `/server-passwordless/verify?connection=email&email=${encodeURIComponent(email)}&error=${encodeURIComponent(e.error_description ?? "Invalid or expired code")}`
        );
      }
    } else {
      console.log("[server-passwordless] SMS OTP verify");
      try {
        await auth0.passwordless.verify({
          connection: "sms",
          phoneNumber: phone,
          verificationCode: code
        });
        console.log("[server-passwordless] SMS OTP verify success — session created");
      } catch (err) {
        const e = err as { error?: string; error_description?: string };
        console.error(`[server-passwordless] SMS OTP verify failed — ${e.error}: ${e.error_description}`);
        redirect(
          `/server-passwordless/verify?connection=sms&phone=${encodeURIComponent(phone)}&error=${encodeURIComponent(e.error_description ?? "Invalid or expired code")}`
        );
      }
    }

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
              minLength={4}
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
