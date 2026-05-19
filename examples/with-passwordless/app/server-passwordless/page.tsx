import { redirect } from "next/navigation";

import { auth0 } from "@/lib/auth0";

type Tab = "email" | "sms" | "magic-link";

export default async function ServerPasswordlessPage({
  searchParams
}: {
  searchParams: Promise<{
    tab?: string;
    sent?: string;
    email?: string;
    error?: string;
  }>;
}) {
  const session = await auth0.getSession();
  if (session) redirect("/dashboard");

  const params = await searchParams;
  const VALID_TABS: Tab[] = ["email", "sms", "magic-link"];
  const tab: Tab = VALID_TABS.includes(params.tab as Tab)
    ? (params.tab as Tab)
    : "email";
  const error = params.error ?? null;

  // Magic link sent — show confirmation screen
  if (params.sent === "1" && params.email) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center p-6">
        <div className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-8 shadow-sm text-center space-y-4">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
            <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
            </svg>
          </div>
          <h1 className="text-xl font-semibold text-gray-900">Check your email</h1>
          <p className="text-sm text-gray-500">
            We sent a magic link to{" "}
            <span className="font-medium text-gray-900">{params.email}</span>.
            Click the link to sign in — no code required.
          </p>
          <p className="text-xs text-gray-400">
            The link expires in 5 minutes. Check your spam folder if you don&apos;t see it.
          </p>
          <a
            href="/server-passwordless?tab=magic-link"
            className="block text-xs text-blue-600 underline hover:text-blue-800"
          >
            ← Use a different email
          </a>
        </div>
      </main>
    );
  }

  // Server Actions — one per flow so each form has a typed action
  async function startEmailOtp(formData: FormData) {
    "use server";
    const email = formData.get("email") as string;
    console.log("[server-passwordless] email OTP start");
    try {
      await auth0.passwordless.start({ connection: "email", email, send: "code" });
      console.log("[server-passwordless] email OTP start success");
    } catch (err) {
      const e = err as { error?: string; error_description?: string };
      console.error(`[server-passwordless] email OTP start failed — ${e.error}: ${e.error_description}`);
      redirect(`/server-passwordless?tab=email&error=${encodeURIComponent(e.error_description ?? "Failed to send code")}`);
    }
    redirect(`/server-passwordless/verify?connection=email&email=${encodeURIComponent(email)}`);
  }

  async function startSmsOtp(formData: FormData) {
    "use server";
    const phone = formData.get("phone") as string;
    console.log("[server-passwordless] SMS OTP start");
    try {
      await auth0.passwordless.start({ connection: "sms", phoneNumber: phone });
      console.log("[server-passwordless] SMS OTP start success");
    } catch (err) {
      const e = err as { error?: string; error_description?: string };
      console.error(`[server-passwordless] SMS OTP start failed — ${e.error}: ${e.error_description}`);
      redirect(`/server-passwordless?tab=sms&error=${encodeURIComponent(e.error_description ?? "Failed to send code")}`);
    }
    redirect(`/server-passwordless/verify?connection=sms&phone=${encodeURIComponent(phone)}`);
  }

  async function startMagicLink(formData: FormData) {
    "use server";
    const email = formData.get("email") as string;
    console.log("[server-passwordless] magic link start");
    try {
      // passwordless.start writes the transaction cookie to next/headers automatically.
      // No client-side code involved — the entire flow runs server-side.
      await auth0.passwordless.start({ connection: "email", email, send: "link" });
      console.log("[server-passwordless] magic link start success — transaction cookie written");
    } catch (err) {
      const e = err as { error?: string; error_description?: string };
      console.error(`[server-passwordless] magic link start failed — ${e.error}: ${e.error_description}`);
      redirect(`/server-passwordless?tab=magic-link&error=${encodeURIComponent(e.error_description ?? "Failed to send link")}`);
    }
    redirect(`/server-passwordless?sent=1&email=${encodeURIComponent(email)}`);
  }

  const inputClass =
    "w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-200";
  const btnPrimary =
    "w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700";

  const tabs: { id: Tab; label: string }[] = [
    { id: "email", label: "Email OTP" },
    { id: "sms", label: "SMS OTP" },
    { id: "magic-link", label: "Magic Link" }
  ];

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6">
      <div className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold tracking-tight">Server-side passwordless</h1>
          <p className="mt-2 text-sm text-gray-500">
            All flows run via Server Actions — no client JS, no fetch calls.
            Check your terminal for per-step server logs.
          </p>
        </div>

        {/* Tab bar — plain links, no JS */}
        <div className="mb-6 flex rounded-lg border border-gray-200 p-1 text-sm">
          {tabs.map(({ id, label }) => (
            <a
              key={id}
              href={`/server-passwordless?tab=${id}`}
              className={`flex-1 rounded-md py-1.5 text-center font-medium transition ${
                tab === id
                  ? "bg-white text-gray-900 shadow-sm"
                  : "text-gray-500 hover:text-gray-700"
              }`}
            >
              {label}
            </a>
          ))}
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        {tab === "email" && (
          <form action={startEmailOtp} className="space-y-4">
            <div>
              <label htmlFor="email" className="mb-1 block text-sm font-medium text-gray-700">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                required
                className={inputClass}
              />
            </div>
            <button type="submit" className={btnPrimary}>
              Send code
            </button>
          </form>
        )}

        {tab === "sms" && (
          <form action={startSmsOtp} className="space-y-4">
            <div>
              <label htmlFor="phone" className="mb-1 block text-sm font-medium text-gray-700">
                Phone number
              </label>
              <input
                id="phone"
                name="phone"
                type="tel"
                autoComplete="tel"
                placeholder="+14155550100"
                required
                className={inputClass}
              />
              <p className="mt-1 text-xs text-gray-400">E.164 format (e.g. +14155550100)</p>
            </div>
            <button type="submit" className={btnPrimary}>
              Send code
            </button>
          </form>
        )}

        {tab === "magic-link" && (
          <form action={startMagicLink} className="space-y-4">
            <div>
              <label htmlFor="ml-email" className="mb-1 block text-sm font-medium text-gray-700">
                Email address
              </label>
              <input
                id="ml-email"
                name="email"
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                required
                className={inputClass}
              />
              <p className="mt-1 text-xs text-gray-400">
                We&apos;ll email a one-click sign-in link — no code to type.
                The transaction cookie is written server-side.
              </p>
            </div>
            <button type="submit" className={btnPrimary}>
              Send magic link
            </button>
          </form>
        )}

        <p className="mt-6 text-center text-xs text-gray-400">
          Want the client-side version?{" "}
          <a href="/" className="text-blue-600 underline hover:text-blue-800">
            Back to home
          </a>
        </p>
      </div>
    </main>
  );
}
