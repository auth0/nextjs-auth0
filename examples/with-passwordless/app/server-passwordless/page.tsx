import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { PasswordlessStartError } from "@auth0/nextjs-auth0/errors";
import { auth0 } from "@/lib/auth0";

type Tab = "email" | "sms" | "magic-link";

// Short-lived HttpOnly cookie that carries the user identifier between the
// start action and the verify page — keeps PII out of the URL entirely.
const PL_COOKIE = "pl_pending";
const PL_COOKIE_MAX_AGE = 600; /**
 * Renders the server-side passwordless sign-in page with Email OTP, SMS OTP, and Magic Link flows.
 *
 * The component gatekeeps authenticated users (redirects to `/dashboard`), reads `searchParams` to determine
 * the active tab and any error state, shows a confirmation screen when `sent=1` (reading the destination
 * email from a short-lived HttpOnly cookie), and provides server actions for starting each passwordless flow.
 *
 * @param searchParams - A promise resolving to optional query parameters: `tab` (one of "email" | "sms" | "magic-link"), `sent`, and `error`.
 * @returns The server-rendered JSX for the passwordless entry page, including the tabbed UI, forms wired to server actions, and any error or confirmation UI.
 */

export default async function ServerPasswordlessPage({
  searchParams
}: {
  searchParams: Promise<{
    tab?: string;
    sent?: string;
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

  // Magic link sent — show confirmation screen.
  // Email is read from the HttpOnly cookie rather than the URL.
  if (params.sent === "1") {
    const cookieStore = await cookies();
    const raw = cookieStore.get(PL_COOKIE)?.value;
    const pending = raw ? (JSON.parse(raw) as { email?: string }) : null;
    const sentEmail = pending?.email ?? "";

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
            <span className="font-medium text-gray-900">{sentEmail}</span>.
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

  /**
   * Initiates sending an email one-time passcode and records the pending request in a short-lived HttpOnly cookie.
   *
   * On failure, redirects back to `/server-passwordless?tab=email&error=...` with an encoded error message.
   * On success, sets the `pl_pending` cookie with `{ connection: "email", email }` (HttpOnly, path `/server-passwordless`, limited maxAge)
   * and redirects to `/server-passwordless/verify`.
   *
   * @param formData - FormData that must include the `email` field to receive the OTP code
   */
  async function startEmailOtp(formData: FormData) {
    "use server";
    const email = formData.get("email") as string;
    console.log("[server-passwordless] email OTP start");
    try {
      await auth0.passwordless.start({ connection: "email", email, send: "code" });
      console.log("[server-passwordless] email OTP start success");
    } catch (err) {
      const message = err instanceof PasswordlessStartError
        ? err.error_description ?? err.message
        : (err instanceof Error ? err.message : "Failed to send code");
      console.error(`[server-passwordless] email OTP start failed — ${message}`);
      redirect(`/server-passwordless?tab=email&error=${encodeURIComponent(message)}`);
    }
    // Store the identifier in an HttpOnly cookie so the verify page can read it
    // without it appearing in the URL or being accessible from client-side JS.
    const cookieStore = await cookies();
    cookieStore.set(PL_COOKIE, JSON.stringify({ connection: "email", email }), {
      httpOnly: true,
      sameSite: "lax",
      path: "/server-passwordless",
      maxAge: PL_COOKIE_MAX_AGE
    });
    redirect("/server-passwordless/verify");
  }

  /**
   * Initiates an SMS one-time-password (OTP) start flow, stores a short-lived transaction cookie, and redirects to the verification page.
   *
   * @param formData - A FormData object containing a `phone` field (the destination phone number, expected in E.164 format).
   */
  async function startSmsOtp(formData: FormData) {
    "use server";
    const phone = formData.get("phone") as string;
    console.log("[server-passwordless] SMS OTP start");
    try {
      await auth0.passwordless.start({ connection: "sms", phoneNumber: phone });
      console.log("[server-passwordless] SMS OTP start success");
    } catch (err) {
      const message = err instanceof PasswordlessStartError
        ? err.error_description ?? err.message
        : (err instanceof Error ? err.message : "Failed to send code");
      console.error(`[server-passwordless] SMS OTP start failed — ${message}`);
      redirect(`/server-passwordless?tab=sms&error=${encodeURIComponent(message)}`);
    }
    const cookieStore = await cookies();
    cookieStore.set(PL_COOKIE, JSON.stringify({ connection: "sms", phone }), {
      httpOnly: true,
      sameSite: "lax",
      path: "/server-passwordless",
      maxAge: PL_COOKIE_MAX_AGE
    });
    redirect("/server-passwordless/verify");
  }

  /**
   * Initiates a passwordless magic-link email flow and stores a short-lived server-side transaction cookie.
   *
   * Calls the Auth0 passwordless start for the email connection to send a magic link. On failure, redirects the request back to the passwordless page with `tab=magic-link` and an `error` query parameter describing the failure. On success, sets an HttpOnly transaction cookie containing `{ connection: "email", email }` and redirects to `/server-passwordless?sent=1`.
   *
   * @param formData - FormData containing an `email` field with the recipient address
   */
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
      const message = err instanceof PasswordlessStartError
        ? err.error_description ?? err.message
        : (err instanceof Error ? err.message : "Failed to send link");
      console.error(`[server-passwordless] magic link start failed — ${message}`);
      redirect(`/server-passwordless?tab=magic-link&error=${encodeURIComponent(message)}`);
    }
    // Store email for the confirmation screen — HttpOnly so it never hits the URL.
    const cookieStore = await cookies();
    cookieStore.set(PL_COOKIE, JSON.stringify({ connection: "email", email }), {
      httpOnly: true,
      sameSite: "lax",
      path: "/server-passwordless",
      maxAge: PL_COOKIE_MAX_AGE
    });
    redirect("/server-passwordless?sent=1");
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
