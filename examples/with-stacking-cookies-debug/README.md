# with-stacking-cookies-debug

Reproduction app for transaction cookie accumulation bugs in `@auth0/nextjs-auth0` v4.

Related issues: [#1917](https://github.com/auth0/nextjs-auth0/issues/1917) / [#2450](https://github.com/auth0/nextjs-auth0/issues/2450)

---

## Setup

```bash
cp .env.local.example .env.local
# Fill in your Auth0 credentials in .env.local

pnpm install
pnpm build   # IMPORTANT: prefetch only runs in production mode
pnpm start
```

Open http://localhost:3000. The **Cookie Inspector** panel at the bottom of every page shows all cookies, their sizes, and a `__txn_*` history timeline in real time.

---

## Failure Cases

### FC-1 — `<Link prefetch={true}>` creates txn cookie on page-load

**Steps:**
1. `pnpm build && pnpm start`
2. Log out (or delete the `__session` cookie in DevTools)
3. Navigate to http://localhost:3000
4. Without clicking anything, watch the Cookie Inspector

**Expected (broken) behavior:** `__txn_*` cookies appear in the inspector immediately on page-load — one per Link in the viewport. Reload the page and the count increases again.

**Cookie fingerprint:** N × `__txn_{state}` after N page-loads, where N = number of prefetch Links in viewport (5 on the home page).

---

### FC-2 — Hover-triggered prefetch creates txn cookie per hover

**Steps:**
1. `pnpm build && pnpm start`
2. Log out
3. Navigate to http://localhost:3000
4. Hover over links in the **FC-2 section** one by one

**Expected (broken) behavior:** Each hover adds a new `__txn_*` cookie. Moving away and back adds another.

---

### FC-3 — Silent auth middleware creates txn cookie on every prefetch

**Steps:**
1. `pnpm build && pnpm start`
2. Log out
3. Navigate to http://localhost:3000
4. Hover over the `/dashboard/silent` links in the **FC-3 section**

**Expected (broken) behavior:** Each prefetch triggers the silent-auth middleware redirect → `handleLogin` creates a txn cookie.

---

### FC-4 — Server Action creates txn cookie per call

**Steps:**
1. Log in
2. Navigate to /dashboard/page-1
3. Click **Trigger Server Action** repeatedly

**Expected (broken) behavior:** Each Server Action call increments the `__txn_*` cookie count. The Server Action form shows `+1` delta per click.

**Note:** This may or may not reproduce depending on your middleware setup — the form logs the delta so you can see immediately.

---

### FC-5 — Multi-tab `Invalid State` (parallel transactions)

**Steps:**
1. Open http://localhost:3000/auth/login in Tab 1 (but don't complete login)
2. Open http://localhost:3000/auth/login in Tab 2 (but don't complete login)
3. Complete login in Tab 1
4. Go back to Tab 2 and complete login

**Expected (broken) behavior with `enableParallelTransactions: false`:** Tab 2 gets "The state parameter is invalid."

**Expected behavior with `enableParallelTransactions: true` (default):** Both tabs log in successfully.

---

### FC-6 — Single-transaction mode silently blocks second login

**Steps:**
1. Add `enableParallelTransactions: false` to `lib/auth0.ts`
2. `pnpm build && pnpm start`
3. Navigate to `/auth/login` — don't complete
4. Open a new tab and navigate to `/auth/login` again

**Expected (broken) behavior:** Second login attempt does nothing (the SDK warns in server logs but the user sees no redirect to Auth0).

**Expected after fix:** Second login overwrites the first transaction and proceeds to Auth0.

---

### FC-7 — `__FC_N` accumulation during passkey cycles

See `examples/with-passkeys/`. Register and delete passkeys repeatedly. After each cycle, check for orphaned `__FC_1`, `__FC_2`, etc. cookies in the inspector.

---

### FC-8 — Session chunk cookies (`__session__0`, `__session__1`)

Add custom claims to inflate the session JWE above 3500 bytes. Verify:
- Chunks appear correctly (`__session__0`, `__session__1`, …)
- When claims are removed, old chunks are deleted (not orphaned)

---

## Load Test

Simulates rapid unauthenticated requests to measure accumulation rate:

```bash
./scripts/load-test.sh http://localhost:3000 100
```

After the fix, the test should report 0 orphaned `__txn_*` cookies (or a count bounded by `maxSizeBytes`).

---

## Verification Matrix

| FC | Before fix | After fix |
|----|-----------|-----------|
| FC-1 | N txn cookies per page-load | 0 txn cookies on prefetch (401 returned) |
| FC-2 | 1 txn cookie per hover | 0 txn cookies on hover-prefetch |
| FC-3 | 1 txn cookie per silent-auth prefetch | 0 txn cookies on undetected prefetch (bounded by maxSizeBytes) |
| FC-4 | +1 txn per Server Action | 0 new txn cookies on Server Action |
| FC-5 | Invalid State on Tab 2 | Both tabs succeed (parallel mode) |
| FC-6 | Second login silently blocked | Second login overwrites first transaction |
| FC-7 | __FC_N orphans after passkey cycles | Stale __FC_N cleaned up on session update |
| FC-8 | (informational, chunks work correctly) | Same |
