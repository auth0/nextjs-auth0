# Next.js MFA Step-up Authentication Example

This example demonstrates how to implement Step-up Authentication (MFA) for specific resources using `@auth0/nextjs-auth0` and Auth0 Actions. It handles the `mfa_required` error and ensures strict MFA enforcement without breaking standard session refreshes.

## Prerequisites

- An Auth0 Tenant.
- A basic understanding of [Auth0 Actions](https://auth0.com/docs/customize/actions).

## ⚠️ Critical Configuration Warnings

1.  **Tenant MFA Policy**: Set your Global MFA Policy to **"Adaptive"** or **"Disabled"**.
    *   **Do NOT** use "Always" or "All Applications" globally. This enforces MFA on `refresh_token` exchanges (background updates), which will break your application's session management and cause infinite loops in Next.js.
2.  **Enforcement via Actions**: We use an Auth0 Action to enforce MFA only when specific conditions are met (e.g., requesting a specific Audience or Scope).

## Setup Instructions

### 1. Configure Auth0 Action

The "Gold Standard" for Step-up Authentication requires handling edge cases that standard documentation often overlooks.

Create a new **Post Login** Action in your Auth0 Dashboard with the following code.

**Why this code?**
*   **Refresh Grant Guard**: `if (grantType === 'refresh_token') return;` is critical. Without it, silent token refreshes will fail.
*   **Enrollment Check**: Checks if the user has factors enrolled before challenging. Calling `challengeWith` on an unenrolled user causes a 500 server error ("Something Went Wrong").

```javascript
/**
 * Handler that will be called during the execution of a PostLogin flow.
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  // 1. CRITICAL: Skip MFA for refresh token grants to prevent loops/errors in background updates
  const grantType = event.request?.body?.grant_type;
  if (grantType === 'refresh_token') {
    return;
  }

  // 2. Define target (Audience or Scope)
  // Adjust this to match the audience requested by your app
  const targetAudience = event.secrets.TARGET_AUDIENCE || 'resource-server-1';
  
  const requestedAudience = event.transaction?.requested_audience || 
                            event.request?.query?.audience ||
                            (event.resource_server?.identifier);
  
  // 3. Check if target is being requested
  if (!requestedAudience || !requestedAudience.includes(targetAudience)) {
    return;
  }
  
  // 4. Check if MFA already completed in this session
  const authMethods = event.authentication?.methods || [];
  const hasMfa = authMethods.some(method => method.name === 'mfa');
  if (hasMfa) {
    return;
  }
  
  // 5. Check if user is enrolled
  const enrolledFactors = event.user.multifactor || [];
  if (enrolledFactors.length === 0) {
    // Option: Force enrollment (api.authentication.enrollWith) or Fail
    // For this test setup, we skip to avoid "Something went wrong" errors for new users
    console.log('User has no MFA enrolled, skipping challenge');
    return;
  }
  
  // 6. Challenge
  api.authentication.challengeWith({ type: 'otp' });
};
```

**Deploy the Action** and add it to your "Login" flow.

### 2. Configure Environment Variables

Copy the example environment file and configure your Auth0 credentials.

```bash
cp .env.local.example .env.local
```

Ensure your `AUTH0_ISSUER_BASE_URL`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` are set.
For this example to work as intended, ensure your application requests the Audience defined in your Action logic (e.g., `AUTH0_AUDIENCE=resource-server-1`).

### 3. Run the Application

```bash
npm install
npm run dev
```

Visit `http://localhost:3000`.

## How It Works

1.  **Initial Login**: The user logs in. If they don't request the sensitive scope/audience, no MFA is required.
2.  **Step-up Request**: When the user accesses a protected route or clicks a button that requests an Access Token for the sensitive audience:
    *   The SDK calls `getAccessToken`.
    *   Auth0 Action triggers and denies the token with `mfa_required`.
3.  **Error Handling**:
    *   The SDK catches the `MfaRequiredError`.
    *   The error object contains an `mfa_token`.
    *   The app redirects the user back to Auth0, passing this `mfa_token` to the `/authorize` endpoint.
4.  **Verification**: The user enters their OTP code.
5.  **Success**: Auth0 redirects back to the app with the step-up completed. The `getAccessToken` call now succeeds.

## Troubleshooting & Common Pitfalls

-   **"Something Went Wrong" on login**: The Action likely called `challengeWith` for a user who hasn't enrolled in MFA yet. Ensure your test user has enrolled manually (e.g., via Account Settings or a separate flow) before testing the step-up. The provided Action code defensively skips this challenge to prevent this error.
-   **Endless interactions/Validation errors**: Check that your "Global Policy" in Auth0 is NOT set to "Always". It must be "Adaptive" or "Disabled" so the Action controls the logic.
-   **Refresh Token fails**: Ensure the Action includes the `if (grantType === 'refresh_token') return;` check. Background requests for tokens must be allowed to proceed without interaction.
