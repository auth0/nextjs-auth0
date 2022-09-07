# Frequently Asked Questions

1. [Why do I get a `checks.state argument is missing` error when logging in from different tabs?](#1-why-do-i-get-a-checks.state-argument-is-missing-error-if-i-try-to-log-in-from-different-tabs)

## 1. Why do I get a `checks.state argument is missing` error if I try to log in from different tabs?

Every time you initiate login, the SDK stores in cookies some transient state (`nonce`, `state`, `code_verifier`) necessary to verify the callback request from Auth0. Initiating login concurrently from different tabs will result in that state being overwritten in each subsequent tab. Once the login is completed in some tab, the SDK will compare the state in the callback with the state stored in the cookies. As the cookies were overwritten, the values will not match (except for the tab that initiated login the last) and the SDK will return the `checks.state argument is missing` error.

For example:

1. Open Tab 1 to log in: stores some state in cookies.
2. Open Tab 2 to log in: stores its own state overwritting Tab 1 state.
3. Complete login on Tab 1: SDK finds Tab 2 state on the cookies and returns error.

**You should handle the error and prompt the user to log in again.** As they will have an active SSO session, they will not be asked to enter their credentials again and will be redirected back to your application.
