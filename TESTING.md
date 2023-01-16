# Testing

By default, the SDK creates and manages a singleton instance to run for the lifetime of the application. When testing your application, you may need to reset this instance, so its state does not leak between tests.

If you're using Jest, we recommend using `jest.resetModules()` after each test. Alternatively, you can look at [creating your own instance of the SDK](./EXAMPLES.md#create-your-own-instance-of-the-sdk), so it can be recreated between tests.

For end to end tests, have a look at how we use a [mock OIDC Provider](./scripts/oidc-provider.js).
