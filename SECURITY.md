# Security Considerations

## Cookies and Security

All cookies will be set to `HttpOnly, SameSite=Lax` and will be set to `Secure` if the application's `AUTH0_BASE_URL` is `https`.

The `HttpOnly` setting will make sure that client-side JavaScript is unable to access the cookie to reduce the attack surface of [XSS attacks](https://auth0.com/blog/developers-guide-to-common-vulnerabilities-and-how-to-prevent-them/#Cross-Site-Scripting--XSS-).

The `SameSite=Lax` setting will help mitigate CSRF attacks. Learn more about SameSite by reading the ["Upcoming Browser Behavior Changes: What Developers Need to Know"](https://auth0.com/blog/browser-behavior-changes-what-developers-need-to-know/) blog post.

## Caching and Security

Many hosting providers will offer to cache your content at the edge in order to serve data to your users as fast as possible. For example Vercel will [cache your content on the Vercel Edge Network](https://vercel.com/docs/concepts/edge-network/caching) for all static content and Serverless Functions if you provide the necessary caching headers on your response.

It's generally a bad idea to cache any response that requires authentication, even if the response's content appears safe to cache there may be other data in the response that isn't.

This SDK offers a rolling session by default, which means that any response that reads the session will have a `Set-Cookie` header to update the cookie's expiry. Vercel and potentially other hosting providers include the `Set-Cookie` header in the cached response, so even if you think the response's content can be cached publicly, the responses `Set-Cookie` header cannot.

Check your hosting provider's caching rules, but in general you should **never** cache responses that either require authentication or even touch the session to check authentication (eg when using `withApiAuthRequired`, `withPageAuthRequired` or even just `getSession` or `getAccessToken`).

## Error Handling and Security

The default server side error handler for the `/api/auth/*` routes prints the error message to screen, eg

```js
try {
  await handler(req, res);
} catch (error) {
  res.status(error.status || 400).end(error.message);
}
```

Because the error can come from the OpenID Connect `error` query parameter we do some [basic escaping](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content) which makes sure the default error handler is safe from XSS.

If you write your own error handler, you should **not** render the error `message`, or `error` and `error_description` properties without using a templating engine that will properly escape it for other HTML contexts first.

## Comparison with the Auth0 React SDK

We also provide an Auth0 React SDK, [auth0-react](https://github.com/auth0/auth0-react), which may be suitable for your Next.js application.

The SPA security model used by `auth0-react` is different from the Web Application security model used by this SDK. In short, this SDK protects pages and API routes with a cookie session (see ["Cookies and Security"](#cookies-and-security)). A SPA library like `auth0-react` will store the user's ID Token and Access Token directly in the browser and use them to access external APIs directly.

You should be aware of the security implications of both models. However, [auth0-react](https://github.com/auth0/auth0-react) may be more suitable for your needs if you meet any of the following scenarios:

- You are using [Static HTML Export](https://nextjs.org/docs/advanced-features/static-html-export) with Next.js.
- You do not need to access user data during server-side rendering.
- You want to get the access token and call external API's directly from the frontend layer rather than using Next.js API Routes as a proxy to call external APIs
