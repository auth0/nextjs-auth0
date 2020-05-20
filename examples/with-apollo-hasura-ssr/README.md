# Apollo + Hasura + Auth0 + SSR + API:s + Logging

This sample is contributed by [Logary Tech](https://logary.tech) — follow us on Twitter — [@logarylib](https://twitter.com/logarylib) and use our NodeJS/.Net open source logging libs.

Getting started:

    git clone https://github.com/auth0/nextjs-auth0.git
    cd nextjs-auth0/examples/with-apollo-hasura-ssr
    cp .env.local.template .env.local

Now, correct for your own Auth0 tenant/application in:

- `.env.local`
- `.env.production` (change `example.com` to your own domain)

If you want to deploy to Vercel NOW, use the `now` CLI to set the secrets found in `now.json`.

You can now test with

    yarn
    yarn dev

and then surfing to [http://localhost:3000](http://localhost:3000).

## Points of interest

- All pages are in `./pages` and all API endpoints in `./pages/api`
- This sample works without Hasura / the `/api/graphql` endpoint, but if you want to try it, follow along below:

## Running in Kubernetes with Hasura/pgsql (optional)

1. Ensure your `docker-desktop` is running (or similar)
1. `make deploy_dev`
1. `kubectl -n app port-forward srv/with-apollo-hasura-ssr 8080:80`
1. Open a browser on `http://localhost:8080`

You can verify the state of things with:

- `kubectl get events --all-namespaces -w`
- `kubectl get pods -n app`
- `kubectl describe deployment with-apollo-hasura-ssr,with-apollo-hasura-ssr-db`

I also recommend downloading `stern` that takes a regex to tail:

    brew install stern
    stern with-apollo --since 5s

## Developing with Kubernetes / Docker (optional)

This repo also has Skaffold configured for Kubernetes + Kustomize, e.g. do:

    brew install skaffold
    skaffold dev

You now have everything running in k8s locally.
    
`.test` is a global domain for specifically testing. You can create domain names under it on your local machine without ever worrying about them conflicting. In this example, I'm using `app.example.test` throughout.

Configure your hosts file by running `make configure_laptop_macos` or at least
`make make_cert add_hosts`, depending on your OS — this ensures you can surf to a self-signed TLS certificate in your browsers.

The last bit is to either tell your ingress to route to `with-apollo-hasura-ssr.app`; file an issue if you need help with this.

## What to expect from Auth0

When running this sample, you can see the `Identity Token` values printed to your browser (and the Auth0 Profile). Examples are below. It's the JWT-encoded Identity Token you should pass as a Bearer token in the Authorization HTTP header, to Hasura. E.g. see `./pages/api/graphql.ts`

### Auth0 IdP

```json
{
  "https://hasura.io/jwt/claims": {
    "x-hasura-default-role": "user",
    "x-hasura-allowed-roles": [
      "user"
    ],
    "x-hasura-user-id": "auth0|5ebfa95c8b239d0bfe6de851"
  },
  "nickname": "test",
  "name": "test@example.com",
  "picture": "https://s.gravatar.com/avatar/55502f40dc8b7c769880b10874abc9d0?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fte.png",
  "updated_at": "2020-05-18T13:44:56.716Z",
  "sub": "auth0|5ebfa95c8b239d0bfe6de851"
}
```


### Google IdP

```json
{
  "https://hasura.io/jwt/claims": {
    "x-hasura-default-role": "user",
    "x-hasura-allowed-roles": [
      "user"
    ],
    "x-hasura-user-id": "google-oauth2|116555801591568093350"
  },
  "given_name": "Henrik",
  "family_name": "F",
  "nickname": "haf",
  "name": "Henrik F",
  "picture": "https://lh3.googleusercontent.com/a-/AOh14GgaJ5HzaI66rnez1WyjhokqRpzIFtz7vXB0kt65Lw",
  "locale": "en",
  "updated_at": "2020-05-18T13:40:21.398Z",
  "sub": "google-oauth2|116555801591568093350"
}
```

### Inserting from Auth0

```graphql
mutation InsertUser($idp: idps_enum, $userId: String!, $userEmail: String) {
  insert_users_one(
    object: {idp: $idp, idp_id: $userId, email: $userEmail},
    on_conflict: {constraint: users_idp_id_key, update_columns: []}) {
    id
  }
}
```

...with vars:

```json
{
  "idp": "google_oauth2",
  "userId": "google-oauth2|abc",
  "userEmail": "test@example.com"
}
```

## Migrating

```
cd schema
hasura migrate apply
```
