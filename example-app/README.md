# Next.js Auth0 Example App

In this folder we'll be showing off how to use the [@auth0/nextjs-auth0](https://www.npmjs.com/package/@auth0/nextjs-auth0) package in your Next.js applications.

- [Local Development](#local-development)
    * [Configuring Auth0](#configuring-auth0)
    * [Environment Variables](#environment-variables)
- [Hosting on Vercel](#hosting-on-vercel)
    * [Configuring Auth0](#configuring-auth0-1)
        + [Wildcards](#wildcards)
    * [Configuring Vercel](#configuring-vercel)
    * [Environment Variables](#environment-variables-1)
        + [Assigning the AUTH0_BASE_URL](#assigning-the-auth0-base-url)
            - [Preview deployments](#preview-deployments)
            - [Production deployments (or other environments with fixed urls)](#production-deployments--or-other-environments-with-fixed-urls-)

### Local Development

#### Configuring Auth0

Go to the [Auth0 dashboard](https://manage.auth0.com/) and create a new application of type **Web Application** and make sure to configure the following:

| Setting               | Description                                                                                                                                                            |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Allowed Callback URLs | Should be set to `http://localhost:3000/api/auth/callback` when testing locally or typically to `https://myapp.com/api/auth/callback` when deploying your application. |
| Allowed Logout URLs   | Should be set to `http://localhost:3000/` when testing locally or typically to `https://myapp.com/` when deploying your application.                                   |

#### Environment Variables

For local development you'll just want to create a `.env.local` file with the necessary settings:

```
AUTH0_SECRET={A SECRET UNIQUE STRING} (at least 32 characters, used to encrypt the cookie)
AUTH0_ISSUER_BASE_URL=https://{YOUR_AUTH0_DOMAIN}
AUTH0_BASE_URL=http://localhost:3000/
AUTH0_CLIENT_ID={YOUR_AUTH0_CLIENT_ID}
AUTH0_CLIENT_SECRET={YOUR_AUTH0_CLIENT_SECRET}
AUTH0_SCOPE=openid profile read:shows
AUTH0_AUDIENCE={YOUR_AUTH0_API_IDENTIFIER}
```

### Hosting on Vercel

The example application is hosted on Vercel, including preview deployments to make Pull Request reviewing a bit easier in terms of verifying the functionalities in the example application.

#### Configuring Auth0

As every environment in Vercel, including preview deployments, has its unique URL, your Auth0 application needs to be configured to allow the corresponding Callback and Logout URLs.
This can be done manually, by going to the Application Settings on your [Auth0 dashboard](https://manage.auth0.com/) and make sure to configure the following:

| Setting               | Description                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------------- |
| Allowed Callback URLs | Should be set to `https://{YOUR_VERCEL_URL_PREFIX}.vercel.app/api/auth/callback` when deploying to vercel. |
| Allowed Logout URLs   | Should be set to `https://{YOUR_VERCEL_URL_PREFIX}.vercel.app/` when deploying to vercel.                  |

##### Wildcards

By default, Vercel uses the `vercel.app` domain for all of your environments. Using wildcards for a shared domain opens the possibility to redirect back to a malicious website, as long as the Callback URLs matches the wildcard configuration. Because of that, you should only consider using wildcards for the preview deployments when using a [Preview Deployment Suffix](https://vercel.com/docs/concepts/deployments/automatic-urls#preview-deployment-suffix), which is available as part of Vercel's Pro or Enterprise plan.

| Setting               | Description                                                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Allowed Callback URLs | Should be set to `https://{VERCEL_GIT_REPO_SLUG}-*-{VERCEL_TEAM}.yourdomain.com/api/auth/callback` when deploying to vercel. |
| Allowed Logout URLs   | Should be set to `https://{VERCEL_GIT_REPO_SLUG}-*-{VERCEL_TEAM}.yourdomain.com/` when deploying to vercel.                  |

#### Configuring Vercel

If you do not have a Vercel account, you can sign up for one at https://vercel.com/.
Once logged in to your account, you can create a new project and import a Git repository.

Vercel should automatically select the `Next.js` Framework Preset.
Because this app's deployment is a bit different from a standard Next.js repository, we override the `Build and Output settings` command:

- Build Command: `npm run build:vercel`
- Output Directory: `example-app/.next`

#### Environment Variables

Configure the following environment variables when importing your project or in "Settings > Environment Variables":

| Name                  | Value                                                                        |
| --------------------- |------------------------------------------------------------------------------|
| AUTH0_SECRET          | {A SECRET UNIQUE STRING} (at least 32 characters, used to encrypt the cookie) |
| AUTH0_ISSUER_BASE_URL | https://{YOUR_AUTH0_DOMAIN}                                                  |
| AUTH0_CLIENT_ID       | {YOUR_AUTH0_CLIENT_ID}                                                       |
| AUTH0_CLIENT_SECRET   | {YOUR_AUTH0_CLIENT_SECRET}                                                   |
| AUTH0_AUDIENCE        | {YOUR_AUTH0_API_IDENTIFIER}                                                  |

##### Assigning the AUTH0_BASE_URL

###### Preview deployments

For preview deployments you will either want to assign this to:

- **Automatic Deployment URL:** For example `project-d418mhwf5-team.vercel.app` which is the `VERCEL_URL` environment variable.
- **Automatic Branch URL:** For example `project-git-update-team.vercel.app` which is the `VERCEL_BRANCH_URL` environment variable.

See here for more information about Vercel's Automatic Urls: https://vercel.com/docs/concepts/deployments/automatic-urls

To do this, make sure **Automatically expose System Environment Variables** is checked in **Settings > Environment Variables** and assign either the Automatic Deployment URL (`VERCEL_URL`) or the Automatic Branch URL (`VERCEL_BRANCH_URL`) to `NEXT_PUBLIC_AUTH0_BASE_URL` in your `.env.production` file. For example:

```shell
# .env.production
NEXT_PUBLIC_AUTH0_BASE_URL=$VERCEL_URL
```

> <strong>Note:</strong> The `NEXT_PUBLIC_` prefix is used so you can specify the base URL in your middleware. You must be on version `2.6.0` or later of this SDK to use `NEXT_PUBLIC_AUTH0_BASE_URL`.

> <strong>Note:</strong> Long URLs (> 63 characters) will get truncated by Vercel. See: https://vercel.com/docs/concepts/deployments/generated-urls#truncation

Unlike other `.env` files, You will need to check in `.env.production` so it should **not** contain any secrets. See how we define `.env.production` in [.env.production](./.env.production).

###### Production deployments (or other environments with fixed urls)

For production deployments or [custom domains assigned to a git branch](https://vercel.com/docs/custom-domains#assigning-a-domain-to-a-git-branch) you should assign the correct url to the `AUTH0_BASE_URL` environment variable in "Settings > Environment Variables". See the [Vercel docs on Environment Variables](https://vercel.com/docs/environment-variables#preview-environment-variables) for more information. This will override your `.env.production` file.
