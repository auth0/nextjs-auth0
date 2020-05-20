/**
 * A proxy that lets you communicate with Hasura using the session cookie
 * that is assigned to you from the browser/Auth0
 *
 * - https://jwt.io/#debugger-io
 * - https://hasura.io/docs/1.0/graphql/manual/guides/integrations/auth0-jwt.html#guides-auth0-jwt
 * - https://api.example.test/console/api-explorer
 */
import { NextApiRequest, NextApiResponse } from 'next'
import auth0 from '../../lib/auth0'

const gqlURL = process.env.HASURA_GRAPHQL_URL
const logHeaders = process.env.HASURA_LOG_HEADERS || 'false'

export default async function graphql(req: NextApiRequest, res: NextApiResponse) {
  if (gqlURL == null) throw new Error('HASURA_GRAPHQL_URL is missing')

  if (req.method !== 'POST') {
    res.status(404)
    return
  }

  const session = await auth0.getSession(req)

  const headers =  {
    'content-type': 'application/json; charset=utf-8',
    'accept': 'application/json',
    'accept-encoding': 'gzip, deflate',
    ...(session?.idToken != null ? {
      authorization: session.idToken && `Bearer ${session.idToken}`,
    } : {})
  }

  try {
    const gqlResponse = await fetch(gqlURL, {
      method: 'POST',
      // @ts-ignore
      headers,
      body: JSON.stringify(req.body),
    })

    const data = await gqlResponse.text()

    if (logHeaders === 'true') console.info('/api/graphql, using headers', headers)

    const ct = gqlResponse.headers.get('content-type')
    if (ct != null) res.setHeader('content-type', ct)
    res.status(gqlResponse.status).send(data)

  } catch (error) {
    console.error(error)
    if (res.writable) {
      res.status(error.status || 500).json({
        error: true,
        message: 'Internal server error',
        code: 500,
      })
    }
  }
}
