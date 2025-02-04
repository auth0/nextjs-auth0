import { Auth0Client } from "@auth0/nextjs-auth0/server"

export const auth0 = new Auth0Client({
    // This is needed for now when using Federated Connection Token Exchange
    authorizationParameters: {
        access_type: 'offline'
    }
})
