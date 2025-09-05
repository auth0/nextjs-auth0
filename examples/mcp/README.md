# Example Nextjs MCP Server with Auth0 Integration

This is a practical example of securing a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs) server
with Auth0.

## Install dependencies

- Run `pnpm install:examples` from the root to install dependencies

## Auth0 Tenant Setup

For detailed instructions on setting up your Auth0 tenant for MCP server integration, please refer to the [Auth0 Tenant Setup guide](https://github.com/auth0/auth0-auth-js/blob/main/examples/example-fastmcp-mcp/README.md#auth0-tenant-setup).

## Configuration

Rename `.env.example` to `.env` and configure the domain and audience:

```
# Auth0 tenant domain
AUTH0_DOMAIN=example-tenant.us.auth0.com
# Auth0 API Identifier
AUTH0_AUDIENCE=http://localhost:3000
```

With the configuration in place, the example can be started by running:

## Running the Server

For development with hot reload:

```bash
pnpm dev
```

Or build and run in production mode:

```bash
pnpm build
pnpm start
```

## Testing

Use an MCP client like [MCP Inspector](https://github.com/modelcontextprotocol/inspector) to test your server interactively:

```bash
npx @modelcontextprotocol/inspector
```

The server will start up and the UI will be accessible at http://localhost:6274.

In the MCP Inspector, select `Streamable HTTP` as the `Transport Type` and enter `http://localhost:3000/mcp` as the URL.
