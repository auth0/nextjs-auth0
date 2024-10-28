import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { Auth0Client } from "./client"
import { StatelessSessionStore } from "./session/stateless-session-store"
import { TransactionStore } from "./transaction-store"

describe("Auth0Client", () => {
  let originalEnv: NodeJS.ProcessEnv

  beforeEach(() => {
    originalEnv = { ...process.env }
  })

  afterEach(() => {
    process.env = originalEnv
  })

  it("should not throw an error if all the required parameters are provided — as env vars", () => {
    process.env.AUTH0_DOMAIN = "example.us.auth0.com"
    process.env.AUTH0_CLIENT_ID = "clientId"
    process.env.AUTH0_CLIENT_SECRET = "clientSecret"
    process.env.AUTH0_SECRET = "secret"
    process.env.APP_BASE_URL = "https://example.com"
    process.env.NODE_ENV = "production"
    expect(() => new Auth0Client()).not.toThrow()
  })

  it("should not throw an error if all the required parameters are provided — as options", () => {
    expect(
      () =>
        new Auth0Client({
          domain: "example.us.auth0.com",
          clientId: "clientId",
          clientSecret: "clientSecret",
          secret: "secret",
          appBaseUrl: "https://example.com",
        })
    ).not.toThrow()
  })

  it("should throw an error if the domain is not provided", () => {
    process.env.AUTH0_CLIENT_ID = "clientId"
    process.env.AUTH0_CLIENT_SECRET = "clientSecret"
    process.env.AUTH0_SECRET = "secret"
    process.env.APP_BASE_URL = "https://example.com"
    process.env.NODE_ENV = "production"
    expect(() => new Auth0Client()).toThrow(
      /The AUTH0_DOMAIN environment variable or domain option is required/i
    )
  })

  it("should throw an error if the client ID is not provided", () => {
    process.env.AUTH0_DOMAIN = "example.us.auth0.com"
    process.env.AUTH0_CLIENT_SECRET = "clientSecret"
    process.env.AUTH0_SECRET = "secret"
    process.env.APP_BASE_URL = "https://example.com"
    process.env.NODE_ENV = "production"
    expect(() => new Auth0Client()).toThrow(
      /The AUTH0_CLIENT_ID environment variable or clientId option is required/i
    )
  })

  it("should throw an error if the client secret is not provided", () => {
    process.env.AUTH0_DOMAIN = "example.us.auth0.com"
    process.env.AUTH0_CLIENT_ID = "clientId"
    process.env.AUTH0_SECRET = "secret"
    process.env.APP_BASE_URL = "https://example.com"
    process.env.NODE_ENV = "production"
    expect(() => new Auth0Client()).toThrow(
      /The AUTH0_CLIENT_SECRET environment variable or clientSecret option is required/i
    )
  })

  it("should throw and error if the app base URL is not provided", () => {
    process.env.AUTH0_DOMAIN = "example.us.auth0.com"
    process.env.AUTH0_CLIENT_ID = "clientId"
    process.env.AUTH0_CLIENT_SECRET = "clientSecret"
    process.env.AUTH0_SECRET = "secret"
    process.env.NODE_ENV = "production"
    expect(() => new Auth0Client()).toThrow(
      /The APP_BASE_URL environment variable or appBaseUrl option is required/i
    )
  })

  it("should throw and error if the app base URL is not provided", () => {
    process.env.AUTH0_DOMAIN = "example.us.auth0.com"
    process.env.AUTH0_CLIENT_ID = "clientId"
    process.env.AUTH0_CLIENT_SECRET = "clientSecret"
    process.env.AUTH0_SECRET = "secret"
    process.env.APP_BASE_URL = "http://example.com"
    process.env.NODE_ENV = "production"
    expect(() => new Auth0Client()).toThrow(
      /The appBaseUrl must use the HTTPS protocol in production/i
    )
  })
})
