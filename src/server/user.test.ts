import { describe, expect, it } from "vitest"

import { filterClaims } from "./user"

describe("filterClaims", async () => {
  it("should return only the allowed claims", () => {
    const claims = {
      sub: "user_123",
      name: "John Doe",
      nickname: "johndoe",
      given_name: "John",
      family_name: "Doe",
      picture: "https://example.com/johndoe.jpg",
      email: "john@example.com",
      email_verified: true,
      org_id: "org_123",

      // Extra claims
      iat: 1234567890,
      exp: 1234567890,
    }

    expect(filterClaims(claims)).toEqual({
      sub: "user_123",
      name: "John Doe",
      nickname: "johndoe",
      given_name: "John",
      family_name: "Doe",
      picture: "https://example.com/johndoe.jpg",
      email: "john@example.com",
      email_verified: true,
      org_id: "org_123",
    })
  })

  it("should return an empty object if no claims are provided", () => {
    expect(filterClaims({})).toEqual({})
  })
})
