import { describe, expect, it } from "vitest";

import { filterDefaultIdTokenClaims } from "./user.js";

describe("filterDefaultIdTokenClaims", async () => {
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
      exp: 1234567890
    };

    expect(filterDefaultIdTokenClaims(claims)).toEqual({
      sub: "user_123",
      name: "John Doe",
      nickname: "johndoe",
      given_name: "John",
      family_name: "Doe",
      picture: "https://example.com/johndoe.jpg",
      email: "john@example.com",
      email_verified: true,
      org_id: "org_123"
    });
  });

  it("should retain the act claim", () => {
    const act = { sub: "agent|abc123" };
    expect(filterDefaultIdTokenClaims({ sub: "user_123", act })).toEqual({
      sub: "user_123",
      act
    });
  });

  it("should retain a nested act chain", () => {
    const act = { sub: "agent|abc123", act: { sub: "service|xyz" } };
    expect(filterDefaultIdTokenClaims({ sub: "user_123", act })).toEqual({
      sub: "user_123",
      act
    });
  });

  it("should return an empty object if no claims are provided", () => {
    expect(filterDefaultIdTokenClaims({})).toEqual({});
  });
});
