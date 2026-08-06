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

  it("should retain urn:auth0:my_org_current_user_permissions with populated permissions", () => {
    const permissions = ["my_org:read_members", "my_org:invite_members"];
    expect(
      filterDefaultIdTokenClaims({
        sub: "user_123",
        "urn:auth0:my_org_current_user_permissions": permissions
      })
    ).toEqual({
      sub: "user_123",
      "urn:auth0:my_org_current_user_permissions": permissions
    });
  });

  it("should retain urn:auth0:my_org_current_user_permissions when the array is empty", () => {
    expect(
      filterDefaultIdTokenClaims({
        sub: "user_123",
        "urn:auth0:my_org_current_user_permissions": []
      })
    ).toEqual({
      sub: "user_123",
      "urn:auth0:my_org_current_user_permissions": []
    });
  });

  it("should retain all standard claims together with urn:auth0:my_org_current_user_permissions", () => {
    const permissions = ["my_org:manage_member_roles"];
    expect(
      filterDefaultIdTokenClaims({
        sub: "user_123",
        name: "Jane",
        email: "jane@example.com",
        org_id: "org_456",
        "urn:auth0:my_org_current_user_permissions": permissions,
        iat: 1234567890,
        exp: 9999999999
      })
    ).toEqual({
      sub: "user_123",
      name: "Jane",
      email: "jane@example.com",
      org_id: "org_456",
      "urn:auth0:my_org_current_user_permissions": permissions
    });
  });

  it("should strip unrecognised custom claims while preserving standard ones", () => {
    expect(
      filterDefaultIdTokenClaims({
        sub: "user_123",
        custom_claim: "foo",
        "https://example.com/role": "admin"
      })
    ).toEqual({
      sub: "user_123"
    });
  });

  it("should return an empty object if no claims are provided", () => {
    expect(filterDefaultIdTokenClaims({})).toEqual({});
  });
});
