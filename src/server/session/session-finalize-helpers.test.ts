import type { StateData } from "@auth0/auth0-server-js";
import { describe, expect, it, vi } from "vitest";

import { SessionData } from "../../types/index.js";
import {
  finalizeSessionData,
  finalizeStateData,
  SessionFinalizeHook
} from "./session-helpers.js";
import { sessionDataToStateData } from "./session-mapper.js";

function createSessionData(overrides: Partial<SessionData> = {}): SessionData {
  return {
    // A non-default claim (`custom_claim`) so the default-filter branch is
    // observable, plus a default one (`email`) that must survive it.
    user: { sub: "user123", email: "a@b.com", custom_claim: "keep-me" },
    internal: { sid: "session123", createdAt: 1000 },
    tokenSet: {
      accessToken: "<access>",
      idToken: "<id-token>",
      refreshToken: "<refresh>",
      audience: "",
      scope: "openid profile",
      expiresAt: 2000
    },
    ...overrides
  };
}

function createStateData(): StateData {
  return sessionDataToStateData(createSessionData());
}

describe("finalizeSessionData", () => {
  it("runs beforeSessionSaved with the id token and preserves internal", async () => {
    const hook: SessionFinalizeHook = vi.fn(async (session) => ({
      ...session,
      user: { ...session.user, added_by_hook: true },
      // A hook must not be able to drop internal.
      internal: { sid: "tampered", createdAt: 0 }
    }));

    const result = await finalizeSessionData(
      createSessionData(),
      "<id-token>",
      hook
    );

    expect(hook).toHaveBeenCalledWith(expect.anything(), "<id-token>");
    expect(result.user.added_by_hook).toBe(true);
    // The hook's changes to user are kept, but internal is restored.
    expect(result.internal).toEqual({ sid: "session123", createdAt: 1000 });
  });

  it("applies the default id token claim filter when no hook is configured", async () => {
    const result = await finalizeSessionData(
      createSessionData(),
      "<id-token>",
      undefined
    );

    // Default claims kept, non-default dropped.
    expect(result.user.email).toBe("a@b.com");
    expect(result.user.custom_claim).toBeUndefined();
  });
});

describe("finalizeStateData", () => {
  it("is a no-op when the context does not opt in", async () => {
    const stateData = createStateData();
    const hook = vi.fn();

    const result = await finalizeStateData(
      stateData,
      undefined,
      hook as unknown as SessionFinalizeHook
    );

    expect(hook).not.toHaveBeenCalled();
    expect(result).toBe(stateData);
  });

  it("runs the hook and round-trips through StateData when opted in", async () => {
    const hook: SessionFinalizeHook = vi.fn(async (session, idToken) => ({
      ...session,
      user: { ...session.user, hook_saw_id_token: idToken }
    }));

    const result = await finalizeStateData(createStateData(), true, hook);

    // The id token the hook receives comes from the session's own tokenSet.
    expect(hook).toHaveBeenCalledWith(expect.anything(), "<id-token>");
    expect((result.user as Record<string, unknown>).hook_saw_id_token).toBe(
      "<id-token>"
    );
    // Tokens survive the StateData -> SessionData -> StateData round-trip.
    expect(result.idToken).toBe("<id-token>");
    expect(result.refreshToken).toBe("<refresh>");
    expect(result.tokenSets[0].accessToken).toBe("<access>");
  });

  it("applies the default filter through the round-trip when no hook is set", async () => {
    const result = await finalizeStateData(createStateData(), true, undefined);

    expect((result.user as Record<string, unknown>).email).toBe("a@b.com");
    expect(
      (result.user as Record<string, unknown>).custom_claim
    ).toBeUndefined();
  });
});
