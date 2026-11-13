import { afterEach, describe, expect, it, vi } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import type { PoppyConfig } from "../types/poppy.js";
import {
  classifyPoppyLogin,
  explainPoppyGuestFailure,
  pickPoppyUserClaims,
  readPoppyAgentState,
  resolvePoppyRuntime,
  toPoppyAgentContext
} from "./poppy-agent.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";

const config: PoppyConfig = {
  protocolVersion: "0.3",
  domain: "fernway.com",
  issuer: "https://auth.fernway.com/",
  browserSessionEndpoint: "https://auth.fernway.com/poppy/web/browser-session"
};

const runtime = resolvePoppyRuntime({ config });
const now = Math.floor(Date.now() / 1000);

// The act Auth0's browser join puts in the web app's tokens.
const agentClientId = "https://muse.example/agent.json";
const agentAct = {
  sub: agentClientId,
  poppy_sid: "s_8Hq2",
  poppy_user_id: "u_Q7c1"
};
const anonymousSubProfile = "user urn:auth0:anonymous_user";
const guestClaims = {
  sub: "anon_poppy@7c2e5a1d",
  sub_profile: anonymousSubProfile,
  exp: now + 7200,
  act: agentAct
};

describe("resolvePoppyRuntime", () => {
  it("defaults the guest prefix", () => {
    expect(runtime).toMatchObject({
      issuer: "https://auth.fernway.com/",
      guestSubjectPrefix: "anon_poppy@"
    });
    expect(runtime.discovery.poppy).toBeDefined();
  });

  it("takes a custom guest prefix", () => {
    expect(
      resolvePoppyRuntime({ config, guestSubjectPrefix: "guest@" })
    ).toMatchObject({ guestSubjectPrefix: "guest@" });
  });

  it.each([[{ guestSubjectPrefix: "" }, /guestSubjectPrefix/]])(
    "rejects an empty option %j",
    (extra, message) => {
      expect(() => resolvePoppyRuntime({ config, ...extra })).toThrow(
        InvalidConfigurationError
      );
      expect(() => resolvePoppyRuntime({ config, ...extra })).toThrow(message);
    }
  );
});

describe("readPoppyAgentState", () => {
  it("keeps the token's own sub and sub_profile, act, and the expiry from exp", () => {
    expect(
      readPoppyAgentState({
        sub: "auth0|ana",
        sub_profile: "user",
        exp: now + 7200,
        act: agentAct
      })
    ).toEqual({
      sub: "auth0|ana",
      sub_profile: "user",
      act: agentAct,
      sessionExpiresAt: now + 7200
    });
  });

  it("leaves sub_profile out when the token has none", () => {
    expect(
      readPoppyAgentState({ sub: "auth0|ana", exp: now + 7200, act: agentAct })
    ).not.toHaveProperty("sub_profile");
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["not a string", 42]
  ])("is not an agent when the token's sub is %s", (_case, sub) => {
    expect(
      readPoppyAgentState({ sub, exp: now + 7200, act: agentAct })
    ).toBeUndefined();
  });

  it("keeps the whole act claim, including claims it doesn't read", () => {
    const act = {
      ...agentAct,
      client_id: "tpc_ckhGFm35ZX7SVZfnEHKkae",
      sub_profile: "ai_agent",
      iss: "https://auth.fernway.com/",
      future_claim: { nested: true }
    };
    expect(
      readPoppyAgentState({ sub: "auth0|ana", exp: now + 7200, act })?.act
    ).toEqual(act);
  });

  it("ignores Poppy IDs outside act", () => {
    expect(
      readPoppyAgentState({
        sub: "auth0|ana",
        exp: now + 7200,
        poppy_sid: "s_top",
        poppy_user_id: "u_top",
        act: { sub: agentClientId }
      })
    ).toBeUndefined();
  });

  it("does not take other names for the Poppy IDs", () => {
    expect(
      readPoppyAgentState({
        sub: "auth0|ana",
        exp: now + 7200,
        act: { sub: agentClientId, poppy_uid: "u_old", sessionId: "s_camel" }
      })
    ).toBeUndefined();
  });

  it.each([
    ["no act", { sub: "auth0|ana", exp: now + 7200 }],
    [
      "an impersonation actor (no Poppy IDs)",
      { sub: "auth0|ana", exp: now + 7200, act: { sub: "auth0|support-rep" } }
    ],
    [
      "act without poppy_sid",
      {
        sub: "auth0|ana",
        exp: now + 7200,
        act: { sub: agentClientId, poppy_user_id: "u" }
      }
    ],
    [
      "act without poppy_user_id",
      {
        sub: "auth0|ana",
        exp: now + 7200,
        act: { sub: agentClientId, poppy_sid: "s" }
      }
    ],
    [
      "act without sub",
      {
        sub: "auth0|ana",
        exp: now + 7200,
        act: { poppy_sid: "s", poppy_user_id: "u" }
      }
    ],
    [
      "act that is not an object",
      { sub: "auth0|ana", exp: now + 7200, act: "x" }
    ],
    ["no exp", { sub: "auth0|ana", act: agentAct }],
    [
      "exp in milliseconds",
      { sub: "auth0|ana", exp: now * 1000, act: agentAct }
    ]
  ])("returns undefined for %s", (_case, claims) => {
    expect(readPoppyAgentState(claims)).toBeUndefined();
  });
});

describe("classifyPoppyLogin", () => {
  it("classifies a person", () => {
    expect(
      classifyPoppyLogin({ sub: "auth0|ana", exp: now + 7200 }, runtime)
    ).toEqual({ kind: "human" });
  });

  it("classifies a signed-in agent", () => {
    expect(
      classifyPoppyLogin(
        { sub: "auth0|ana", exp: now + 7200, act: agentAct },
        runtime
      ).kind
    ).toBe("agent");
  });

  it("classifies an agent guest", () => {
    expect(classifyPoppyLogin(guestClaims, runtime)).toMatchObject({
      kind: "guest",
      state: { sub: "anon_poppy@7c2e5a1d", sub_profile: anonymousSubProfile }
    });
  });

  it("finds the anonymous marker anywhere in sub_profile", () => {
    expect(
      classifyPoppyLogin(
        { ...guestClaims, sub_profile: "urn:auth0:anonymous_user user" },
        runtime
      ).kind
    ).toBe("guest");
  });

  it.each([
    ["no Poppy act", { ...guestClaims, act: { sub: "auth0|rep" } }],
    ["no anonymous sub_profile", { ...guestClaims, sub_profile: "user" }],
    ["no anon_poppy@ subject", { ...guestClaims, sub: "auth0|someone" }],
    ["no exp", { ...guestClaims, exp: undefined }]
  ])("fails closed on a guest-looking login with %s", (_case, claims) => {
    expect(classifyPoppyLogin(claims, runtime).kind).toBe("invalid_guest");
  });

  it("does not treat the SDK's own anonymous subject format as a Poppy guest", () => {
    expect(
      classifyPoppyLogin(
        { sub: "anon@1234", exp: now + 7200, act: agentAct },
        runtime
      ).kind
    ).toBe("agent");
  });
});

describe("explainPoppyGuestFailure", () => {
  it("says the subject lacks the prefix", () => {
    expect(
      explainPoppyGuestFailure(
        { ...guestClaims, sub: "auth0|someone" },
        runtime
      )
    ).toBe(
      'sub_profile marks an anonymous subject, but sub does not start with "anon_poppy@"'
    );
  });

  it("names a wrong or missing sub_profile", () => {
    expect(
      explainPoppyGuestFailure({ ...guestClaims, sub_profile: "user" }, runtime)
    ).toBe(
      'sub_profile is "user", expected it to include "urn:auth0:anonymous_user"'
    );
    expect(
      explainPoppyGuestFailure(
        { ...guestClaims, sub_profile: undefined },
        runtime
      )
    ).toBe(
      'sub_profile is missing, expected it to include "urn:auth0:anonymous_user"'
    );
  });

  it("says there is no act claim, and lists the claims that are there", () => {
    const { act: _act, ...withoutAct } = guestClaims;
    expect(explainPoppyGuestFailure(withoutAct, runtime)).toBe(
      'there is no "act" claim (the ID token has: sub, sub_profile, exp)'
    );
  });

  it("says act is not an object", () => {
    expect(
      explainPoppyGuestFailure({ ...guestClaims, act: ["a"] }, runtime)
    ).toBe('"act" is an array, not an object');
  });

  it.each([
    [
      "sub",
      { poppy_sid: "s", poppy_user_id: "u" },
      '"act" has: poppy_sid, poppy_user_id'
    ],
    [
      "poppy_sid",
      { sub: agentClientId, poppy_user_id: "u" },
      '"act" has: sub, poppy_user_id'
    ],
    [
      "poppy_user_id",
      { sub: agentClientId, poppy_sid: "s" },
      '"act" has: sub, poppy_sid'
    ]
  ])("says act.%s is missing", (name, act, keys) => {
    expect(explainPoppyGuestFailure({ ...guestClaims, act }, runtime)).toBe(
      `act.${name} is missing or not a string (${keys})`
    );
  });

  it("says the expiry is unusable when everything else is fine", () => {
    expect(
      explainPoppyGuestFailure({ ...guestClaims, exp: undefined }, runtime)
    ).toBe("the ID token exp is not a valid Unix time in seconds");
  });

  it("never prints claim values other than the sub_profile label", () => {
    const text = explainPoppyGuestFailure(
      {
        sub: "anon_poppy@secret-subject",
        sub_profile: anonymousSubProfile,
        email: "ana@example.com",
        act: { sub: agentClientId, poppy_sid: "secret-sid" }
      },
      runtime
    );
    expect(text).not.toContain("secret-subject");
    expect(text).not.toContain("ana@example.com");
    expect(text).not.toContain("muse.example");
    expect(text).not.toContain("secret-sid");
  });
});

describe("pickPoppyUserClaims", () => {
  it("picks only the profile claims", () => {
    expect(
      pickPoppyUserClaims({
        sub: "auth0|ana",
        sub_profile: "user",
        client_profile: "web",
        poppy_sid: "s",
        other: "dropped"
      })
    ).toEqual({ sub_profile: "user", client_profile: "web" });
  });
});

describe("toPoppyAgentContext", () => {
  const state = {
    sub: "auth0|ana",
    sub_profile: "user",
    act: agentAct,
    sessionExpiresAt: now + 7200
  };

  it("mirrors the ID token: its own sub and sub_profile, and its act", () => {
    expect(
      toPoppyAgentContext(state, "signed_in", "openid orders:write  profile")
    ).toEqual({
      kind: "agent",
      state: "signed_in",
      sub: "auth0|ana",
      sub_profile: "user",
      act: agentAct,
      scopes: ["openid", "orders:write", "profile"]
    });
  });

  it("returns the whole act as Auth0 sent it, nested", () => {
    // The act on an RFD signed-in join token, plus a claim Auth0 may add later.
    const act = {
      sub: "agt_gZameUasxQq5wLiFTW7rxF",
      sub_profile: "ai_agent",
      client_id: "tpc_ckhGFm35ZX7SVZfnEHKkae",
      poppy_sid: "g4B43922Ut9eOkjgDb7xFA",
      poppy_user_id: "n9YYwSTyEXoeF1tr3Yr_-A",
      poppy_agent_id: "muse-12q1312",
      iss: "https://auth.fernway.com/",
      future_claim: { nested: true }
    };
    expect(
      toPoppyAgentContext({ ...state, act }, "signed_in", "openid")
    ).toEqual({
      kind: "agent",
      state: "signed_in",
      sub: "auth0|ana",
      sub_profile: "user",
      act,
      scopes: ["openid"]
    });
  });

  it("keeps the token's sub apart from the agent's sub in act", () => {
    const context = toPoppyAgentContext(state, "guest");
    expect(context).toMatchObject({ sub: "auth0|ana" });
    expect((context as { act: { sub: string } }).act.sub).toBe(agentClientId);
  });

  it("leaves sub_profile out when the token had none", () => {
    const { sub_profile: _unused, ...withoutSubProfile } = state;
    expect(toPoppyAgentContext(withoutSubProfile, "guest")).not.toHaveProperty(
      "sub_profile"
    );
  });

  it("gives a guest no scopes", () => {
    expect(toPoppyAgentContext(state, "guest", "orders:write")).toMatchObject({
      state: "guest",
      scopes: []
    });
  });
});

describe("calculateMaxAge with a ceiling", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const secret = "a-very-long-secret-that-is-at-least-32-characters-long";

  it("caps a rolling session at the ceiling", () => {
    const store = new StatelessSessionStore({ secret, rolling: true });
    const epoch = store.epoch();
    expect(store.calculateMaxAge(epoch, epoch + 600)).toBe(600);
    expect(store.calculateMaxAge(epoch)).toBe(86400);
  });

  it("caps a non-rolling session at the ceiling", () => {
    const store = new StatelessSessionStore({ secret, rolling: false });
    const epoch = store.epoch();
    expect(store.calculateMaxAge(epoch, epoch + 600)).toBe(600);
    expect(store.calculateMaxAge(epoch)).toBe(259200);
  });

  it("never rolls past the ceiling and reaches zero once it has passed", () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const store = new StatelessSessionStore({ secret, rolling: true });
    const createdAt = store.epoch();
    const ceiling = createdAt + 600;

    vi.setSystemTime((createdAt + 500) * 1000);
    expect(store.calculateMaxAge(createdAt, ceiling)).toBe(100);

    vi.setSystemTime((createdAt + 700) * 1000);
    expect(store.calculateMaxAge(createdAt, ceiling)).toBe(0);
  });
});
