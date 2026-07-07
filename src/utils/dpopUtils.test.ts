import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance
} from "vitest";

import {
  validateDpopConfiguration,
  validateKeyPairCompatibility
} from "./dpopUtils.js";

// A real P-256 key pair in PEM format for tests that load from env vars
const VALID_EC_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp0wDA8gMnjHekh89
LOuaGjAVBXEokqnNrBlVziKlTfOhRANCAARw9YHYil7Ewilw9JVC/lUui+0/AyiF
M6mJF+ihRfxP2fN4coyDRRKMgi87bRnyiMW0qOECyWxVfoi2u4avHZ+l
-----END PRIVATE KEY-----`;

const VALID_EC_PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcPWB2IpexMIpcPSVQv5VLovtPwMo
hTOpiRfooUX8T9nzeHKMg0USjIIvO20Z8ojFtKjhAslsVX6ItruGrx2fpQ==
-----END PUBLIC KEY-----`;

// ============================================================================
// validateKeyPairCompatibility
// ============================================================================
describe("validateKeyPairCompatibility", () => {
  it("returns true for a valid P-256 key pair", async () => {
    const crypto = await import("crypto");
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    const result = await validateKeyPairCompatibility(privateKey, publicKey);
    expect(result).toBe(true);
  });

  it("returns false and warns when keys do not form a valid pair", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const crypto = await import("crypto");
    // Two independent key pairs — sign with pair1 private, verify with pair2 public → mismatch
    const { privateKey: priv1 } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    const { publicKey: pub2 } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });

    const result = await validateKeyPairCompatibility(priv1, pub2);
    expect(result).toBe(false);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("do not form a valid key pair")
    );
    warnSpy.mockRestore();
  });

  it("returns true (skip) in Edge Runtime", async () => {
    (globalThis as any).EdgeRuntime = "edge";
    try {
      const crypto = await import("crypto");
      const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1"
      });
      const result = await validateKeyPairCompatibility(privateKey, publicKey);
      expect(result).toBe(true);
    } finally {
      delete (globalThis as any).EdgeRuntime;
    }
  });

  it("returns false and warns when crypto throws during sign/verify", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const crypto = await import("crypto");
    // RSA private key — createSign("sha256").sign() works but createVerify("sha256") against
    // an EC public key should throw or fail — use an actually-broken EC key by passing a
    // mock object that causes an error
    const { privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    // Provide a malformed public key mock that throws on verify
    const badPublicKey = {
      asymmetricKeyType: "ec"
    } as any;

    const result = await validateKeyPairCompatibility(privateKey, badPublicKey);
    expect(result).toBe(false);
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Failed to validate key pair compatibility")
    );
    warnSpy.mockRestore();
  });
});

// ============================================================================
// validateDpopConfiguration
// ============================================================================
describe("validateDpopConfiguration", () => {
  let warnSpy: MockInstance;
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = [
    "AUTH0_DPOP_CLOCK_TOLERANCE",
    "AUTH0_DPOP_CLOCK_TOLERANCE_MAX_PROD",
    "AUTH0_DPOP_CLOCK_SKEW",
    "AUTH0_RETRY_DELAY",
    "AUTH0_RETRY_JITTER",
    "AUTH0_DPOP_PRIVATE_KEY",
    "AUTH0_DPOP_PUBLIC_KEY",
    "NODE_ENV"
  ];

  beforeEach(() => {
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    warnSpy.mockRestore();
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = savedEnv[key];
      }
    }
    delete (globalThis as any).EdgeRuntime;
    vi.unstubAllEnvs();
  });

  // ---------------------------------------------------------------------------
  // DPoP disabled
  // ---------------------------------------------------------------------------
  it("returns undefined values when useDPoP is false", async () => {
    const result = await validateDpopConfiguration({ useDPoP: false });
    expect(result).toEqual({
      dpopKeyPair: undefined,
      dpopOptions: undefined
    });
  });

  it("returns undefined values when useDPoP is omitted", async () => {
    const result = await validateDpopConfiguration({});
    expect(result).toEqual({
      dpopKeyPair: undefined,
      dpopOptions: undefined
    });
  });

  // ---------------------------------------------------------------------------
  // Pre-supplied keypair
  // ---------------------------------------------------------------------------
  it("returns the supplied keypair with default dpopOptions when useDPoP and dpopKeyPair are both set", async () => {
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair
    });
    expect(result.dpopKeyPair).toBe(fakeKeyPair);
    expect(result.dpopOptions).toMatchObject({
      clockSkew: 0,
      clockTolerance: 30,
      retry: { delay: 100, jitter: true }
    });
  });

  it("uses dpopOptions overrides when a keypair is supplied", async () => {
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair,
      dpopOptions: {
        clockSkew: 5,
        clockTolerance: 60,
        retry: { delay: 200, jitter: false }
      }
    });
    expect(result.dpopOptions).toMatchObject({
      clockSkew: 5,
      clockTolerance: 60,
      retry: { delay: 200, jitter: false }
    });
  });

  // ---------------------------------------------------------------------------
  // clockTolerance > MAX_RECOMMENDED — warn but don't throw in non-prod
  // ---------------------------------------------------------------------------
  it("warns when clockTolerance exceeds 300s in non-production", async () => {
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair,
      dpopOptions: { clockTolerance: 400 }
    });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "clockTolerance of 400s exceeds recommended maximum"
      )
    );
    expect(result.dpopKeyPair).toBe(fakeKeyPair);
  });

  // ---------------------------------------------------------------------------
  // clockTolerance > MAX — throw in production
  // ---------------------------------------------------------------------------
  it("throws in production when clockTolerance exceeds the production maximum", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    await expect(
      validateDpopConfiguration({
        useDPoP: true,
        dpopKeyPair: fakeKeyPair,
        dpopOptions: { clockTolerance: 400 }
      })
    ).rejects.toThrow("exceeds maximum allowed");
  });

  it("does not throw in production when clockTolerance equals the default max (300)", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair,
      dpopOptions: { clockTolerance: 300 }
    });
    expect(result.dpopKeyPair).toBe(fakeKeyPair);
  });

  it("respects AUTH0_DPOP_CLOCK_TOLERANCE_MAX_PROD env var for production ceiling", async () => {
    vi.stubEnv("NODE_ENV", "production");
    process.env.AUTH0_DPOP_CLOCK_TOLERANCE_MAX_PROD = "500";
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    // 400s > MAX_RECOMMENDED(300) but < 500 so warn but no throw
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair,
      dpopOptions: { clockTolerance: 400 }
    });
    expect(warnSpy).toHaveBeenCalled();
    expect(result.dpopKeyPair).toBe(fakeKeyPair);
  });

  // ---------------------------------------------------------------------------
  // Negative retry delay
  // ---------------------------------------------------------------------------
  it("throws when retry delay is negative", async () => {
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    await expect(
      validateDpopConfiguration({
        useDPoP: true,
        dpopKeyPair: fakeKeyPair,
        dpopOptions: { retry: { delay: -1, jitter: false } }
      })
    ).rejects.toThrow("Retry delay must be non-negative");
  });

  // ---------------------------------------------------------------------------
  // Env var overrides for dpopOptions
  // ---------------------------------------------------------------------------
  it("reads clockTolerance from AUTH0_DPOP_CLOCK_TOLERANCE env var", async () => {
    process.env.AUTH0_DPOP_CLOCK_TOLERANCE = "120";
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair
    });
    expect(result.dpopOptions?.clockTolerance).toBe(120);
  });

  it("reads clockSkew from AUTH0_DPOP_CLOCK_SKEW env var", async () => {
    process.env.AUTH0_DPOP_CLOCK_SKEW = "15";
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair
    });
    expect(result.dpopOptions?.clockSkew).toBe(15);
  });

  it("reads retry delay from AUTH0_RETRY_DELAY env var", async () => {
    process.env.AUTH0_RETRY_DELAY = "250";
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair
    });
    expect(result.dpopOptions?.retry?.delay).toBe(250);
  });

  it("reads retry jitter from AUTH0_RETRY_JITTER env var (false)", async () => {
    process.env.AUTH0_RETRY_JITTER = "false";
    const fakeKeyPair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    };
    const result = await validateDpopConfiguration({
      useDPoP: true,
      dpopKeyPair: fakeKeyPair
    });
    expect(result.dpopOptions?.retry?.jitter).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // No keypair + no env var keys → warning + return options without keypair
  // ---------------------------------------------------------------------------
  it("warns and returns dpopOptions without keypair when useDPoP is true but no keypair or env vars", async () => {
    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "useDPoP is set to true but dpopKeyPair is not provided"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
    expect(result.dpopOptions).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // Edge Runtime with env var keys — disable DPoP
  // ---------------------------------------------------------------------------
  it("warns and disables DPoP in Edge Runtime when env var keys are set", async () => {
    (globalThis as any).EdgeRuntime = "edge";
    process.env.AUTH0_DPOP_PRIVATE_KEY = VALID_EC_PRIVATE_PEM;
    process.env.AUTH0_DPOP_PUBLIC_KEY = VALID_EC_PUBLIC_PEM;

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Running in Edge Runtime environment")
    );
    expect(result).toEqual({
      dpopKeyPair: undefined,
      dpopOptions: undefined
    });
  });

  // ---------------------------------------------------------------------------
  // Load keypair from env vars — valid P-256 keys
  // ---------------------------------------------------------------------------
  it("loads a valid P-256 keypair from AUTH0_DPOP_PRIVATE_KEY and AUTH0_DPOP_PUBLIC_KEY", async () => {
    process.env.AUTH0_DPOP_PRIVATE_KEY = VALID_EC_PRIVATE_PEM;
    process.env.AUTH0_DPOP_PUBLIC_KEY = VALID_EC_PUBLIC_PEM;

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(result.dpopKeyPair).toBeDefined();
    expect(result.dpopKeyPair?.privateKey).toBeDefined();
    expect(result.dpopKeyPair?.publicKey).toBeDefined();
    expect(result.dpopOptions).toBeDefined();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  // ---------------------------------------------------------------------------
  // Non-EC key type → throw inside try/catch → warn + return undefined
  // ---------------------------------------------------------------------------
  it("warns and disables DPoP when private key is not an EC key", async () => {
    const crypto = await import("crypto");
    const { privateKey: rsaPriv } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048
    });
    const { publicKey: ecPub } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });

    process.env.AUTH0_DPOP_PRIVATE_KEY = rsaPriv
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    process.env.AUTH0_DPOP_PUBLIC_KEY = ecPub
      .export({ type: "spki", format: "pem" })
      .toString();

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Failed to load DPoP keypair from environment variables"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
  });

  it("warns and disables DPoP when public key is not an EC key", async () => {
    const crypto = await import("crypto");
    const { privateKey: ecPriv } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    const { publicKey: rsaPub } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048
    });

    process.env.AUTH0_DPOP_PRIVATE_KEY = ecPriv
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    process.env.AUTH0_DPOP_PUBLIC_KEY = rsaPub
      .export({ type: "spki", format: "pem" })
      .toString();

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Failed to load DPoP keypair from environment variables"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // Wrong EC curve (P-384 instead of P-256) → throw + warn + return undefined
  // ---------------------------------------------------------------------------
  it("warns and disables DPoP when private key uses a non-P-256 curve", async () => {
    const crypto = await import("crypto");
    const { privateKey: p384Priv } = crypto.generateKeyPairSync("ec", {
      namedCurve: "secp384r1"
    });
    const { publicKey: p256Pub } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });

    process.env.AUTH0_DPOP_PRIVATE_KEY = p384Priv
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    process.env.AUTH0_DPOP_PUBLIC_KEY = p256Pub
      .export({ type: "spki", format: "pem" })
      .toString();

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Failed to load DPoP keypair from environment variables"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
  });

  it("warns and disables DPoP when public key uses a non-P-256 curve", async () => {
    const crypto = await import("crypto");
    const { privateKey: p256Priv } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    const { publicKey: p384Pub } = crypto.generateKeyPairSync("ec", {
      namedCurve: "secp384r1"
    });

    process.env.AUTH0_DPOP_PRIVATE_KEY = p256Priv
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    process.env.AUTH0_DPOP_PUBLIC_KEY = p384Pub
      .export({ type: "spki", format: "pem" })
      .toString();

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Failed to load DPoP keypair from environment variables"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // Mismatched valid P-256 keys (different pairs) → key pair validation fails
  // ---------------------------------------------------------------------------
  it("warns and disables DPoP when private and public keys are mismatched P-256 pairs", async () => {
    const crypto = await import("crypto");
    const { privateKey: priv1 } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });
    const { publicKey: pub2 } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1"
    });

    process.env.AUTH0_DPOP_PRIVATE_KEY = priv1
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    process.env.AUTH0_DPOP_PUBLIC_KEY = pub2
      .export({ type: "spki", format: "pem" })
      .toString();

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "DPoP key pair validation failed. DPoP has been completely disabled"
      )
    );
    expect(result).toEqual({
      dpopKeyPair: undefined,
      dpopOptions: undefined
    });
  });

  // ---------------------------------------------------------------------------
  // Only one env var key present (missing either private or public)
  // ---------------------------------------------------------------------------
  it("warns and returns dpopOptions without keypair when only private key env var is set", async () => {
    process.env.AUTH0_DPOP_PRIVATE_KEY = VALID_EC_PRIVATE_PEM;
    // No AUTH0_DPOP_PUBLIC_KEY

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "useDPoP is set to true but dpopKeyPair is not provided"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
    expect(result.dpopOptions).toBeDefined();
  });

  it("warns and returns dpopOptions without keypair when only public key env var is set", async () => {
    process.env.AUTH0_DPOP_PUBLIC_KEY = VALID_EC_PUBLIC_PEM;
    // No AUTH0_DPOP_PRIVATE_KEY

    const result = await validateDpopConfiguration({ useDPoP: true });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "useDPoP is set to true but dpopKeyPair is not provided"
      )
    );
    expect(result.dpopKeyPair).toBeUndefined();
    expect(result.dpopOptions).toBeDefined();
  });
});
