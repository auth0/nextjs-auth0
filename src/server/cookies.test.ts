import { describe, expect, it } from "vitest"

import { generateSecret } from "../test/utils"
import { decrypt, encrypt } from "./cookies"

describe("encrypt/decrypt", async () => {
  const secret = await generateSecret(32)
  const incorrectSecret = await generateSecret(32)

  it("should encrypt/decrypt a payload with the correct secret", async () => {
    const payload = { key: "value" }
    const encrypted = await encrypt(payload, secret)
    const decrypted = await decrypt(encrypted, secret)

    expect(decrypted).toEqual(payload)
  })

  it("should fail to decrypt a payload with the incorrect secret", async () => {
    const payload = { key: "value" }
    const encrypted = await encrypt(payload, secret)
    await expect(() =>
      decrypt(encrypted, incorrectSecret)
    ).rejects.toThrowError()
  })

  it("should fail to encrypt if a secret is not provided", async () => {
    const payload = { key: "value" }
    await expect(() => encrypt(payload, "")).rejects.toThrowError()
  })

  it("should fail to decrypt if a secret is not provided", async () => {
    const payload = { key: "value" }
    const encrypted = await encrypt(payload, secret)
    await expect(() => decrypt(encrypted, "")).rejects.toThrowError()
  })
})
