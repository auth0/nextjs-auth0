// generateSecret generates a secure random string of the given length.
export async function generateSecret(length: number) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Strip the value prefix that TransactionStore encodes in cookie values.
 * "p:{jwe}"    → prefetch cookie — strips "p:" prefix
 * "{ts}:{jwe}" → real login — strips "{ts}:" prefix
 * "{jwe}"      → legacy (no prefix) — returned as-is
 *
 * Use this in tests that decrypt transaction cookie values directly.
 */
export function stripTransactionValuePrefix(value: string): string {
  const colonIdx = value.indexOf(":");
  return colonIdx !== -1 ? value.slice(colonIdx + 1) : value;
}
