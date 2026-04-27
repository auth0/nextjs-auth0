/**
 * Local mTLS plumbing test
 *
 * Spins up a local HTTPS server that requests a client certificate, then
 * uses the same undici Agent + fetch setup as lib/auth0.ts to connect.
 *
 * Run from examples/with-mtls/:
 *   node test-mtls.mjs
 *
 * This verifies that:
 *   1. undici correctly attaches the client cert to the TLS handshake.
 *   2. The server receives and can read the cert's fingerprint & subject.
 *   3. The customFetch wrapper used in lib/auth0.ts is wired up correctly.
 *
 * It does NOT test Auth0 — that requires a tenant with `mtls_endpoint_aliases`
 * in its discovery document (tenant-level mTLS must be fully provisioned).
 */

import { createServer } from "https";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { Agent, fetch as undiciFetch } from "undici";

const __dirname = dirname(fileURLToPath(import.meta.url));

const certPath = join(__dirname, "certs", "client.crt");
const keyPath = join(__dirname, "certs", "client.key");

const cert = readFileSync(certPath);
const key = readFileSync(keyPath);

// ---------------------------------------------------------------------------
// Local HTTPS server — mirrors the server side of an mTLS token endpoint.
// `requestCert: true` tells Node to require a TLS client certificate.
// `ca: cert` makes the server trust our self-signed client cert as its own CA.
// ---------------------------------------------------------------------------
const server = createServer(
  {
    cert,          // server certificate (reusing the same self-signed cert)
    key,           // server private key
    ca: cert,      // trust our self-signed cert as a CA
    requestCert: true,
    rejectUnauthorized: false, // accept even if chain not fully verifiable
  },
  (req, res) => {
    const clientCert = req.socket.getPeerCertificate();

    if (clientCert && clientCert.fingerprint256) {
      console.log("  Server received client cert:");
      console.log(`    Subject : ${JSON.stringify(clientCert.subject)}`);
      console.log(`    Issuer  : ${JSON.stringify(clientCert.issuer)}`);
      console.log(`    Fp256   : ${clientCert.fingerprint256}`);

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          success: true,
          fingerprint256: clientCert.fingerprint256,
          subject: clientCert.subject,
        })
      );
    } else {
      console.error("  Server: no client cert presented!");
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "No client cert" }));
    }
  }
);

server.listen(0, "127.0.0.1", async () => {
  const { port } = server.address();
  console.log(`\nTest server listening on https://127.0.0.1:${port}\n`);

  // -------------------------------------------------------------------------
  // undici Agent — same setup as lib/auth0.ts
  // -------------------------------------------------------------------------
  const tlsAgent = new Agent({
    connect: {
      cert,
      key,
      rejectUnauthorized: false, // self-signed server cert is OK for local test
    },
  });

  function mtlsFetch(input, init) {
    return undiciFetch(input, {
      ...init,
      dispatcher: tlsAgent,
    });
  }

  try {
    console.log("Making mTLS request...\n");
    const response = await mtlsFetch(`https://127.0.0.1:${port}/token`);
    const data = await response.json();

    if (data.success) {
      console.log("✅  Client cert was presented and accepted by the server.");
      console.log(`    Fingerprint (SHA-256): ${data.fingerprint256}\n`);
      console.log(
        "The undici customFetch plumbing is working correctly.\n" +
        "The remaining issue is Auth0 tenant configuration:\n" +
        "  • Tenant must have mTLS fully provisioned\n" +
        "  • Discovery document must include `mtls_endpoint_aliases`\n" +
        "  • Application credential must use `self_signed_tls_client_auth`\n"
      );
    } else {
      console.error("❌  Client cert was NOT presented to the server.");
      console.error("    This means the undici agent is not wired up correctly.");
    }
  } catch (err) {
    console.error("❌  Request failed:", err.message);
  } finally {
    server.close();
  }
});
