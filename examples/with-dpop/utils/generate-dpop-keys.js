#!/usr/bin/env node

/**
 * DPoP Key Generation Utility
 * 
 * This utility generates ES256 key pairs for use with DPoP (Demonstration of Proof-of-Possession).
 * It can output keys in PEM format for environment variables or as a JSON object for programmatic use.
 */

const { generateKeyPair } = require('node:crypto');
const { promisify } = require('util');

const generateKeyPairAsync = promisify(generateKeyPair);

async function generateDpopKeys() {
  try {
    console.log('Generating ES256 key pair for DPoP...\n');
    
    const { publicKey, privateKey } = await generateKeyPairAsync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    console.log('=== DPoP Key Pair Generated ===\n');
    
    console.log('Public Key (PEM format):');
    console.log(publicKey);
    
    console.log('\nPrivate Key (PEM format):');
    console.log(privateKey);
    
    console.log('\n=== Environment Variables ===\n');
    console.log('Add these to your .env.local file:\n');
    
    // Escape the keys for environment variables
    const escapedPublicKey = publicKey.replace(/\n/g, '\\n');
    const escapedPrivateKey = privateKey.replace(/\n/g, '\\n');
    
    console.log(`AUTH0_DPOP_PUBLIC_KEY="${escapedPublicKey}"`);
    console.log(`AUTH0_DPOP_PRIVATE_KEY="${escapedPrivateKey}"`);
    
    console.log('\n=== Security Notes ===\n');
    console.log('• Keep the private key secure and never commit it to version control');
    console.log('• Generate new key pairs for each environment (dev, staging, prod)');
    console.log('• For maximum security, generate new key pairs per session or application instance');
    console.log('• These keys are for ES256 algorithm (Elliptic Curve P-256)');
    
  } catch (error) {
    console.error('Error generating DPoP key pair:', error);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  generateDpopKeys();
}

module.exports = { generateDpopKeys };
