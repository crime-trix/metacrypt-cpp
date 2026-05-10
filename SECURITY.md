# Security Model

MetaCrypt is a public envelope format. The byte layout is not secret, and the implementation assumes an attacker can read the source code and inspect produced envelopes.

## Guarantees

- AES-256-GCM protects confidentiality and integrity of the ciphertext.
- The authentication tag covers the ciphertext, the AAD supplied to `seal` or `seal_with_key`, and the fixed envelope header with the tag field zeroed.
- Password mode derives a 256-bit encryption key with PBKDF2-HMAC-SHA256 and a random 128-bit salt.
- Direct-key mode uses caller-provided 256-bit key material and a random 96-bit GCM nonce.
- The parser rejects unknown flags, trailing bytes, malformed headers, and non-canonical base64url input.

## Non-goals

- MetaCrypt does not hide secrets embedded in a binary from someone who can reverse that binary.
- MetaCrypt does not provide transport security, key exchange, anti-debugging, or tamper resistance for the caller's process.
- MetaCrypt does not claim memory-forensics resistance. Temporary key material is wiped where the implementation owns the buffer, but the caller controls password and direct-key lifetimes.

## Operational notes

- Keep the default PBKDF2 iteration count for stored user secrets unless you have measured a better application-specific value.
- Never reuse a direct key with a manually reused nonce. The library generates nonces internally for sealing.
- Treat AAD as public context, not as a place to store secrets.
