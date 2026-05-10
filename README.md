# metacrypt-cpp

`metacrypt-cpp` is a C++20 implementation of the MetaCrypt envelope: a versioned authenticated-encryption container for binary payloads.

[![ci](https://github.com/crime-trix/metacrypt-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/crime-trix/metacrypt-cpp/actions/workflows/ci.yml)

MetaCrypt is intentionally public. The format is not supposed to be secret; security comes from key material, random salt, random nonce, PBKDF2-HMAC-SHA256, and AES-256-GCM authentication.

## Envelope

```text
magic               4 bytes   "MCR1"
version             1 byte    2
algorithm           1 byte    AES-256-GCM
kdf                 1 byte    PBKDF2-HMAC-SHA256, or 0 for direct 256-bit key mode
flags               1 byte    reserved
iterations          u32le
aad_size            u32le
ciphertext_size     u32le
salt                16 bytes
nonce               12 bytes
tag                 16 bytes
aad                 aad_size bytes
ciphertext          ciphertext_size bytes
```

The authentication tag covers the ciphertext, the user AAD, and the fixed envelope header with the tag field zeroed. This binds metadata such as KDF id, iteration count, salt, nonce, and sizes to the encrypted payload.

## Example

```cpp
auto sealed = metacrypt::seal(plaintext, password, aad);
auto token = metacrypt::base64url::encode(*sealed);

auto decoded = metacrypt::base64url::decode(token);
auto opened = metacrypt::open(*decoded, password, aad);
```

`seal_with_key` and `open_with_key` are available when the caller already owns a 256-bit key and does not want password-based derivation.

## Notes

- Public cryptographic formats are normal. A hidden algorithm is not a security boundary.
- AES-GCM gives confidentiality and integrity; wrong passwords or wrong AAD fail authentication.
- Envelope header metadata is authenticated as part of the AEAD associated data.
- The default PBKDF2 cost is 600,000 iterations. Lower values are useful for tests, not for stored user secrets.
- The parser rejects unknown flags, malformed base64url, and trailing bytes after the ciphertext.
- Do not embed long-term secrets directly in binaries if the attacker controls the machine.

See [SECURITY.md](SECURITY.md) for the threat model and non-goals.

## Build

```sh
cmake -S . -B build -DMETACRYPT_BUILD_EXAMPLES=ON -DMETACRYPT_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Tests

The repository includes a dependency-free test runner in `tests/test_cases.cpp`.

Covered cases:

- password envelope roundtrip;
- envelope metadata inspection;
- wrong password rejection;
- wrong AAD rejection;
- ciphertext tamper rejection;
- header salt tamper rejection;
- header nonce tamper rejection;
- authentication tag tamper rejection;
- envelope version tamper rejection;
- trailing byte rejection;
- base64url roundtrip;
- malformed base64url rejection;
- direct 256-bit key roundtrip;
- direct-key envelope rejection in password mode;
- low PBKDF2 iteration rejection.
