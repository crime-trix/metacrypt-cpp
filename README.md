# metacrypt-cpp

`metacrypt-cpp` is a C++20 implementation of the MetaCrypt envelope: a versioned authenticated-encryption container for binary payloads.

[![ci](https://github.com/crime-trix/metacrypt-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/crime-trix/metacrypt-cpp/actions/workflows/ci.yml)

MetaCrypt is intentionally public. The format is not supposed to be secret; security comes from the password/key material, random salt, random nonce, PBKDF2-HMAC-SHA256, and AES-256-GCM authentication.

## Envelope

```text
magic               4 bytes   "MCR1"
version             1 byte    1
algorithm           1 byte    AES-256-GCM
kdf                 1 byte    PBKDF2-HMAC-SHA256
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

## Example

```cpp
auto sealed = metacrypt::seal(plaintext, password, aad);
auto token = metacrypt::base64url::encode(*sealed);

auto decoded = metacrypt::base64url::decode(token);
auto opened = metacrypt::open(*decoded, password, aad);
```

## Notes

- Public cryptographic formats are normal. A hidden algorithm is not a security boundary.
- AES-GCM gives confidentiality and integrity; wrong passwords or wrong AAD fail authentication.
- Do not embed long-term secrets directly in binaries if the attacker controls the machine.

## Build

```sh
cmake -S . -B build -DMETACRYPT_BUILD_EXAMPLES=ON -DMETACRYPT_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```
