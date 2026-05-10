#include <metacrypt/metacrypt.hpp>

#include <cassert>
#include <span>
#include <string>

static std::span<const std::byte> bytes(std::string_view text)
{
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

int main()
{
    const std::string plain = "payload";
    const std::string pass = "test-password";
    const std::string aad = "unit-test";

    auto sealed = metacrypt::seal(bytes(plain), bytes(pass), bytes(aad), {.iterations = 25'000});
    assert(sealed);
    assert(sealed->size() > plain.size());

    auto info = metacrypt::inspect(*sealed);
    assert(info);
    assert(info->version == metacrypt::format_version);
    assert(info->kdf == metacrypt::kdf_pbkdf2_sha256);
    assert(info->ciphertext_size == plain.size());

    auto opened = metacrypt::open(*sealed, bytes(pass), bytes(aad));
    assert(opened);
    assert(std::string(reinterpret_cast<const char*>(opened->data()), opened->size()) == plain);

    auto wrong_password = metacrypt::open(*sealed, bytes("wrong"), bytes(aad));
    assert(!wrong_password);
    assert(wrong_password.error() == metacrypt::error_code::authentication_failed);

    auto wrong_aad = metacrypt::open(*sealed, bytes(pass), bytes("wrong-aad"));
    assert(!wrong_aad);
    assert(wrong_aad.error() == metacrypt::error_code::authentication_failed);

    std::vector<std::byte> tampered = *sealed;
    tampered.back() ^= std::byte{0x01};
    auto tampered_open = metacrypt::open(tampered, bytes(pass), bytes(aad));
    assert(!tampered_open);
    assert(tampered_open.error() == metacrypt::error_code::authentication_failed);

    const auto token = metacrypt::base64url::encode(*sealed);
    auto decoded = metacrypt::base64url::decode(token);
    assert(decoded);
    assert(decoded->size() == sealed->size());

    auto bad_base64 = metacrypt::base64url::decode("A");
    assert(!bad_base64);
    auto bad_base64_char = metacrypt::base64url::decode("AA=A");
    assert(!bad_base64_char);

    std::vector<std::byte> with_trailing = *sealed;
    with_trailing.push_back(std::byte{0});
    auto trailing = metacrypt::open(with_trailing, bytes(pass), bytes(aad));
    assert(!trailing);
    assert(trailing.error() == metacrypt::error_code::bad_format);

    auto key = metacrypt::random_key();
    assert(key);
    auto sealed_key = metacrypt::seal_with_key(bytes(plain), *key, bytes(aad));
    assert(sealed_key);
    auto key_info = metacrypt::inspect(*sealed_key);
    assert(key_info);
    assert(key_info->kdf == 0);
    auto opened_key = metacrypt::open_with_key(*sealed_key, *key, bytes(aad));
    assert(opened_key);
    assert(std::string(reinterpret_cast<const char*>(opened_key->data()), opened_key->size()) == plain);

    auto wrong_open_mode = metacrypt::open(*sealed_key, bytes(pass), bytes(aad));
    assert(!wrong_open_mode);
    assert(wrong_open_mode.error() == metacrypt::error_code::unsupported_algorithm);
}
