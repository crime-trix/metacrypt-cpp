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

    auto opened = metacrypt::open(*sealed, bytes(pass), bytes(aad));
    assert(opened);
    assert(std::string(reinterpret_cast<const char*>(opened->data()), opened->size()) == plain);

    auto wrong_password = metacrypt::open(*sealed, bytes("wrong"), bytes(aad));
    assert(!wrong_password);
    assert(wrong_password.error() == metacrypt::error_code::authentication_failed);

    auto wrong_aad = metacrypt::open(*sealed, bytes(pass), bytes("wrong-aad"));
    assert(!wrong_aad);
    assert(wrong_aad.error() == metacrypt::error_code::authentication_failed);

    const auto token = metacrypt::base64url::encode(*sealed);
    auto decoded = metacrypt::base64url::decode(token);
    assert(decoded);
    assert(decoded->size() == sealed->size());
}
