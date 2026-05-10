#include <metacrypt/metacrypt.hpp>

#include <iostream>
#include <span>
#include <string>

static std::span<const std::byte> bytes(std::string_view text)
{
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

int main()
{
    const std::string message = "MetaCrypt protects data with a versioned AEAD envelope.";
    const std::string password = "correct horse battery staple";
    const std::string aad = "metacrypt-demo:v1";

    auto sealed = metacrypt::seal(bytes(message), bytes(password), bytes(aad), {.iterations = 25'000});
    if (!sealed) {
        std::cerr << metacrypt::to_string(sealed.error()) << '\n';
        return 1;
    }

    auto info = metacrypt::inspect(*sealed);
    if (!info) {
        std::cerr << metacrypt::to_string(info.error()) << '\n';
        return 1;
    }

    const auto token = metacrypt::base64url::encode(*sealed);
    std::cout << "token: " << token << '\n';
    std::cout << "ciphertext bytes: " << info->ciphertext_size << '\n';

    auto decoded = metacrypt::base64url::decode(token);
    if (!decoded) {
        return 1;
    }

    auto opened = metacrypt::open(*decoded, bytes(password), bytes(aad));
    if (!opened) {
        std::cerr << metacrypt::to_string(opened.error()) << '\n';
        return 1;
    }

    std::string plain(reinterpret_cast<const char*>(opened->data()), opened->size());
    std::cout << "plain: " << plain << '\n';
    return plain == message ? 0 : 1;
}
