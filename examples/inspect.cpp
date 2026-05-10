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
    const std::string payload = "metadata example";
    const std::string password = "example-password";
    const std::string aad = "example:inspect";

    auto sealed = metacrypt::seal(bytes(payload), bytes(password), bytes(aad), {.iterations = 25'000});
    if (!sealed) {
        std::cerr << metacrypt::to_string(sealed.error()) << '\n';
        return 1;
    }

    auto info = metacrypt::inspect(*sealed);
    if (!info) {
        std::cerr << metacrypt::to_string(info.error()) << '\n';
        return 1;
    }

    std::cout << "version: " << static_cast<int>(info->version) << '\n';
    std::cout << "algorithm: " << static_cast<int>(info->algorithm) << '\n';
    std::cout << "kdf: " << static_cast<int>(info->kdf) << '\n';
    std::cout << "iterations: " << info->iterations << '\n';
    std::cout << "aad bytes: " << info->aad_size << '\n';
    std::cout << "ciphertext bytes: " << info->ciphertext_size << '\n';
}
