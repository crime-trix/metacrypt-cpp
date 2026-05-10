#include <metacrypt/metacrypt.hpp>

#include <cstddef>
#include <functional>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::span<const std::byte> bytes(std::string_view text)
{
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

std::string as_string(std::span<const std::byte> data)
{
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}

struct case_result {
    bool passed = false;
    std::string message;
};

case_result pass()
{
    return {true, {}};
}

case_result fail(std::string message)
{
    return {false, std::move(message)};
}

case_result password_roundtrip()
{
    const std::string plain = "payload";
    const std::string passphrase = "test-password";
    const std::string aad = "unit-test";

    auto sealed = metacrypt::seal(bytes(plain), bytes(passphrase), bytes(aad), {.iterations = 25'000});
    if (!sealed) {
        return fail(std::string("seal failed: ") + std::string(metacrypt::to_string(sealed.error())));
    }

    auto opened = metacrypt::open(*sealed, bytes(passphrase), bytes(aad));
    if (!opened) {
        return fail(std::string("open failed: ") + std::string(metacrypt::to_string(opened.error())));
    }

    return as_string(*opened) == plain ? pass() : fail("plaintext mismatch");
}

case_result inspect_metadata()
{
    const std::string plain = "inspect me";
    auto sealed = metacrypt::seal(bytes(plain), bytes("password"), bytes("context"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    auto info = metacrypt::inspect(*sealed);
    if (!info) {
        return fail("inspect failed");
    }

    if (info->version != metacrypt::format_version) {
        return fail("unexpected version");
    }
    if (info->kdf != metacrypt::kdf_pbkdf2_sha256) {
        return fail("unexpected kdf");
    }
    if (info->ciphertext_size != plain.size()) {
        return fail("unexpected ciphertext size");
    }

    return pass();
}

case_result wrong_password_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("correct"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    auto opened = metacrypt::open(*sealed, bytes("wrong"), bytes("aad"));
    if (opened) {
        return fail("wrong password decrypted");
    }

    return opened.error() == metacrypt::error_code::authentication_failed
        ? pass()
        : fail("wrong error for wrong password");
}

case_result wrong_aad_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("other-aad"));
    if (opened) {
        return fail("wrong AAD decrypted");
    }

    return opened.error() == metacrypt::error_code::authentication_failed
        ? pass()
        : fail("wrong error for wrong AAD");
}

case_result tamper_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    sealed->back() ^= std::byte{0x01};
    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("tampered ciphertext decrypted");
    }

    return opened.error() == metacrypt::error_code::authentication_failed
        ? pass()
        : fail("wrong error for tampered ciphertext");
}

case_result header_salt_tamper_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    (*sealed)[metacrypt::layout::salt] ^= std::byte{0x01};
    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("salt-tampered envelope decrypted");
    }

    return opened.error() == metacrypt::error_code::authentication_failed
        ? pass()
        : fail("wrong error for salt tamper");
}

case_result header_nonce_tamper_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    (*sealed)[metacrypt::layout::nonce] ^= std::byte{0x01};
    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("nonce-tampered envelope decrypted");
    }

    return opened.error() == metacrypt::error_code::authentication_failed
        ? pass()
        : fail("wrong error for nonce tamper");
}

case_result header_tag_tamper_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    (*sealed)[metacrypt::layout::tag] ^= std::byte{0x01};
    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("tag-tampered envelope decrypted");
    }

    return opened.error() == metacrypt::error_code::authentication_failed
        ? pass()
        : fail("wrong error for tag tamper");
}

case_result header_version_tamper_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    (*sealed)[metacrypt::layout::version] ^= std::byte{0x7f};
    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("version-tampered envelope decrypted");
    }

    return opened.error() == metacrypt::error_code::unsupported_version
        ? pass()
        : fail("wrong error for version tamper");
}

case_result trailing_bytes_are_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    sealed->push_back(std::byte{0});
    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("trailing bytes accepted");
    }

    return opened.error() == metacrypt::error_code::bad_format
        ? pass()
        : fail("wrong error for trailing bytes");
}

case_result base64url_roundtrip()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 25'000});
    if (!sealed) {
        return fail("seal failed");
    }

    const auto token = metacrypt::base64url::encode(*sealed);
    auto decoded = metacrypt::base64url::decode(token);
    if (!decoded) {
        return fail("decode failed");
    }

    return *decoded == *sealed ? pass() : fail("base64url roundtrip mismatch");
}

case_result malformed_base64url_is_rejected()
{
    auto bad_length = metacrypt::base64url::decode("A");
    if (bad_length) {
        return fail("bad base64url length accepted");
    }

    auto bad_character = metacrypt::base64url::decode("AA=A");
    if (bad_character) {
        return fail("bad base64url character accepted");
    }

    return pass();
}

case_result direct_key_roundtrip()
{
    const std::string plain = "direct key payload";
    const std::string aad = "direct-key-test";

    auto key = metacrypt::random_key();
    if (!key) {
        return fail("random_key failed");
    }

    auto sealed = metacrypt::seal_with_key(bytes(plain), *key, bytes(aad));
    if (!sealed) {
        return fail("seal_with_key failed");
    }

    auto info = metacrypt::inspect(*sealed);
    if (!info || info->kdf != 0) {
        return fail("direct-key envelope metadata mismatch");
    }

    auto opened = metacrypt::open_with_key(*sealed, *key, bytes(aad));
    if (!opened) {
        return fail("open_with_key failed");
    }

    return as_string(*opened) == plain ? pass() : fail("direct-key plaintext mismatch");
}

case_result direct_key_envelope_rejects_password_mode()
{
    auto key = metacrypt::random_key();
    if (!key) {
        return fail("random_key failed");
    }

    auto sealed = metacrypt::seal_with_key(bytes("payload"), *key, bytes("aad"));
    if (!sealed) {
        return fail("seal_with_key failed");
    }

    auto opened = metacrypt::open(*sealed, bytes("password"), bytes("aad"));
    if (opened) {
        return fail("password mode opened direct-key envelope");
    }

    return opened.error() == metacrypt::error_code::unsupported_algorithm
        ? pass()
        : fail("wrong error for direct-key envelope in password mode");
}

case_result low_iteration_count_is_rejected()
{
    auto sealed = metacrypt::seal(bytes("payload"), bytes("password"), bytes("aad"), {.iterations = 999});
    if (sealed) {
        return fail("low iteration count accepted");
    }

    return sealed.error() == metacrypt::error_code::invalid_argument
        ? pass()
        : fail("wrong error for low iteration count");
}

} // namespace

int main()
{
    const std::vector<std::pair<std::string_view, std::function<case_result()>>> tests{
        {"password_roundtrip", password_roundtrip},
        {"inspect_metadata", inspect_metadata},
        {"wrong_password_is_rejected", wrong_password_is_rejected},
        {"wrong_aad_is_rejected", wrong_aad_is_rejected},
        {"tamper_is_rejected", tamper_is_rejected},
        {"header_salt_tamper_is_rejected", header_salt_tamper_is_rejected},
        {"header_nonce_tamper_is_rejected", header_nonce_tamper_is_rejected},
        {"header_tag_tamper_is_rejected", header_tag_tamper_is_rejected},
        {"header_version_tamper_is_rejected", header_version_tamper_is_rejected},
        {"trailing_bytes_are_rejected", trailing_bytes_are_rejected},
        {"base64url_roundtrip", base64url_roundtrip},
        {"malformed_base64url_is_rejected", malformed_base64url_is_rejected},
        {"direct_key_roundtrip", direct_key_roundtrip},
        {"direct_key_envelope_rejects_password_mode", direct_key_envelope_rejects_password_mode},
        {"low_iteration_count_is_rejected", low_iteration_count_is_rejected},
    };

    for (const auto& [name, run] : tests) {
        const auto result = run();
        std::cout << (result.passed ? "[pass] " : "[fail] ") << name;
        if (!result.message.empty()) {
            std::cout << " - " << result.message;
        }
        std::cout << '\n';

        if (!result.passed) {
            return 1;
        }
    }

    std::cout << tests.size() << " MetaCrypt test cases passed\n";
}
