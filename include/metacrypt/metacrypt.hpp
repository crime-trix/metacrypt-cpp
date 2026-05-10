#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace metacrypt {

constexpr std::array<std::byte, 4> magic{
    std::byte{'M'}, std::byte{'C'}, std::byte{'R'}, std::byte{'1'}
};

constexpr std::uint8_t format_version = 1;
constexpr std::uint8_t algorithm_aes_256_gcm = 1;
constexpr std::uint8_t kdf_pbkdf2_sha256 = 1;
constexpr std::uint32_t minimum_iterations = 10'000;
constexpr std::uint32_t default_iterations = 600'000;
constexpr std::size_t salt_size = 16;
constexpr std::size_t nonce_size = 12;
constexpr std::size_t key_size = 32;
constexpr std::size_t tag_size = 16;
constexpr std::size_t header_size = 4 + 4 + 12 + salt_size + nonce_size + tag_size;

enum class error_code {
    ok,
    windows_crypto_error,
    invalid_argument,
    bad_format,
    unsupported_version,
    unsupported_algorithm,
    unsupported_flags,
    authentication_failed,
};

constexpr std::string_view to_string(error_code code) noexcept
{
    switch (code) {
    case error_code::ok: return "ok";
    case error_code::windows_crypto_error: return "Windows crypto error";
    case error_code::invalid_argument: return "invalid argument";
    case error_code::bad_format: return "bad MetaCrypt envelope";
    case error_code::unsupported_version: return "unsupported MetaCrypt version";
    case error_code::unsupported_algorithm: return "unsupported MetaCrypt algorithm";
    case error_code::unsupported_flags: return "unsupported MetaCrypt flags";
    case error_code::authentication_failed: return "authentication failed";
    }
    return "unknown error";
}

template <class T>
class expected {
public:
    expected(T value) : ok_(true), value_(std::move(value)) {}
    expected(error_code error) : ok_(false), error_(error) {}

    [[nodiscard]] explicit operator bool() const noexcept { return ok_; }
    [[nodiscard]] error_code error() const noexcept { return error_; }
    [[nodiscard]] const T& operator*() const noexcept { return value_; }
    [[nodiscard]] T& operator*() noexcept { return value_; }
    [[nodiscard]] const T* operator->() const noexcept { return &value_; }
    [[nodiscard]] T* operator->() noexcept { return &value_; }

private:
    bool ok_ = false;
    T value_{};
    error_code error_ = error_code::ok;
};

struct options {
    std::uint32_t iterations = default_iterations;
};

struct envelope_info {
    std::uint8_t version = 0;
    std::uint8_t algorithm = 0;
    std::uint8_t kdf = 0;
    std::uint8_t flags = 0;
    std::uint32_t iterations = 0;
    std::uint32_t aad_size = 0;
    std::uint32_t ciphertext_size = 0;
};

struct envelope_header {
    std::array<std::byte, 4> magic_value = magic;
    std::uint8_t version = format_version;
    std::uint8_t algorithm = algorithm_aes_256_gcm;
    std::uint8_t kdf = kdf_pbkdf2_sha256;
    std::uint8_t flags = 0;
    std::uint32_t iterations = default_iterations;
    std::uint32_t aad_size = 0;
    std::uint32_t ciphertext_size = 0;
    std::array<std::byte, salt_size> salt{};
    std::array<std::byte, nonce_size> nonce{};
    std::array<std::byte, tag_size> tag{};
};

namespace detail {

[[nodiscard]] inline bool nt_success(NTSTATUS status) noexcept
{
    return status >= 0;
}

inline void secure_zero(std::span<std::byte> bytes) noexcept
{
    if (!bytes.empty()) {
        ::SecureZeroMemory(bytes.data(), bytes.size());
    }
}

class algorithm_handle {
public:
    algorithm_handle() = default;
    ~algorithm_handle()
    {
        if (handle_) {
            ::BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    algorithm_handle(const algorithm_handle&) = delete;
    algorithm_handle& operator=(const algorithm_handle&) = delete;
    algorithm_handle(algorithm_handle&& other) noexcept : handle_(other.handle_)
    {
        other.handle_ = nullptr;
    }

    algorithm_handle& operator=(algorithm_handle&& other) noexcept
    {
        if (this != &other) {
            if (handle_) {
                ::BCryptCloseAlgorithmProvider(handle_, 0);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    [[nodiscard]] static expected<algorithm_handle> open(LPCWSTR id, ULONG flags = 0)
    {
        algorithm_handle out;
        if (!nt_success(::BCryptOpenAlgorithmProvider(&out.handle_, id, nullptr, flags))) {
            return error_code::windows_crypto_error;
        }
        return out;
    }

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class key_handle {
public:
    key_handle() = default;
    ~key_handle()
    {
        if (handle_) {
            ::BCryptDestroyKey(handle_);
        }
        secure_zero(object_);
    }

    key_handle(const key_handle&) = delete;
    key_handle& operator=(const key_handle&) = delete;

    key_handle(key_handle&& other) noexcept :
        handle_(other.handle_),
        object_(std::move(other.object_))
    {
        other.handle_ = nullptr;
    }

    key_handle& operator=(key_handle&& other) noexcept
    {
        if (this != &other) {
            if (handle_) {
                ::BCryptDestroyKey(handle_);
            }
            secure_zero(object_);
            handle_ = other.handle_;
            object_ = std::move(other.object_);
            other.handle_ = nullptr;
        }
        return *this;
    }

    [[nodiscard]] static expected<key_handle> generate(BCRYPT_ALG_HANDLE algorithm, std::span<const std::byte, key_size> key)
    {
        key_handle out;

        ULONG object_length = 0;
        ULONG written = 0;
        if (!nt_success(::BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_length),
                sizeof(object_length),
                &written,
                0))) {
            return error_code::windows_crypto_error;
        }

        out.object_.resize(object_length);
        if (!nt_success(::BCryptGenerateSymmetricKey(
                algorithm,
                &out.handle_,
                reinterpret_cast<PUCHAR>(out.object_.data()),
                static_cast<ULONG>(out.object_.size()),
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(key.data())),
                static_cast<ULONG>(key.size()),
                0))) {
            return error_code::windows_crypto_error;
        }

        return out;
    }

    [[nodiscard]] BCRYPT_KEY_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
    std::vector<std::byte> object_;
};

template <class T>
void append_le(std::vector<std::byte>& out, T value)
{
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::byte>((static_cast<std::uint64_t>(value) >> (i * 8)) & 0xff));
    }
}

template <class T>
[[nodiscard]] std::optional<T> read_le(std::span<const std::byte> in, std::size_t& offset)
{
    if (offset > in.size() || sizeof(T) > in.size() - offset) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(in[offset + i])) << (i * 8);
    }

    offset += sizeof(T);
    return static_cast<T>(value);
}

inline void append_bytes(std::vector<std::byte>& out, std::span<const std::byte> bytes)
{
    out.insert(out.end(), bytes.begin(), bytes.end());
}

[[nodiscard]] inline expected<std::array<std::byte, key_size>> derive_key(
    std::span<const std::byte> password,
    std::span<const std::byte, salt_size> salt,
    std::uint32_t iterations)
{
    if (password.empty() || iterations < minimum_iterations) {
        return error_code::invalid_argument;
    }

    auto hash = algorithm_handle::open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!hash) {
        return hash.error();
    }

    std::array<std::byte, key_size> key{};
    if (!nt_success(::BCryptDeriveKeyPBKDF2(
            hash->get(),
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(password.data())),
            static_cast<ULONG>(password.size()),
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(salt.data())),
            static_cast<ULONG>(salt.size()),
            iterations,
            reinterpret_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()),
            0))) {
        return error_code::windows_crypto_error;
    }

    return key;
}

[[nodiscard]] inline expected<algorithm_handle> aes_gcm_algorithm()
{
    auto aes = algorithm_handle::open(BCRYPT_AES_ALGORITHM);
    if (!aes) {
        return aes.error();
    }

    if (!nt_success(::BCryptSetProperty(
            aes->get(),
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>((std::wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
            0))) {
        return error_code::windows_crypto_error;
    }

    return aes;
}

[[nodiscard]] inline expected<key_handle> aes_key(std::span<const std::byte, key_size> key)
{
    auto aes = aes_gcm_algorithm();
    if (!aes) {
        return aes.error();
    }
    return key_handle::generate(aes->get(), key);
}

[[nodiscard]] inline expected<std::array<std::byte, salt_size>> random_salt()
{
    std::array<std::byte, salt_size> salt{};
    if (!nt_success(::BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return error_code::windows_crypto_error;
    }
    return salt;
}

[[nodiscard]] inline expected<std::array<std::byte, nonce_size>> random_nonce()
{
    std::array<std::byte, nonce_size> nonce{};
    if (!nt_success(::BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(nonce.data()), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return error_code::windows_crypto_error;
    }
    return nonce;
}

} // namespace detail

[[nodiscard]] inline expected<std::array<std::byte, key_size>> random_key()
{
    std::array<std::byte, key_size> key{};
    if (!detail::nt_success(::BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return error_code::windows_crypto_error;
    }
    return key;
}

[[nodiscard]] inline std::vector<std::byte> serialize_header(const envelope_header& header)
{
    std::vector<std::byte> out;
    out.reserve(header_size);
    detail::append_bytes(out, header.magic_value);
    out.push_back(static_cast<std::byte>(header.version));
    out.push_back(static_cast<std::byte>(header.algorithm));
    out.push_back(static_cast<std::byte>(header.kdf));
    out.push_back(static_cast<std::byte>(header.flags));
    detail::append_le(out, header.iterations);
    detail::append_le(out, header.aad_size);
    detail::append_le(out, header.ciphertext_size);
    detail::append_bytes(out, header.salt);
    detail::append_bytes(out, header.nonce);
    detail::append_bytes(out, header.tag);
    return out;
}

[[nodiscard]] inline expected<envelope_header> parse_header(std::span<const std::byte> bytes, std::size_t& offset)
{
    envelope_header header;
    offset = 0;
    if (bytes.size() < header_size) {
        return error_code::bad_format;
    }

    std::memcpy(header.magic_value.data(), bytes.data(), 4);
    offset += 4;
    if (header.magic_value != magic) {
        return error_code::bad_format;
    }

    header.version = std::to_integer<std::uint8_t>(bytes[offset++]);
    header.algorithm = std::to_integer<std::uint8_t>(bytes[offset++]);
    header.kdf = std::to_integer<std::uint8_t>(bytes[offset++]);
    header.flags = std::to_integer<std::uint8_t>(bytes[offset++]);

    if (header.version != format_version) {
        return error_code::unsupported_version;
    }
    if (header.algorithm != algorithm_aes_256_gcm ||
        (header.kdf != kdf_pbkdf2_sha256 && header.kdf != 0)) {
        return error_code::unsupported_algorithm;
    }
    if (header.flags != 0) {
        return error_code::unsupported_flags;
    }

    const auto iterations = detail::read_le<std::uint32_t>(bytes, offset);
    const auto aad_size_value = detail::read_le<std::uint32_t>(bytes, offset);
    const auto ciphertext_size_value = detail::read_le<std::uint32_t>(bytes, offset);
    if (!iterations || !aad_size_value || !ciphertext_size_value) {
        return error_code::bad_format;
    }

    header.iterations = *iterations;
    header.aad_size = *aad_size_value;
    header.ciphertext_size = *ciphertext_size_value;

    if (offset + salt_size + nonce_size + tag_size > bytes.size()) {
        return error_code::bad_format;
    }

    std::memcpy(header.salt.data(), bytes.data() + offset, salt_size);
    offset += salt_size;
    std::memcpy(header.nonce.data(), bytes.data() + offset, nonce_size);
    offset += nonce_size;
    std::memcpy(header.tag.data(), bytes.data() + offset, tag_size);
    offset += tag_size;
    return header;
}

[[nodiscard]] inline expected<envelope_info> inspect(std::span<const std::byte> envelope)
{
    std::size_t offset = 0;
    auto header = parse_header(envelope, offset);
    if (!header) {
        return header.error();
    }

    if (offset > envelope.size() ||
        header->aad_size > envelope.size() - offset ||
        header->ciphertext_size > envelope.size() - offset - header->aad_size ||
        offset + header->aad_size + header->ciphertext_size != envelope.size()) {
        return error_code::bad_format;
    }

    return envelope_info{
        header->version,
        header->algorithm,
        header->kdf,
        header->flags,
        header->iterations,
        header->aad_size,
        header->ciphertext_size,
    };
}

[[nodiscard]] inline expected<std::vector<std::byte>> seal_with_key(
    std::span<const std::byte> plaintext,
    std::span<const std::byte, key_size> key,
    std::span<const std::byte> aad = {})
{
    if (plaintext.size() > UINT32_MAX || aad.size() > UINT32_MAX) {
        return error_code::invalid_argument;
    }

    auto nonce = detail::random_nonce();
    if (!nonce) {
        return nonce.error();
    }

    auto aes = detail::aes_gcm_algorithm();
    if (!aes) {
        return aes.error();
    }

    auto imported = detail::key_handle::generate(aes->get(), key);
    if (!imported) {
        return imported.error();
    }

    envelope_header header;
    header.kdf = 0;
    header.iterations = 0;
    header.aad_size = static_cast<std::uint32_t>(aad.size());
    header.ciphertext_size = static_cast<std::uint32_t>(plaintext.size());
    header.nonce = *nonce;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = reinterpret_cast<PUCHAR>(header.nonce.data());
    auth.cbNonce = static_cast<ULONG>(header.nonce.size());
    auth.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(aad.data()));
    auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = reinterpret_cast<PUCHAR>(header.tag.data());
    auth.cbTag = static_cast<ULONG>(header.tag.size());

    std::vector<std::byte> ciphertext(plaintext.size());
    ULONG written = 0;
    const auto status = ::BCryptEncrypt(
        imported->get(),
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(plaintext.data())),
        static_cast<ULONG>(plaintext.size()),
        &auth,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        &written,
        0);

    if (!detail::nt_success(status) || written != ciphertext.size()) {
        return error_code::windows_crypto_error;
    }

    auto out = serialize_header(header);
    detail::append_bytes(out, aad);
    detail::append_bytes(out, ciphertext);
    return out;
}

[[nodiscard]] inline expected<std::vector<std::byte>> seal(
    std::span<const std::byte> plaintext,
    std::span<const std::byte> password,
    std::span<const std::byte> aad = {},
    options opts = {})
{
    if (plaintext.size() > UINT32_MAX || aad.size() > UINT32_MAX) {
        return error_code::invalid_argument;
    }

    auto salt = detail::random_salt();
    auto nonce = detail::random_nonce();
    if (!salt) {
        return salt.error();
    }
    if (!nonce) {
        return nonce.error();
    }

    auto key = detail::derive_key(password, *salt, opts.iterations);
    if (!key) {
        return key.error();
    }

    auto aes = detail::aes_gcm_algorithm();
    if (!aes) {
        return aes.error();
    }

    auto imported = detail::key_handle::generate(aes->get(), *key);
    detail::secure_zero(std::span<std::byte, key_size>(*key));
    if (!imported) {
        return imported.error();
    }

    envelope_header header;
    header.iterations = opts.iterations;
    header.aad_size = static_cast<std::uint32_t>(aad.size());
    header.ciphertext_size = static_cast<std::uint32_t>(plaintext.size());
    header.salt = *salt;
    header.nonce = *nonce;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = reinterpret_cast<PUCHAR>(header.nonce.data());
    auth.cbNonce = static_cast<ULONG>(header.nonce.size());
    auth.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(aad.data()));
    auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = reinterpret_cast<PUCHAR>(header.tag.data());
    auth.cbTag = static_cast<ULONG>(header.tag.size());

    std::vector<std::byte> ciphertext(plaintext.size());
    ULONG written = 0;
    const auto status = ::BCryptEncrypt(
        imported->get(),
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(plaintext.data())),
        static_cast<ULONG>(plaintext.size()),
        &auth,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        &written,
        0);

    if (!detail::nt_success(status) || written != ciphertext.size()) {
        return error_code::windows_crypto_error;
    }

    auto out = serialize_header(header);
    detail::append_bytes(out, aad);
    detail::append_bytes(out, ciphertext);
    return out;
}

[[nodiscard]] inline expected<std::vector<std::byte>> open(
    std::span<const std::byte> envelope,
    std::span<const std::byte> password,
    std::optional<std::span<const std::byte>> expected_aad = std::nullopt)
{
    std::size_t offset = 0;
    auto header = parse_header(envelope, offset);
    if (!header) {
        return header.error();
    }

    if (offset > envelope.size() ||
        header->aad_size > envelope.size() - offset ||
        header->ciphertext_size > envelope.size() - offset - header->aad_size ||
        offset + header->aad_size + header->ciphertext_size != envelope.size()) {
        return error_code::bad_format;
    }
    if (header->kdf != kdf_pbkdf2_sha256 || header->iterations < minimum_iterations) {
        return error_code::unsupported_algorithm;
    }

    const auto aad = envelope.subspan(offset, header->aad_size);
    offset += header->aad_size;
    const auto ciphertext = envelope.subspan(offset, header->ciphertext_size);

    if (expected_aad && (*expected_aad).size() != aad.size()) {
        return error_code::authentication_failed;
    }
    if (expected_aad && !std::equal(aad.begin(), aad.end(), (*expected_aad).begin())) {
        return error_code::authentication_failed;
    }

    auto key = detail::derive_key(password, header->salt, header->iterations);
    if (!key) {
        return key.error();
    }

    auto aes = detail::aes_gcm_algorithm();
    if (!aes) {
        return aes.error();
    }

    auto imported = detail::key_handle::generate(aes->get(), *key);
    detail::secure_zero(std::span<std::byte, key_size>(*key));
    if (!imported) {
        return imported.error();
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(header->nonce.data()));
    auth.cbNonce = static_cast<ULONG>(header->nonce.size());
    auth.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(aad.data()));
    auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(header->tag.data()));
    auth.cbTag = static_cast<ULONG>(header->tag.size());

    std::vector<std::byte> plaintext(ciphertext.size());
    ULONG written = 0;
    const auto status = ::BCryptDecrypt(
        imported->get(),
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(ciphertext.data())),
        static_cast<ULONG>(ciphertext.size()),
        &auth,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        &written,
        0);

    if (!detail::nt_success(status)) {
        return error_code::authentication_failed;
    }
    if (written != plaintext.size()) {
        return error_code::windows_crypto_error;
    }

    return plaintext;
}

[[nodiscard]] inline expected<std::vector<std::byte>> open_with_key(
    std::span<const std::byte> envelope,
    std::span<const std::byte, key_size> key,
    std::optional<std::span<const std::byte>> expected_aad = std::nullopt)
{
    std::size_t offset = 0;
    auto header = parse_header(envelope, offset);
    if (!header) {
        return header.error();
    }
    if (header->kdf != 0 || header->iterations != 0) {
        return error_code::unsupported_algorithm;
    }
    if (offset > envelope.size() ||
        header->aad_size > envelope.size() - offset ||
        header->ciphertext_size > envelope.size() - offset - header->aad_size ||
        offset + header->aad_size + header->ciphertext_size != envelope.size()) {
        return error_code::bad_format;
    }

    const auto aad = envelope.subspan(offset, header->aad_size);
    offset += header->aad_size;
    const auto ciphertext = envelope.subspan(offset, header->ciphertext_size);

    if (expected_aad && ((*expected_aad).size() != aad.size() ||
        !std::equal(aad.begin(), aad.end(), (*expected_aad).begin()))) {
        return error_code::authentication_failed;
    }

    auto aes = detail::aes_gcm_algorithm();
    if (!aes) {
        return aes.error();
    }

    auto imported = detail::key_handle::generate(aes->get(), key);
    if (!imported) {
        return imported.error();
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(header->nonce.data()));
    auth.cbNonce = static_cast<ULONG>(header->nonce.size());
    auth.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(aad.data()));
    auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = reinterpret_cast<PUCHAR>(const_cast<std::byte*>(header->tag.data()));
    auth.cbTag = static_cast<ULONG>(header->tag.size());

    std::vector<std::byte> plaintext(ciphertext.size());
    ULONG written = 0;
    const auto status = ::BCryptDecrypt(
        imported->get(),
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(ciphertext.data())),
        static_cast<ULONG>(ciphertext.size()),
        &auth,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        &written,
        0);

    if (!detail::nt_success(status)) {
        return error_code::authentication_failed;
    }
    if (written != plaintext.size()) {
        return error_code::windows_crypto_error;
    }

    return plaintext;
}

namespace base64url {

inline constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

[[nodiscard]] inline std::string encode(std::span<const std::byte> input)
{
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    std::uint32_t buffer = 0;
    int bits = 0;
    for (const auto byte : input) {
        buffer = (buffer << 8) | std::to_integer<unsigned char>(byte);
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(alphabet[(buffer >> bits) & 0x3f]);
        }
    }

    if (bits) {
        out.push_back(alphabet[(buffer << (6 - bits)) & 0x3f]);
    }

    return out;
}

[[nodiscard]] inline expected<std::vector<std::byte>> decode(std::string_view input)
{
    if (input.size() % 4 == 1) {
        return error_code::bad_format;
    }

    std::array<int, 256> table{};
    table.fill(-1);
    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(alphabet[i])] = i;
    }

    std::vector<std::byte> out;
    std::uint32_t buffer = 0;
    int bits = 0;

    for (const unsigned char c : input) {
        if (table[c] < 0) {
            return error_code::bad_format;
        }

        buffer = (buffer << 6) | static_cast<std::uint32_t>(table[c]);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::byte>((buffer >> bits) & 0xff));
        }
    }

    if (bits > 0) {
        const auto mask = (1u << bits) - 1u;
        if ((buffer & mask) != 0) {
            return error_code::bad_format;
        }
    }

    return out;
}

} // namespace base64url

} // namespace metacrypt
