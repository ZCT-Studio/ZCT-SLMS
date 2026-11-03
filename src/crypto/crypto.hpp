// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_CRYPTO_CRYPTO
#define ZCT_SLMS_CRYPTO_CRYPTO
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <optional>
#include <limits>
#include <stdexcept>
#include <openssl/crypto.h>
#include <cstddef>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <argon2.h>

namespace zct_slms::crypto {
    inline std::string toHex(const std::string_view input) {
        static const char* HEX = "0123456789abcdef";
        std::string out;
        out.reserve(input.size() * 2);
        for (unsigned char b : input) {
            out.push_back(HEX[b >> 4]);
            out.push_back(HEX[b & 0x0F]);
        }
        return out;
    }

    inline std::string fromHex(const std::string_view input) {
        auto hex2byte = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        if (input.size() % 2 != 0) return {};
        std::string out;
        out.reserve(input.size() / 2);
        for (size_t i = 0; i + 1 < input.size(); i += 2) {
            int hi = hex2byte(input[i]);
            int lo = hex2byte(input[i + 1]);
            if (hi < 0 || lo < 0) return {};
            out.push_back(static_cast<char>((hi << 4) | lo));
        }
        return out;
    }

    inline std::string base64Encode(const std::string_view input) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, input.data(), static_cast<int>(input.size()));
        BIO_flush(b64);
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(b64, &bptr);
        std::string out(bptr->data, bptr->length);
        BIO_free_all(b64);
        return out;
    }

    inline std::string base64Decode(const std::string_view input) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        b64 = BIO_push(b64, bmem);
        std::string out(input.size(), '\0');
        int n = BIO_read(b64, out.data(), static_cast<int>(out.size()));
        out.resize(n > 0 ? n : 0);
        BIO_free_all(b64);
        return out;
    }

    inline std::string sha256(const std::string_view input) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(
            reinterpret_cast<const unsigned char*>(input.data()),
            input.size(),
            digest
        );
        return {reinterpret_cast<char*>(digest), SHA256_DIGEST_LENGTH};
    }

    inline std::string sha256Hex(const std::string_view input) {
        return toHex(sha256(input));
    }

    inline std::string sha512(const std::string_view input) {
        unsigned char digest[SHA512_DIGEST_LENGTH];
        SHA512(
            reinterpret_cast<const unsigned char*>(input.data()),
            input.size(),
            digest
        );
        return {reinterpret_cast<char*>(digest), SHA512_DIGEST_LENGTH};
    }

    inline std::string sha512Hex(const std::string_view input) {
        return toHex(sha512(input));
    }

    inline std::string hmacSha256(const std::string_view data, const std::string_view key) {
        unsigned int len = 0;
        unsigned char out[EVP_MAX_MD_SIZE];
        HMAC(
            EVP_sha256(),
            key.data(),
            static_cast<int>(key.size()),
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            out,
            &len
        );
        return {reinterpret_cast<char*>(out), len};
    }

    inline std::string hmacSha256Hex(const std::string_view data, const std::string_view key) {
        return toHex(hmacSha256(data, key));
    }

    inline std::string randomBytes(const size_t n) {
        std::string buf(n, '\0');
        if (n > static_cast<size_t>(std::numeric_limits<int>::max()) || (n && RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), static_cast<int>(n)) != 1)) throw std::runtime_error("secure random generation failed");
        return buf;
    }

    inline std::string randomHex(const size_t bytes) {
        return toHex(randomBytes(bytes));
    }

    inline std::string randomUppercaseAlphanumeric(const size_t len) {
        static constexpr char CHARS[] =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static constexpr size_t N = sizeof(CHARS) - 1;
        std::string out;
        out.reserve(len);
        std::vector<unsigned char> rnd(len);
        if (len > static_cast<size_t>(std::numeric_limits<int>::max()) || (len && RAND_bytes(rnd.data(), static_cast<int>(len)) != 1)) throw std::runtime_error("secure random generation failed");
        for (size_t i = 0; i < len; ++i)
            out.push_back(CHARS[rnd[i] % N]);
        return out;
    }

    inline std::string randomAlphanumeric(const size_t len) {
        static constexpr char CHARS[] =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        static constexpr size_t N = sizeof(CHARS) - 1;
        std::string out;
        out.reserve(len);
        std::vector<unsigned char> rnd(len);
        if (len > static_cast<size_t>(std::numeric_limits<int>::max()) || (len && RAND_bytes(rnd.data(), static_cast<int>(len)) != 1)) throw std::runtime_error("secure random generation failed");
        for (size_t i = 0; i < len; ++i)
            out.push_back(CHARS[rnd[i] % N]);
        return out;
    }

    inline std::string randomNumeric(const size_t len) {
        static constexpr char DIGITS[] = "0123456789";
        static constexpr size_t N = 10;
        std::string out;
        out.reserve(len);
        std::vector<unsigned char> rnd(len);
        if (len > static_cast<size_t>(std::numeric_limits<int>::max()) || (len && RAND_bytes(rnd.data(), static_cast<int>(len)) != 1)) throw std::runtime_error("secure random generation failed");
        for (size_t i = 0; i < len; ++i)
            out.push_back(DIGITS[rnd[i] % N]);
        return out;
    }

    #if defined(ZCT_SLMS_HAS_ARGON2)
    inline std::string argon2idHash(const std::string_view password, const std::string_view salt) {
        constexpr uint32_t t_cost = 2;
        constexpr uint32_t m_cost = 64 * 1024; // 64MB
        constexpr uint32_t parallelism = 1;
        constexpr size_t hash_len = 32;

        std::string out(hash_len, '\0');
        const int rc = argon2id_hash_raw(
            t_cost,
            m_cost,
            parallelism,
            password.data(),
            password.size(),
            salt.data(),
            salt.size(),
            out.data(),
            hash_len
        );
        if (rc != ARGON2_OK) return {};
        return toHex(out);
    }

    inline bool argon2idVerify(
        const std::string_view password,
        const std::string_view salt,
        const std::string_view expected_hex
    ) {
        const auto actual = argon2idHash(password, salt);
        if (actual.size() != expected_hex.size()) return false;

        volatile unsigned char diff = 0;
        for (size_t i = 0; i < actual.size(); ++i)
            diff |= actual[i] ^ expected_hex[i];
        return diff == 0;
    }
    #else
    inline std::string argon2idHash(const std::string_view password, const std::string_view salt) {
        // 降级：SHA-512 + salt（生产环境应启用 argon2）
        const std::string combined = std::string(salt) + std::string(password) + std::string(salt);
        return toHex(sha512(combined));
    }
    inline bool argon2idVerify(
        const std::string_view password,
        const std::string_view salt,
        const std::string_view expected_hex
    ) {
        const auto actual = argon2idHash(password, salt);
        if (actual.size() != expected_hex.size()) return false;
        volatile unsigned char diff = 0;
        for (size_t i = 0; i < actual.size(); ++i)
            diff |= actual[i] ^ expected_hex[i];
        return diff == 0;
    }
    #endif

    inline std::string aeadEncrypt(const std::string_view plaintext, const std::string_view key, const EVP_CIPHER* algorithm) {
        if (key.size() != static_cast<size_t>(EVP_CIPHER_key_length(algorithm))) return {};
        const auto* k = reinterpret_cast<const unsigned char*>(key.data());

        unsigned char nonce[12];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) return {};

        std::string cipher(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
        int cipher_len = 0;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};

        int out_len = 0;
        if (1 != EVP_EncryptInit_ex(ctx, algorithm, nullptr, k, nonce)) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        if (1 != EVP_EncryptUpdate(
                ctx,
                reinterpret_cast<unsigned char*>(cipher.data()),
                &out_len,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())
            )) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        cipher_len = out_len;

        if (1 != EVP_EncryptFinal_ex(
                ctx,
                reinterpret_cast<unsigned char*>(cipher.data()) + cipher_len,
                &out_len
            )) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        cipher_len += out_len;

        unsigned char tag[16];
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        EVP_CIPHER_CTX_free(ctx);

        std::string out;
        out.assign(reinterpret_cast<char*>(nonce), sizeof(nonce));
        out.append(cipher.data(), cipher_len);
        out.append(reinterpret_cast<char*>(tag), 16);
        return out;
    }

    inline std::optional<std::string> aeadDecrypt(const std::string_view blob, const std::string_view key, const EVP_CIPHER* algorithm) {
        if (key.size() != static_cast<size_t>(EVP_CIPHER_key_length(algorithm)) || blob.size() < 12 + 16) return std::nullopt;
        const auto* k = reinterpret_cast<const unsigned char*>(key.data());

        const auto* nonce = reinterpret_cast<const unsigned char*>(blob.data());
        const auto* tag = reinterpret_cast<const unsigned char*>(blob.data() + blob.size() - 16);
        const size_t ct_len = blob.size() - 12 - 16;
        const unsigned char* ct = nonce + 12;

        std::string plain(ct_len + EVP_MAX_BLOCK_LENGTH, '\0');
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return std::nullopt;

        int out_len = 0, total = 0;
        if (1 != EVP_DecryptInit_ex(ctx, algorithm, nullptr, k, nonce)) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
        if (1 != EVP_DecryptUpdate(
                ctx,
                reinterpret_cast<unsigned char*>(plain.data()),
                &out_len,
                ct,
                static_cast<int>(ct_len)
            )) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
        total = out_len;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag))) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
        if (1 != EVP_DecryptFinal_ex(
                ctx,
                reinterpret_cast<unsigned char*>(plain.data()) + total,
                &out_len
            )) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
        total += out_len;
        EVP_CIPHER_CTX_free(ctx);

        plain.resize(total);
        return plain;
    }
    inline std::string aes128GcmEncrypt(std::string_view p, std::string_view k) { return aeadEncrypt(p, k, EVP_aes_128_gcm()); }
    inline std::optional<std::string> aes128GcmDecrypt(std::string_view p, std::string_view k) { return aeadDecrypt(p, k, EVP_aes_128_gcm()); }
    inline std::string aes256GcmEncrypt(std::string_view p, std::string_view k) { return aeadEncrypt(p, k, EVP_aes_256_gcm()); }
    inline std::optional<std::string> aes256GcmDecrypt(std::string_view p, std::string_view k) { return aeadDecrypt(p, k, EVP_aes_256_gcm()); }
    inline std::string chacha20Poly1305Encrypt(std::string_view p, std::string_view k) { return aeadEncrypt(p, k, EVP_chacha20_poly1305()); }
    inline std::optional<std::string> chacha20Poly1305Decrypt(std::string_view p, std::string_view k) { return aeadDecrypt(p, k, EVP_chacha20_poly1305()); }
    inline bool constantTimeEqual(std::string_view a, std::string_view b) { return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0; }

}

#endif // ZCT_SLMS_CRYPTO_CRYPTO
