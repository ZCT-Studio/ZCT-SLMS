// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/identity_service.hpp"
#include <openssl/rsa.h>
#include <memory>

namespace zct_slms::identity {
    inline std::string oidcDecode(std::string value) {
        if (value.empty() || value.size() > 32768 || !std::regex_match(value, std::regex("[A-Za-z0-9_-]+"))) throw std::runtime_error("OIDC 编码无效");
        std::ranges::replace(value, '-', '+');
        std::ranges::replace(value, '_', '/');
        while (value.size() % 4) value += '=';
        return zct_slms::crypto::base64Decode(value);
    }

    inline Json telegramClaims(const std::string& token, const Json& jwks, const std::string& client, const std::string& nonce) {
        if (token.size() > 32768) throw std::runtime_error("Telegram token 无效");
        const auto first = token.find('.'), last = token.rfind('.');
        if (first == std::string::npos || first == last) throw std::runtime_error("Telegram token 无效");
        auto header = parse(oidcDecode(token.substr(0, first)));
        if (header.get("alg", "").asString() != "RS256" || !header["kid"].isString() || header["kid"].asString().empty()) throw std::runtime_error("Telegram 需使用 RS256 签名");
        Json key;
        if (!jwks["keys"].isArray() || jwks["keys"].size() > 32) throw std::runtime_error("Telegram 公钥无效");
        for (const auto& item : jwks["keys"]) {
            if (item.get("kid", "") == header["kid"] && item.get("kty", "") == "RSA" && item.get("use", "sig") == "sig" && item.get("alg", "RS256") == "RS256") key = item;
        }
        if (key.isNull()) throw std::runtime_error("Telegram 签名公钥不存在");
        const auto n = oidcDecode(key["n"].asString()), e = oidcDecode(key["e"].asString());
        if (n.size() < 256 || n.size() > 1024 || e.empty() || e.size() > 8) throw std::runtime_error("Telegram RSA 公钥无效");
        std::unique_ptr<BIGNUM, decltype(&BN_free)> modulus(BN_bin2bn(reinterpret_cast<const unsigned char*>(n.data()), static_cast<int>(n.size()), nullptr), BN_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> exponent(BN_bin2bn(reinterpret_cast<const unsigned char*>(e.data()), static_cast<int>(e.size()), nullptr), BN_free);
        std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
        if (!rsa || !modulus || !exponent || RSA_set0_key(rsa.get(), modulus.get(), exponent.get(), nullptr) != 1) throw std::runtime_error("Telegram 公钥初始化失败");
        modulus.release();
        exponent.release();
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk(EVP_PKEY_new(), EVP_PKEY_free);
        if (!pk || EVP_PKEY_assign_RSA(pk.get(), rsa.get()) != 1) throw std::runtime_error("Telegram 公钥初始化失败");
        rsa.release();
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        const auto signature = oidcDecode(token.substr(last + 1));
        if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pk.get()) != 1 ||
            EVP_DigestVerify(
                ctx.get(),
                reinterpret_cast<const unsigned char*>(signature.data()),
                signature.size(),
                reinterpret_cast<const unsigned char*>(token.data()),
                last
            ) != 1)
            throw std::runtime_error("Telegram 签名验证失败");
        auto claims = parse(oidcDecode(token.substr(first + 1, last - first - 1)));
        bool audience = claims["aud"].isString() && claims["aud"].asString() == client;
        if (claims["aud"].isArray()) {
            for (const auto& aud : claims["aud"]) if (aud.isString() && aud.asString() == client) audience = true;
            if (claims["aud"].size() > 1 && claims.get("azp", "").asString() != client) audience = false;
        }
        if (claims.get("iss", "").asString() != "https://oauth.telegram.org" || !audience ||
            !claims["exp"].isInt64() || claims["exp"].asInt64() <= now() ||
            !claims["iat"].isInt64() || claims["iat"].asInt64() > now() + 60 ||
            (claims.isMember("nbf") && (!claims["nbf"].isInt64() || claims["nbf"].asInt64() > now() + 60)) ||
            !claims["sub"].isString() || claims["sub"].asString().empty() ||
            !zct_slms::crypto::constantTimeEqual(claims.get("nonce", "").asString(), nonce))
            throw std::runtime_error("Telegram 身份声明无效或已过期");
        return claims;
    }
}
