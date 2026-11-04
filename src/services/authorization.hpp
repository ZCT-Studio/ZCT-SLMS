// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/portal_auth.hpp"
#include <string_view>

namespace zct_slms::authorization {
    using namespace zct_slms::identity;
    inline constexpr std::string_view credentialPrefix = "zct_slms-auth:";
    namespace common = zct_slms::inside::api::v1::common;

    struct Proof {
        std::string session, ip, ua, fingerprint, account, policy;
        int version;
        int64_t expires;
        bool closure = false;
    };

    inline std::string policy() {
        return zct_slms::crypto::sha256Hex(
            json(zct_slms::factors::settings()) + "\n" +
            json(zct_slms::identity::config())
        );
    }

    inline std::mutex proofGuard;
    inline std::map<std::string, Proof> proofs;

    inline std::string sessionHash(const Req& req) {
        return zct_slms::crypto::sha256Hex(common::authBearer(req));
    }

    inline std::string accountFingerprint(const Json& session) {
        Json value;
        value["password"] = zct_slms::portal_auth::fingerprint(session);
        value["bindings"] = Json(::Json::arrayValue);
        const auto role = session["user_type"].asString();
        const auto uid = session["user_id"].asInt64();
        if (role == "USER") {
            zct_slms::identity::schema();
            for (const auto& row : zct_slms::db::Database::instance().queryParams(
                     "SELECT provider,subject FROM auth_identities WHERE user_id = ? "
                     "ORDER BY provider,subject",
                     uid
                 )) {
                Json b;
                b["provider"] = zct_slms::repo::getStr(row, "provider");
                b["subject"] = zct_slms::repo::getStr(row, "subject");
                value["bindings"].append(b);
            }
        }
        for (const auto& [provider, target] : contactsFor(role, uid))
            value["contacts"][provider] = target;
        return zct_slms::crypto::sha256Hex(json(value));
    }

    inline Json sessionOf(const Req& req) {
        auto a =
            zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
        if (!a.success)
            throw std::runtime_error("请重新登录");
        Json s;
        s["user_type"] = a.user_type;
        s["user_id"] = ::Json::Int64(a.user_id);
        s["username"] = a.username;
        return s;
    }

    inline bool trusted(
        const Json& session,
        const Json& factors,
        const std::string& hash
    ) {
        auto raw = zct_slms::repo::ConfigRepo::get("authorization_trust:" + hash, "");
        if (raw.empty())
            return false;
        try {
            auto t = parse(raw);
            return t.get("expires", 0).asInt64() > now() &&
                   t.get("version", -1) == factors.get("version", 0) &&
                   t.get("fingerprint", "").asString() == accountFingerprint(session) &&
                   t.get("policy", "").asString() == policy();
        } catch (...) {
            return false;
        }
    }

    inline void trust(
        const Json& session,
        const Json& factors,
        const std::string& hash
    ) {
        Json t;
        t["expires"] = ::Json::Int64(now() + 3600);
        t["version"] = factors.get("version", 0);
        t["fingerprint"] = accountFingerprint(session);
        t["policy"] = policy();
        zct_slms::repo::ConfigRepo::set("authorization_trust:" + hash, json(t), now());
    }

    inline bool requiresTwo(
        const Json& session,
        const Json& a,
        const std::string& hash
    ) {
        return zct_slms::factors::settings().get("two_factor_enabled", false).asBool() &&
               zct_slms::portal_auth::methods(session, a).size() >= 2 &&
               !trusted(session, a, hash);
    }

    inline Json describe(
        const std::string& id,
        zct_slms::portal_auth::Challenge& p,
        const Json& a
    ) {
        Json out;
        out["authorization_required"] = true;
        out["challenge_id"] = id;
        out["primary_method"] = p.primary;
        out["two_factor_required"] =
            p.session.get("_closure", false).asBool() ||
            requiresTwo(p.session, a, p.session["_authorization_session"].asString());
        out["methods"] = Json(::Json::arrayValue);
        for (const auto& method : zct_slms::portal_auth::methods(p.session, a))
            if (method != p.primary)
                out["methods"].append(method);
        out["recovery_available"] = !p.session.get("_closure", false).asBool() &&
                                    !p.primary.empty() && !a["recovery"].empty();
        if (!a["keys"].empty())
            out["public_key"] = zct_slms::portal_auth::publicKey(a, p.challenge);
        return out;
    }

    inline Json complete(
        const std::string& id,
        zct_slms::portal_auth::Challenge& p,
        Json a
    ) {
        const auto method = p.session["_verified_method"].asString(),
                   hash = p.session["_authorization_session"].asString();
        if (p.primary.empty() && (p.session.get("_closure", false).asBool() ||
                                  requiresTwo(p.session, a, hash))) {
            p.primary = method;
            p.challenge = b64url(zct_slms::crypto::randomBytes(32));
            p.attempts = 0;
            p.expires = now() + 180;
            return describe(id, p, a);
        }
        if (!p.primary.empty())
            trust(p.session, a, hash);
        const auto token = zct_slms::crypto::randomHex(32);
        {
            std::lock_guard lock(proofGuard);
            for (auto it = proofs.begin(); it != proofs.end();)
                if (it->second.expires < now())
                    it = proofs.erase(it);
                else
                    ++it;
            if (proofs.size() > 10000)
                throw std::runtime_error("授权服务繁忙");
            proofs[zct_slms::crypto::sha256Hex(token)] = {
                    hash,
                    p.ip,
                    p.ua,
                    accountFingerprint(p.session),
                    p.account,
                    policy(),
                    a.get("version", 0).asInt(),
                    now() + 120,
                    p.session.get("_closure", false).asBool() && !p.primary.empty() &&
                    method != "recovery"
                };
        }
        zct_slms::portal_auth::challenges.erase(id);
        Json out;
        out["authorization_token"] = token;
        out["expires_in"] = 120;
        return out;
    }

    inline void start(const Req& req, Callback&& cb) {
        try {
            auto session = sessionOf(req);
            {
                std::lock_guard lock(mutex);
                prune();
                rate("authorize-start:" + sessionHash(req), 10, 60);
            }
            std::scoped_lock lock(zct_slms::portal_auth::guard, zct_slms::factors::guard);
            auto account = zct_slms::factors::accountKey(
                     session["user_type"].asString(),
                     session["user_id"].asInt64()
                 ),
                 id = zct_slms::crypto::randomHex(32),
                 challenge = b64url(zct_slms::crypto::randomBytes(32));
            auto a = zct_slms::factors::load(account);
            if (common::paramStr(req, "purpose") == "closure") {
                if (zct_slms::portal_auth::methods(session, a).size() < 2)
                    throw std::runtime_error(
                        "注销必须验证两种登录方式，请先绑定第二种登录方式"
                    );
                session["_closure"] = true;
            }
            session["_fingerprint"] = zct_slms::portal_auth::fingerprint(session);
            session["_factor_version"] = a.get("version", 0);
            session["_authorization_session"] = sessionHash(req);
            std::string origin, rp;
            if (!a["keys"].empty()) {
                auto o = zct_slms::factors::origin();
                origin = o.first;
                rp = o.second;
            }
            zct_slms::portal_auth::pruneChallenges();
            auto& p = zct_slms::portal_auth::challenges[id];
            p = {
                    session,
                    account,
                    "",
                    challenge,
                    origin,
                    rp,
                    common::clientIp(req),
                    common::clientUa(req),
                    "authorize",
                    now() + 180
                };
            ok(cb, describe(id, p, a));
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline bool verify(const Req& req, const std::string& credential) {
        try {
            auto session = sessionOf(req);
            const auto hash = sessionHash(req),
                       account =
                           zct_slms::factors::accountKey(
                               session["user_type"].asString(),
                               session["user_id"].asInt64()
                           );
            if (credential.starts_with(credentialPrefix)) {
                Proof proof;
                {
                    std::lock_guard lock(proofGuard);
                    auto it = proofs.find(zct_slms::crypto::sha256Hex(credential.substr(credentialPrefix.size())));
                    if (it == proofs.end())
                        return false;
                    proof = it->second;
                }
                if (proof.expires < now() || proof.session != hash ||
                    proof.account != account || proof.ip != common::clientIp(req) ||
                    proof.ua != common::clientUa(req) ||
                    proof.fingerprint != accountFingerprint(session))
                    return false;
                std::lock_guard lock(zct_slms::factors::guard);
                if (proof.version != zct_slms::factors::load(account).get("version", 0).asInt() || proof.policy != policy()) return false;
                const auto captcha = zct_slms::factors::settings();
                if (captcha.get("captcha_provider", "none").asString() != "none" &&
                    (captcha.get("captcha_for_authorization", false).asBool() || captcha.get("captcha_for_passkey", false).asBool())) {
                    std::lock_guard proofLock(proofGuard);
                    const auto proofKey = zct_slms::crypto::sha256Hex(credential.substr(credentialPrefix.size()));
                    const auto it = proofs.find(proofKey);
                    if (it == proofs.end()) return false;
                    proofs.erase(it);
                }
                return true;
            }
            const auto captchaPolicy = zct_slms::factors::settings();
            if (captchaPolicy.get("captcha_for_authorization", false).asBool() && captchaPolicy.get("captcha_provider", "none").asString() != "none") return false;
            {
                std::lock_guard lock(mutex);
                prune();
                rate("authorize-password:" + hash, 10, 60);
            }
            {
                std::lock_guard lock(zct_slms::factors::guard);
                if (requiresTwo(session, zct_slms::factors::load(account), hash))
                    return false;
            }
            auto row = zct_slms::db::Database::instance().queryParams(
                "SELECT password_hash,salt FROM " +
                zct_slms::portal::table(session["user_type"].asString()) +
                " WHERE id = ?",
                session["user_id"].asInt64()
            );
            return !row.empty() &&
                   zct_slms::service::verifyPassword(
                       credential,
                       zct_slms::repo::getStr(row[0], "password_hash"),
                       zct_slms::repo::getStr(row[0], "salt")
                   );
        } catch (...) {
            return false;
        }
    }

    inline bool consumeClosure(const Req& req, const std::string& credential) {
        if (!credential.starts_with(credentialPrefix) || !verify(req, credential))
            return false;
        std::lock_guard lock(proofGuard);
        auto it = proofs.find(zct_slms::crypto::sha256Hex(credential.substr(credentialPrefix.size())));
        if (it == proofs.end() || !it->second.closure)
            return false;
        proofs.erase(it);
        return true;
    }

    inline void install() {
        common::sensitiveAuthorization = verify;
        zct_slms::portal_auth::authorizationComplete = complete;
        zct_slms::portal_auth::twoFactorCompleted = [](
            const Json& session,
            const Json& a
        ) {
                trust(
                    session,
                    a,
                    zct_slms::crypto::sha256Hex("Bearer " + session["token"].asString())
                );
            };
    }
} // namespace zct_slms::authorization
