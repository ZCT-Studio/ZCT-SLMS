// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/portal_auth.hpp"

namespace zct_slms::recovery {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;
    inline std::mutex guard;

    struct Flow {
        Json account;
        std::string method, target, kind, fingerprint, challenge, origin, rp;
        int64_t expires;
        int attempts = 0;
    };

    inline std::map<std::string, Flow> flows, grants;

    inline bool allowed(const std::string& method) {
        return zct_slms::factors::settings()
              .get("recovery_" + method + "_enabled", true)
              .asBool();
    }

    inline Json transport(const std::string& method) {
        auto c = config();
        c[method + "_enabled"] = true;
        if (!ready(c, method))
            throw std::runtime_error("恢复服务尚未配置，请联系平台管理员");
        return c;
    }

    inline std::map<std::string, std::string> contacts(const Json& account) {
        return contactsFor(
            account["user_type"].asString(),
            account["user_id"].asInt64()
        );
    }

    inline void clean() {
        for (auto* map : {&flows, &grants})
            for (auto it = map->begin(); it != map->end();)
                if (it->second.expires < now())
                    it = map->erase(it);
                else
                    ++it;
        if (flows.size() > 5000 || grants.size() > 5000)
            throw std::runtime_error("恢复服务繁忙");
    }

    inline void throttle(
        const Req& req,
        const Json& account,
        const std::string& purpose,
        int count,
        int window
    ) {
        std::lock_guard limit(mutex);
        prune();
        rate(purpose + ":ip:" + common::clientIp(req), count, window);
        rate(
            purpose + ":account:" + account["user_type"].asString() +
            std::to_string(account["user_id"].asInt64()),
            count,
            window
        );
    }

    inline std::string grant(Flow flow) {
        clean();
        auto id = zct_slms::crypto::randomHex(32);
        flow.expires = now() + 600;
        grants[id] = std::move(flow);
        return id;
    }

    inline Flow takeGrant(const std::string& id, const std::string& kind) {
        auto it = grants.find(id);
        if (it == grants.end() || it->second.expires < now() ||
            it->second.kind != kind ||
            it->second.fingerprint !=
            zct_slms::portal_auth::fingerprint(it->second.account))
            throw std::runtime_error("恢复授权无效或已过期");
        auto flow = it->second;
        grants.erase(it);
        return flow;
    }

    inline void options(const Req& req, Callback&& cb) {
        try {
            auto account = zct_slms::portal_auth::findAccount(
                zct_slms::portal_auth::roleName(common::paramStr(req, "role", "USER")),
                common::paramStr(req, "username")
            );
            throttle(req, account, "recover-options", 20, 60);
            auto bound = contacts(account);
            auto a = zct_slms::factors::load(
                zct_slms::factors::accountKey(
                    account["user_type"].asString(),
                    account["user_id"].asInt64()
                )
            );
            Json out;
            out["methods"] = Json(::Json::arrayValue);
            for (auto method : {"email", "phone"})
                if (bound.contains(method) && allowed(method)) {
                    try {
                        transport(method);
                        out["methods"].append(method);
                    } catch (...) {}
                }
            if (bound.contains("email")) {
                auto email = bound["email"];
                out["email_domain"] = email.substr(email.find('@') + 1);
            }
            if (allowed("totp") && a.get("totp_enabled", false).asBool())
                out["methods"].append("totp");
            if (allowed("passkey") && !a["keys"].empty())
                out["methods"].append("passkey");
            out["security_ticket_allowed"] = allowed("ticket");
            out["ticket_allowed"] = bound.empty() && allowed("ticket");
            out["has_bound_contact"] = !bound.empty();
            ok(cb, out);
        } catch (const std::exception&) {
            fail(cb, "无法获取恢复方式，请检查账号信息或联系平台支持");
        }
    }

    inline void sendCode(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto account = zct_slms::portal_auth::findAccount(
                        zct_slms::portal_auth::roleName(common::paramStr(req, "role", "USER")),
                        common::paramStr(req, "username")
                    );
                    auto method = common::paramStr(req, "method"),
                         kind = common::paramStr(req, "kind", "reset"),
                         target = normalize(method, common::paramStr(req, "target"));
                    if (kind != "reset" && kind != "ticket" && kind != "security-ticket" ||
                        method != "email" && method != "phone")
                        throw std::runtime_error("恢复方式无效");
                    auto bound = contacts(account);
                    if (kind == "reset") {
                        if (!allowed(method) || !bound.contains(method) ||
                            !zct_slms::crypto::constantTimeEqual(bound[method], target))
                            throw std::runtime_error("无法验证此恢复信息");
                    } else if (!allowed("ticket") || (kind == "ticket" && !bound.empty()))
                        throw std::runtime_error("此账号请使用已绑定的方式自助恢复");
                    auto cfg = transport(method);
                    throttle(req, account, "recover-send", 5, 3600);
                    const auto id = zct_slms::crypto::randomHex(24),
                               code = zct_slms::crypto::randomNumeric(6),
                               purpose = "recovery:" + kind + ":" +
                                         account["user_type"].asString() + ":" +
                                         account["user_id"].asString();
                    if (method == "email")
                        deliverEmail(cfg, target, code, false, "", "", "recovery", mailAccount(account["user_type"].asString(), account["user_id"].asInt64(), target));
                    else
                        deliverPhone(cfg, target, code);
                    Flow flow{
                            account,
                            method,
                            target,
                            kind,
                            zct_slms::portal_auth::fingerprint(account),
                            "",
                            "",
                            "",
                            now() + 300
                        };
                    {
                        std::lock_guard lock(guard);
                        clean();
                        flows[id] = flow;
                    }
                    {
                        std::lock_guard lock(mutex);
                        zct_slms::identity::challenges[id] = {
                                method,
                                target,
                                zct_slms::crypto::hmacSha256Hex(id + ":" + code, otpSecret),
                                purpose,
                                now() + 300,
                                0
                            };
                    }
                    Json out;
                    out["challenge_id"] = id;
                    ok(cb, out);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void verifyCode(const Req& req, Callback&& cb) {
        try {
            std::lock_guard lock(guard);
            auto id = common::paramStr(req, "challenge_id");
            auto it = flows.find(id);
            if (it == flows.end() || it->second.expires < now() ||
                it->second.fingerprint !=
                zct_slms::portal_auth::fingerprint(it->second.account))
                throw std::runtime_error("恢复验证已过期");
            auto flow = it->second;
            if (flow.kind == "reset" &&
                (!allowed(flow.method) ||
                 contacts(flow.account)[flow.method] != flow.target))
                throw std::runtime_error("恢复方式已变更，请重新验证");
            auto purpose = "recovery:" + flow.kind + ":" +
                           flow.account["user_type"].asString() + ":" +
                           flow.account["user_id"].asString();
            consume(id, common::paramStr(req, "code"), purpose);
            flows.erase(it);
            Json out;
            out[flow.kind == "ticket" || flow.kind == "security-ticket" ? "contact_token" : "reset_token"] = grant(flow);
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void verifyTotp(const Req& req, Callback&& cb) {
        try {
            std::scoped_lock lock(guard, zct_slms::factors::guard);
            if (!allowed("totp"))
                throw std::runtime_error("动态令牌恢复尚未开放");
            auto account = zct_slms::portal_auth::findAccount(
                zct_slms::portal_auth::roleName(common::paramStr(req, "role", "USER")),
                common::paramStr(req, "username")
            );
            throttle(req, account, "recover-totp", 6, 60);
            auto key = zct_slms::factors::accountKey(
                account["user_type"].asString(),
                account["user_id"].asInt64()
            );
            auto a = zct_slms::factors::load(key);
            if (!a.get("totp_enabled", false).asBool() ||
                !zct_slms::factors::checkTotp(a, common::paramStr(req, "code")))
                throw std::runtime_error("账号或动态验证码不正确");
            zct_slms::factors::store(key, a);
            account["recovery_factor_version"] = a.get("version", 0);
            Flow flow{
                    account,
                    "totp",
                    "",
                    "reset",
                    zct_slms::portal_auth::fingerprint(account),
                    "",
                    "",
                    "",
                    now() + 300
                };
            Json out;
            out["reset_token"] = grant(flow);
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void passkeyStart(const Req& req, Callback&& cb) {
        try {
            std::scoped_lock lock(guard, zct_slms::factors::guard);
            if (!allowed("passkey"))
                throw std::runtime_error("通行密钥恢复尚未开放");
            auto account = zct_slms::portal_auth::findAccount(
                zct_slms::portal_auth::roleName(common::paramStr(req, "role", "USER")),
                common::paramStr(req, "username")
            );
            throttle(req, account, "recover-passkey", 10, 60);
            auto a = zct_slms::factors::load(
                zct_slms::factors::accountKey(
                    account["user_type"].asString(),
                    account["user_id"].asInt64()
                )
            );
            if (a["keys"].empty())
                throw std::runtime_error("账号或验证信息不正确");
            auto o = zct_slms::factors::origin();
            auto id = zct_slms::crypto::randomHex(24),
                 challenge = b64url(zct_slms::crypto::randomBytes(32));
            clean();
            flows[id] = {
                    account,
                    "passkey",
                    "",
                    "reset",
                    zct_slms::portal_auth::fingerprint(account),
                    challenge,
                    o.first,
                    o.second,
                    now() + 180
                };
            Json out;
            out["challenge_id"] = id;
            out["public_key"] = zct_slms::portal_auth::publicKey(a, challenge);
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void passkeyFinish(const Req& req, Callback&& cb) {
        try {
            std::scoped_lock lock(guard, zct_slms::factors::guard);
            auto id = common::paramStr(req, "challenge_id");
            auto it = flows.find(id);
            if (it == flows.end() || it->second.method != "passkey" ||
                it->second.expires < now() || ++it->second.attempts > 5)
                throw std::runtime_error("恢复验证无效或已过期");
            auto flow = it->second;
            if (flow.fingerprint != zct_slms::portal_auth::fingerprint(flow.account))
                throw std::runtime_error("账号凭据已改变");
            auto key = zct_slms::factors::accountKey(
                flow.account["user_type"].asString(),
                flow.account["user_id"].asInt64()
            );
            auto a = zct_slms::factors::load(key);
            auto body = req->getJsonObject();
            if (!body)
                throw std::runtime_error("认证数据无效");
            zct_slms::factors::assertion(
                a,
                (*body)["credential"],
                flow.challenge,
                flow.origin,
                flow.rp
            );
            zct_slms::factors::store(key, a);
            flow.account["recovery_factor_version"] = a.get("version", 0);
            flows.erase(it);
            Json out;
            out["reset_token"] = grant(flow);
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void reset(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto password = common::paramStr(req, "new_password");
                    if (password.size() < 12 || password.size() > 256)
                        throw std::runtime_error("新密码须为 12–256 字节");
                    auto hp = zct_slms::service::hashPassword(password);
                    std::scoped_lock lock(guard, zct_slms::factors::guard);
                    auto flow = takeGrant(common::paramStr(req, "reset_token"), "reset");
                    auto role = flow.account["user_type"].asString();
                    auto uid = flow.account["user_id"].asInt64();
                    if (!zct_slms::portal_auth::active(flow.account))
                        throw std::runtime_error("账号不可用");
                    if (!allowed(flow.method))
                        throw std::runtime_error("此恢复方式已关闭");
                    if (flow.method == "email" || flow.method == "phone") {
                        if (contacts(flow.account)[flow.method] != flow.target)
                            throw std::runtime_error("恢复联系方式已变更");
                    } else {
                        auto factors = zct_slms::factors::load(zct_slms::factors::accountKey(role, uid));
                        if (factors.get("version", 0) !=
                            flow.account.get("recovery_factor_version", -1))
                            throw std::runtime_error("验证方式已变更，请重新验证");
                    }
                    bool success = zct_slms::db::Database::instance().transaction(
                        [&] {
                            if (flow.fingerprint != zct_slms::portal_auth::fingerprint(flow.account))
                                return false;
                            zct_slms::db::Database::instance().execParams(
                                "UPDATE " + zct_slms::portal::table(role) +
                                " SET password_hash = ?,salt = ?,updated_at = ? WHERE id = ?",
                                hp.hash,
                                hp.salt,
                                now(),
                                uid
                            );
                            zct_slms::db::Database::instance().execParams(
                                "UPDATE sessions SET revoked = 1 WHERE user_type = ? AND user_id = "
                                "?",
                                role,
                                uid
                            );
                            zct_slms::repo::ConfigRepo::set(
                                "force_password:" + role + ":" + std::to_string(uid),
                                "0",
                                now()
                            );
                            return true;
                        }
                    );
                    if (!success)
                        throw std::runtime_error("恢复授权已过期，请重新验证");
                    zct_slms::repo::AuditRepo::log(
                        role,
                        uid,
                        "SelfResetPassword",
                        "ACCOUNT",
                        uid,
                        "",
                        "success",
                        common::clientIp(req),
                        "{}",
                        now()
                    );
                    ok(cb);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }
} // namespace zct_slms::recovery
