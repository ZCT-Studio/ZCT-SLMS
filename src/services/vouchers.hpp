// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "api/v1/auth/factors.hpp"
#include "services/moderation.hpp"

namespace zct_slms::vouchers {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    inline void schema() {
        static std::once_flag once;
        std::call_once(
            once,
            [] {
                auto& db = zct_slms::db::Database::instance();
                db.exec(
                    "CREATE TABLE IF NOT EXISTS voucher_codes (code_hash VARCHAR(64) "
                    "PRIMARY KEY, kind VARCHAR(16) NOT NULL, issuer_role VARCHAR(16) "
                    "NOT NULL, issuer_id BIGINT NOT NULL, target_role VARCHAR(16) NOT "
                    "NULL, amount BIGINT NOT NULL, expires_at BIGINT NOT NULL, used_by "
                    "BIGINT NOT NULL DEFAULT 0, used_at BIGINT NOT NULL DEFAULT 0, "
                    "created_at BIGINT NOT NULL)"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS invitation_bindings (user_id BIGINT "
                    "PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, code_hash "
                    "VARCHAR(64) NOT NULL UNIQUE, bound_at BIGINT NOT NULL)"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS voucher_secrets (code_hash VARCHAR(64) "
                    "PRIMARY KEY REFERENCES voucher_codes(code_hash) ON DELETE "
                    "CASCADE,code_cipher TEXT NOT NULL)"
                );
            }
        );
    }

    inline unsigned randomIndex(unsigned size) {
        unsigned limit = 256 - (256 % size);
        for (;;) {
            auto byte = static_cast<unsigned char>(zct_slms::crypto::randomBytes(1)[0]);
            if (byte < limit)
                return byte % size;
        }
    }

    inline std::string generate(bool symbols) {
        const std::vector<std::string> groups = {
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "abcdefghijklmnopqrstuvwxyz",
                "0123456789",
                "!@#$%^&*_-+=?"
            };
        auto alphabet =
            groups[0] + groups[1] + groups[2] + (symbols ? groups[3] : "");
        std::string code;
        for (size_t i = 0; i < (symbols ? 4 : 3); ++i)
            code += groups[i][randomIndex(static_cast<unsigned>(groups[i].size()))];
        while (code.size() < 64)
            code += alphabet[randomIndex(static_cast<unsigned>(alphabet.size()))];
        for (size_t i = code.size() - 1; i > 0; --i)
            std::swap(code[i], code[randomIndex(static_cast<unsigned>(i + 1))]);
        return code;
    }

    inline bool bound(int64_t uid) {
        schema();
        return !zct_slms::db::Database::instance()
               .queryParams(
                    "SELECT user_id FROM invitation_bindings WHERE user_id = ?",
                    uid
                )
               .empty();
    }

    inline void bindInvite(int64_t uid, const std::string& code) {
        schema();
        if (bound(uid))
            throw std::runtime_error("每个用户只能绑定一次邀请码");
        if (code.size() != 64)
            throw std::runtime_error("邀请码必须为 64 位");
        auto& db = zct_slms::db::Database::instance();
        auto rows = db.queryParams(
            "SELECT amount,expires_at,used_by,kind FROM "
            "voucher_codes WHERE code_hash = ?",
            zct_slms::crypto::sha256Hex(code)
        );
        if (rows.empty() || zct_slms::repo::getStr(rows[0], "kind") != "INVITE" ||
            zct_slms::repo::getInt(rows[0], "used_by") != 0 ||
            (zct_slms::repo::getInt(rows[0], "expires_at") != -1 &&
             zct_slms::repo::getInt(rows[0], "expires_at") < now()))
            throw std::runtime_error("邀请码无效、已使用或已过期");
        auto amount = zct_slms::repo::getInt(rows[0], "amount");
        auto u = zct_slms::repo::UserRepo::findById(uid);
        if (!u || u->balance != -1 && u->balance > INT64_MAX - amount)
            throw std::runtime_error("账号或余额无效");
        db.execParams(
            "INSERT INTO invitation_bindings(user_id,code_hash,bound_at) "
            "VALUES (?,?,?)",
            uid,
            zct_slms::crypto::sha256Hex(code),
            now()
        );
        db.execParams(
            "UPDATE voucher_codes SET used_by = ?,used_at = ? WHERE "
            "code_hash = ? AND used_by = 0",
            uid,
            now(),
            zct_slms::crypto::sha256Hex(code)
        );
        if (u->balance != -1)
            db.execParams(
                "UPDATE users SET balance = balance + ?,updated_at = ? WHERE id = ?",
                amount,
                now(),
                uid
            );
    }

    inline void create(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req, true);
            const auto kind = common::paramStr(req, "kind");
            const auto count = common::paramI64(req, "count", 1),
                       amount = common::paramI64(req, "amount", 0),
                       expires = common::paramI64(req, "expires_at", -1);
            if (kind != "INVITE" && kind != "BALANCE")
                throw std::runtime_error("兑换码类型无效");
            if (a.user_type != "ADMIN" && (a.user_type != "USER" || kind != "BALANCE"))
                throw std::runtime_error("无权生成此类型兑换码");
            if (count < 1 || count > 500 || amount < 0 || amount > 1000000000 ||
                (kind == "BALANCE" && amount == 0) ||
                (expires != -1 && expires <= now()))
                throw std::runtime_error("数量、余额或有效期无效");
            Json out;
            out["codes"] = Json(::Json::arrayValue);
            auto& db = zct_slms::db::Database::instance();
            bool success = db.transaction(
                [&] {
                    for (int i = 0; i < count; ++i) {
                        auto code = generate(kind == "BALANCE");
                        db.execParams(
                            "INSERT INTO "
                            "voucher_codes(code_hash,kind,issuer_role,issuer_id,target_role,"
                            "amount,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?)",
                            zct_slms::crypto::sha256Hex(code),
                            kind,
                            a.user_type,
                            a.user_id,
                            a.user_type == "USER" ? "SUBUSER" : "USER",
                            amount,
                            expires,
                            now()
                        );
                        out["codes"].append(code);
                        db.execParams(
                            "INSERT INTO voucher_secrets(code_hash,code_cipher) VALUES (?,?)",
                            zct_slms::crypto::sha256Hex(code),
                            zct_slms::crypto::base64Encode(
                                zct_slms::crypto::aes256GcmEncrypt(code, masterKey())
                            )
                        );
                    }
                    return true;
                }
            );
            if (!success)
                throw std::runtime_error("生成失败");
            zct_slms::repo::AuditRepo::log(
                a.user_type,
                a.user_id,
                "CreateVouchers",
                "VOUCHER",
                0,
                "",
                "success",
                common::clientIp(req),
                "{}",
                now()
            );
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void list(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req);
            if (a.user_type != "ADMIN" && a.user_type != "USER")
                throw std::runtime_error("无权查看生成记录");
            auto kind = common::paramStr(req, "kind");
            if (!kind.empty() && kind != "INVITE" && kind != "BALANCE")
                throw std::runtime_error("兑换码类型筛选无效");
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT kind,amount,expires_at,used_by,used_at,created_at,code_hash "
                "FROM voucher_codes WHERE issuer_role = ? AND issuer_id = ? AND (? = "
                "'' OR kind = ?) ORDER BY "
                "created_at DESC LIMIT 500",
                a.user_type,
                a.user_id,
                kind,
                kind
            );
            Json out(::Json::arrayValue);
            for (auto& row : rows) {
                Json item;
                for (auto key :
                     {"amount", "expires_at", "used_by", "used_at", "created_at"})
                    item[key] = ::Json::Int64(zct_slms::repo::getInt(row, key));
                item["kind"] = zct_slms::repo::getStr(row, "kind");
                item["reference"] = zct_slms::repo::getStr(row, "code_hash").substr(0, 12);
                item["id"] = zct_slms::repo::getStr(row, "code_hash");
                item["can_reveal"] =
                    !zct_slms::db::Database::instance()
                    .queryParams(
                         "SELECT code_hash FROM voucher_secrets WHERE code_hash = ?",
                         item["id"].asString()
                     )
                    .empty();
                out.append(item);
            }
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void reveal(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req, true);
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT s.code_cipher FROM voucher_codes v JOIN voucher_secrets s ON "
                "s.code_hash = v.code_hash WHERE v.code_hash = ? AND v.issuer_role = ? "
                "AND v.issuer_id = ?",
                common::paramStr(req, "id"),
                a.user_type,
                a.user_id
            );
            if (rows.empty())
                throw std::runtime_error("无权查看或此旧兑换码未保留可恢复明文");
            auto code = zct_slms::crypto::aes256GcmDecrypt(
                zct_slms::crypto::base64Decode(zct_slms::repo::getStr(rows[0], "code_cipher")),
                masterKey()
            );
            if (!code)
                throw std::runtime_error("兑换码无法解密，请检查认证主密钥");
            Json out;
            out["code"] = *code;
            auto response =
                drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(out));
            response->addHeader("Cache-Control", "no-store");
            cb(response);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void remove(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req, true);
            auto id = common::paramStr(req, "id");
            auto& db = zct_slms::db::Database::instance();
            if (!db.transaction(
                [&] {
                    auto rows = db.queryParams(
                        "SELECT used_by FROM voucher_codes WHERE code_hash = ? AND "
                        "issuer_role = ? AND issuer_id = ?",
                        id,
                        a.user_type,
                        a.user_id
                    );
                    if (rows.empty() || zct_slms::repo::getInt(rows[0], "used_by") != 0)
                        throw std::runtime_error("只能删除自己生成且尚未使用的兑换码");
                    db.execParams("DELETE FROM voucher_secrets WHERE code_hash = ?", id);
                    db.execParams(
                        "DELETE FROM voucher_codes WHERE code_hash = ? AND used_by = 0",
                        id
                    );
                    if (db.rowsChanged() != 1)
                        throw std::runtime_error("兑换码已被使用，未删除");
                    return true;
                }
            ))
                throw std::runtime_error("删除失败");
            zct_slms::repo::AuditRepo::log(
                a.user_type,
                a.user_id,
                "DeleteUnusedVoucher",
                "VOUCHER",
                0,
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

    inline void redeem(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req);
            if (a.user_type != "USER" && a.user_type != "SUBUSER")
                throw std::runtime_error("仅用户和子用户可兑换");
            const auto code = common::paramStr(req, "code"),
                       kind = common::paramStr(req, "kind");
            {
                std::lock_guard lock(mutex);
                prune();
                rate("redeem:" + a.user_type + std::to_string(a.user_id), 15, 60);
            }
            auto& db = zct_slms::db::Database::instance();
            if (code.size() != 64)
                throw std::runtime_error("兑换码必须为 64 位");
            if (kind == "INVITE" && a.user_type != "USER")
                throw std::runtime_error("只有应用所有者可以绑定邀请码");
            Json out;
            const bool success = db.transaction(
                [&] {
                    if (kind == "INVITE") {
                        bindInvite(a.user_id, code);
                        out["invite_bound"] = true;
                        return true;
                    }
                    if (kind != "BALANCE")
                        throw std::runtime_error("兑换类型无效");
                    auto hash = zct_slms::crypto::sha256Hex(code);
                    auto rows = db.queryParams(
                        "SELECT * FROM voucher_codes WHERE code_hash = ?",
                        hash
                    );
                    if (rows.empty())
                        throw std::runtime_error("余额码无效");
                    auto& row = rows[0];
                    if (zct_slms::repo::getStr(row, "kind") != "BALANCE" ||
                        zct_slms::repo::getStr(row, "target_role") != a.user_type ||
                        zct_slms::repo::getInt(row, "used_by") != 0 ||
                        (zct_slms::repo::getInt(row, "expires_at") != -1 &&
                         zct_slms::repo::getInt(row, "expires_at") < now()))
                        throw std::runtime_error("余额码已使用、已过期或不适用于此账号");
                    auto amount = zct_slms::repo::getInt(row, "amount");
                    db.execParams(
                        "UPDATE voucher_codes SET used_by = ?,used_at = ? WHERE "
                        "code_hash = ? AND used_by = 0",
                        a.user_id,
                        now(),
                        hash
                    );
                    if (db.rowsChanged() != 1)
                        throw std::runtime_error("余额码已被使用");
                    if (a.user_type == "USER") {
                        auto u = zct_slms::repo::UserRepo::findById(a.user_id);
                        if (!u || u->balance != -1 && u->balance > INT64_MAX - amount)
                            throw std::runtime_error("余额超出范围");
                        if (u->balance != -1)
                            db.execParams(
                                "UPDATE users SET balance = balance + ?,updated_at = ? "
                                "WHERE id = ?",
                                amount,
                                now(),
                                a.user_id
                            );
                    } else {
                        auto sub = db.queryParams(
                            "SELECT parent_id,quota_limit FROM sub_users WHERE id = ?",
                            a.user_id
                        );
                        if (sub.empty() || zct_slms::repo::getStr(row, "issuer_role") != "USER" ||
                            zct_slms::repo::getInt(row, "issuer_id") !=
                            zct_slms::repo::getInt(sub[0], "parent_id"))
                            throw std::runtime_error("只能使用所属主用户生成的余额码");
                        auto quota = zct_slms::repo::getInt(sub[0], "quota_limit");
                        if (quota != -1 && quota > INT64_MAX - amount)
                            throw std::runtime_error("额度超出范围");
                        if (quota != -1)
                            db.execParams(
                                "UPDATE sub_users SET quota_limit = quota_limit + "
                                "?,updated_at = ? WHERE id = ?",
                                amount,
                                now(),
                                a.user_id
                            );
                    }
                    out["amount"] = ::Json::Int64(amount);
                    return true;
                }
            );
            if (!success)
                throw std::runtime_error("兑换失败");
            zct_slms::repo::AuditRepo::log(
                a.user_type,
                a.user_id,
                "RedeemVoucher",
                "VOUCHER",
                0,
                "",
                "success",
                common::clientIp(req),
                "{}",
                now()
            );
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void status(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            Json out;
            if (a.user_type == "USER") {
                out["invite_bound"] = bound(a.user_id);
                auto user = zct_slms::repo::UserRepo::findById(a.user_id);
                out["balance"] = ::Json::Int64(user ? user->balance : 0);
            } else if (a.user_type == "SUBUSER") {
                auto rows = zct_slms::db::Database::instance().queryParams(
                    "SELECT quota_limit,quota_used FROM sub_users WHERE id = ?",
                    a.user_id
                );
                if (!rows.empty()) {
                    out["quota_limit"] =
                        ::Json::Int64(zct_slms::repo::getInt(rows[0], "quota_limit"));
                    out["quota_used"] =
                        ::Json::Int64(zct_slms::repo::getInt(rows[0], "quota_used"));
                }
            } else
                throw std::runtime_error("不支持此账号类型");
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void registerInvite(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto c = config();
                    if (!c.get("registration_enabled", true).asBool() ||
                        !c.get("invite_registration_enabled", true).asBool())
                        throw std::runtime_error("邀请码注册尚未开放");
                    auto username = common::paramStr(req, "username"),
                         password = common::paramStr(req, "password"),
                         nickname = common::paramStr(req, "nickname"),
                         code = common::paramStr(req, "invite_code");
                    if (!std::regex_match(username, std::regex("[A-Za-z0-9_.-]{3,64}")) ||
                        password.size() < 12 || password.size() > 256 || nickname.empty() ||
                        nickname.size() > 96)
                        throw std::runtime_error("用户名、昵称或密码格式不正确");
                    zct_slms::moderation::check(username);
                    zct_slms::moderation::check(nickname);
                    auto hp = zct_slms::service::hashPassword(password);
                    int64_t uid = 0;
                    schema();
                    const auto success = zct_slms::db::Database::instance().transaction(
                        [&] {
                            if (zct_slms::repo::UserRepo::findByUsername(username))
                                throw std::runtime_error("用户名已存在");
                            uid = zct_slms::repo::UserRepo::insert(
                                username,
                                hp.hash,
                                hp.salt,
                                nickname,
                                now(),
                                0
                            );
                            bindInvite(uid, code);
                            return true;
                        }
                    );
                    if (!success)
                        throw std::runtime_error("注册失败");
                    ok(cb, session(uid, common::clientIp(req), common::clientUa(req)));
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }
} // namespace zct_slms::vouchers
