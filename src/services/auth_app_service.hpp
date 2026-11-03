// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_SERVICES_AUTH_APP_SERVICE
#define ZCT_SLMS_SERVICES_AUTH_APP_SERVICE

#include <string>
#include <ctime>
#include <cstdint>
#include <optional>
#include <vector>
#include "common/types.hpp"
#include "config/app_config.hpp"
#include "crypto/crypto.hpp"
#include "repositories/user_app_repo.hpp"
#include "services/license_service.hpp"

namespace zct_slms::service {
    struct HashedPassword {
        std::string hash;
        std::string salt;
    };

    inline HashedPassword hashPassword(std::string_view password) {
        std::string salt = zct_slms::crypto::randomHex(16);
        std::string h;
        #if defined(ZCT_SLMS_HAS_ARGON2)
        h = zct_slms::crypto::argon2idHash(password, salt);
        #else
        h = zct_slms::crypto::sha512Hex(salt + std::string(password) + salt);
        #endif
        if(h.empty())throw std::runtime_error("密码哈希失败，请稍后重试");
        return {h, salt};
    }

    inline bool verifyPassword(std::string_view password, const std::string& hash, const std::string& salt) {
        #if defined(ZCT_SLMS_HAS_ARGON2)
        return zct_slms::crypto::argon2idVerify(password, salt, hash);
        #else
        auto actual = zct_slms::crypto::sha512Hex(salt + std::string(password) + salt);
        volatile unsigned char diff = 0;
        for (size_t i = 0; i < actual.size() && i < hash.size(); ++i)
            diff |= actual[i] ^ hash[i];
        return diff == 0;
        #endif
    }

    namespace AuthService {
        struct LoginResult {
            bool success;
            std::string token;     // Bearer Token（十六进制）
            std::string user_type; // ADMIN / USER / SUBUSER
            int64_t user_id;
            std::string username;
            int status;
            std::string message;
        };

        inline LoginResult loginAdmin(
            const std::string& username,
            const std::string& password,
            const std::string& ip,
            const std::string& ua
        ) {
            LoginResult r{false, {}, {}, 0, {}, 0, ""};
            auto admin = repo::AdminRepo::findByUsername(username);
            if (!admin) {
                r.message = "用户名或密码错误";
                return r;
            }
            if (admin->status != 1) {
                r.message = "账号已被禁用";
                return r;
            }
            if (!verifyPassword(password, admin->password_hash, admin->salt)) {
                r.message = "用户名或密码错误";
                return r;
            }

            int64_t now = std::time(nullptr);
            int64_t ttl = zct_slms::AppConfig::instance().security().session_ttl_seconds;
            std::string token = zct_slms::crypto::randomHex(32);
            std::string token_hash = zct_slms::crypto::sha256Hex(token);

            const auto staff_role=repo::ConfigRepo::get("staff_role:"+std::to_string(admin->id),"ADMIN");repo::SessionRepo::insert(staff_role=="SUPPORT"?"SUPPORT":"ADMIN", admin->id, token_hash, now + ttl, now, ip, ua);
            repo::AdminRepo::updateLastLogin(admin->id, now);

            r.success = true;
            r.token = token;
            r.user_type = staff_role=="SUPPORT"?"SUPPORT":"ADMIN";
            r.user_id = admin->id;
            r.username = admin->username;
            r.status = admin->status;
            r.message = "OK";
            return r;
        }

        inline LoginResult loginOwner(
            const std::string& username,
            const std::string& password,
            const std::string& ip,
            const std::string& ua
        ) {
            LoginResult r{false, {}, {}, 0, {}, 0, ""};
            auto user = repo::UserRepo::findByUsername(username);
            if (!user) {
                r.message = "用户名或密码错误";
                return r;
            }
            if (user->status != 1) {
                r.message = "账号已禁用";
                return r;
            }
            if (user->expires_at != -1 && user->expires_at < std::time(nullptr)) {
                r.message = "账号已过期";
                return r;
            }
            if (!verifyPassword(password, user->password_hash, user->salt)) {
                r.message = "用户名或密码错误";
                return r;
            }
            int64_t now = std::time(nullptr);
            int64_t ttl = zct_slms::AppConfig::instance().security().session_ttl_seconds;
            std::string token = zct_slms::crypto::randomHex(32);
            std::string token_hash = zct_slms::crypto::sha256Hex(token);
            repo::SessionRepo::insert("USER", user->id, token_hash, now + ttl, now, ip, ua);

            r.success = true;
            r.token = token;
            r.user_type = "USER";
            r.user_id = user->id;
            r.username = user->username;
            r.status = user->status;
            r.message = "OK";
            return r;
        }

        inline LoginResult loginSubUser(
            const std::string& username,
            const std::string& password,
            const std::string& ip,
            const std::string& ua
        ) {
            LoginResult r{.success = false, .token = {}, .user_type = {}, .user_id = 0, .username = {}, .status = 0, .message = ""};
            auto rows = db::Database::instance().queryParams(
                "SELECT * FROM sub_users WHERE username = ?",
                username
            );
            if (rows.empty()) {
                r.message = "用户名或密码错误";
                return r;
            }
            const auto& su = rows[0];
            std::string pw_hash = repo::getStr(su, "password_hash");
            std::string salt = repo::getStr(su, "salt");
            int status = static_cast<int>(repo::getInt(su, "status"));
            int64_t expires_at = repo::getInt(su, "expires_at");
            int64_t id = repo::getInt(su, "id");

            if (status != 1) {
                r.message = "账号已禁用";
                return r;
            }
            if (expires_at != -1 && expires_at < std::time(nullptr)) {
                r.message = "账号已过期";
                return r;
            }
            if (!verifyPassword(password, pw_hash, salt)) {
                r.message = "用户名或密码错误";
                return r;
            }

            int64_t now = std::time(nullptr);
            int64_t ttl = zct_slms::AppConfig::instance().security().session_ttl_seconds;
            std::string token = zct_slms::crypto::randomHex(32);
            repo::SessionRepo::insert("SUBUSER", id, zct_slms::crypto::sha256Hex(token), now + ttl, now, ip, ua);

            r.success = true;
            r.token = token;
            r.user_type = "SUBUSER";
            r.user_id = id;
            r.username = username;
            r.status = status;
            r.message = "OK";
            return r;
        }

        struct AuthenticatedUser {
            bool success = false;
            std::string user_type;
            int64_t user_id = 0;
            std::string username;
            int status = 0;
        };

        inline AuthenticatedUser authenticateSession(const std::string& bearer) {
            AuthenticatedUser u;
            if (bearer.empty()) return u;
            std::string token = bearer;
            if (token.starts_with("Bearer ")) token = token.substr(7);
            std::string token_hash = zct_slms::crypto::sha256Hex(token);
            auto sess = repo::SessionRepo::findByTokenHash(token_hash);
            if (!sess) return u;

            u.user_type = sess->user_type;
            u.user_id = sess->user_id;

            if (u.user_type == "ADMIN" || u.user_type == "SUPPORT") {
                auto a = repo::AdminRepo::findById(u.user_id);
                if (!a || repo::ConfigRepo::get("staff_role:"+std::to_string(a->id),"ADMIN")!=u.user_type) return u;
                u.username = a->username;
                u.status = a->status;
            } else if (u.user_type == "USER") {
                auto ou = repo::UserRepo::findById(u.user_id);
                if (!ou || (ou->expires_at != -1 && ou->expires_at < std::time(nullptr))) return u;
                u.username = ou->username;
                u.status = ou->status;
            } else if (u.user_type == "SUBUSER") {
                auto rows = db::Database::instance().queryParams(
                    "SELECT username, status, expires_at FROM sub_users WHERE id = ?",
                    u.user_id
                );
                if (rows.empty() || (repo::getInt(rows[0],"expires_at") != -1 && repo::getInt(rows[0],"expires_at") < std::time(nullptr))) return u;
                u.username = repo::getStr(rows[0], "username");
                u.status = static_cast<int>(repo::getInt(rows[0], "status"));
            }
            if (u.status != 1) return u;
            const auto current_time = std::time(nullptr);
            const auto ttl = zct_slms::AppConfig::instance().security().session_ttl_seconds;
            if (sess->expires_at < current_time + ttl - 300)
                db::Database::instance().execParams(
                    "UPDATE sessions SET expires_at = ? WHERE token_hash = ? AND revoked = 0 AND expires_at > ?",
                    current_time + ttl, token_hash, current_time);
            u.success = true;
            return u;
        }

        inline bool logout(const std::string& bearer) {
            std::string token = bearer;
            if (token.starts_with("Bearer ")) token = token.substr(7);
            repo::SessionRepo::revokeByHash(zct_slms::crypto::sha256Hex(token));
            return true;
        }
    } // namespace AuthService

    namespace AppService {
        struct AppSecretPair {
            std::string appid;
            std::string secret;
        };

        inline zct_slms::common::ResultOf<AppSecretPair> createApp(
            const int64_t owner_id,
            const std::string& name,
            const std::string& description
        ) {
            std::string appid;
            for (int i = 0; i < 5; ++i) {
                appid = zct_slms::crypto::randomNumeric(12);
                if (const auto existing = repo::AppRepo::findByAppid(appid); !existing) break;
            }
            const std::string secret = zct_slms::crypto::randomHex(32);
            const int64_t now = std::time(nullptr);
            int64_t app_db_id = repo::AppRepo::insert(owner_id, appid, name, description, secret, now);

            // 自动创建 4 个默认频道
            for (auto& ch : {"release", "beta", "alpha"}) {
                zct_slms::db::Database::instance().execParams(
                    "INSERT OR IGNORE INTO update_channels(app_id, channel, created_at) VALUES (?, ?, ?)",
                    app_db_id,
                    ch,
                    now
                );
            }

            return zct_slms::common::ResultOf<AppSecretPair>::ok({appid, secret});
        }

        inline zct_slms::common::Result regenerateSecret(int64_t app_db_id) {
            const auto app = repo::AppRepo::findById(app_db_id);
            if (!app) return zct_slms::common::Result::fail(3001, "APP 不存在");
            const std::string secret = zct_slms::crypto::randomHex(32);
            repo::AppRepo::updateAppSecret(app_db_id, secret, std::time(nullptr));
            repo::AuditRepo::log(
                "OWNER",
                app->owner_id,
                "RegenerateAppSecret",
                "APP",
                app_db_id,
                app->appid,
                "success",
                "",
                "{}",
                std::time(nullptr)
            );
            return zct_slms::common::Result::ok();
        }

        inline bool verifyAppSecret(const int64_t app_db_id, const std::string_view secret_try) {
            const auto app = repo::AppRepo::findById(app_db_id);
            if (!app) return false;
            return secret_try == app->secret;
        }
    }
}

#endif // ZCT_SLMS_SERVICES_AUTH_APP_SERVICE
