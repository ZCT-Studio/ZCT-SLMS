// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#ifndef ZCT_SLMS_REPOSITORIES_USER_APP_REPO
#define ZCT_SLMS_REPOSITORIES_USER_APP_REPO

#include <utility>
#include <functional>
#include <optional>
#include <string>
#include <ctime>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "common/types.hpp"
#include "database/database.hpp"
#include "models/models.hpp"
#include "repositories/license_repo.hpp"  // 提供 getInt/getStr/getOptInt/getOptStr

namespace zct_slms::repo {
    inline std::function<void(const std::string &)> validatePublicText = [](const std::string&) {};

    namespace AdminRepo {
        inline std::optional<zct_slms::models::Admin> findByUsername(const std::string& u) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM admins WHERE username = ?",

                u

            );

            if (rows.empty()) return std::nullopt;

            auto r = rows[0];

            zct_slms::models::Admin a;

            a.id = getInt(r, "id");

            a.username = getStr(r, "username");

            a.password_hash = getStr(r, "password_hash");

            a.salt = getStr(r, "salt");

            a.display_name = getStr(r, "display_name");

            a.created_at = getInt(r, "created_at");

            a.updated_at = getInt(r, "updated_at");

            a.last_login_at = getOptInt(r, "last_login_at");

            a.status = static_cast<int>(getInt(r, "status"));

            return a;
        }


        inline std::optional<zct_slms::models::Admin> findById(int64_t id) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM admins WHERE id = ?",

                id

            );

            if (rows.empty()) return std::nullopt;

            auto r = rows[0];

            zct_slms::models::Admin a;

            a.id = getInt(r, "id");

            a.username = getStr(r, "username");

            a.password_hash = getStr(r, "password_hash");

            a.salt = getStr(r, "salt");

            a.display_name = getStr(r, "display_name");

            a.created_at = getInt(r, "created_at");

            a.updated_at = getInt(r, "updated_at");

            a.last_login_at = getOptInt(r, "last_login_at");

            a.status = static_cast<int>(getInt(r, "status"));

            return a;
        }


        inline int64_t insert(

            const std::string& username,

            const std::string& pw_hash,

            const std::string& salt,

            const std::string& display,

            int64_t now

        ) {
            zct_slms::db::Database::instance().execParams(

                "INSERT INTO admins(username, password_hash, salt, display_name, created_at, updated_at, status)"

                " VALUES (?, ?, ?, ?, ?, ?, 1)",

                username,

                pw_hash,

                salt,

                display,

                now,

                now

            );

            return zct_slms::db::Database::instance().lastInsertId();
        }


        inline void updateLastLogin(int64_t id, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE admins SET last_login_at = ? WHERE id = ?",

                now,

                id

            );
        }
    } // namespace AdminRepo


    // ============================================================

    // UserRepository

    // ============================================================

    namespace UserRepo {
        inline std::optional<zct_slms::models::User> findByUsername(const std::string& u) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM users WHERE username = ?",

                u

            );

            if (rows.empty()) return std::nullopt;

            auto r = rows[0];

            zct_slms::models::User user;

            user.id = getInt(r, "id");

            user.username = getStr(r, "username");

            user.password_hash = getStr(r, "password_hash");

            user.salt = getStr(r, "salt");

            user.display_name = getStr(r, "display_name");

            user.balance = getInt(r, "balance");

            user.expires_at = getInt(r, "expires_at");

            user.status = static_cast<int>(getInt(r, "status"));

            user.created_by = getOptInt(r, "created_by");

            user.created_at = getInt(r, "created_at");

            user.updated_at = getInt(r, "updated_at");

            return user;
        }


        inline std::optional<zct_slms::models::User> findById(int64_t id) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM users WHERE id = ?",

                id

            );

            if (rows.empty()) return std::nullopt;

            auto r = rows[0];

            zct_slms::models::User user;

            user.id = getInt(r, "id");

            user.username = getStr(r, "username");

            user.password_hash = getStr(r, "password_hash");

            user.salt = getStr(r, "salt");

            user.display_name = getStr(r, "display_name");

            user.balance = getInt(r, "balance");

            user.expires_at = getInt(r, "expires_at");

            user.status = static_cast<int>(getInt(r, "status"));

            user.created_by = getOptInt(r, "created_by");

            user.created_at = getInt(r, "created_at");

            user.updated_at = getInt(r, "updated_at");

            return user;
        }


        inline int64_t insert(

            const std::string& username,

            const std::string& pw_hash,

            const std::string& salt,

            const std::string& display,

            int64_t now,

            int64_t created_by = 0

        ) {
            validatePublicText(username);
            validatePublicText(display);
            zct_slms::db::Database::instance().execParams(

                "INSERT INTO users(username, password_hash, salt, display_name, balance, expires_at, status, created_by, created_at, updated_at)"

                " VALUES (?, ?, ?, ?, 0, -1, 1, NULLIF(?,0), ?, ?)",

                username,

                pw_hash,

                salt,

                display,

                created_by == 0 ? std::nullopt : std::optional<int64_t>(created_by),

                now,

                now

            );

            return zct_slms::db::Database::instance().lastInsertId();
        }


        inline void addBalance(int64_t id, int64_t delta, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE users SET balance = balance + ?, updated_at = ? WHERE id = ?",

                delta,

                now,

                id

            );
        }


        inline void setBalance(int64_t id, int64_t value, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE users SET balance = ?, updated_at = ? WHERE id = ?",

                value,

                now,

                id

            );
        }


        inline void setExpires(int64_t id, int64_t expires_at, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE users SET expires_at = ?, updated_at = ? WHERE id = ?",

                expires_at,

                now,

                id

            );
        }


        inline int64_t atomicConsumeBalance(int64_t id, int64_t amount) {
            // 注意：调用者必须已在 transaction 中（避免 SQLite 嵌套 BEGIN）

            auto cur = zct_slms::db::Database::instance().queryScalar(

                "SELECT balance FROM users WHERE id = ?",

                id

            );

            if (!cur) return -1;

            int64_t b = 0;

            try { b = std::stoll(*cur); } catch (...) { return -1; }

            if (b != -1 && b < amount) return -1;

            int64_t new_balance = (b == -1) ? -1 : (b - amount);

            int64_t now = std::time(nullptr);

            zct_slms::db::Database::instance().execParams(

                "UPDATE users SET balance = ?, updated_at = ? WHERE id = ?",

                new_balance,

                now,

                id

            );

            return new_balance;
        }
    } // namespace UserRepo


    // ============================================================

    // AppRepository

    // ============================================================

    namespace AppRepo {
        inline std::optional<zct_slms::models::App> findByAppid(const std::string& appid) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM apps WHERE appid = ?",

                appid

            );

            if (rows.empty()) return std::nullopt;

            auto r = rows[0];

            zct_slms::models::App a;

            a.id = getInt(r, "id");

            a.owner_id = getInt(r, "owner_id");

            a.appid = getStr(r, "appid");

            a.name = getStr(r, "name");

            a.description = getStr(r, "description");


            a.secret = getStr(r, "secret");

            a.dec_mode = getStr(r, "dec_mode");

            a.dec_key = getStr(r, "dec_key");

            a.sign_enable = static_cast<int>(getInt(r, "sign_enable"));

            a.binding_mode = getStr(r, "binding_mode");

            a.notice = getStr(r, "notice");

            a.status = static_cast<int>(getInt(r, "status"));

            a.created_at = getInt(r, "created_at");

            a.updated_at = getInt(r, "updated_at");

            return a;
        }


        inline std::optional<zct_slms::models::App> findById(int64_t id) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM apps WHERE id = ?",

                id

            );

            if (rows.empty()) return std::nullopt;

            auto r = rows[0];

            zct_slms::models::App a;

            a.id = getInt(r, "id");

            a.owner_id = getInt(r, "owner_id");

            a.appid = getStr(r, "appid");

            a.name = getStr(r, "name");

            a.description = getStr(r, "description");


            a.secret = getStr(r, "secret");

            a.dec_mode = getStr(r, "dec_mode");

            a.dec_key = getStr(r, "dec_key");

            a.sign_enable = static_cast<int>(getInt(r, "sign_enable"));

            a.binding_mode = getStr(r, "binding_mode");

            a.notice = getStr(r, "notice");

            a.status = static_cast<int>(getInt(r, "status"));

            a.created_at = getInt(r, "created_at");

            a.updated_at = getInt(r, "updated_at");

            return a;
        }


        inline int64_t insert(

            int64_t owner_id,

            const std::string& appid,

            const std::string& name,

            const std::string& desc,

            const std::string& secret,

            int64_t now,

            const std::string& binding_mode = "NONE"

        ) {
            zct_slms::db::Database::instance().execParams(

                "INSERT INTO apps(owner_id, appid, name, description, secret, binding_mode, status, created_at, updated_at)"

                " VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",

                owner_id,

                appid,

                name,

                desc,

                secret,

                binding_mode,

                now,

                now

            );

            return zct_slms::db::Database::instance().lastInsertId();
        }


        inline void updateAppSecret(int64_t id, const std::string& new_secret, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE apps SET secret = ?, updated_at = ? WHERE id = ?",

                new_secret,

                now,

                id

            );
        }


        inline void updateBindingMode(int64_t id, const std::string& mode, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE apps SET binding_mode = ?, updated_at = ? WHERE id = ?",

                mode,

                now,

                id

            );
        }


        inline void updateDecodeMode(int64_t id, const std::string& mode, const std::string& key, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE apps SET dec_mode = ?, dec_key = ?, updated_at = ? WHERE id = ?",
                mode,
                key,
                now,
                id
            );
        }

        inline void updateSignEnable(int64_t id, int enable, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE apps SET sign_enable = ?, updated_at = ? WHERE id = ?",
                enable,
                now,
                id
            );
        }

        inline void updateNotice(int64_t id, const std::string& notice, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE apps SET notice = ?, updated_at = ? WHERE id = ?",
                notice,
                now,
                id
            );
        }


        inline void setStatus(int64_t id, int status, int64_t now) {
            zct_slms::db::Database::instance().execParams(

                "UPDATE apps SET status = ?, updated_at = ? WHERE id = ?",

                status,

                now,

                id

            );
        }


        inline std::vector<zct_slms::models::App> listByOwner(int64_t owner_id) {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM apps WHERE owner_id = ? ORDER BY id DESC",

                owner_id

            );

            std::vector<zct_slms::models::App> out;

            for (auto& r : rows) {
                zct_slms::models::App a;

                a.id = getInt(r, "id");

                a.owner_id = getInt(r, "owner_id");

                a.appid = getStr(r, "appid");

                a.name = getStr(r, "name");

                a.description = getStr(r, "description");


                a.secret = getStr(r, "secret");

                a.dec_mode = getStr(r, "dec_mode");

                a.dec_key = getStr(r, "dec_key");

                a.sign_enable = static_cast<int>(getInt(r, "sign_enable"));

                a.binding_mode = getStr(r, "binding_mode");

                a.notice = getStr(r, "notice");

                a.status = static_cast<int>(getInt(r, "status"));

                a.created_at = getInt(r, "created_at");

                a.updated_at = getInt(r, "updated_at");

                out.push_back(std::move(a));
            }

            return out;
        }


        inline void removeById(int64_t id) {
            zct_slms::db::Database::instance().execParams("DELETE FROM apps WHERE id = ?", id);
        }


        inline std::vector<zct_slms::models::App> listAll() {
            auto rows = zct_slms::db::Database::instance().queryParams(

                "SELECT * FROM apps ORDER BY id DESC"

            );

            std::vector<zct_slms::models::App> out;

            for (auto& r : rows) {
                zct_slms::models::App a;

                a.id = getInt(r, "id");

                a.owner_id = getInt(r, "owner_id");

                a.appid = getStr(r, "appid");

                a.name = getStr(r, "name");

                a.description = getStr(r, "description");

                a.secret = getStr(r, "secret");

                a.dec_mode = getStr(r, "dec_mode");

                a.dec_key = getStr(r, "dec_key");

                a.sign_enable = static_cast<int>(getInt(r, "sign_enable"));

                a.binding_mode = getStr(r, "binding_mode");

                a.notice = getStr(r, "notice");

                a.status = static_cast<int>(getInt(r, "status"));

                a.created_at = getInt(r, "created_at");

                a.updated_at = getInt(r, "updated_at");

                out.push_back(std::move(a));
            }

            return out;
        }
    }}


#endif // ZCT_SLMS_REPOSITORIES_USER_APP_REPO
