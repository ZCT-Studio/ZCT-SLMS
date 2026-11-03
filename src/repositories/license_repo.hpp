// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_REPOSITORIES_LICENSE_REPO
#define ZCT_SLMS_REPOSITORIES_LICENSE_REPO

#include <cstdint>
#include <ctime>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "common/types.hpp"
#include "database/database.hpp"
#include "models/models.hpp"

namespace zct_slms::repo {
    namespace row_helper {
        inline std::string findCol(const zct_slms::db::Row& r, const std::string& name) {
            for (auto& [k, v] : r) if (k == name) return v;
            return {};
        }

        inline bool colIsNull(const zct_slms::db::Row& r, const std::string& name) {
            for (auto& [k, v] : r) if (k == name) return v.empty();
            return true;
        }
    } // namespace row_helper

    inline int64_t getInt(const zct_slms::db::Row& r, const std::string& col) {
        const auto v = row_helper::findCol(r, col);
        if (v.empty()) return 0;
        try { return std::stoll(v); } catch (...) { return 0; }
    }

    inline std::string getStr(const zct_slms::db::Row& r, const std::string& col) {
        return row_helper::findCol(r, col);
    }

    inline std::optional<int64_t> getOptInt(const zct_slms::db::Row& r, const std::string& col) {
        const auto v = row_helper::findCol(r, col);
        if (v.empty()) return std::nullopt;
        try { return std::stoll(v); } catch (...) { return std::nullopt; }
    }

    inline std::optional<std::string> getOptStr(const zct_slms::db::Row& r, const std::string& col) {
        auto v = row_helper::findCol(r, col);
        if (v.empty()) return std::nullopt;
        return v;
    }

    namespace LicenseRepo {
        inline zct_slms::models::License fromRow(const zct_slms::db::Row& r) {
            zct_slms::models::License l;
            l.id = getInt(r, "id");
            l.app_id = getInt(r, "app_id");
            l.license = getStr(r, "license");
            l.remark = getStr(r, "remark");
            l.created_at = getInt(r, "created_at");
            l.activated_at = getOptInt(r, "activated_at");
            l.expires_at = getInt(r, "expires_at");
            l.status = getStr(r, "status");
            l.banned = static_cast<int>(getInt(r, "banned"));
            l.binding_mode = getStr(r, "binding_mode");
            l.bound_ip_hash = getOptStr(r, "bound_ip_hash");
            l.bound_device_hash = getOptStr(r, "bound_device_hash");
            l.last_used_at = getOptInt(r, "last_used_at");
            l.last_used_ip = getOptStr(r, "last_used_ip");
            l.last_used_device_hash = getOptStr(r, "last_used_device_hash");
            l.unbind_count = static_cast<int>(getInt(r, "unbind_count"));
            l.unbind_limit = static_cast<int>(getInt(r, "unbind_limit"));
            l.unbind_time_cost = static_cast<int>(getInt(r, "unbind_time_cost"));
            l.unbind_count_cost = static_cast<int>(getInt(r, "unbind_count_cost"));
            l.max_devices = static_cast<int>(getInt(r, "max_devices"));
            l.max_ips = static_cast<int>(getInt(r, "max_ips"));
            l.created_by = getInt(r, "created_by");
            l.created_by_role = getStr(r, "created_by_role");
            l.updated_at = getInt(r, "updated_at");
            l.storage_mode = getStr(r, "storage_mode");
            l.license_type = getStr(r, "license_type");
            return l;
        }

        inline std::optional<zct_slms::models::License> findById(int64_t id) {
            const auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT * FROM licenses WHERE id = ?",
                id
            );
            if (rows.empty()) return std::nullopt;
            return fromRow(rows[0]);
        }


        // 优先用 id，否则用明文卡密查 id
        inline std::optional<int64_t> resolveLicenseId(
            int64_t license_id,
            const std::string& license_str,
            int64_t app_id = 0
        ) {
            if (license_id > 0) return license_id;
            if (license_str.empty()) return std::nullopt;

            const char* sql = app_id > 0
                ? "SELECT id FROM licenses WHERE app_id = ? AND license = ? AND status != 'deleted'"
                : "SELECT id FROM licenses WHERE license = ? AND status != 'deleted'";

            if (app_id > 0) {
                auto rows = zct_slms::db::Database::instance().queryParams(sql, app_id, license_str);
                if (!rows.empty()) return repo::getInt(rows[0], "id");
            } else {
                auto rows = zct_slms::db::Database::instance().queryParams(sql, license_str);
                if (!rows.empty()) return repo::getInt(rows[0], "id");
            }
            return std::nullopt;
        }
        inline std::optional<zct_slms::models::License> findByAppAndLicense(
            int64_t app_id,
            const std::string& license
        ) {
            const auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT * FROM licenses WHERE app_id = ? AND license = ? AND status != 'deleted'",
                app_id,
                license
            );
            if (rows.empty()) return std::nullopt;
            return fromRow(rows[0]);
        }

        inline int64_t insert(const zct_slms::models::License& l) {
            zct_slms::db::Database::instance().execParams(
                "INSERT INTO licenses("
                "app_id, license, remark, created_at, activated_at, expires_at, "
                "status, banned, binding_mode, bound_ip_hash, bound_device_hash, "
                "last_used_at, last_used_ip, last_used_device_hash, "
                "unbind_count, unbind_limit, unbind_time_cost, unbind_count_cost, "
                "max_devices, max_ips, created_by, created_by_role, updated_at, storage_mode, license_type"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                l.app_id,
                l.license,
                l.remark,
                l.created_at,
                l.activated_at,
                l.expires_at,
                l.status,
                l.banned,
                l.binding_mode,
                l.bound_ip_hash,
                l.bound_device_hash,
                l.last_used_at,
                l.last_used_ip,
                l.last_used_device_hash,
                l.unbind_count,
                l.unbind_limit,
                l.unbind_time_cost,
                l.unbind_count_cost,
                l.max_devices,
                l.max_ips,
                l.created_by,
                l.created_by_role,
                l.updated_at,
                l.storage_mode,
                l.license_type
            );
            return zct_slms::db::Database::instance().lastInsertId();
        }

        inline void updateField(int64_t id, const std::string& col, const std::string& value) {
            zct_slms::db::Database::instance().execParams(
                std::format("UPDATE licenses SET {} = ?, updated_at = ? WHERE id = ?", col),
                value,
                static_cast<int64_t>(std::time(nullptr)),
                id
            );
        }

        inline void updateFieldInt(int64_t id, const std::string& col, int64_t value) {
            zct_slms::db::Database::instance().execParams(
                std::format("UPDATE licenses SET {} = ?, updated_at = ? WHERE id = ?", col),
                value,
                static_cast<int64_t>(std::time(nullptr)),
                id
            );
        }

        inline void softDelete(int64_t id) {
            updateField(id, "status", "deleted");
        }

        inline void hardDelete(int64_t id) {
            zct_slms::db::Database::instance().execParams("DELETE FROM licenses WHERE id = ?", id);
        }

        inline void bindIp(int64_t id, const std::string& ip_hash, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE licenses SET bound_ip_hash = ?, status = 'active', "
                "activated_at = COALESCE(activated_at, ?), updated_at = ? WHERE id = ?",
                ip_hash,
                now,
                now,
                id
            );
        }

        inline void bindDevice(int64_t id, const std::string& dev_hash, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE licenses SET bound_device_hash = ?, status = 'active', "
                "activated_at = COALESCE(activated_at, ?), updated_at = ? WHERE id = ?",
                dev_hash,
                now,
                now,
                id
            );
        }

        inline void bindIpAndDevice(
            int64_t id,
            const std::string& ip_hash,
            const std::string& dev_hash,
            int64_t now
        ) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE licenses SET bound_ip_hash = ?, bound_device_hash = ?, "
                "status = 'active', activated_at = COALESCE(activated_at, ?), updated_at = ? WHERE id = ?",
                ip_hash,
                dev_hash,
                now,
                now,
                id
            );
        }

        inline void clearBinding(int64_t id, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE licenses SET bound_ip_hash = NULL, bound_device_hash = NULL, "
                "updated_at = ? WHERE id = ?",
                now,
                id
            );
        }

        inline void incrUnbindCount(int64_t id, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE licenses SET unbind_count = unbind_count + 1, updated_at = ? WHERE id = ?",
                now,
                id
            );
        }

        inline void touchLastUsed(
            int64_t id,
            const std::string& ip,
            const std::optional<std::string>& dev_hash,
            int64_t now
        ) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE licenses SET last_used_at = ?, last_used_ip = ?, last_used_device_hash = ?, "
                "updated_at = ? WHERE id = ?",
                now,
                ip,
                dev_hash,
                now,
                id
            );
        }

        inline std::vector<zct_slms::models::License> listByApp(int64_t app_id, int limit = 200) {
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT * FROM licenses WHERE app_id = ? AND status != 'deleted' ORDER BY id DESC LIMIT ?",
                app_id,
                limit
            );
            std::vector<zct_slms::models::License> out;
            out.reserve(rows.size());
            for (auto& r : rows) out.push_back(fromRow(r));
            return out;
        }

        inline std::vector<zct_slms::models::License> listByAppAndCreator(
            int64_t app_id,
            int64_t created_by,
            const std::string& created_by_role,
            int limit = 200
        ) {
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT * FROM licenses WHERE app_id = ? AND created_by = ? AND created_by_role = ? "
                "AND status != 'deleted' ORDER BY id DESC LIMIT ?",
                app_id,
                created_by,
                created_by_role,
                limit
            );
            std::vector<zct_slms::models::License> out;
            out.reserve(rows.size());
            for (auto& r : rows) out.push_back(fromRow(r));
            return out;
        }
    } // namespace LicenseRepo

    namespace SessionRepo {
        inline std::optional<zct_slms::models::Session> findByTokenHash(const std::string& hash) {
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT * FROM sessions WHERE token_hash = ? AND revoked = 0 AND expires_at > strftime('%s','now')",
                hash
            );
            if (rows.empty()) return std::nullopt;
            const auto& r = rows[0];
            zct_slms::models::Session s;
            s.id = getInt(r, "id");
            s.user_type = getStr(r, "user_type");
            s.user_id = getInt(r, "user_id");
            s.token_hash = getStr(r, "token_hash");
            s.expires_at = getInt(r, "expires_at");
            s.revoked = static_cast<int>(getInt(r, "revoked"));
            s.created_at = getInt(r, "created_at");
            s.created_ip = getStr(r, "created_ip");
            s.user_agent = getStr(r, "user_agent");
            return s;
        }

        inline int64_t insert(
            const std::string& user_type,
            int64_t user_id,
            const std::string& token_hash,
            int64_t expires_at,
            int64_t now,
            const std::string& ip,
            const std::string& ua
        ) {
            zct_slms::db::Database::instance().execParams(
                "INSERT INTO sessions(user_type, user_id, token_hash, expires_at, revoked, created_at, created_ip, user_agent)"
                " VALUES (?, ?, ?, ?, 0, ?, ?, ?)",
                user_type,
                user_id,
                token_hash,
                expires_at,
                now,
                ip,
                ua
            );
            return zct_slms::db::Database::instance().lastInsertId();
        }

        inline void revoke(int64_t session_id, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE sessions SET revoked = 1 WHERE id = ?",
                session_id
            );
        }

        inline void revokeByHash(const std::string& hash) {
            zct_slms::db::Database::instance().execParams(
                "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
                hash
            );
        }
    } // namespace SessionRepo

    namespace ConfigRepo {
        inline std::string get(const std::string& key, const std::string& def = "") {
            auto v = zct_slms::db::Database::instance().queryScalar(
                "SELECT value FROM system_config WHERE key = ?",
                key
            );
            return v.value_or(def);
        }

        inline int64_t getI64(const std::string& key, int64_t def = 0) {
            auto v = get(key);
            try { return v.empty() ? def : std::stoll(v); } catch (...) { return def; }
        }

        inline bool getBool(const std::string& key, bool def = false) {
            auto v = get(key);
            if (v.empty()) return def;
            return v == "1" || v == "true";
        }

        inline void set(const std::string& key, const std::string& value, int64_t now) {
            zct_slms::db::Database::instance().execParams(
                "INSERT INTO system_config(key, value, description, updated_at) VALUES (?, ?, '', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                key,
                value,
                now
            );
        }
    } // namespace ConfigRepo

    namespace AuditRepo {
        inline void log(
            const std::string& actor_type,
            int64_t actor_id,
            const std::string& action,
            const std::string& target_type,
            std::optional<int64_t> target_id,
            const std::string& target_detail,
            const std::string& result,
            const std::string& ip,
            const std::string& extra,
            int64_t now
        ) {
            zct_slms::db::Database::instance().execParams(
                "INSERT INTO audit_logs(actor_type, actor_id, action, target_type, target_id, "
                "target_detail, result, ip, extra, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                actor_type,
                actor_id,
                action,
                target_type,
                target_id,
                target_detail,
                result,
                ip,
                extra,
                now
            );
        }

        inline std::vector<zct_slms::models::AuditLog> listRecent(int limit = 200) {
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                limit
            );
            std::vector<zct_slms::models::AuditLog> out;
            for (auto& r : rows) {
                zct_slms::models::AuditLog a;
                a.id = getInt(r, "id");
                a.actor_type = getStr(r, "actor_type");
                a.actor_id = getInt(r, "actor_id");
                a.action = getStr(r, "action");
                a.target_type = getStr(r, "target_type");
                a.target_id = getOptInt(r, "target_id");
                a.target_detail = getStr(r, "target_detail");
                a.result = getStr(r, "result");
                a.ip = getStr(r, "ip");
                a.extra = getStr(r, "extra");
                a.created_at = getInt(r, "created_at");
                out.push_back(std::move(a));
            }
            return out;
        }
    } // namespace AuditRepo

    namespace NonceRepo {
        inline bool tryUseNonce(int64_t app_id, const std::string& nonce, int64_t ts, int window_sec) {
            int64_t now = std::time(nullptr);
            bool inserted = false;
            try {
                inserted = zct_slms::db::Database::instance().transaction(
                    [&] {
                        const auto existing = zct_slms::db::Database::instance().queryScalar(
                            "SELECT timestamp FROM nonces WHERE app_id = ? AND nonce = ?",
                            app_id,
                            nonce
                        );
                        if (existing) return false;
                        zct_slms::db::Database::instance().execParams(
                            "INSERT INTO nonces(app_id, nonce, timestamp, used_at) VALUES (?,?,?,?)",
                            app_id,
                            nonce,
                            ts,
                            now
                        );
                        return true;
                    }
                );
            } catch (...) { return false; }
            zct_slms::db::Database::instance().execParams(
                "DELETE FROM nonces WHERE used_at < ?",
                now - window_sec * 10
            );
            return inserted;
        }
    } // namespace NonceRepo

    namespace GlobalTimer {
        inline bool isPaused() {
            return ConfigRepo::getBool("license_timer_paused", false);
        }

        inline int64_t pause(int64_t now) {
            int64_t paused_at = ConfigRepo::getI64("license_timer_paused_at", 0);
            int64_t offset = ConfigRepo::getI64("license_timer_offset", 0);
            if (paused_at > 0) {
                offset += now - paused_at;
            }
            ConfigRepo::set("license_timer_paused", "1", now);
            ConfigRepo::set("license_timer_paused_at", std::to_string(now), now);
            ConfigRepo::set("license_timer_offset", std::to_string(offset), now);
            return offset;
        }

        inline int64_t resume(int64_t now) {
            int64_t paused_at = ConfigRepo::getI64("license_timer_paused_at", 0);
            int64_t offset = ConfigRepo::getI64("license_timer_offset", 0);
            if (paused_at > 0) {
                offset += now - paused_at;
            }
            ConfigRepo::set("license_timer_paused", "0", now);
            ConfigRepo::set("license_timer_paused_at", "0", now);
            ConfigRepo::set("license_timer_offset", std::to_string(offset), now);
            return offset;
        }

        inline int64_t effectiveNow(const int64_t now) {
            if (!isPaused()) return now;
            const int64_t paused_at = ConfigRepo::getI64("license_timer_paused_at", 0);
            const int64_t offset = ConfigRepo::getI64("license_timer_offset", 0);
            const int64_t virtual_now = now - offset - (now - paused_at);
            return paused_at > 0 ? virtual_now : (now - offset);
        }
    }
}

#endif // ZCT_SLMS_REPOSITORIES_LICENSE_REPO
