// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_SERVICES_SUBUSER_UPDATE_SERVICE
#define ZCT_SLMS_SERVICES_SUBUSER_UPDATE_SERVICE

#include "common/types.hpp"
#include <string>
#include <ctime>
#include <vector>
#include <json/json.h>
#include <format>

namespace zct_slms::service {
    namespace SubUserService {
        inline zct_slms::common::ResultOf<int64_t> create(
            int64_t parent_id,
            const std::string& username,
            const std::string& password,
            const std::string& display,
            int64_t quota_limit,
            int64_t expires_at
        ) {
            const auto existing = db::Database::instance().queryParams(
                "SELECT id FROM sub_users WHERE username = ?",
                username
            );
            if (!existing.empty()) return zct_slms::common::ResultOf<int64_t>::fail(1001, "用户名已存在");

            auto [hash, salt] = hashPassword(password);
            int64_t now = std::time(nullptr);
            db::Database::instance().execParams(
                "INSERT INTO sub_users(parent_id, username, password_hash, salt, display_name, "
                "quota_limit, quota_used, expires_at, status, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, 0, ?, 1, ?, ?)",
                parent_id,
                username,
                hash,
                salt,
                display,
                quota_limit,
                expires_at,
                now,
                now
            );
            int64_t id = db::Database::instance().lastInsertId();

            repo::AuditRepo::log(
                "OWNER",
                parent_id,
                "CreateSubUser",
                "SUBUSER",
                id,
                std::format("quota={}", quota_limit),
                "success",
                "",
                "{}",
                now
            );
            return zct_slms::common::ResultOf<int64_t>::ok(id);
        }

        inline zct_slms::common::Result setQuota(int64_t subuser_id, int64_t limit) {
            db::Database::instance().execParams(
                "UPDATE sub_users SET quota_limit = ?, updated_at = ? WHERE id = ?",
                limit,
                static_cast<int64_t>(std::time(nullptr)),
                subuser_id
            );
            return zct_slms::common::Result::ok();
        }

        inline zct_slms::common::Result setExpires(int64_t subuser_id, int64_t expires_at) {
            db::Database::instance().execParams(
                "UPDATE sub_users SET expires_at = ?, updated_at = ? WHERE id = ?",
                expires_at,
                static_cast<int64_t>(std::time(nullptr)),
                subuser_id
            );
            return zct_slms::common::Result::ok();
        }

        inline zct_slms::common::Result deleteSubUser(int64_t id) {
            db::Database::instance().execParams("DELETE FROM sub_users WHERE id = ?", id);
            return zct_slms::common::Result::ok();
        }

        inline zct_slms::common::Result assignApp(int64_t subuser_id, int64_t app_id) {
            db::Database::instance().execParams(
                "INSERT OR IGNORE INTO user_app_permissions(sub_user_id, app_id, created_at) VALUES (?,?,?)",
                subuser_id,
                app_id,
                static_cast<int64_t>(std::time(nullptr))
            );
            return zct_slms::common::Result::ok();
        }

        inline zct_slms::common::Result unassignApp(int64_t subuser_id, int64_t app_id) {
            db::Database::instance().execParams(
                "DELETE FROM user_app_permissions WHERE sub_user_id = ? AND app_id = ?",
                subuser_id,
                app_id
            );
            return zct_slms::common::Result::ok();
        }

        inline std::vector<int64_t> listAssignedApps(int64_t subuser_id) {
            const auto rows = db::Database::instance().queryParams(
                "SELECT app_id FROM user_app_permissions WHERE sub_user_id = ?",
                subuser_id
            );
            std::vector<int64_t> out;
            for (auto& r : rows) out.push_back(repo::getInt(r, "app_id"));
            return out;
        }
    } // namespace SubUserService

    namespace UpdateService {
        inline zct_slms::common::ResultOf<int64_t> createChannel(
            int64_t app_id,
            const std::string& channel,
            const std::string& description
        ) {
            if (!repo::AppRepo::findById(app_id)) {
                return zct_slms::common::ResultOf<int64_t>::fail(3001, "APP 不存在");
            }
            db::Database::instance().execParams(
                "INSERT OR IGNORE INTO update_channels(app_id, channel, description, created_at)"
                " VALUES (?, ?, ?, ?)",
                app_id,
                channel,
                description,
                static_cast<int64_t>(std::time(nullptr))
            );
            const auto rows = db::Database::instance().queryParams(
                "SELECT id FROM update_channels WHERE app_id = ? AND channel = ?",
                app_id,
                channel
            );
            if (rows.empty()) return zct_slms::common::ResultOf<int64_t>::fail(1003, "创建频道失败");
            return zct_slms::common::ResultOf<int64_t>::ok(repo::getInt(rows[0], "id"));
        }

        inline zct_slms::common::ResultOf<int64_t> createVersion(
            int64_t channel_id,
            const std::string& version,
            const std::string& download_url,
            const std::string& file_hash,
            const std::string& hash_algo,
            const std::string& changelog,
            const std::string& minimum_version
        ) {
            int64_t now = std::time(nullptr);
            db::Database::instance().execParams(
                "INSERT INTO update_versions(channel_id, version, release_time, download_url, file_hash, "
                "hash_algorithm, changelog, minimum_version, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                channel_id,
                version,
                now,
                download_url,
                file_hash,
                hash_algo,
                changelog,
                minimum_version,
                now
            );
            return zct_slms::common::ResultOf<int64_t>::ok(db::Database::instance().lastInsertId());
        }

        inline std::vector<Json::Value> listChannels(const std::string& appid) {
            std::vector<Json::Value> out;
            auto app = repo::AppRepo::findByAppid(appid);
            if (!app) return out;
            auto rows = db::Database::instance().queryParams(
                "SELECT c.id, c.channel, c.description, "
                "(SELECT v.version FROM update_versions v WHERE v.channel_id = c.id ORDER BY v.release_time DESC LIMIT 1) AS latest_version "
                "FROM update_channels c WHERE c.app_id = ? ORDER BY c.id ASC",
                app->id
            );
            for (auto& r : rows) {
                Json::Value v;
                v["channel_id"] = static_cast<Json::Int64>(repo::getInt(r, "id"));
                v["channel"] = repo::getStr(r, "channel");
                v["description"] = repo::getStr(r, "description");
                std::string lv = repo::getStr(r, "latest_version");
                v["has_version"] = !lv.empty();
                if (!lv.empty()) v["latest_version"] = lv;
                out.push_back(std::move(v));
            }
            return out;
        }

        inline Json::Value getLatest(const std::string& appid, const std::string& channel = "release") {
            Json::Value out;
            out["found"] = false;
            auto app = repo::AppRepo::findByAppid(appid);
            if (!app) return out;
            auto rows = db::Database::instance().queryParams(
                "SELECT v.* FROM update_versions v "
                "JOIN update_channels c ON c.id = v.channel_id "
                "WHERE c.app_id = ? AND c.channel = ? "
                "ORDER BY v.release_time DESC LIMIT 1",
                app->id,
                channel
            );
            if (rows.empty()) return out;
            const auto& r = rows[0];
            out["found"] = true;
            out["version"] = repo::getStr(r, "version");
            out["download_url"] = repo::getStr(r, "download_url");
            out["file_hash"] = repo::getStr(r, "file_hash");
            out["hash_algorithm"] = repo::getStr(r, "hash_algorithm");
            out["changelog"] = repo::getStr(r, "changelog");
            out["minimum_version"] = repo::getStr(r, "minimum_version");
            out["release_time"] = static_cast<Json::Int64>(repo::getInt(r, "release_time"));
            return out;
        }
    }
}

#endif // ZCT_SLMS_SERVICES_SUBUSER_UPDATE_SERVICE
