// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"
#include "services/oauth_profile.hpp"

namespace zct_slms::inside::api::v1::admin::account {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
        namespace c = zct_slms::inside::api::v1::common;
        const auto id = c::currentUserId(req);
        const auto old = c::paramStr(req, "current_password");
        const auto username = c::paramStr(req, "new_username");
        const auto password = c::paramStr(req, "new_password");
        const auto display_name = c::paramStr(req, "display_name");
        const auto avatar = c::paramStr(req, "avatar");
        if (!zct_slms::identity::profileAvatarAllowed(avatar, zct_slms::repo::ConfigRepo::get("profile:ADMIN:" + std::to_string(id) + ":avatar", ""))) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "Invalid avatar")));
            return;
        }
        auto fail = [&](int code, const std::string& message) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, message))); };
        const auto admin = zct_slms::repo::AdminRepo::findById(id);
        const bool initial_setup = !zct_slms::repo::ConfigRepo::getBool("admin_initial_setup_done:" + std::to_string(id), true);
        if (initial_setup && (username.empty() || username == admin->username || password.empty() || display_name.empty())) {
            fail(zct_slms::api::ErrorCode::VALIDATION, "首次登录必须设置用户名、密码和昵称");
            return;
        }
        if (!admin || !c::sensitiveAuthorization(req, old)) {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "Current password is incorrect");
            return;
        }
        if (username.empty() && password.empty()) {
            fail(zct_slms::api::ErrorCode::VALIDATION, "Provide new_username or new_password");
            return;
        }
        if ((!username.empty() && (username.size() < 3 || username.size() > 64 || username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") !=
                                   std::string::npos)) || (!password.empty() && (password.size() < 12 || password.size() > 256))) {
            fail(zct_slms::api::ErrorCode::VALIDATION, "Username must be 3-64 ASCII letters, digits, _, . or -; password must be 12-256 bytes");
            return;
        }
        if (!username.empty()) {
            auto existing = zct_slms::repo::AdminRepo::findByUsername(username);
            if (existing && existing->id != id) {
                fail(zct_slms::api::ErrorCode::VALIDATION, "Username already exists");
                return;
            }
        }
        auto hash = admin->password_hash, salt = admin->salt;
        if (!password.empty()) {
            auto hp = zct_slms::service::hashPassword(password);
            if (hp.hash.empty()) {
                fail(zct_slms::api::ErrorCode::INTERNAL, "Password hashing failed");
                return;
            }
            hash = hp.hash;
            salt = hp.salt;
        }
        auto& db = zct_slms::db::Database::instance();
        const bool ok = db.transaction(
            [&] {
                db.execParams(
                    "UPDATE admins SET username = ?, display_name = ?, password_hash = ?, salt = ?, updated_at = ? WHERE id = ?",
                    username.empty() ? admin->username : username,
                    display_name.empty() ? admin->display_name : display_name,
                    hash,
                    salt,
                    static_cast<int64_t>(std::time(nullptr)),
                    id
                );
                zct_slms::repo::ConfigRepo::set("admin_initial_setup_done:" + std::to_string(id), "1", std::time(nullptr));
                if (!display_name.empty()) zct_slms::repo::ConfigRepo::set("profile:ADMIN:" + std::to_string(id) + ":nickname", display_name, std::time(nullptr));
                zct_slms::repo::ConfigRepo::set("profile:ADMIN:" + std::to_string(id) + ":avatar", zct_slms::identity::persistAvatar(avatar), std::time(nullptr));
                db.execParams("UPDATE sessions SET revoked = 1 WHERE user_type = ? AND user_id = ?", "ADMIN", id);
                return true;
            }
        );
        if (!ok) {
            fail(zct_slms::api::ErrorCode::INTERNAL, "Account update failed");
            return;
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}
