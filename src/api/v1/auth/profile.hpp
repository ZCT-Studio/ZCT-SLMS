// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"
#include "services/oauth_profile.hpp"

namespace zct_slms::inside::api::v1::auth::profile {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr &)>&& cb) {
        namespace c = zct_slms::inside::api::v1::common;
        const auto auth = zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
        auto fail = [&](int code, const char* m) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, m))); };
        if (!auth.success || (auth.user_type != "ADMIN" && auth.user_type != "SUPPORT" && auth.user_type != "USER" && auth.user_type != "SUBUSER")) {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "未登录或登录已过期");
            return;
        }
        const auto prefix = std::string("profile:") + auth.user_type + ":" + std::to_string(auth.user_id) + ":";
        if (req->method() == drogon::Post) {
            const auto name = c::paramStr(req, "nickname");
            const auto avatar = c::paramStr(req, "avatar");
            if (name.empty() || name.size() > 96) {
                fail(zct_slms::api::ErrorCode::VALIDATION, "昵称不能为空或过长");
                return;
            }
            if (!zct_slms::identity::profileAvatarAllowed(avatar, zct_slms::repo::ConfigRepo::get(prefix + "avatar", ""))) {
                fail(zct_slms::api::ErrorCode::VALIDATION, "头像超过大小限制或格式不支持");
                return;
            }
            const auto now = std::time(nullptr);
            zct_slms::repo::ConfigRepo::set(prefix + "nickname", name, now);
            zct_slms::repo::ConfigRepo::set(prefix + "avatar", zct_slms::identity::persistAvatar(avatar), now);
            c::reviewContentChanged("USER", auth.user_type, auth.user_id);
        }
        std::string default_name = auth.username;
        if (auth.user_type == "USER") {
            auto user = zct_slms::repo::UserRepo::findById(auth.user_id);
            if (user && !user->display_name.empty())default_name = user->display_name;
        } else if (auth.user_type == "ADMIN" || auth.user_type == "SUPPORT") {
            auto user = zct_slms::repo::AdminRepo::findById(auth.user_id);
            if (user && !user->display_name.empty())default_name = user->display_name;
        } else {
            auto rows = zct_slms::db::Database::instance().queryParams("SELECT display_name FROM sub_users WHERE id = ?", auth.user_id);
            if (!rows.empty() && !zct_slms::repo::getStr(rows[0], "display_name").empty())default_name = zct_slms::repo::getStr(rows[0], "display_name");
        }
        Json::Value v;
        v["nickname"] = zct_slms::repo::ConfigRepo::get(prefix + "nickname", default_name);
        auto currentAvatar = zct_slms::repo::ConfigRepo::get(prefix + "avatar", "");
        if (zct_slms::identity::safeAvatarUrl(currentAvatar)) {
            try {
                auto cached = zct_slms::identity::persistAvatar(currentAvatar);
                if (cached != currentAvatar) {
                    zct_slms::db::Database::instance().execParams("UPDATE system_config SET value=? WHERE key=? AND value=?", cached, prefix + "avatar", currentAvatar);
                    currentAvatar = zct_slms::repo::ConfigRepo::get(prefix + "avatar", "");
                }
            } catch (const std::exception&) { /* Keep the original when storage is unavailable. */ }
        }
        v["avatar"] = currentAvatar;
        v["user_id"] = static_cast<Json::Int64>(auth.user_id);
        v["username"] = auth.username;
        v["user_type"] = auth.user_type;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}
