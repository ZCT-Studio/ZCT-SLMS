// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::subusers {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
        namespace c = zct_slms::inside::api::v1::common;
        const auto type = c::currentUserType(req);
        const auto uid = c::currentUserId(req);
        auto fail = [&](int code, const char* m) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, m))); };
        if (type != "USER") {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "仅应用所有者可管理子用户");
            return;
        }
        if (req->method() == drogon::Post) {
            if (!zct_slms::repo::ConfigRepo::getBool("owner_can_create_subuser", false)) {
                fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "管理员尚未允许创建子用户");
                return;
            }
            auto username = c::paramStr(req, "username"), password = c::paramStr(req, "password"), display = c::paramStr(req, "display_name");
            auto quota = c::paramI64(req, "quota_limit", 0);
            if (username.size() < 3 || username.size() > 64 || username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos
                || password.size() < 12 || password.size() > 256 || quota < -1) {
                fail(zct_slms::api::ErrorCode::VALIDATION, "用户名须为 3–64 位字母数字或 _ . -，密码须为 12–256 字节，额度不得小于 -1");
                return;
            }
            auto result = zct_slms::service::SubUserService::create(uid, username, password, display, quota, -1);
            if (!result.success) {
                fail(result.code, result.message.c_str());
                return;
            }
        }
        auto rows = zct_slms::db::Database::instance().queryParams(
            "SELECT id, username, display_name, quota_limit, quota_used, status FROM sub_users WHERE parent_id = ? ORDER BY id DESC",
            uid
        );
        Json::Value list(Json::arrayValue);
        for (auto& row : rows) {
            Json::Value v;
            const auto sub_id = zct_slms::repo::getInt(row, "id");
            v["id"] = static_cast<Json::Int64>(sub_id);
            v["username"] = zct_slms::repo::getStr(row, "username");
            v["display_name"] = zct_slms::repo::getStr(row, "display_name");
            v["quota_limit"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "quota_limit"));
            v["quota_used"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "quota_used"));
            v["status"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "status"));
            Json::Value assigned(Json::arrayValue);
            auto permissions = zct_slms::db::Database::instance().queryParams(
                "SELECT a.appid FROM user_app_permissions p JOIN apps a ON a.id = p.app_id WHERE p.sub_user_id = ? ORDER BY a.id",
                sub_id
            );
            for (const auto& permission : permissions)assigned.append(zct_slms::repo::getStr(permission, "appid"));
            v["assigned_apps"] = assigned;
            list.append(v);
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(list)));
    }
}

namespace zct_slms::inside::api::v1::app::subuser_access {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
        namespace c = zct_slms::inside::api::v1::common;
        auto auth = zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
        auto fail = [&](int code, const char* m) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, m))); };
        if (!auth.success || auth.user_type != "USER") {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要应用所有者登录");
            return;
        }
        auto sub_id = c::paramI64(req, "subuser_id");
        auto app = zct_slms::repo::AppRepo::findByAppid(c::paramStr(req, "app_id"));
        auto action = c::paramStr(req, "action");
        auto rows = zct_slms::db::Database::instance().queryParams("SELECT id FROM sub_users WHERE id = ? AND parent_id = ?", sub_id, auth.user_id);
        if (rows.empty() || !app || app->owner_id != auth.user_id) {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权操作此子用户或应用");
            return;
        }
        if (action == "assign")zct_slms::service::SubUserService::assignApp(sub_id, app->id);
        else if (action == "unassign")zct_slms::service::SubUserService::unassignApp(sub_id, app->id);
        else {
            fail(zct_slms::api::ErrorCode::VALIDATION, "无效操作");
            return;
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}

namespace zct_slms::inside::api::v1::admin::subuser_policy {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
        const auto session = zct_slms::service::AuthService::authenticateSession(zct_slms::inside::api::v1::common::authBearer(req));
        if (!session.success || session.user_type != "ADMIN") {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要管理员登录")));
            return;
        }
        const auto flag = zct_slms::inside::api::v1::common::paramStr(req, "enabled");
        if (flag != "0" && flag != "1") {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "enabled 必须为 0 或 1")));
            return;
        }
        zct_slms::repo::ConfigRepo::set("owner_can_create_subuser", flag, std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}
