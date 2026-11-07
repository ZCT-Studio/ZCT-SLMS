// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::owner::list {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
        const auto auth = zct_slms::service::AuthService::authenticateSession(zct_slms::inside::api::v1::common::authBearer(req));
        if (!auth.success || auth.user_type != "ADMIN") {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要管理员登录")));
            return;
        }
        auto rows = zct_slms::db::Database::instance().queryParams("SELECT id, username, display_name, balance, expires_at, status, created_at FROM users ORDER BY id DESC");
        Json::Value result(Json::arrayValue);
        for (const auto& row : rows) {
            Json::Value user;
            user["id"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "id"));
            user["username"] = zct_slms::repo::getStr(row, "username");
            user["display_name"] = zct_slms::repo::getStr(row, "display_name");
            user["balance"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "balance"));
            user["expires_at"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "expires_at"));
            user["status"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "status"));
            user["created_at"] = static_cast<Json::Int64>(zct_slms::repo::getInt(row, "created_at"));
            result.append(user);
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(result)));
    }
}
