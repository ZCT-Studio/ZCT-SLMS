// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::auth::balance {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr &)>&& cb) {
        try {
            namespace c = zct_slms::inside::api::v1::common;
            auto a = zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
            if (!a.success || a.user_type == "SUPPORT")throw std::runtime_error("无权查看卡密余额");
            int64_t owner = a.user_id, remaining = -1;
            auto appId = c::paramStr(req, "app_id");
            auto& db = zct_slms::db::Database::instance();
            if (a.user_type == "SUBUSER") {
                auto rows = db.queryParams("SELECT parent_id,quota_limit,quota_used FROM sub_users WHERE id=?", a.user_id);
                if (rows.empty())throw std::runtime_error("子用户不存在");
                owner = zct_slms::repo::getInt(rows[0], "parent_id");
                auto limit = zct_slms::repo::getInt(rows[0], "quota_limit");
                remaining = limit == -1 ? -1 : std::max<int64_t>(0, limit - zct_slms::repo::getInt(rows[0], "quota_used"));
            }
            if (!appId.empty()) {
                auto app = zct_slms::repo::AppRepo::findByAppid(appId);
                if (!app)throw std::runtime_error("应用不存在");
                if (a.user_type == "ADMIN")owner = app->owner_id;
                else if (app->owner_id != owner)throw std::runtime_error("无权查看此应用余额");
                if (a.user_type == "SUBUSER" && db.queryParams("SELECT app_id FROM user_app_permissions WHERE sub_user_id=? AND app_id=?", a.user_id, app->id).empty())
                    throw
                        std::runtime_error("无权访问此应用");
            } else if (a.user_type == "ADMIN") {
                Json::Value out;
                out["available"] = Json::nullValue;
                out["cost_per_license"] = 1;
                cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(out)));
                return;
            }
            auto u = zct_slms::repo::UserRepo::findById(owner);
            if (!u)throw std::runtime_error("主用户不存在");
            auto available = u->balance;
            if (remaining != -1)available = available == -1 ? remaining : std::min(available, remaining);
            Json::Value out;
            out["available"] = Json::Int64(available);
            out["quota_remaining"] = Json::Int64(remaining);
            out["cost_per_license"] = 1;
            if (a.user_type == "ADMIN")out["owner_username"] = u->username;
            auto response = drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(out));
            response->addHeader("Cache-Control", "no-store");
            cb(response);
        } catch (const std::exception& e) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(1003, e.what()))); }
    }
}
