// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_AUTH_BOOTSTRAP_ADMIN
#define ZCT_SLMS_API_V1_AUTH_BOOTSTRAP_ADMIN

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::auth::bootstrap_admin {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto existing = zct_slms::db::Database::instance().queryScalar("SELECT COUNT(*) FROM admins");
        if (existing && *existing != "0") {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(1001, "已存在管理员")
                )
            );
            return;
        }
        const auto username = zct_slms::inside::api::v1::common::paramStr(req, "username");
        const auto password = zct_slms::inside::api::v1::common::paramStr(req, "password");
        const auto display = zct_slms::inside::api::v1::common::paramStr(req, "display_name", "");
        if (username.empty() || password.size() < 4) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "参数不合法")
                )
            );
            return;
        }
        const auto [hash, salt] = zct_slms::service::hashPassword(password);
        const auto admin_id = zct_slms::repo::AdminRepo::insert(username, hash, salt, display, std::time(nullptr));
        zct_slms::repo::ConfigRepo::set("admin_initial_setup_done:" + std::to_string(admin_id), "0", std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}

#endif // ZCT_SLMS_API_V1_AUTH_BOOTSTRAP_ADMIN
