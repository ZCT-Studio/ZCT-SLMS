// Copyright 2026 ZCT-Studio
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
