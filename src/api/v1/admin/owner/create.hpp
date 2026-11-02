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

#ifndef ZCT_SLMS_API_V1_ADMIN_OWNER_CREATE
#define ZCT_SLMS_API_V1_ADMIN_OWNER_CREATE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::owner::create {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto username = zct_slms::inside::api::v1::common::paramStr(req, "username");
        const auto password = zct_slms::inside::api::v1::common::paramStr(req, "password");
        const auto display = zct_slms::inside::api::v1::common::paramStr(req, "display_name");
        const int64_t admin_id = zct_slms::inside::api::v1::common::paramI64(req, "_admin_id", 0);
        if (username.empty() || password.empty()) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "参数不完整")
                )
            );
            return;
        }
        try {
            auto hp = zct_slms::service::hashPassword(password);
            int64_t id = zct_slms::repo::UserRepo::insert(username, hp.hash, hp.salt, display, std::time(nullptr), admin_id);
            zct_slms::repo::AuditRepo::log(
                "ADMIN",
                admin_id,
                "CreateOwner",
                "USER",
                id,
                "",
                "success",
                zct_slms::inside::api::v1::common::clientIp(req),
                "{}",
                std::time(nullptr)
            );
            Json::Value v;
            v["user_id"] = id;
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
        } catch (const std::exception& e) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(1003, e.what())));
        }
    }
}

#endif // ZCT_SLMS_API_V1_ADMIN_OWNER_CREATE
