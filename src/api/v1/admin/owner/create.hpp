// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

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
