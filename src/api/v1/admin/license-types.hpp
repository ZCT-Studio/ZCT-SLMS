// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once
#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::license_types {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr &)>&& cb) {
        const auto session = zct_slms::service::AuthService::authenticateSession(zct_slms::inside::api::v1::common::authBearer(req));
        if (!session.success || session.user_type != "ADMIN") {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要管理员登录")));
            return;
        }
        const auto raw = zct_slms::inside::api::v1::common::paramStr(req, "types");
        if (raw.size() > 4096) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "类型列表过长")));
            return;
        }
        zct_slms::repo::ConfigRepo::set("license_types", raw, std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}
