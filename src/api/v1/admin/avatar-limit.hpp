// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#ifndef ZCT_SLMS_API_V1_ADMIN_AVATAR_LIMIT
#define ZCT_SLMS_API_V1_ADMIN_AVATAR_LIMIT
#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::avatar_limit {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr &)>&& cb) {
        namespace c = zct_slms::inside::api::v1::common;
        const auto auth = zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
        auto fail = [&](int code, const char* msg) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, msg))); };
        if (!auth.success || auth.user_type != "ADMIN") {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要管理员登录");
            return;
        }
        const auto bytes = c::paramI64(req, "max_avatar_bytes", 1048576);
        if (bytes < 102400 || bytes > 1048576 || bytes % 1024 != 0) {
            fail(zct_slms::api::ErrorCode::VALIDATION, "头像限制范围为 100 至 1024 KB，请输入整数");
            return;
        }
        zct_slms::repo::ConfigRepo::set("max_avatar_bytes", std::to_string(bytes), std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}
#endif
