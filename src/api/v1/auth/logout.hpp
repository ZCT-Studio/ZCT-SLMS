// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_AUTH_LOGOUT
#define ZCT_SLMS_API_V1_AUTH_LOGOUT

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::auth::logout {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        zct_slms::service::AuthService::logout(zct_slms::inside::api::v1::common::authBearer(req));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}

#endif // ZCT_SLMS_API_V1_AUTH_LOGOUT
