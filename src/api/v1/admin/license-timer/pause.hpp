// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_ADMIN_LICENSE_TIMER_PAUSE
#define ZCT_SLMS_API_V1_ADMIN_LICENSE_TIMER_PAUSE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::license_timer::pause {
    inline void handle(
        const drogon::HttpRequestPtr&,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int64_t offset = zct_slms::repo::GlobalTimer::pause(std::time(nullptr));
        Json::Value v;
        v["offset_seconds"] = offset;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_ADMIN_LICENSE_TIMER_PAUSE
