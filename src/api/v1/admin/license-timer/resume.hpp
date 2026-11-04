// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::license_timer::resume {
    inline void handle(
        const drogon::HttpRequestPtr&,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int64_t offset = zct_slms::repo::GlobalTimer::resume(std::time(nullptr));
        Json::Value v;
        v["offset_seconds"] = offset;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

