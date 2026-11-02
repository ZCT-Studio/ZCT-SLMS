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

#ifndef ZCT_SLMS_API_V1_ADMIN_LICENSE_TIMER_RESUME
#define ZCT_SLMS_API_V1_ADMIN_LICENSE_TIMER_RESUME

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

#endif // ZCT_SLMS_API_V1_ADMIN_LICENSE_TIMER_RESUME
