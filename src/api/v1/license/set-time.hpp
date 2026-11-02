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

#ifndef ZCT_SLMS_API_V1_LICENSE_SET_TIME
#define ZCT_SLMS_API_V1_LICENSE_SET_TIME

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::license::set_time {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int64_t id_raw = zct_slms::inside::api::v1::common::paramI64(req, "license_id");
        const std::string lic_plain = zct_slms::inside::api::v1::common::paramStr(req, "license");
        auto id_opt = zct_slms::service::resolveLicenseId(id_raw, lic_plain);
        if (!id_opt) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeResponse(4000, "请传 license_id 或 license", Json::Value{})
            ));
            return;
        }
        const int64_t id = *id_opt;
        if (!zct_slms::inside::api::v1::common::subuserOwnsLicense(req, id)) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权操作此卡密")
            ));
            return;
        }
        const bool permanent = zct_slms::inside::api::v1::common::paramBool(req, "permanent");
        const int64_t exp = permanent
            ? -1
            : zct_slms::inside::api::v1::common::paramI64(req, "expires_at");
        const auto r = zct_slms::service::LicenseService::setTime(id, exp);
        cb(
            drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeResponse(r.code, r.message, Json::Value{})
            )
        );
    }
}

#endif // ZCT_SLMS_API_V1_LICENSE_SET_TIME