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

#ifndef ZCT_SLMS_API_V1_ADMIN_OWNER_BALANCE
#define ZCT_SLMS_API_V1_ADMIN_OWNER_BALANCE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::owner::balance {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        int64_t user_id = zct_slms::inside::api::v1::common::paramI64(req, "user_id");
        int64_t balance = zct_slms::inside::api::v1::common::paramI64(req, "balance");
        const int64_t admin_id = zct_slms::inside::api::v1::common::paramI64(req, "_admin_id", 0);
        zct_slms::repo::UserRepo::setBalance(user_id, balance, std::time(nullptr));
        zct_slms::repo::AuditRepo::log(
            "ADMIN",
            admin_id,
            "SetOwnerBalance",
            "USER",
            user_id,
            std::format("balance={}", balance),
            "success",
            zct_slms::inside::api::v1::common::clientIp(req),
            "{}",
            std::time(nullptr)
        );
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}

#endif // ZCT_SLMS_API_V1_ADMIN_OWNER_BALANCE
