// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

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
