// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::license::unban {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int64_t id_raw = zct_slms::inside::api::v1::common::paramI64(req, "license_id");
        const std::string lic_plain = zct_slms::inside::api::v1::common::paramStr(req, "license");
        auto id_opt = zct_slms::service::resolveLicenseId(id_raw, lic_plain);
        if (!id_opt) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeResponse(4000, "请传 license_id 或 license", Json::Value{})
                )
            );
            return;
        }
        const int64_t id = *id_opt;
        if (!zct_slms::inside::api::v1::common::subuserOwnsLicense(req, id)) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权操作此卡密")
                )
            );
            return;
        }
        const auto r = zct_slms::service::LicenseService::unban(id);
        cb(
            drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeResponse(r.code, r.message, Json::Value{})
            )
        );
    }
}

