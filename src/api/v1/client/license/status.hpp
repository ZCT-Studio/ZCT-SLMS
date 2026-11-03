// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_CLIENT_LICENSE_STATUS
#define ZCT_SLMS_API_V1_CLIENT_LICENSE_STATUS

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::client::license::status {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto appid = zct_slms::inside::api::v1::common::paramStr(req, "appid");
        const auto license_plain = zct_slms::inside::api::v1::common::paramStr(req, "license");
        const auto app = zct_slms::repo::AppRepo::findByAppid(appid);
        if (!app) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APPID 不存在")
                )
            );
            return;
        }
        const auto lic = zct_slms::repo::LicenseRepo::findByAppAndLicense(app->id, license_plain);
        if (!lic) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::LICENSE_NOT_FOUND, "卡密不存在")
                )
            );
            return;
        }
        cb(
            drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeOk(zct_slms::service::LicenseService::statusOf(*lic))
            )
        );
    }
}

#endif // ZCT_SLMS_API_V1_CLIENT_LICENSE_STATUS
