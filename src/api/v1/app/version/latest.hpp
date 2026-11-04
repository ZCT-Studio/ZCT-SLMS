// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::version::latest {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto appid = zct_slms::inside::api::v1::common::paramStr(req, "appid");
        const auto channel = zct_slms::inside::api::v1::common::paramStr(req, "channel", "release");

        auto app = zct_slms::repo::AppRepo::findByAppid(appid);
        if (!app) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APPID 不存在")
                )
            );
            return;
        }

        auto v = zct_slms::service::UpdateService::getLatest(appid, channel);
        if (!v["found"].asBool()) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::NOT_FOUND, "该频道暂无版本")
                )
            );
            return;
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

