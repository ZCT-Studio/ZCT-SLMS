// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::client::app::notice {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto appid = zct_slms::inside::api::v1::common::paramStr(req, "appid");
        const auto app = zct_slms::repo::AppRepo::findByAppid(appid);
        if (!app) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APPID 不存在")
                )
            );
            return;
        }

        Json::Value v;
        v["appid"] = app->appid;
        v["notice"] = app->notice;
        v["has_notice"] = !app->notice.empty();
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

