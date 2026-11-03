// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/10/2.
//

#ifndef ZCT_SLMS_API_V1_APP_CHANNEL_LIST
#define ZCT_SLMS_API_V1_APP_CHANNEL_LIST

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::channel::list_ {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto appid = zct_slms::inside::api::v1::common::paramStr(req, "appid");

        auto app = zct_slms::repo::AppRepo::findByAppid(appid);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APPID 不存在")));
            return;
        }

        auto channels = zct_slms::service::UpdateService::listChannels(appid);
        Json::Value arr(Json::arrayValue);
        for (auto& c : channels) arr.append(c);
        Json::Value v;
        v["channels"] = arr;
        v["count"] = static_cast<int>(channels.size());
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_APP_CHANNEL_LIST