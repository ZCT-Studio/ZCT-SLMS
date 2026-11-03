// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/10/2.
//

#ifndef ZCT_SLMS_API_V1_APP_NOTICE
#define ZCT_SLMS_API_V1_APP_NOTICE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::notice {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto appid_str = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        const auto notice_text = zct_slms::inside::api::v1::common::paramStr(req, "notice", "");

        if (user_type != "USER" && user_type != "ADMIN") {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "仅主用户可修改")));
            return;
        }

        auto app = zct_slms::repo::AppRepo::findByAppid(appid_str);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APP 不存在")));
            return;
        }

        const int64_t cur_user_id = zct_slms::inside::api::v1::common::currentUserId(req);
        if (user_type != "ADMIN" && app->owner_id != cur_user_id) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权修改此 APP")));
            return;
        }

        zct_slms::repo::AppRepo::updateNotice(app->id, notice_text, std::time(nullptr));
        zct_slms::inside::api::v1::common::reviewContentChanged("APP","USER",app->id);
        Json::Value v;
        v["appid"] = app->appid;
        v["notice"] = notice_text;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_APP_NOTICE
