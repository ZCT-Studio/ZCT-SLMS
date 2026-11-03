// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_APP_CREATE
#define ZCT_SLMS_API_V1_APP_CREATE

#include "api/v1/uih.h"
#include "services/app_secret_policy.hpp"

namespace zct_slms::inside::api::v1::app::create {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        if (user_type == "SUBUSER") {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "子用户无权创建应用")
            ));
            return;
        }
        const int64_t owner_id = user_type == "ADMIN"
            ? zct_slms::inside::api::v1::common::paramI64(req, "owner_id")
            : zct_slms::inside::api::v1::common::currentUserId(req);
        const auto owner = zct_slms::repo::UserRepo::findById(owner_id);
        if (owner_id <= 0 || !owner || owner->status != 1) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "请选择有效的应用所有者账户")
            ));
            return;
        }
        const auto name = zct_slms::inside::api::v1::common::paramStr(req, "name");
        if (name.empty()) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "应用名称不能为空")
            ));
            return;
        }
        const auto desc = zct_slms::inside::api::v1::common::paramStr(req, "description");
        const auto r = zct_slms::service::AppService::createApp(owner_id, name, desc);
        if (!r.success) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(r.code, r.message)));
            return;
        }
        const auto app = zct_slms::repo::AppRepo::findByAppid(r.value->appid);
        Json::Value v;
        v["appid"] = r.value->appid;
        if(app&&!zct_slms::service::repeatAppSecret()&&zct_slms::service::claimAppSecret(*app))v["secret"]=app->secret;
        v["notice"] = app ? app->notice : "";
        v["binding_mode"] = app ? app->binding_mode : "NONE";
        auto response=drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v));response->addHeader("Cache-Control","no-store");cb(response);
    }
}

#endif // ZCT_SLMS_API_V1_APP_CREATE
