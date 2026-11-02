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

#ifndef ZCT_SLMS_API_V1_APP_SECRET_REGENERATE
#define ZCT_SLMS_API_V1_APP_SECRET_REGENERATE

#include "api/v1/uih.h"
#include "services/app_secret_policy.hpp"

namespace zct_slms::inside::api::v1::app::secret::regenerate {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int64_t id = zct_slms::inside::api::v1::common::paramI64(req, "id");
        const auto current_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto current_id = zct_slms::inside::api::v1::common::currentUserId(req);
        const auto target_app = zct_slms::repo::AppRepo::findById(id);
        if (!target_app) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "应用不存在"))); return; }
        if (current_type != "ADMIN" && (current_type != "USER" || target_app->owner_id != current_id)) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权操作此应用"))); return; }
        const auto app = zct_slms::repo::AppRepo::findById(id);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(3001, "APP 不存在")));
            return;
        }
        const auto password = zct_slms::inside::api::v1::common::paramStr(req, "password");
        bool valid = false;
        if (current_type == "ADMIN") { auto u=zct_slms::repo::AdminRepo::findById(current_id); valid=u && zct_slms::inside::api::v1::common::sensitiveAuthorization(req,password); }
        else { auto u=zct_slms::repo::UserRepo::findById(current_id); valid=u && zct_slms::inside::api::v1::common::sensitiveAuthorization(req,password); }
        if (!valid) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "密码错误"))); return; }
        const auto new_secret = zct_slms::crypto::randomHex(32);
        zct_slms::repo::AppRepo::updateAppSecret(id, new_secret, std::time(nullptr));
        auto changed=zct_slms::repo::AppRepo::findById(id);
        if(changed)zct_slms::service::claimAppSecret(*changed);
        Json::Value v;
        v["secret"] = new_secret;
        auto response=drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v));response->addHeader("Cache-Control","no-store");cb(response);
    }
}

#endif // ZCT_SLMS_API_V1_APP_SECRET_REGENERATE
