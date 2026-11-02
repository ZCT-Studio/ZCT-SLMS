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
// Created by wanjiangzhi on 2026/9/27.
//

#ifndef ZCT_SLMS_API_V1_APP_BINDING
#define ZCT_SLMS_API_V1_APP_BINDING

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::binding {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto appid_str = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        const auto mode = zct_slms::inside::api::v1::common::paramStr(req, "binding_mode", "NONE");

        if (user_type != "USER" && user_type != "ADMIN") {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "仅主用户可修改绑定模式")
            ));
            return;
        }

        // 验证 mode 值
        if (mode != "NONE" && mode != "IP" && mode != "DEVICE" && mode != "IP_AND_DEVICE") {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "binding_mode 必须为 NONE/IP/DEVICE/IP_AND_DEVICE")
            ));
            return;
        }

        auto app = zct_slms::repo::AppRepo::findByAppid(appid_str);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APP 不存在")
            ));
            return;
        }

        const int64_t cur_user_id = zct_slms::inside::api::v1::common::currentUserId(req);
        if (user_type != "ADMIN" && app->owner_id != cur_user_id) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权修改此 APP 的绑定模式")
            ));
            return;
        }

        zct_slms::repo::AppRepo::updateBindingMode(app->id, mode, std::time(nullptr));
        Json::Value v;
        v["appid"] = app->appid;
        v["binding_mode"] = mode;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_APP_BINDING