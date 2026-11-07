// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::binding {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& cb
    ) {
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto appid_str = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        const auto mode = zct_slms::inside::api::v1::common::paramStr(req, "binding_mode", "NONE");

        if (user_type != "USER" && user_type != "ADMIN") {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "仅主用户可修改绑定模式")
                )
            );
            return;
        }

        // 验证 mode 值
        if (mode != "NONE" && mode != "IP" && mode != "DEVICE" && mode != "IP_AND_DEVICE") {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "binding_mode 必须为 NONE/IP/DEVICE/IP_AND_DEVICE")
                )
            );
            return;
        }

        auto app = zct_slms::repo::AppRepo::findByAppid(appid_str);
        if (!app) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APP 不存在")
                )
            );
            return;
        }

        const int64_t cur_user_id = zct_slms::inside::api::v1::common::currentUserId(req);
        if (user_type != "ADMIN" && app->owner_id != cur_user_id) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权修改此 APP 的绑定模式")
                )
            );
            return;
        }

        zct_slms::repo::AppRepo::updateBindingMode(app->id, mode, std::time(nullptr));
        Json::Value v;
        v["appid"] = app->appid;
        v["binding_mode"] = mode;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}
