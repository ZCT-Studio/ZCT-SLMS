// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_APP_DELETE
#define ZCT_SLMS_API_V1_APP_DELETE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::delete_ {
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
        if (!zct_slms::inside::api::v1::common::sensitiveAuthorization(req, zct_slms::inside::api::v1::common::paramStr(req, "password"))) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "请验证身份后删除应用")));
            return;
        }
        zct_slms::repo::AppRepo::removeById(id);
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}

#endif // ZCT_SLMS_API_V1_APP_DELETE
