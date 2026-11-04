// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::auth::subuser::login {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const std::string username = zct_slms::inside::api::v1::common::paramStr(req, "username");
        const std::string password = zct_slms::inside::api::v1::common::paramStr(req, "password");
        const auto r = zct_slms::service::AuthService::loginSubUser(
            username,
            password,
            zct_slms::inside::api::v1::common::clientIp(req),
            zct_slms::inside::api::v1::common::clientUa(req)
        );
        if (!r.success) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::USER_BAD_CREDENTIALS, r.message)
                )
            );
            return;
        }
        Json::Value v;
        v["token"] = r.token;
        v["user_type"] = r.user_type;
        v["user_id"] = r.user_id;
        v["username"] = r.username;
        v = zct_slms::inside::api::v1::common::gateLogin(v, zct_slms::inside::api::v1::common::clientIp(req), zct_slms::inside::api::v1::common::clientUa(req));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

