// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include <exception>
#include <functional>
#include <ctime>
#include <drogon/drogon.h>
#include <json/json.h>
#include "constants.hpp"
#include "api/response.hpp"
#include "api/v1/common.hpp"
#include "common/types.hpp"
#include "crypto/crypto.hpp"
#include "database/database.hpp"
#include "models/models.hpp"
#include "repositories/license_repo.hpp"
#include "services/auth_app_service.hpp"
#include "services/license_service.hpp"
#include "services/security_service.hpp"
#include "services/subuser_update_service.hpp"
#include "ZCLibLog/inside/logger_constants.hpp"
#include "ZACLib/ZACLib_Constants.hpp"

namespace zct_slms::inside::api::v1::system::ping {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        Json::Value v;
        v["pong"] = true;
        v["project"] = zct_slms::constants::PROJECT_NAME;
        v["version"] = zct_slms::constants::PROJECT_VERSION;
        auto auth = zct_slms::service::AuthService::authenticateSession(zct_slms::inside::api::v1::common::authBearer(req));
        if (auth.success && auth.user_type == "ADMIN") {
            v["components"]["ZCLibLog"] = ZCLibLog::Constants::VersionName;
            v["components"]["ZACLib"] = ZACLIB::Constants::VersionName;
        }
        v["server_time"] = static_cast<Json::Int64>(std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

