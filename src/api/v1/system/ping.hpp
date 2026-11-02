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

#ifndef ZCT_SLMS_API_V1_SYSTEM_PING
#define ZCT_SLMS_API_V1_SYSTEM_PING

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
        auto auth=zct_slms::service::AuthService::authenticateSession(zct_slms::inside::api::v1::common::authBearer(req));
        if(auth.success&&auth.user_type=="ADMIN"){v["components"]["ZCLibLog"]=ZCLibLog::Constants::VersionName;v["components"]["ZACLib"]=ZACLIB::Constants::VersionName;}
        v["server_time"] = static_cast<Json::Int64>(std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_SYSTEM_PING
