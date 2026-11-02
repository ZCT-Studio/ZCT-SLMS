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

#ifndef ZCT_SLMS_API_V1_SYSTEM_CONFIGS
#define ZCT_SLMS_API_V1_SYSTEM_CONFIGS

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::system::configs {
    inline void handle(
        const drogon::HttpRequestPtr&,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        Json::Value v;
        v["admin_security_level"] = zct_slms::repo::ConfigRepo::get("admin_security_level", "LAN");
        v["replay_window_seconds"] = zct_slms::repo::ConfigRepo::getI64("replay_window_seconds", 60);
        v["license_timer_paused"] = zct_slms::repo::GlobalTimer::isPaused();
        v["owner_can_create_subuser"] = zct_slms::repo::ConfigRepo::getBool("owner_can_create_subuser", false);
        v["max_avatar_bytes"] = zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes", 1048576);
        v["app_secret_reveal_allowed"] = zct_slms::repo::ConfigRepo::getBool("app_secret_reveal_allowed",zct_slms::AppConfig::instance().security().app_secret_reveal_allowed);
        v["allowed_encoding_modes"] = zct_slms::repo::ConfigRepo::get("allowed_encoding_modes", "NONE,BASE64,HEX,AES128-GCM,AES256-GCM,CHACHA20-POLY1305");
        v["server_time"] = static_cast<Json::Int64>(std::time(nullptr));
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_SYSTEM_CONFIGS
