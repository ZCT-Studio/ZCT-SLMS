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

#ifndef ZCT_SLMS_API_V1_APP_LIST
#define ZCT_SLMS_API_V1_APP_LIST

#include "api/v1/uih.h"
#include "services/app_secret_policy.hpp"

namespace zct_slms::inside::api::v1::app::list {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const int64_t cur_user_id = zct_slms::inside::api::v1::common::currentUserId(req);


        std::vector<zct_slms::models::App> apps;
        if (user_type == "ADMIN") {
            apps = zct_slms::repo::AppRepo::listAll();
        } else if (user_type == "SUBUSER") {
            for (auto app_id : zct_slms::service::SubUserService::listAssignedApps(cur_user_id)) {
                if (auto app = zct_slms::repo::AppRepo::findById(app_id)) apps.push_back(*app);
            }
        } else {
            apps = zct_slms::repo::AppRepo::listByOwner(cur_user_id);
        }

        Json::Value arr(Json::arrayValue);
        for (auto& a : apps) {
            Json::Value v;
            v["id"] = static_cast<Json::Int64>(a.id);
            v["appid"] = a.appid;
            v["name"] = a.name;
            v["description"] = a.description;
            v["binding_mode"] = a.binding_mode;
            v["dec_mode"] = a.dec_mode;
            v["sign_enable"] = a.sign_enable;
            v["notice"] = a.notice;
            v["status"] = a.status;
            v["created_at"] = a.created_at;
            v["secret_view_available"] = zct_slms::service::appSecretAvailable(a);
            v["secret_repeat_allowed"] = zct_slms::service::repeatAppSecret();


            auto owner = zct_slms::repo::UserRepo::findById(a.owner_id);
            std::string creator_name = owner ? owner->username : "unknown";
            if (creator_name.empty()) creator_name = "unknown";
            if (user_type == "USER" && a.owner_id == cur_user_id) {
                creator_name += "*";
            }
            if (user_type == "SUBUSER") {
                auto su_rows = zct_slms::db::Database::instance().queryParams(
                    "SELECT parent_id FROM sub_users WHERE id = ?", cur_user_id
                );
                if (!su_rows.empty()) {
                    int64_t parent_id = repo::getInt(su_rows[0], "parent_id");
                    if (a.owner_id == parent_id) {
                        creator_name = owner ? owner->username : "unknown";
                    }
                }
            }
            v["creator"] = creator_name;
            v["owner_id"] = static_cast<Json::Int64>(a.owner_id);
            v["owner_username"] = owner ? owner->username : "unknown";
            arr.append(v);
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(arr)));
    }
}

#endif // ZCT_SLMS_API_V1_APP_LIST
