// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_LICENSE_LIST
#define ZCT_SLMS_API_V1_LICENSE_LIST

#include <exception>
#include <functional>
#include <ctime>
#include <drogon/drogon.h>
#include <json/json.h>
#include "api/response.hpp"
#include "api/v1/common.hpp"
#include "common/types.hpp"
#include "crypto/crypto.hpp"
#include "database/database.hpp"
#include "models/models.hpp"
#include "repositories/user_app_repo.hpp"
#include "repositories/license_repo.hpp"
#include "services/auth_app_service.hpp"
#include "services/license_service.hpp"
#include "services/security_service.hpp"
#include "services/subuser_update_service.hpp"

namespace zct_slms::inside::api::v1::license::list {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        auto appid_str = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        auto app = zct_slms::repo::AppRepo::findByAppid(appid_str);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "app_id 对应的 APP 不存在")
            ));
            return;
        }
        const int64_t app_id = app->id;
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const int64_t cur_user_id = zct_slms::inside::api::v1::common::currentUserId(req);
        bool allowed = user_type == "ADMIN" || (user_type == "USER" && app->owner_id == cur_user_id);
        if (user_type == "SUBUSER") {
            const auto assigned = zct_slms::db::Database::instance().queryParams("SELECT p.app_id FROM user_app_permissions p JOIN sub_users s ON s.id = p.sub_user_id WHERE p.sub_user_id = ? AND p.app_id = ? AND s.parent_id = ?",cur_user_id,app->id,app->owner_id);
            allowed = !assigned.empty();
        }
        if (!allowed) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED,"无权查看此应用卡密"))); return; }

        std::vector<zct_slms::models::License> lics;
        if (user_type == "SUBUSER") {
            lics = zct_slms::repo::LicenseRepo::listByAppAndCreator(app_id, cur_user_id, "SUBUSER");
        } else {
            lics = zct_slms::repo::LicenseRepo::listByApp(app_id);
        }

        Json::Value arr(Json::arrayValue);
        for (auto& l : lics) {
            Json::Value v;
            v["id"] = l.id;
            v["license"] = l.license;
            v["status"] = l.status;
            v["banned"] = l.banned != 0;
            v["binding_mode"] = app->binding_mode;
            if (app->binding_mode == "DEVICE" || app->binding_mode == "IP_AND_DEVICE") {
                v["bound_device_fingerprint"] = l.bound_device_hash.value_or("");
            }
            if (app->binding_mode == "IP" || app->binding_mode == "IP_AND_DEVICE") {
                v["bound_ip_hash"] = l.bound_ip_hash.value_or("");
                v["bound_ip"] = l.bound_ip_hash && l.last_used_ip && zct_slms::crypto::sha256Hex(*l.last_used_ip) == *l.bound_ip_hash ? *l.last_used_ip : "";
            }
            v["license_type"] = l.license_type;
            v["expires_at"] = l.expires_at;
            v["created_at"] = l.created_at;
            v["unbind_count"] = l.unbind_count;
            v["unbind_limit"] = l.unbind_limit;

            if (l.created_by_role == "SUBUSER") {
                auto su_rows = zct_slms::db::Database::instance().queryParams(
                    "SELECT username FROM sub_users WHERE id = ?", l.created_by
                );
                std::string creator = su_rows.empty() ? "subuser" : repo::getStr(su_rows[0], "username");
                if (user_type == "SUBUSER" && l.created_by == cur_user_id) {
                    creator += '*';
                } else if (user_type == "OWNER") {
                }
                v["creator"] = creator;
            } else {
                auto owner = zct_slms::repo::UserRepo::findById(l.created_by);
                std::string creator = owner ? owner->username : "owner";
                if (user_type == "USER" && l.created_by == cur_user_id) {
                    creator += '*';
                }
                v["creator"] = creator;
            }
            arr.append(v);
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(arr)));
    }
}

#endif // ZCT_SLMS_API_V1_LICENSE_LIST
