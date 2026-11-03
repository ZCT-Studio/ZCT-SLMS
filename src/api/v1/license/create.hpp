// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_LICENSE_CREATE
#define ZCT_SLMS_API_V1_LICENSE_CREATE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::license::create {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        zct_slms::service::LicenseService::CreateBatchInput in;
        in.app_id = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        in.count = zct_slms::inside::api::v1::common::paramI64(req, "count", 1);
        in.seconds_per_license = zct_slms::inside::api::v1::common::paramI64(req, "seconds_per_license", 86400);
        in.owner_id = zct_slms::inside::api::v1::common::currentUserId(req);
        in.owner_role = zct_slms::inside::api::v1::common::currentUserRole(req);
        in.remark = zct_slms::inside::api::v1::common::paramStr(req, "remark");
        in.binding_mode = zct_slms::inside::api::v1::common::paramStr(req, "binding_mode", "");
        in.unbind_limit = static_cast<int>(zct_slms::inside::api::v1::common::paramI64(req, "unbind_limit", 0));
        in.unbind_time_cost = static_cast<int>(zct_slms::inside::api::v1::common::paramI64(req, "unbind_time_cost", 0));
        in.unbind_count_cost = static_cast<int>(zct_slms::inside::api::v1::common::paramI64(req, "unbind_count_cost", 0));
        in.license_length = static_cast<int>(zct_slms::inside::api::v1::common::paramI64(req, "license_length", 32));
        in.license_type = zct_slms::inside::api::v1::common::paramStr(req, "license_type");

        if (in.count < 1 || in.count > 1000 || (in.seconds_per_license != -1 && in.seconds_per_license <= 0)) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(
                zct_slms::api::ErrorCode::VALIDATION, "数量须为 1 到 1000，有效时长须为正数或 -1")));
            return;
        }
        const auto app = zct_slms::repo::AppRepo::findByAppid(in.app_id);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APP 不存在")));
            return;
        }
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto actor_id = in.owner_id;
        if (user_type == "ADMIN") {
            in.owner_id = app->owner_id;
            in.owner_role = "OWNER";
        } else if (user_type == "USER" && app->owner_id != in.owner_id) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权操作此应用")));
            return;
        } else if (user_type == "SUBUSER") {
            auto allowed = zct_slms::db::Database::instance().queryParams(
                "SELECT p.app_id FROM user_app_permissions p JOIN sub_users s ON s.id = p.sub_user_id WHERE p.sub_user_id = ? AND p.app_id = ? AND s.parent_id = ?",
                in.owner_id, app->id, app->owner_id);
            if (allowed.empty()) {
                cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "子用户未获此应用授权")));
                return;
            }
        }

        const auto r = zct_slms::service::LicenseService::createBatch(in);
        if (!r.success) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(1003, r.error)));
            return;
        }
        if (user_type == "ADMIN") {
            zct_slms::repo::AuditRepo::log("ADMIN", actor_id, "CreateLicenseForOwner", "APP", app->id,
                std::format("count={}", r.actual_created), "success",
                zct_slms::inside::api::v1::common::clientIp(req), "{}", std::time(nullptr));
        }
        Json::Value v;
        v["created"] = r.actual_created;
        v["first_plain_license"] = r.first_license_plain;
        Json::Value arr(Json::arrayValue);
        for (const auto& lic : r.plain_licenses)
            arr.append(lic);
        v["licenses"] = arr;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_LICENSE_CREATE
