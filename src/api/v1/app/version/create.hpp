// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/10/2.
//

#ifndef ZCT_SLMS_API_V1_APP_VERSION_CREATE
#define ZCT_SLMS_API_V1_APP_VERSION_CREATE

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::version::create_ {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const auto appid_str = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto user_id = zct_slms::inside::api::v1::common::currentUserId(req);
        const auto channel = zct_slms::inside::api::v1::common::paramStr(req, "channel", "release");
        if (channel != "release" && channel != "beta" && channel != "alpha") {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "channel 必须为 release/beta/alpha")));
            return;
        }
        const auto version = zct_slms::inside::api::v1::common::paramStr(req, "version");
        const auto url = zct_slms::inside::api::v1::common::paramStr(req, "download_url");
        const auto hash = zct_slms::inside::api::v1::common::paramStr(req, "file_hash");
        const auto algo = zct_slms::inside::api::v1::common::paramStr(req, "hash_algorithm", "SHA256");
        const auto changelog = zct_slms::inside::api::v1::common::paramStr(req, "changelog");
        const auto minv = zct_slms::inside::api::v1::common::paramStr(req, "minimum_version");
        const int64_t release_time = zct_slms::inside::api::v1::common::paramI64(req, "release_time", std::time(nullptr));

        if (version.empty() || url.empty()) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "version 和 download_url 为必填")));
            return;
        }

        auto app = zct_slms::repo::AppRepo::findByAppid(appid_str);
        if (!app) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APP 不存在")));
            return;
        }

        // 找或自动创建 channel
        auto ch_rows = zct_slms::db::Database::instance().queryParams(
            "SELECT id FROM update_channels WHERE app_id = ? AND channel = ?",
            app->id,
            channel
        );
        int64_t channel_id;
        if (ch_rows.empty()) {
            auto r = zct_slms::service::UpdateService::createChannel(app->id, channel, "");
            if (!r.success) {
                cb(drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(r.code, r.message)));
                return;
            }
            channel_id = *r.value;
        } else {
            channel_id = zct_slms::repo::getInt(ch_rows[0], "id");
        }

        auto r = zct_slms::service::UpdateService::createVersion(
            channel_id, version, url, hash, algo, changelog, minv
        );
        if (!r.success) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(r.code, r.message)));
            return;
        }
        Json::Value v;
        v["version_id"] = static_cast<Json::Int64>(*r.value);
        zct_slms::inside::api::v1::common::reviewContentChanged("APP","USER",app->id);
        v["appid"] = app->appid;
        v["channel"] = channel;
        v["version"] = version;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_APP_VERSION_CREATE
