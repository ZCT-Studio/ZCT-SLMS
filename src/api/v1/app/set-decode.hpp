// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::app::set_decode {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& cb
    ) {
        const auto user_type = zct_slms::inside::api::v1::common::currentUserType(req);
        const auto appid_str = zct_slms::inside::api::v1::common::paramStr(req, "app_id");
        const auto mode = zct_slms::inside::api::v1::common::paramStr(req, "dec_mode", "NONE");
        const auto key = zct_slms::inside::api::v1::common::paramStr(req, "dec_key", "");

        if (user_type != "USER" && user_type != "ADMIN") {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "仅主用户可修改")
                )
            );
            return;
        }

        if (mode != "NONE" && mode != "AES128-GCM" && mode != "AES256-GCM" && mode != "CHACHA20-POLY1305" && mode != "BASE64" && mode != "HEX") {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "dec_mode 必须为 NONE/AES256-GCM/CHACHA20-POLY1305/BASE64/HEX")
                )
            );
            return;
        }
        if ((mode == "AES256-GCM" || mode == "CHACHA20-POLY1305") && (key.size() != 64 || zct_slms::crypto::fromHex(key).size() != 32)) {
            cb(
                drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "dec_key 必须为 64 位 hex")
                )
            );
            return;
        }

        if (mode == "AES128-GCM" && (key.size() != 32 || zct_slms::crypto::fromHex(key).size() != 16)) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "AES-128-GCM 密钥必须为 32 位十六进制字符")));
            return;
        }
        const auto allowed = "," + zct_slms::repo::ConfigRepo::get("allowed_encoding_modes", "NONE,BASE64,HEX,AES128-GCM,AES256-GCM,CHACHA20-POLY1305") + ",";
        if (allowed.find("," + mode + ",") == std::string::npos) {
            cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "管理员未允许此编码或加密方式")));
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
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权修改此 APP")
                )
            );
            return;
        }

        zct_slms::repo::AppRepo::updateDecodeMode(app->id, mode, key, std::time(nullptr));
        Json::Value v;
        v["appid"] = app->appid;
        v["dec_mode"] = mode;
        // dec_key 不回显
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}
