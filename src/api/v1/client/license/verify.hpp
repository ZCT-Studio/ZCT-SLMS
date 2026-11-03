// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_CLIENT_LICENSE_VERIFY
#define ZCT_SLMS_API_V1_CLIENT_LICENSE_VERIFY

#include "api/v1/uih.h"
#include "services/heartbeat.hpp"

namespace zct_slms::inside::api::v1::client::license::verify {

inline void handle(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr &)>&& cb
) {
    // wrap() 已经在 paramStr 之前处理了 encode 解密 → attributes.zct_slms.decoded_kv
    // 如果请求没加密，paramStr 正常从 query/form/header/json 取值
    auto appid = zct_slms::inside::api::v1::common::paramStr(req, "appid");
    auto license_plain = zct_slms::inside::api::v1::common::paramStr(req, "license");
    auto device = zct_slms::inside::api::v1::common::paramStr(req, "device");
    auto ip = zct_slms::inside::api::v1::common::clientIp(req);

    auto app = zct_slms::repo::AppRepo::findByAppid(appid);
    if (!app) {
        cb(drogon::HttpResponse::newHttpJsonResponse(
            zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APPID 不存在")));
        return;
    }
    if (app->status != 1) {
        cb(drogon::HttpResponse::newHttpJsonResponse(
            zct_slms::api::makeFail(zct_slms::api::ErrorCode::APP_DISABLED, "APP 已禁用")));
        return;
    }

    if (license_plain.empty()) {
        cb(drogon::HttpResponse::newHttpJsonResponse(
            zct_slms::api::makeFail(zct_slms::api::ErrorCode::BAD_REQUEST, "missing license")));
        return;
    }

    zct_slms::service::LicenseVerifyInput in;
    in.license_plain = license_plain;
    in.ip = ip;
    if (!device.empty()) in.device = device;
    auto r = zct_slms::service::LicenseService::verify(in, app->id);

    Json::Value v;
    v["status"] = r.status;
    v["remaining"] = r.remaining;
    v["expired"] = r.expired;
    v["expires_at"] = r.expires_at;
    v["binding_mode"] = r.binding_mode;
    v["remark"] = r.remark;
    v["license_type"] = r.license_type;
    if(r.success){auto heartbeat=zct_slms::heartbeat::config(app->id);v["heartbeat_required"]=heartbeat["enabled"];v["heartbeat_interval_seconds"]=heartbeat["interval_seconds"];v["heartbeat_timeout_seconds"]=heartbeat["timeout_seconds"];if(req->path()=="/api/v1/client/license/heartbeat")zct_slms::heartbeat::record(app->id,license_plain,ip,device);}
    cb(drogon::HttpResponse::newHttpJsonResponse(
        zct_slms::api::makeResponse(r.success ? 0 : r.code, r.message, v)));
}

} // namespace zct_slms::inside::api::v1::client::license::verify

#endif // ZCT_SLMS_API_V1_CLIENT_LICENSE_VERIFY
