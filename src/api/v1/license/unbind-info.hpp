// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/27.
//

#ifndef ZCT_SLMS_API_V1_LICENSE_UNBIND_INFO
#define ZCT_SLMS_API_V1_LICENSE_UNBIND_INFO

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::license::unbind_info {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int64_t id_raw = zct_slms::inside::api::v1::common::paramI64(req, "license_id");
        const std::string lic_plain = zct_slms::inside::api::v1::common::paramStr(req, "license");
        auto id_opt = zct_slms::service::resolveLicenseId(id_raw, lic_plain);
        if (!id_opt) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeResponse(4000, "请传 license_id 或 license", Json::Value{})
            ));
            return;
        }
        const int64_t id = *id_opt;
        if (!zct_slms::inside::api::v1::common::subuserOwnsLicense(req, id)) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "无权操作此卡密")
            ));
            return;
        }

        const auto lic = zct_slms::repo::LicenseRepo::findById(id);
        if (!lic) {
            cb(drogon::HttpResponse::newHttpJsonResponse(
                zct_slms::api::makeFail(zct_slms::api::ErrorCode::LICENSE_NOT_FOUND, "卡密不存在")
            ));
            return;
        }

        // POST: 修改 unbind_limit
        if (req->method() == drogon::Post) {
            int new_limit = static_cast<int>(zct_slms::inside::api::v1::common::paramI64(req, "unbind_limit", -1));
            if (new_limit < 0) {
                cb(drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION, "unbind_limit 必须 >= 0")
                ));
                return;
            }
            const auto r = zct_slms::service::LicenseService::setUnbindLimit(id, new_limit);
            if (!r.success) {
                cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(r.code, r.message)));
                return;
            }
        }

        Json::Value v;
        v["license_id"] = id;
        v["unbind_count"] = lic->unbind_count;
        v["unbind_limit"] = lic->unbind_limit;
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
    }
}

#endif // ZCT_SLMS_API_V1_LICENSE_UNBIND_INFO