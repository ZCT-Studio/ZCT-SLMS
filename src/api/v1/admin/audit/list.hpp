// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_ADMIN_AUDIT_LIST_THIS
#define ZCT_SLMS_API_V1_ADMIN_AUDIT_LIST_THIS

#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::admin::audit::list {
    inline void handle(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr &)>&& cb
    ) {
        const int limit = static_cast<int>(zct_slms::inside::api::v1::common::paramI64(req, "limit", 200));
        const auto logs = zct_slms::repo::AuditRepo::listRecent(limit);
        Json::Value arr(Json::arrayValue);
        for (auto& a : logs) {
            Json::Value v;
            v["actor_type"] = a.actor_type;
            v["actor_id"] = a.actor_id;
            v["action"] = a.action;
            v["target_type"] = a.target_type;
            v["target_id"] = a.target_id.has_value() ? static_cast<Json::Int64>(*a.target_id) : 0;
            v["result"] = a.result;
            v["ip"] = a.ip;
            v["created_at"] = a.created_at;
            arr.append(v);
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(arr)));
    }
}

#endif // ZCT_SLMS_API_V1_ADMIN_AUDIT_LIST_THIS
