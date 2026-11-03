// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_PING
#define ZCT_SLMS_API_V1_PING

#include <functional>
#include <drogon/drogon.h>

namespace zct_slms::inside::api::v1::ping {
    inline void handle(
        const drogon::HttpRequestPtr&,
        std::function<void(const drogon::HttpResponsePtr&)>&& cb
    ) {
        const auto resp = drogon::HttpResponse::newHttpResponse(
            drogon::k200OK,
            drogon::CT_TEXT_PLAIN
        );

        resp->setBody("pong");
        cb(resp);
    }
}

#endif // ZCT_SLMS_API_V1_PING
