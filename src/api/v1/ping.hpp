// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

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
