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
