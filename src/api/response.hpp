// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include <utility>
#include <string>
#include <json/json.h>

namespace zct_slms::api {
    // URP
    // { "code": 0, "message": "OK", "data": ... }
    template <typename T>
    Json::Value makeResponse(const int code, const std::string& message, T&& data) {
        Json::Value resp;
        resp["code"] = code;
        resp["message"] = message;
        resp["data"] = std::forward<T>(data);
        return resp;
    }

    inline Json::Value makeOk() {
        return makeResponse(0, "OK", Json::Value{});
    }

    template <typename T>
    Json::Value makeOk(T&& data) {
        return makeResponse(0, "OK", std::forward<T>(data));
    }

    inline Json::Value makeFail(const int code, const std::string& message) {
        return makeResponse(code, message, Json::Value{});
    }

    namespace ErrorCode {
        constexpr int OK = 0;

        constexpr int BAD_REQUEST = 1001;
        constexpr int NOT_FOUND = 1002;
        constexpr int INTERNAL = 1003;
        constexpr int VALIDATION = 1004;

        constexpr int UNAUTHORIZED = 2001;
        constexpr int TOKEN_EXPIRED = 2002;
        constexpr int TOKEN_REVOKED = 2003;
        constexpr int IP_NOT_ALLOWED = 2004;

        constexpr int APP_NOT_FOUND = 3001;
        constexpr int APP_DISABLED = 3002;
        constexpr int APP_SECRET_BAD = 3003;
        constexpr int FUNC_NOT_FOUND = 3004;
        constexpr int FUNC_NOT_IN_APP = 3005;

        constexpr int SIGNATURE_BAD = 4001;
        constexpr int TIMESTAMP_BAD = 4002;
        constexpr int NONCE_REPLAY = 4003;
        constexpr int NONCE_MISSING = 4004;

        constexpr int LICENSE_NOT_FOUND = 5001;
        constexpr int LICENSE_BANNED = 5002;
        constexpr int LICENSE_EXPIRED = 5003;
        constexpr int LICENSE_UNUSED = 5004;
        constexpr int LICENSE_BOUND_IP = 5005;
        constexpr int LICENSE_BOUND_DEV = 5006;
        constexpr int LICENSE_NO_UNBIND = 5007;
        constexpr int LICENSE_QUOTA_LIMIT = 5008;
        constexpr int LICENSE_BALANCE_INS = 5009;

        constexpr int USER_NOT_FOUND = 6001;
        constexpr int USER_EXPIRED = 6002;
        constexpr int USER_DISABLED = 6003;
        constexpr int USER_BAD_CREDENTIALS = 6004;

        constexpr int RATE_LIMITED = 9001;
    } // CLion 格式化牛大了，老是把这里`}}`放一起，下面一行占位
    #ifdef END_OF_NAMESPACE_ZCT_SLMS_API_VOID
    #endif
}

