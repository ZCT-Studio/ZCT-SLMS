// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_SERVICES_SECURITY_SERVICE
#define ZCT_SLMS_SERVICES_SECURITY_SERVICE

#include <deque>
#include <cstdlib>
#include <utility>
#include <mutex>
#include <string>
#include <ctime>
#include <unordered_map>
#include "common/types.hpp"

namespace zct_slms::service {
    namespace SecurityService {
        inline std::string canonicalRequest(
            const std::string_view method,
            const std::string_view path,
            const std::string_view appid,
            const std::string_view timestamp,
            const std::string_view nonce,
            const std::string_view encode
        ) {
            std::string s;
            s.reserve(256);
            s.append(method);
            s.push_back('\n');
            s.append(path);
            s.push_back('\n');
            s.append(appid);
            s.push_back('\n');
            s.append(timestamp);
            s.push_back('\n');
            s.append(nonce);
            s.push_back('\n');
            s.append(encode);
            return s;
        }

        inline std::string computeSignature(const std::string_view canonical, const std::string_view app_secret) {
            return zct_slms::crypto::hmacSha256Hex(canonical, app_secret);
        }

        struct AppVerifyContext {
            int64_t app_db_id = 0;
            int64_t app_owner_id = 0;
            std::string appid;
            std::string app_secret;
            int app_status = 1;
        };

        inline zct_slms::common::ResultOf<AppVerifyContext> verifyAppOnly(
            const std::string& appid
        ) {
            const auto app = repo::AppRepo::findByAppid(appid);
            if (!app) return zct_slms::common::ResultOf<AppVerifyContext>::fail(api::ErrorCode::APP_NOT_FOUND, "APPID 不存在");
            if (app->status != 1) return zct_slms::common::ResultOf<AppVerifyContext>::fail(api::ErrorCode::APP_DISABLED, "APP 已禁用");

            AppVerifyContext ctx;
            ctx.app_db_id = app->id;
            ctx.app_owner_id = app->owner_id;
            ctx.appid = app->appid;
            ctx.app_status = app->status;
            return zct_slms::common::ResultOf<AppVerifyContext>::ok(std::move(ctx));
        }

        struct SignatureVerifyResult {
            bool success = false;
            int code = 0;
            std::string message;
        };

        inline SignatureVerifyResult verifyAll(
            const std::string& method,
            const std::string& path,
            const std::string& appid,
            const std::string& timestamp_str,
            const std::string& nonce,
            const std::string& encode,
            const std::string& signature,
            const std::string& app_secret
        ) {
            SignatureVerifyResult r;
            auto& cfg = zct_slms::AppConfig::instance().security();
            const int64_t now = std::time(nullptr);

            int64_t ts = 0;
            try { ts = std::stoll(timestamp_str); } catch (...) {}
            if (ts <= 0) {
                r.code = api::ErrorCode::TIMESTAMP_BAD;
                r.message = "timestamp 非法";
                return r;
            }
            if (std::llabs(now - ts) > cfg.replay_window_seconds) {
                r.code = api::ErrorCode::TIMESTAMP_BAD;
                r.message = "timestamp 超出窗口";
                return r;
            }

            const std::string appid_hash = zct_slms::crypto::sha256Hex(appid); // : 用 app_db_id 更合适
            // 这里先占位，让调用方从 App 查出 db_id 再试 nonce
            // 在中间件里再用 db_id 调 NonceRepo::tryUseNonce
            (void)appid_hash;

            const auto canonical = canonicalRequest(method, path, appid, timestamp_str, nonce, encode);
            if (const auto expected = computeSignature(canonical, app_secret); !zct_slms::crypto::constantTimeEqual(expected, signature)) {
                r.code = api::ErrorCode::SIGNATURE_BAD;
                r.message = "signature 校验失败";
                return r;
            }

            r.success = true;
            r.code = 0;
            r.message = "OK";
            return r;
        }
    } // namespace SecurityService

    class RateLimiter {
    public:
        static RateLimiter& instance() {
            static RateLimiter inst;
            return inst;
        }

        bool tryAcquire(const std::string& key, int per_sec_limit) {
            const std::lock_guard<std::mutex> lock(mtx_);
            const int64_t now = std::time(nullptr);
            auto& slot = buckets_[key];
            // 清理1秒前的
            while (!slot.empty() && slot.front() < now - 1) slot.pop_front();
            if (static_cast<int>(slot.size()) >= per_sec_limit) return false;
            slot.push_back(now);
            return true;
        }

    private:
        RateLimiter() = default;
        std::mutex mtx_;
        std::unordered_map<std::string, std::deque<int64_t>> buckets_;
    };
}

#endif // ZCT_SLMS_SERVICES_SECURITY_SERVICE
