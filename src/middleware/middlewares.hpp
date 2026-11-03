// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_MIDDLEWARE_MIDDLEWARES
#define ZCT_SLMS_MIDDLEWARE_MIDDLEWARES

#include <functional>
#include <string>
#include <ctime>
#include <memory>
#include <drogon/drogon.h>
#include "common/logger.hpp"
#include "common/types.hpp"
#include "crypto/crypto.hpp"
#include "repositories/license_repo.hpp"
#include "services/auth_app_service.hpp"
#include "services/security_service.hpp"
#include "services/identity_service.hpp"

namespace zct_slms::middleware {
    class RateLimitMiddleware : public drogon::HttpMiddleware<RateLimitMiddleware, false> {
    public:
        void invoke(
            const drogon::HttpRequestPtr& req,
            drogon::MiddlewareNextCallback&& nextCb,
            drogon::MiddlewareCallback&& mcb
        ) override {
            auto& rl = zct_slms::AppConfig::instance().rateLimit();
            if (!rl.enabled) {
                nextCb(nullptr);
                return;
            }

            const auto ip = req->getPeerAddr().toIp();
            const std::string key_ip = "ip:" + ip;
            if (!zct_slms::service::RateLimiter::instance().tryAcquire(key_ip, rl.ip_per_sec)) {
                const auto resp = drogon::HttpResponse::newHttpJsonResponse(
                    api::makeFail(api::ErrorCode::RATE_LIMITED, "请求过于频繁")
                );
                resp->setStatusCode(drogon::k429TooManyRequests);
                mcb(resp);
                return;
            }
            nextCb(nullptr);
        }
    };

    class BearerAuthMiddleware : public drogon::HttpMiddleware<BearerAuthMiddleware, false> {
    public:
        void invoke(
            const drogon::HttpRequestPtr& req,
            drogon::MiddlewareNextCallback&& nextCb,
            drogon::MiddlewareCallback&& mcb
        ) override {
            auto path = req->path();
            zct_slms::logger().DEBUG("[MW:Bearer] path={}", path);
            bool need = path.rfind("/api/v1/app/", 0) == 0 ||
                        path.rfind("/api/v1/license/", 0) == 0;
            zct_slms::logger().DEBUG("[MW:Bearer] need={}", need);
            if (!need) {
                nextCb(nullptr);
                return;
            }

            std::string bearer;
            auto& hdrs = req->headers();
            if (const auto it = hdrs.find("authorization"); it != hdrs.end()) bearer = it->second;
            else if (const auto IT = hdrs.find("Authorization"); IT != hdrs.end()) bearer = IT->second;

            auto u = zct_slms::service::AuthService::authenticateSession(bearer);
            zct_slms::logger().DEBUG("[MW:Bearer] auth success={} uid={} type={}", u.success, u.user_id, u.user_type);
            if (!u.success || u.user_type=="SUPPORT") {
                mcb(
                    drogon::HttpResponse::newHttpJsonResponse(
                        api::makeFail(api::ErrorCode::UNAUTHORIZED, "未登录或登录已过期")
                    )
                );
                return;
            }

            (*req->attributes())["zct_slms.user_type"] = u.user_type;
            (*req->attributes())["zct_slms.user_id"] = u.user_id;
            zct_slms::logger().DEBUG("[MW:Bearer] attributes set!");
            nextCb(nullptr);
        }
    };

    class AdminAuthMiddleware : public drogon::HttpMiddleware<AdminAuthMiddleware, false> {
    public:
        void invoke(
            const drogon::HttpRequestPtr& req,
            drogon::MiddlewareNextCallback&& nextCb,
            drogon::MiddlewareCallback&& mcb
        ) override {
            auto path = req->path();
            bool need = path.rfind("/api/v1/admin/", 0) == 0;
            if (!need) {
                nextCb(nullptr);
                return;
            }

            auto ip = req->getPeerAddr().toIp();
            std::string bearer;
            auto& hdrs = req->headers();
            if (const auto it = hdrs.find("authorization"); it != hdrs.end()) bearer = it->second;
            else if (const auto IT = hdrs.find("Authorization"); IT != hdrs.end()) bearer = IT->second;

            auto u = zct_slms::service::AuthService::authenticateSession(bearer);
            if (!u.success || u.user_type != "ADMIN") {
                mcb(
                    drogon::HttpResponse::newHttpJsonResponse(
                        api::makeFail(api::ErrorCode::UNAUTHORIZED, "需要管理员登录")
                    )
                );
                return;
            }

            const auto level = zct_slms::repo::ConfigRepo::get("admin_security_level", "LAN");
            const bool is_local = (ip == "127.0.0.1" || ip == "::1");
            if (level == "LOCAL" && !is_local) {
                mcb(
                    drogon::HttpResponse::newHttpJsonResponse(
                        api::makeFail(api::ErrorCode::IP_NOT_ALLOWED, "LOCAL 级别仅允许本机访问")
                    )
                );
                return;
            }
            if (level == "PUBLIC") {
                const auto wh = zct_slms::db::Database::instance().queryParams(
                    "SELECT 1 FROM ip_whitelist WHERE ip = ?",
                    ip
                );
                if (wh.empty()) {
                    mcb(
                        drogon::HttpResponse::newHttpJsonResponse(
                            api::makeFail(api::ErrorCode::IP_NOT_ALLOWED, "IP 不在白名单")
                        )
                    );
                    return;
                }
            }

            (*req->attributes())["zct_slms.user_type"] = u.user_type;
            (*req->attributes())["zct_slms.user_id"] = u.user_id;
            nextCb(nullptr);
        }
    };

    class AppSignatureMiddleware : public drogon::HttpMiddleware<AppSignatureMiddleware, false> {
    public:
        void invoke(
            const drogon::HttpRequestPtr& req,
            drogon::MiddlewareNextCallback&& nextCb,
            drogon::MiddlewareCallback&& mcb
        ) override {
            // Client authentication is performed once by common::wrap().
            nextCb(nullptr);
        }
    };

    inline bool allowedFrontend(const drogon::HttpRequestPtr& req) {
      auto origin=req->getHeader("Origin");if(origin.empty()||origin=="null")return false;
      try{auto config=zct_slms::identity::config();return origin==zct_slms::identity::baseUrl(config)||origin==zct_slms::identity::backendBaseUrl(config);}catch(...){return false;}
    }
    inline void corsHeaders(const drogon::HttpRequestPtr& req,const drogon::HttpResponsePtr& response) {
      if(req->path().rfind("/api/",0)!=0)return;
      auto vary=response->getHeader("Vary");if(vary.find("Origin")==std::string::npos)response->addHeader("Vary",vary.empty()?"Origin":vary+", Origin");
      auto origin=req->attributes()->get<std::string>("zct_slms.cors_origin");if(origin.empty())return;
      response->addHeader("Access-Control-Allow-Origin",origin);
    }
    inline void registerAllMiddlewares(drogon::HttpAppFramework& app) {
        app.registerPreRoutingAdvice([](const drogon::HttpRequestPtr& req,drogon::AdviceCallback&& stop,drogon::AdviceChainCallback&& next){
          if(req->path().rfind("/api/",0)==0&&allowedFrontend(req))req->attributes()->insert("zct_slms.cors_origin",req->getHeader("Origin"));
          if(req->path().rfind("/api/",0)==0&&req->method()==drogon::Options){auto response=drogon::HttpResponse::newHttpResponse();if(!allowedFrontend(req)){response->setStatusCode(drogon::k403Forbidden);}else{response->setStatusCode(drogon::k204NoContent);corsHeaders(req,response);response->addHeader("Access-Control-Allow-Methods","GET, POST, OPTIONS");response->addHeader("Access-Control-Allow-Headers","Authorization, Content-Type, X-Ticket-Contact");response->addHeader("Access-Control-Max-Age","300");}stop(response);return;}next();
        });
        app.registerPreSendingAdvice([](const drogon::HttpRequestPtr& req,const drogon::HttpResponsePtr& response){corsHeaders(req,response);});

        app.registerPreRoutingAdvice([](const drogon::HttpRequestPtr& req,drogon::AdviceCallback&& stop,drogon::AdviceChainCallback&& next){
            auto path=req->path();std::transform(path.begin(),path.end(),path.begin(),[](unsigned char c){return std::tolower(c);});
            if(path.rfind("/captcha/",0)==0||path=="/captcha"){auto response=drogon::HttpResponse::newHttpResponse();response->setStatusCode(drogon::k404NotFound);stop(response);return;}next();
        });
        app.registerMiddleware(std::make_shared<RateLimitMiddleware>());
        app.registerMiddleware(std::make_shared<BearerAuthMiddleware>());
        app.registerMiddleware(std::make_shared<AdminAuthMiddleware>());
        app.registerMiddleware(std::make_shared<AppSignatureMiddleware>());
    }
}

#endif // ZCT_SLMS_MIDDLEWARE_MIDDLEWARES
