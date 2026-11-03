// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_COMMON
#define ZCT_SLMS_API_V1_COMMON

#include <chrono>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <utility>
#include <string>
#include <drogon/drogon.h>
#include <json/json.h>
#include "api/response.hpp"
#include "common/logger.hpp"
#include "crypto/crypto.hpp"
#include "database/database.hpp"
#include "repositories/license_repo.hpp"
#include "repositories/user_app_repo.hpp"
#include "services/auth_app_service.hpp"
#include "services/security_service.hpp"

namespace zct_slms::inside::api::v1::common {
inline std::function<bool(const drogon::HttpRequestPtr&,const std::string&)> sensitiveAuthorization=[](const drogon::HttpRequestPtr&,const std::string&){return false;};
inline std::function<Json::Value(Json::Value,const std::string&,const std::string&)> gateLogin = [](Json::Value value,const std::string&,const std::string&){return value;};
inline std::function<void(const drogon::HttpRequestPtr&)> contentGuard=[](const drogon::HttpRequestPtr&){};
inline std::function<void(const std::string&,const std::string&,int64_t)> reviewContentChanged=[](const std::string&,const std::string&,int64_t){};
inline std::function<bool(const std::string&,int64_t)> forcePassword=[](const std::string&,int64_t){return false;};

// ── URL k=v 解析（verify.hpp 原本有一份，提成公共） ──
inline std::map<std::string, std::string> parseKvs(const std::string& body) {
    std::map<std::string, std::string> out;
    size_t pos = 0;
    while (pos < body.size()) {
        size_t amp = body.find('&', pos);
        std::string pair = (amp == std::string::npos) ? body.substr(pos) : body.substr(pos, amp - pos);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            out[pair.substr(0, eq)] = pair.substr(eq + 1);
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return out;
}

// ── AES256-GCM / BASE64 / HEX 统一加密（响应） ──
// plaintext: 要加密的明文（通常是 JSON 字符串）
// dec_mode: AES256-GCM / BASE64 / HEX / NONE（NONE 不应该调用本函数）
// dec_key: hex-encoded AES key（仅 AES256-GCM 需要，其他忽略）
inline std::string encryptByMode(
    const std::string& plaintext,
    const std::string& dec_mode,
    const std::string& dec_key
) {
    if (dec_mode == "AES128-GCM") {
        return zct_slms::crypto::base64Encode(zct_slms::crypto::aes128GcmEncrypt(plaintext, zct_slms::crypto::fromHex(dec_key)));
    } else if (dec_mode == "AES256-GCM") {
        const auto key_raw = zct_slms::crypto::fromHex(dec_key);
        const auto blob = zct_slms::crypto::aes256GcmEncrypt(plaintext, key_raw);
        return zct_slms::crypto::base64Encode(blob);
    } else if (dec_mode == "CHACHA20-POLY1305") {
        return zct_slms::crypto::base64Encode(zct_slms::crypto::chacha20Poly1305Encrypt(plaintext, zct_slms::crypto::fromHex(dec_key)));
    } else if (dec_mode == "BASE64") {
        return zct_slms::crypto::base64Encode(plaintext);
    } else if (dec_mode == "HEX") {
        return zct_slms::crypto::toHex(plaintext);
    }
    return plaintext; // NONE 或未知 → 明文返回
}

// ── AES256-GCM / BASE64 / HEX 统一解密（请求） ──
// 返回解密后的 URL k=v 字符串（或空表示失败）
inline std::optional<std::string> decryptByMode(
    const std::string& encoded,
    const std::string& dec_mode,
    const std::string& dec_key
) {
    if (dec_mode == "AES128-GCM") {
        return zct_slms::crypto::aes128GcmDecrypt(zct_slms::crypto::base64Decode(encoded), zct_slms::crypto::fromHex(dec_key));
    } else if (dec_mode == "AES256-GCM") {
        const auto blob = zct_slms::crypto::base64Decode(encoded);
        const auto key_raw = zct_slms::crypto::fromHex(dec_key);
        return zct_slms::crypto::aes256GcmDecrypt(blob, key_raw);
    } else if (dec_mode == "CHACHA20-POLY1305") {
        return zct_slms::crypto::chacha20Poly1305Decrypt(zct_slms::crypto::base64Decode(encoded), zct_slms::crypto::fromHex(dec_key));
    } else if (dec_mode == "BASE64" || dec_mode == "NONE") {
        return zct_slms::crypto::base64Decode(encoded);
    } else if (dec_mode == "HEX") {
        return zct_slms::crypto::fromHex(encoded);
    }
    return std::nullopt;
}

// ── 从请求取参数：优先用 wrap() 解密后注入的 decoded_kv ──
inline std::string paramStr(
    const drogon::HttpRequestPtr& req,
    const std::string& key,
    const std::string& def = ""
) {
    if (req->attributes()->find("zct_slms.signed") && key != "appid") {
        auto m = req->attributes()->get<std::map<std::string, std::string>>("zct_slms.decoded_kv");
        auto it = m.find(key);
        return it == m.end() ? def : it->second;
    }
    if (req->attributes()->find("zct_slms.signed") && key == "appid") return req->attributes()->get<std::string>("zct_slms.signed_appid");
    // 1. 优先查 wrap() 里 decrypted 的 encode 内容（URL k=v 对）
    auto attrs = req->attributes();
    if (attrs && attrs->find("zct_slms.decoded_kv")) {
        try {
            auto m = attrs->get<std::map<std::string, std::string>>("zct_slms.decoded_kv");
            if (auto it = m.find(key); it != m.end() && !it->second.empty()) return it->second;
        } catch (...) {}
    }

    // 2. 再查常规参数（query / form / header / json body）
        auto& p = req->getParameters();
        if (const auto it = p.find(key); it != p.end() && !it->second.empty()) return it->second;

        auto& fp = req->getParameters();

        const auto& hdrs = req->headers();
        for (const auto& k : {
                 key,
                 std::string(1, static_cast<char>(toupper(key[0]))) + key.substr(1)
             }) {
            if (auto h = hdrs.find(k); h != hdrs.end()) return h->second;
        }

        const auto body = req->getJsonObject();
        if (body && body->isMember(key)) {
            const auto& v = (*body)[key];
            if (v.isString()) return v.asString();
            if (v.isInt() || v.isInt64()) return std::to_string(v.asInt64());
            if (v.isBool()) return v.asBool() ? "1" : "0";
        }
        return def;
    }

    inline int64_t paramI64(const drogon::HttpRequestPtr& req, const std::string& key, int64_t def = 0) {
        const auto s = paramStr(req, key);
        if (s.empty()) return def;
        try { return std::stoll(s); } catch (...) { return def; }
    }

    inline bool paramBool(const drogon::HttpRequestPtr& req, const std::string& key, bool def = false) {
        const auto s = paramStr(req, key);
        if (s.empty()) return def;
        return s == "1" || s == "true" || s == "TRUE";
    }

    inline std::string clientIp(const drogon::HttpRequestPtr& req) {
        return req->getPeerAddr().toIp();
    }

    inline std::string clientUa(const drogon::HttpRequestPtr& req) {
        const auto& h = req->headers();
        for (const auto k : {"user-agent", "User-Agent"}) {
            if (auto it = h.find(k); it != h.end()) return it->second;
        }
        return "";
    }

    inline std::string authBearer(const drogon::HttpRequestPtr& req) {
        const auto& h = req->headers();
        for (const auto k : {"authorization", "Authorization"}) {
            if (auto it = h.find(k); it != h.end()) return it->second;
        }
        return "";
    }

    inline int64_t currentUserId(const drogon::HttpRequestPtr& req) {
        const auto attrs = req->attributes();
        if (!attrs || !attrs->find("zct_slms.user_id")) return 0;
        try {
            const auto v = attrs->get<int64_t>("zct_slms.user_id");
            return v;
        } catch (...) {}
        try {
            const auto v = attrs->get<int>("zct_slms.user_id");
            return v;
        } catch (...) { return 0; }
    }

    inline std::string currentUserType(const drogon::HttpRequestPtr& req) {
        const auto attrs = req->attributes();
        if (!attrs || !attrs->find("zct_slms.user_type")) return "";
        try { return attrs->get<std::string>("zct_slms.user_type"); } catch (...) { return ""; }
    }

    // user_type → role string (OWNER / SUBUSER)
    inline std::string currentUserRole(const drogon::HttpRequestPtr& req) {
        auto ut = currentUserType(req);
        if (ut == "SUBUSER") return "SUBUSER";
        if (ut == "USER") return "OWNER";
        if (ut == "ADMIN") return "ADMIN";
        return "OWNER";
    }

    // SUBUSER 只能操作自己创建的卡密
    inline bool subuserOwnsLicense(const drogon::HttpRequestPtr& req, int64_t license_id) {
        auto ut = currentUserType(req);
        if (ut != "SUBUSER") return true;
        auto lic = repo::LicenseRepo::findById(license_id);
        if (!lic) return false;
        return lic->created_by == currentUserId(req) && lic->created_by_role == "SUBUSER";
    }

    template <typename Fn>
    auto wrap(Fn fn) {
        return [fn = std::move(fn)](
            const drogon::HttpRequestPtr& req,
            std::function<void(const drogon::HttpResponsePtr &)>&& cb
        ) {
            auto t0 = std::chrono::steady_clock::now();
            auto method = std::string(req->methodString());
            std::string path = req->path();
            std::string ip = req->getPeerAddr().toIp();
            zct_slms::apiLog("-> {} {} from {}", method, path, ip);
            try {
                auto req_path = req->path();
                if(req_path!="/api/v1/auth/onboarding"&&req_path!="/api/v1/auth/logout"&&req_path!="/api/v1/system/ping"&&req_path!="/api/v1/auth/captcha"){auto auth=zct_slms::service::AuthService::authenticateSession(authBearer(req));if(auth.success&&forcePassword(auth.user_type,auth.user_id)){cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(2010,"为了您的账号安全请设置新的密码")));return;}}

                if (req_path.rfind("/api/v1/admin/", 0) == 0) {
                    std::string bearer = authBearer(req);
                    auto u = zct_slms::service::AuthService::authenticateSession(bearer);
                    if (!u.success || u.user_type != "ADMIN") {
                        cb(
                            drogon::HttpResponse::newHttpJsonResponse(
                                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要管理员登录")
                            )
                        );
                        return;
                    }

                    auto req_ip = req->getPeerAddr().toIp();
                    auto level = zct_slms::repo::ConfigRepo::get("admin_security_level", "LAN");
                    if (bool is_local = (req_ip == "127.0.0.1" || req_ip == "::1"); level == "LOCAL" && !is_local) {
                        cb(
                            drogon::HttpResponse::newHttpJsonResponse(
                                zct_slms::api::makeFail(zct_slms::api::ErrorCode::IP_NOT_ALLOWED, "LOCAL 级别仅允许本机访问")
                            )
                        );
                        return;
                    }
                    if (level == "PUBLIC") {
                        auto wh = zct_slms::db::Database::instance().queryParams(
                            "SELECT 1 FROM ip_whitelist WHERE ip = ?",
                            req_ip
                        );
                        if (wh.empty()) {
                            cb(
                                drogon::HttpResponse::newHttpJsonResponse(
                                    zct_slms::api::makeFail(zct_slms::api::ErrorCode::IP_NOT_ALLOWED, "IP 不在白名单")
                                )
                            );
                            return;
                        }
                    }
                    (*req->attributes())["zct_slms.user_type"] = u.user_type;
                    (*req->attributes())["zct_slms.user_id"] = u.user_id;
                }

                else if (req_path.rfind("/api/v1/app/", 0) == 0 ||
                         req_path.rfind("/api/v1/license/", 0) == 0) {
                    std::string bearer = authBearer(req);
                    auto u = zct_slms::service::AuthService::authenticateSession(bearer);
                    if (!u.success || u.user_type=="SUPPORT") {
                        cb(
                            drogon::HttpResponse::newHttpJsonResponse(
                                zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED, "未登录或登录已过期")
                            )
                        );
                        return;
                    }
                    (*req->attributes())["zct_slms.user_type"] = u.user_type;
                    (*req->attributes())["zct_slms.user_id"] = u.user_id;
                }

                else if (req_path.rfind("/api/v1/client/", 0) == 0) {
                    auto& cfg = zct_slms::AppConfig::instance().security();
                    const auto appid = paramStr(req, "appid");
                    const auto timestamp = paramStr(req, "timestamp");
                    const auto nonce = paramStr(req, "nonce");
                    const auto encoded = paramStr(req, "encode");
                    auto fail = [&](int code, const std::string& message) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, message))); };
                    if (appid.empty()) { fail(zct_slms::api::ErrorCode::BAD_REQUEST, "缺少 appid"); return; }
                    const auto app = zct_slms::repo::AppRepo::findByAppid(appid);
                    if (!app) { fail(zct_slms::api::ErrorCode::APP_NOT_FOUND, "APPID 不存在"); return; }
                    if (app->status != 1) { fail(zct_slms::api::ErrorCode::APP_DISABLED, "APP 已禁用"); return; }
                    int64_t ts = 0;
                    try { size_t n = 0; ts = std::stoll(timestamp, &n); if (n != timestamp.size()) ts = 0; } catch (...) { ts = 0; }
                    const int64_t now = std::time(nullptr);
                    if (ts <= 0 || ts < now - cfg.replay_window_seconds || ts > now + cfg.replay_window_seconds) { fail(zct_slms::api::ErrorCode::TIMESTAMP_BAD, "timestamp 非法或超出窗口"); return; }
                    if (nonce.empty() || nonce.size() > 128) { fail(zct_slms::api::ErrorCode::BAD_REQUEST, "nonce 必须为 1-128 字符"); return; }
                    if (app->sign_enable == 1) {
                        if (encoded.empty()) { fail(zct_slms::api::ErrorCode::SIGNATURE_BAD, "签名请求必须包含 encode"); return; }
                        const auto canonical = zct_slms::service::SecurityService::canonicalRequest(method, req_path, appid, timestamp, nonce, encoded);
                        const auto expected = zct_slms::service::SecurityService::computeSignature(canonical, app->secret);
                        if (!zct_slms::crypto::constantTimeEqual(expected, paramStr(req, "signature"))) { fail(zct_slms::api::ErrorCode::SIGNATURE_BAD, "signature 校验失败"); return; }
                    }
                    bool request_encrypted = false;
                    std::string used_dec_mode;
                    if (!encoded.empty()) {
                        const auto decoded = decryptByMode(encoded, app->dec_mode, app->dec_key);
                        if (!decoded) { fail(zct_slms::api::ErrorCode::BAD_REQUEST, "encode 解密失败"); return; }
                        auto kv = parseKvs(*decoded);
                        for (const auto* key : {"appid", "timestamp", "nonce", "signature", "encode"}) kv.erase(key);
                        (*req->attributes())["zct_slms.decoded_kv"] = std::move(kv);
                        request_encrypted = app->dec_mode != "NONE";
                        used_dec_mode = app->dec_mode;
                    }
                    if (app->sign_enable == 1) { (*req->attributes())["zct_slms.signed"] = true; (*req->attributes())["zct_slms.signed_appid"] = appid; }
                    if (!zct_slms::repo::NonceRepo::tryUseNonce(app->id, nonce, ts, cfg.replay_window_seconds)) { fail(zct_slms::api::ErrorCode::NONCE_REPLAY, "nonce 重复"); return; }

                    auto orig_cb = std::move(cb);
                    auto wrapped_cb = [
                        orig_cb = std::move(orig_cb),
                        request_encrypted,
                        used_dec_mode,
                        dec_key = app ? app->dec_key : std::string()
                    ](const drogon::HttpResponsePtr& resp) {
                        if (!request_encrypted) {
                            orig_cb(resp);
                            return;
                        }

                        const auto body = resp->body();
                        auto json = Json::Value{};
                        Json::CharReaderBuilder rb;
                        auto errs = std::string{};
                        std::string body_str(body);
                        std::istringstream iss(body_str);
                        if (Json::parseFromStream(rb, iss, &json, &errs) && json.isObject()) {
                            Json::Value wrapped;
                            if (json.isMember("code"))      wrapped["code"] = json["code"];
                            if (json.isMember("message"))   wrapped["message"] = json["message"];
                            if (json.isMember("data"))      wrapped["data"] = json["data"];
                            std::string orig_str;
                            Json::StreamWriterBuilder wb;
                            wb["indentation"] = "";
                            orig_str = Json::writeString(wb, json);

                            const auto enc = encryptByMode(orig_str, used_dec_mode, dec_key);
                            Json::Value out;
                            out["code"] = json.isMember("code") ? json["code"].asInt() : 0;
                            out["message"] = json.isMember("message") ? json["message"].asString() : "ok";
                            out["encode"] = enc;
                            auto new_body = Json::writeString(wb, out);
                            resp->setBody(new_body);
                        }
                        orig_cb(resp);
                    };
                    cb = std::move(wrapped_cb);
                }
                try{contentGuard(req);}catch(const std::invalid_argument& e){cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION,e.what())));return;}
                fn(req, std::move(cb));
                auto t1 = std::chrono::steady_clock::now();
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
                zct_slms::apiLog("<- {} {} done in {}ms", method, req_path, ms);
            } catch (const std::exception& e) {
                zct_slms::logger().FATAL("Handler exception on {} {}: {}", method, path, e.what());
                auto resp = drogon::HttpResponse::newHttpJsonResponse(
                    zct_slms::api::makeFail(
                        zct_slms::api::ErrorCode::INTERNAL,
                        std::string("internal: ") + e.what()
                    )
                );
                cb(resp);
            }
        };
    }
}

#endif // ZCT_SLMS_API_V1_COMMON





