// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "services/security_identity.hpp"

namespace zct_slms::heartbeat {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    inline void schema() {
        static std::once_flag once;
        std::call_once(
            once,
            [] {
                zct_slms::db::Database::instance().exec(
                    "CREATE TABLE IF NOT EXISTS license_heartbeats (license_id BIGINT "
                    "PRIMARY KEY REFERENCES licenses(id) ON DELETE CASCADE,last_seen "
                    "BIGINT NOT NULL,ip TEXT NOT NULL,device_fingerprint TEXT NOT "
                    "NULL,requests BIGINT NOT NULL DEFAULT 1)"
                );
            }
        );
    }

    inline Json config(int64_t app) {
        auto raw = zct_slms::repo::ConfigRepo::get("heartbeat:" + std::to_string(app), "");
        Json out = raw.empty() ? Json(::Json::objectValue) : parse(raw);
        if (!out.isMember("enabled"))
            out["enabled"] = false;
        if (!out.isMember("interval_seconds"))
            out["interval_seconds"] = 30;
        if (!out.isMember("timeout_seconds"))
            out["timeout_seconds"] = 90;
        return out;
    }

    inline void record(
        int64_t app,
        const std::string& license,
        const std::string& ip,
        const std::string& device
    ) {
        schema();
        auto lic = zct_slms::repo::LicenseRepo::findByAppAndLicense(app, license);
        if (!lic)
            return;
        zct_slms::db::Database::instance().execParams(
            "INSERT INTO "
            "license_heartbeats(license_id,last_seen,ip,device_fingerprint,requests) "
            "VALUES (?,?,?,?,1) ON CONFLICT(license_id) DO UPDATE SET last_seen = "
            "excluded.last_seen,ip = excluded.ip,device_fingerprint = "
            "excluded.device_fingerprint,requests = license_heartbeats.requests + 1",
            lic->id,
            now(),
            ip,
            device.empty() ? "" : zct_slms::crypto::sha256Hex(device)
        );
    }

    inline void settings(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req, req->method() == drogon::Post);
            auto app = zct_slms::repo::AppRepo::findByAppid(common::paramStr(req, "app_id"));
            if (!app || a.user_type != "ADMIN" &&
                (a.user_type != "USER" || app->owner_id != a.user_id))
                throw std::runtime_error("无权管理此应用的心跳验证");
            auto cfg = config(app->id);
            if (req->method() == drogon::Post) {
                auto body = req->getJsonObject();
                if (!body || !(*body)["enabled"].isBool())
                    throw std::runtime_error("心跳配置无效");
                auto interval = common::paramI64(req, "interval_seconds", 30),
                     timeout = common::paramI64(req, "timeout_seconds", 90);
                if (interval < 5 || interval > 3600 || timeout < interval * 2 ||
                    timeout > 86400)
                    throw std::runtime_error(
                        "间隔须为5–3600秒，超时须至少为间隔的两倍且不超过86400秒"
                    );
                cfg["enabled"] = (*body)["enabled"];
                cfg["interval_seconds"] = ::Json::Int64(interval);
                cfg["timeout_seconds"] = ::Json::Int64(timeout);
                zct_slms::repo::ConfigRepo::set(
                    "heartbeat:" + std::to_string(app->id),
                    json(cfg),
                    now()
                );
            }
            cfg["endpoint"] = "/api/v1/client/license/heartbeat";
            cfg["records"] = Json(::Json::arrayValue);
            for (const auto& row : zct_slms::db::Database::instance().queryParams(
                     "SELECT "
                     "l.id,l.license,l.status,l.banned,l.expires_at,h.last_seen,h.ip,h."
                     "device_fingerprint,h.requests FROM licenses l LEFT JOIN "
                     "license_heartbeats h ON h.license_id = l.id WHERE l.app_id = ? "
                     "AND l.status != 'deleted' ORDER BY COALESCE(h.last_seen,0) "
                     "DESC,l.id DESC LIMIT 1000",
                     app->id
                 )) {
                Json item;
                for (auto key : {"id", "last_seen", "requests"})
                    item[key] = ::Json::Int64(zct_slms::repo::getInt(row, key));
                auto license = zct_slms::repo::getStr(row, "license");
                item["reference"] = license.size() > 10
                                        ? "…" + license.substr(license.size() - 10)
                                        : license;
                item["ip"] = zct_slms::repo::getStr(row, "ip");
                item["device_fingerprint"] = zct_slms::repo::getStr(row, "device_fingerprint");
                auto last = zct_slms::repo::getInt(row, "last_seen");
                const bool invalid = zct_slms::repo::getInt(row, "banned") != 0 ||
                                     zct_slms::repo::getStr(row, "status") == "expired" ||
                                     (zct_slms::repo::getInt(row, "expires_at") != -1 &&
                                      zct_slms::service::LicenseService::calcRemaining(
                                          zct_slms::repo::getInt(row, "expires_at")
                                      ) == 0);
                item["state"] = invalid
                                    ? "INVALID"
                                    : !cfg["enabled"].asBool()
                                    ? "DISABLED"
                                    : last == 0
                                    ? "WAITING"
                                    : now() - last <= cfg["timeout_seconds"].asInt64()
                                    ? "ONLINE"
                                    : "OFFLINE";
                cfg["records"].append(item);
            }
            ok(cb, cfg);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }
} // namespace zct_slms::heartbeat
