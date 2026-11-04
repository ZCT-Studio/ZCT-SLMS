// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once
#include "api/v1/uih.h"

namespace zct_slms::inside::api::v1::auth::password {
    inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr &)>&& cb) {
        namespace c = zct_slms::inside::api::v1::common;
        const auto auth = zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
        auto fail = [&](int code, const char* m) { cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code, m))); };
        if (!auth.success || (auth.user_type != "USER" && auth.user_type != "SUBUSER" && auth.user_type != "SUPPORT")) {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "需要用户登录");
            return;
        }
        const auto old = c::paramStr(req, "current_password"), pass = c::paramStr(req, "new_password");
        if (pass.size() < 12 || pass.size() > 256) {
            fail(zct_slms::api::ErrorCode::VALIDATION, "新密码须为 12–256 字节");
            return;
        }
        const std::string table = auth.user_type == "USER" ? "users" : auth.user_type == "SUPPORT" ? "admins" : "sub_users";
        auto rows = zct_slms::db::Database::instance().queryParams("SELECT password_hash, salt FROM " + table + " WHERE id = ?", auth.user_id);
        if (rows.empty() || !c::sensitiveAuthorization(req, old)) {
            fail(zct_slms::api::ErrorCode::UNAUTHORIZED, "当前密码错误");
            return;
        }
        auto hp = zct_slms::service::hashPassword(pass);
        if (hp.hash.empty()) {
            fail(zct_slms::api::ErrorCode::INTERNAL, "密码处理失败");
            return;
        }
        auto& db = zct_slms::db::Database::instance();
        const auto ok = db.transaction(
            [&] {
                db.execParams(
                    "UPDATE " + table + " SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?",
                    hp.hash,
                    hp.salt,
                    static_cast<int64_t>(std::time(nullptr)),
                    auth.user_id
                );
                db.execParams("UPDATE sessions SET revoked = 1 WHERE user_type = ? AND user_id = ?", auth.user_type, auth.user_id);
                return true;
            }
        );
        if (!ok) {
            fail(zct_slms::api::ErrorCode::INTERNAL, "修改密码失败");
            return;
        }
        cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
    }
}
