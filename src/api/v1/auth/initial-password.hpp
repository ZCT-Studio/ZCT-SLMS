// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/identity_service.hpp"

namespace zct_slms::identity {
    inline void initialPassword(const Req& req, Callback&& cb) {
        try {
            auto auth = zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
            if (!auth.success || auth.user_type != "USER")throw std::runtime_error("需要用户登录");
            const auto key = "identity_password_pending:" + std::to_string(auth.user_id);
            Json result;
            result["required"] = zct_slms::repo::ConfigRepo::getBool(key, false);
            if (req->method() == drogon::Post) {
                if (!common::sensitiveAuthorization(req, common::paramStr(req, "current_password")))throw std::runtime_error("请完成身份验证");
                if (!result["required"].asBool())throw std::runtime_error("此账号已有密码，请使用修改密码功能");
                const auto password = common::paramStr(req, "new_password");
                if (password.size() < 12 || password.size() > 256)throw std::runtime_error("密码长度须为 12–256 字节");
                auto hp = zct_slms::service::hashPassword(password);
                const bool success = zct_slms::db::Database::instance().transaction(
                    [&] {
                        if (!zct_slms::repo::ConfigRepo::getBool(key, false))return false;
                        zct_slms::db::Database::instance().execParams(
                            "UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?",
                            hp.hash,
                            hp.salt,
                            now(),
                            auth.user_id
                        );
                        zct_slms::repo::ConfigRepo::set(key, "0", now());
                        zct_slms::db::Database::instance().execParams("UPDATE sessions SET revoked = 1 WHERE user_type = ? AND user_id = ?", "USER", auth.user_id);
                        return true;
                    }
                );
                if (!success)throw std::runtime_error("密码设置失败");
                result["required"] = false;
            }
            ok(cb, result);
        } catch (const std::exception& e) { fail(cb, e.what()); }
    }
}
