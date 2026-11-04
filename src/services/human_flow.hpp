// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "api/v1/auth/factors.hpp"
#include "services/portal_auth.hpp"

namespace zct_slms::human {
    template <class Fn> inline auto passkeyProtected(Fn fn) {
        return [fn](const Req& req, Callback&& cb) {
            if (zct_slms::factors::settings().get("captcha_for_passkey", false).asBool()) {
                auto securedHandler = secured(fn);
                securedHandler(req, std::move(cb));
            } else fn(req, std::move(cb));
        };
    }

    template <class Fn> inline auto factorProtected(Fn fn) {
        return [fn](const Req& req, Callback&& callback) {
            background(
                req,
                std::move(callback),
                [fn](auto req, const Callback& cb) {
                    try {
                        const auto id = common::paramStr(req, "challenge_id");
                        const auto method = req->path().ends_with("/oauth/start") ? common::paramStr(req, "provider") : common::paramStr(req, "method");
                        const auto cfg = zct_slms::factors::settings();
                        const auto policyHash = zct_slms::crypto::sha256Hex(json(cfg));
                        bool required = false;
                        {
                            std::lock_guard lock(zct_slms::portal_auth::guard);
                            auto& p = zct_slms::portal_auth::pending(id, common::clientIp(req), common::clientUa(req), false);
                            required = p.session.get("_human_policy", "").asString() != policyHash &&
                                       ((p.kind == "authorize" && (method == "passkey"
                                                                       ? cfg.get("captcha_for_passkey", false).asBool()
                                                                       : cfg.get("captcha_for_authorization", false).asBool())) ||
                                        (p.kind == "secondary" && cfg.get("captcha_for_2fa", false).asBool() && (
                                             method != "passkey" || cfg.get("captcha_for_passkey", false).asBool())));
                        }
                        if (required) {
                            validate(req);
                            std::lock_guard lock(zct_slms::portal_auth::guard);
                            auto& p = zct_slms::portal_auth::pending(id, common::clientIp(req), common::clientUa(req), false);
                            p.session["_human_policy"] = policyHash;
                        }
                        auto next = cb;
                        fn(req, std::move(next));
                    } catch (const std::exception& e) { fail(cb, e.what()); }
                }
            );
        };
    }
}
