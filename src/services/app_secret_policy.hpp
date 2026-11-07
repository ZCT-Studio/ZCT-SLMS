// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "api/v1/uih.h"

namespace zct_slms::service {
    inline bool repeatAppSecret() {
        return zct_slms::repo::ConfigRepo::getBool(
            "app_secret_reveal_allowed",
            zct_slms::AppConfig::instance().security().app_secret_reveal_allowed
        );
    }

    inline std::string secretSeenKey(const zct_slms::models::App& app) {
        return "app_secret_seen:" + std::to_string(app.id) + ":" +
               zct_slms::crypto::sha256Hex(app.secret);
    }

    inline bool appSecretAvailable(const zct_slms::models::App& app) {
        return repeatAppSecret() ||
               !zct_slms::repo::ConfigRepo::getBool(secretSeenKey(app), false);
    }

    inline bool claimAppSecret(const zct_slms::models::App& app) {
        return zct_slms::db::Database::instance().transaction(
            [&] {
                if (!appSecretAvailable(app))
                    return false;
                zct_slms::repo::ConfigRepo::set(secretSeenKey(app), "1", std::time(nullptr));
                return true;
            }
        );
    }
} // namespace zct_slms::service
