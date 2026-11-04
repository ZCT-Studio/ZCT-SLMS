// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/identity_service.hpp"

namespace zct_slms::identity {
    inline bool safeAvatarUrl(const std::string& value) {
        return value.starts_with("https://") && value.size() <= 2048 && value.size() > 8 && value.find_first_of("\r\n\t \\") == std::string::npos;
    }

    inline bool profileAvatarAllowed(const std::string& avatar, const std::string& original) {
        if (avatar.empty()) return true;
        if (avatar == original && safeAvatarUrl(original)) return true;
        const auto comma = avatar.find(',');
        if (!(avatar.starts_with("data:image/png;base64,") || avatar.starts_with("data:image/jpeg;base64,") || avatar.starts_with("data:image/webp;base64,")) || comma ==
            std::string::npos)
            return false;
        const auto limit = zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes", 1048576);
        if (avatar.size() > static_cast<size_t>(limit * 4 / 3 + 256) || avatar.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", comma + 1) !=
            std::string::npos)
            return false;
        try { return zct_slms::crypto::base64Decode(avatar.substr(comma + 1)).size() <= static_cast<size_t>(limit); } catch (...) { return false; }
    }

    inline std::string profileText(const Json& profile, std::initializer_list<const char*> fields) {
        for (auto field : fields) if (profile[field].isString() && !profile[field].asString().empty()) return profile[field].asString();
        return "";
    }

    inline Json oauthProfile(const std::string& provider, const Json& profile) {
        Json out;
        auto username = profileText(profile, {"preferred_username", "login", "username"});
        if (provider == "microsoft") {
            auto at = username.find('@');
            if (at != std::string::npos) username.resize(at);
        }
        username.erase(
            std::remove_if(
                username.begin(),
                username.end(),
                [](unsigned char c) { return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'); }
            ),
            username.end()
        );
        if (username.size() > 64) username.resize(64);
        if (username.size() < 3) username.clear();
        out["username"] = username;
        auto nickname = profileText(profile, {"global_name", "name", "displayName", "preferred_username", "login", "username"});
        if (nickname.empty()) nickname = "用户";
        // Trim at a UTF-8 boundary.
        if (nickname.size() > 96) {
            size_t end = 96;
            while (end && (static_cast<unsigned char>(nickname[end]) & 0xc0) == 0x80) --end;
            nickname.resize(end);
        }
        out["nickname"] = nickname;
        auto avatar = profileText(profile, {"_avatar", "picture", "avatar_url"});
        if (provider == "discord" && profile["id"].isString() && profile["avatar"].isString()) {
            const auto id = profile["id"].asString(), hash = profile["avatar"].asString();
            if (std::regex_match(id, std::regex("[0-9]+")) && std::regex_match(hash, std::regex("[A-Za-z0-9_]+")))
                avatar = "https://cdn.discordapp.com/avatars/" + id + "/" + hash + ".png?size=128";
        }
        if (provider == "discord" && avatar.empty() && profile["id"].isString()) {
            try {
                const auto discriminator = profile.get("discriminator", "0").asString();
                const auto index = discriminator == "0" ? (std::stoull(profile["id"].asString()) >> 22) % 6 : std::stoull(discriminator) % 5;
                avatar = "https://cdn.discordapp.com/embed/avatars/" + std::to_string(index) + ".png";
            } catch (const std::exception&) {}
        }
        out["avatar"] = safeAvatarUrl(avatar) || avatar.starts_with("data:image/") ? avatar : "";
        return out;
    }

    inline std::string microsoftAvatar(const std::string& access) {
        // Fetch only the fixed Graph endpoint, never a user-supplied URL or redirect.
        Curl c;
        std::string body;
        curl_easy_setopt(c.h, CURLOPT_URL, "https://graph.microsoft.com/v1.0/me/photos/96x96/$value");
        curl_easy_setopt(c.h, CURLOPT_PROTOCOLS_STR, "https");
        curl_easy_setopt(c.h, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(c.h, CURLOPT_WRITEFUNCTION, writeData);
        curl_easy_setopt(c.h, CURLOPT_WRITEDATA, &body);
        c.header("Authorization: Bearer " + access);
        curl_easy_setopt(c.h, CURLOPT_HTTPHEADER, c.headers);
        if (curl_easy_perform(c.h) != CURLE_OK) return "";
        long status = 0;
        curl_easy_getinfo(c.h, CURLINFO_RESPONSE_CODE, &status);
        char* type = nullptr;
        curl_easy_getinfo(c.h, CURLINFO_CONTENT_TYPE, &type);
        std::string mime = type ? type : "";
        if (status != 200 || body.empty() || body.size() > static_cast<size_t>(zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes", 1048576)) || (
                mime != "image/jpeg" && mime != "image/png" && mime != "image/webp"))
            return "";
        return "data:" + mime + ";base64," + zct_slms::crypto::base64Encode(body);
    }
}
