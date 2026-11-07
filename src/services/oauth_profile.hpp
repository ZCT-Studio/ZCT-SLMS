// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "services/identity_service.hpp"
#include "services/object_storage.hpp"

namespace zct_slms::identity {
    inline bool safeAvatarUrl(const std::string& value) {
        return value.starts_with("https://") && value.size() <= 2048 && value.size() > 8 && value.find_first_of("\r\n\t \\") == std::string::npos;
    }

    inline bool allowedAvatarHost(const std::string& host) {
        const auto sub = [&](const std::string& suffix) { return host == suffix || (host.size() > suffix.size() && host.ends_with("." + suffix)); };
        return host == "avatars.githubusercontent.com" || host == "cdn.discordapp.com" || host == "gitlab.com" || sub("googleusercontent.com");
    }

    inline size_t avatarWrite(char* data, size_t size, size_t count, void* target) {
        auto* out = static_cast<std::string*>(target);
        const auto n = size * count;
        if (n > 1048576 || out->size() > 1048576 - n) return 0;
        out->append(data, n);
        return n;
    }

    inline std::string downloadAvatar(const std::string& url) {
        if (!safeAvatarUrl(url)) return "";
        auto* parsed = curl_url();
        if (!parsed) return "";
        char* host = nullptr;
        char* user = nullptr;
        char* port = nullptr;
        const auto valid = curl_url_set(parsed, CURLUPART_URL, url.c_str(), 0) == CURLUE_OK &&
                           curl_url_get(parsed, CURLUPART_HOST, &host, 0) == CURLUE_OK && host && allowedAvatarHost(host) &&
                           curl_url_get(parsed, CURLUPART_USER, &user, 0) != CURLUE_OK &&
                           (curl_url_get(parsed, CURLUPART_PORT, &port, 0) != CURLUE_OK || (port && std::string(port) == "443"));
        if (host)curl_free(host);
        if (user)curl_free(user);
        if (port)curl_free(port);
        curl_url_cleanup(parsed);
        if (!valid)return "";
        Curl c;
        std::string body;
        curl_easy_setopt(c.h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c.h, CURLOPT_PROTOCOLS_STR, "https");
        curl_easy_setopt(c.h, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(c.h, CURLOPT_CONNECTTIMEOUT, 3L);
        curl_easy_setopt(c.h, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(c.h, CURLOPT_WRITEFUNCTION, avatarWrite);
        curl_easy_setopt(c.h, CURLOPT_WRITEDATA, &body);
        if (curl_easy_perform(c.h) != CURLE_OK)return "";
        long status = 0;
        curl_easy_getinfo(c.h, CURLINFO_RESPONSE_CODE, &status);
        if (status != 200)return "";
        std::string mime;
        if (body.size() >= 8 && body.compare(0, 8, std::string("\x89PNG\r\n\x1a\n", 8)) == 0)mime = "image/png";
        else if (body.size() >= 3 && (unsigned char)body[0] == 255 && (unsigned char)body[1] == 216 && (unsigned char)body[2] == 255)mime = "image/jpeg";
        else if (body.size() >= 12 && body.substr(0, 4) == "RIFF" && body.substr(8, 4) == "WEBP")mime = "image/webp";
        if (mime.empty())return "";
        return "data:" + mime + ";base64," + zct_slms::crypto::base64Encode(body);
    }

    inline void avatarSchema() {
        zct_slms::db::Database::instance().exec("CREATE TABLE IF NOT EXISTS avatar_objects(id VARCHAR(64) PRIMARY KEY,location TEXT NOT NULL,mime VARCHAR(32) NOT NULL)");
    }

    inline std::string persistAvatar(const std::string& avatar) {
        if (avatar.empty()) return avatar;
        if (safeAvatarUrl(avatar)) {
            const auto image = downloadAvatar(avatar);
            if (image.empty()) return avatar;
            return persistAvatar(image);
        }
        if (!avatar.starts_with("data:image/")) return avatar;
        const auto comma = avatar.find(',');
        if (comma == std::string::npos) throw std::runtime_error("Invalid avatar");
        const auto mime = avatar.substr(5, avatar.find(';') - 5);
        if (mime != "image/png" && mime != "image/jpeg" && mime != "image/webp") throw std::runtime_error("Invalid avatar format");
        const auto bytes = zct_slms::crypto::base64Decode(avatar.substr(comma + 1));
        if (bytes.empty() || bytes.size() > static_cast<size_t>(zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes", 1048576))) throw std::runtime_error("Avatar too large");
        avatarSchema();
        const auto id = zct_slms::crypto::randomHex(32);
        const auto location = zct_slms::object_storage::put("avatars/" + id, bytes);
        if (zct_slms::object_storage::get(location) != bytes) throw std::runtime_error("Avatar storage verification failed");
        zct_slms::db::Database::instance().execParams("INSERT INTO avatar_objects(id,location,mime) VALUES(?,?,?)", id, location, mime);
        return "/api/v1/media/avatar?id=" + id;
    }

    inline void migrateAvatars() {
        avatarSchema();
        auto& db = zct_slms::db::Database::instance();
        for (const auto& row : db.queryParams("SELECT key,value FROM system_config WHERE key LIKE 'profile:%:avatar' OR key LIKE 'identity_profile_avatar:%'")) {
            const auto value = zct_slms::repo::getStr(row, "value");
            if (value.starts_with("data:image/")) db.execParams(
                "UPDATE system_config SET value=? WHERE key=? AND value=?",
                persistAvatar(value),
                zct_slms::repo::getStr(row, "key"),
                value
            );
        }
    }

    inline void readAvatar(const Req& req, Callback&& cb) {
        try {
            const auto id = common::paramStr(req, "id");
            zct_slms::object_storage::validateKey("avatars/" + id);
            auto rows = zct_slms::db::Database::instance().queryParams("SELECT location,mime FROM avatar_objects WHERE id=?", id);
            if (rows.empty()) throw std::runtime_error("Avatar not found");
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setBody(zct_slms::object_storage::get(zct_slms::repo::getStr(rows[0], "location")));
            response->setContentTypeString(zct_slms::repo::getStr(rows[0], "mime"));
            response->addHeader("Cache-Control", "public, max-age=86400, immutable");
            response->addHeader("X-Content-Type-Options", "nosniff");
            cb(response);
        } catch (const std::exception&) {
            auto r = drogon::HttpResponse::newHttpResponse();
            r->setStatusCode(drogon::k404NotFound);
            cb(r);
        }
    }

    inline bool profileAvatarAllowed(const std::string& avatar, const std::string& original) {
        if (avatar.empty()) return true;
        if (avatar == original && (safeAvatarUrl(original) || original.starts_with("/api/v1/media/avatar?id="))) return true;
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
        if (safeAvatarUrl(avatar)) {
            const auto local = downloadAvatar(avatar);
            if (!local.empty()) avatar = local;
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
