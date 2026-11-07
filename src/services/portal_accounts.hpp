// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "services/vouchers.hpp"
#include "services/oauth_profile.hpp"

namespace zct_slms::portal {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    inline std::string table(const std::string& role) {
        if (role == "ADMIN" || role == "SUPPORT")
            return "admins";
        if (role == "USER")
            return "users";
        if (role == "SUBUSER")
            return "sub_users";
        throw std::runtime_error("账号角色无效");
    }

    inline bool forceRequired(const std::string& role, int64_t id) {
        return zct_slms::repo::ConfigRepo::getBool(
                   "force_password:" + role + ":" + std::to_string(id),
                   false
               ) ||
               (role == "ADMIN" &&
                !zct_slms::repo::ConfigRepo::getBool(
                    "admin_initial_setup_done:" + std::to_string(id),
                    true
                )) ||
               (role == "USER" &&
                zct_slms::repo::ConfigRepo::getBool(
                    "identity_password_pending:" + std::to_string(id),
                    false
                ) &&
                !zct_slms::repo::ConfigRepo::getBool("identity_profile_done:" + std::to_string(id), false));
    }

    inline void onboarding(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto a = zct_slms::factors::auth(req);
                    bool initial =
                        a.user_type == "ADMIN" &&
                        !zct_slms::repo::ConfigRepo::getBool(
                            "admin_initial_setup_done:" + std::to_string(a.user_id),
                            true
                        );
                    Json out;
                    out["required"] = forceRequired(a.user_type, a.user_id);
                    out["initial_admin"] = initial;
                    const auto profile_key = "identity_profile_done:" + std::to_string(a.user_id);
                    const bool profile_setup = a.user_type == "USER" &&
                                               zct_slms::repo::ConfigRepo::getBool("identity_password_pending:" + std::to_string(a.user_id), false) &&
                                               !zct_slms::repo::ConfigRepo::getBool(profile_key, false);
                    out["profile_setup"] = profile_setup;
                    if (profile_setup && !zct_slms::repo::ConfigRepo::getBool("force_password:USER:" + std::to_string(a.user_id), false)) {
                        auto user = zct_slms::repo::UserRepo::findById(a.user_id);
                        if (!user) throw std::runtime_error("账号不存在");
                        out["username"] = zct_slms::repo::ConfigRepo::get("identity_profile_username:" + std::to_string(a.user_id), "");
                        out["nickname"] = zct_slms::repo::ConfigRepo::get("identity_profile_nickname:" + std::to_string(a.user_id), user->display_name);
                        const auto suggested_avatar = zct_slms::repo::ConfigRepo::get("identity_profile_avatar:" + std::to_string(a.user_id), "");
                        out["avatar"] = suggested_avatar;
                        out["max_avatar_bytes"] = ::Json::Int64(zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes", 1048576));
                        if (req->method() == drogon::Post) {
                            const auto username = common::paramStr(req, "username"),
                                       nickname = common::paramStr(req, "nickname"),
                                       password = common::paramStr(req, "new_password");
                            if (!std::regex_match(username, std::regex("[A-Za-z0-9_.-]{3,64}")) ||
                                username == user->username || nickname.empty() || nickname.size() > 96)
                                throw std::runtime_error("请设置新的用户名和昵称");
                            if (!password.empty() && (password.size() < 12 || password.size() > 256))
                                throw std::runtime_error("密码须为 12–256 字节，或留空暂不设置");
                            const auto avatar = common::paramStr(req, "avatar", suggested_avatar);
                            if (!profileAvatarAllowed(avatar, suggested_avatar)) throw std::runtime_error("头像超过大小限制或格式不支持");
                            zct_slms::moderation::check(username);
                            zct_slms::moderation::check(nickname);
                            const auto hp = password.empty() ? zct_slms::service::HashedPassword{} : zct_slms::service::hashPassword(password);
                            auto& db = zct_slms::db::Database::instance();
                            if (!db.transaction(
                                [&] {
                                    if (zct_slms::repo::ConfigRepo::getBool(profile_key, false)) return false;
                                    if (zct_slms::repo::UserRepo::findByUsername(username)) throw std::runtime_error("用户名已存在");
                                    db.execParams("UPDATE users SET username = ?,display_name = ?,updated_at = ? WHERE id = ?", username, nickname, now(), a.user_id);
                                    zct_slms::repo::ConfigRepo::set("profile:USER:" + std::to_string(a.user_id) + ":nickname", nickname, now());
                                    zct_slms::repo::ConfigRepo::set("profile:USER:" + std::to_string(a.user_id) + ":avatar", zct_slms::identity::persistAvatar(avatar), now());
                                    if (!password.empty()) {
                                        db.execParams("UPDATE users SET password_hash = ?,salt = ? WHERE id = ?", hp.hash, hp.salt, a.user_id);
                                        zct_slms::repo::ConfigRepo::set("identity_password_pending:" + std::to_string(a.user_id), "0", now());
                                    }
                                    zct_slms::repo::ConfigRepo::set(profile_key, "1", now());
                                    return true;
                                }
                            ))
                                throw std::runtime_error("资料已设置，请刷新页面");
                            out["required"] = false;
                            out["username"] = username;
                            out["nickname"] = nickname;
                            out["login_required"] = false;
                        }
                        ok(cb, out);
                        return;
                    }
                    out["profile_setup"] = false;
                    if (req->method() == drogon::Post) {
                        if (!out["required"].asBool())
                            throw std::runtime_error("请在账号设置中修改密码");
                        auto password = common::paramStr(req, "new_password"),
                             username = common::paramStr(req, "username"),
                             nickname = common::paramStr(req, "nickname");
                        if (password.size() < 12 || password.size() > 256)
                            throw std::runtime_error("新密码须为 12–256 字节");
                        if (initial) {
                            if (!std::regex_match(username, std::regex("[A-Za-z0-9_.-]{3,64}")) ||
                                username == a.username || nickname.empty() ||
                                nickname.size() > 96)
                                throw std::runtime_error("首次登录请设置新的用户名和昵称");
                            zct_slms::moderation::check(username);
                            zct_slms::moderation::check(nickname);
                        }
                        auto hp = zct_slms::service::hashPassword(password);
                        auto& db = zct_slms::db::Database::instance();
                        auto rows = db.queryParams(
                            "SELECT password_hash,salt FROM " +
                            table(a.user_type) + " WHERE id = ?",
                            a.user_id
                        );
                        if (rows.empty() ||
                            zct_slms::service::verifyPassword(
                                password,
                                zct_slms::repo::getStr(rows[0], "password_hash"),
                                zct_slms::repo::getStr(rows[0], "salt")
                            ))
                            throw std::runtime_error("请设置与临时密码不同的新密码");
                        bool changed = db.transaction(
                            [&] {
                                if (!forceRequired(a.user_type, a.user_id))
                                    return false;
                                db.execParams(
                                    "UPDATE " + table(a.user_type) +
                                    " SET password_hash = ?,salt = ?,updated_at = ? WHERE id = ?",
                                    hp.hash,
                                    hp.salt,
                                    now(),
                                    a.user_id
                                );
                                if (initial) {
                                    auto existing = zct_slms::repo::AdminRepo::findByUsername(username);
                                    if (existing && existing->id != a.user_id)
                                        throw std::runtime_error("用户名已存在");
                                    db.execParams(
                                        "UPDATE admins SET username = ?,display_name = ? WHERE id = ?",
                                        username,
                                        nickname,
                                        a.user_id
                                    );
                                    zct_slms::repo::ConfigRepo::set(
                                        "profile:ADMIN:" + std::to_string(a.user_id) + ":nickname",
                                        nickname,
                                        now()
                                    );
                                    zct_slms::repo::ConfigRepo::set(
                                        "admin_initial_setup_done:" +
                                        std::to_string(a.user_id),
                                        "1",
                                        now()
                                    );
                                }
                                zct_slms::repo::ConfigRepo::set(
                                    "force_password:" + a.user_type + ":" +
                                    std::to_string(a.user_id),
                                    "0",
                                    now()
                                );
                                if (a.user_type == "USER")
                                    zct_slms::repo::ConfigRepo::set(
                                        "identity_password_pending:" +
                                        std::to_string(a.user_id),
                                        "0",
                                        now()
                                    );
                                db.execParams(
                                    "UPDATE sessions SET revoked = 1 WHERE user_type = ? "
                                    "AND user_id = ?",
                                    a.user_type,
                                    a.user_id
                                );
                                return true;
                            }
                        );
                        if (!changed)
                            throw std::runtime_error("密码已设置，请重新登录");
                        out["required"] = false;
                        out["login_required"] = true;
                    }
                    ok(cb, out);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void staff(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            if (a.user_type != "ADMIN")
                throw std::runtime_error("需要管理员登录");
            if (req->method() == drogon::Post) {
                if (!adminPassword(req))
                    throw std::runtime_error("当前管理员密码错误");
                auto username = common::paramStr(req, "username"),
                     nickname = common::paramStr(req, "nickname"),
                     password = common::paramStr(req, "initial_password");
                if (!std::regex_match(username, std::regex("[A-Za-z0-9_.-]{3,64}")) ||
                    nickname.empty() || nickname.size() > 96 || password.size() < 12 ||
                    password.size() > 256)
                    throw std::runtime_error("用户名、昵称或初始密码格式无效");
                zct_slms::moderation::check(username);
                zct_slms::moderation::check(nickname);
                auto hp = zct_slms::service::hashPassword(password);
                auto& db = zct_slms::db::Database::instance();
                bool success = db.transaction(
                    [&] {
                        if (zct_slms::repo::AdminRepo::findByUsername(username))
                            throw std::runtime_error("用户名已存在");
                        auto id = zct_slms::repo::AdminRepo::insert(
                            username,
                            hp.hash,
                            hp.salt,
                            nickname,
                            now()
                        );
                        zct_slms::repo::ConfigRepo::set(
                            "staff_role:" + std::to_string(id),
                            "SUPPORT",
                            now()
                        );
                        zct_slms::repo::ConfigRepo::set(
                            "force_password:SUPPORT:" + std::to_string(id),
                            "1",
                            now()
                        );
                        return true;
                    }
                );
                if (!success)
                    throw std::runtime_error("创建失败");
            }
            Json out(::Json::arrayValue);
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT id,username,display_name,status FROM admins ORDER BY id DESC"
            );
            for (auto& row : rows) {
                auto id = zct_slms::repo::getInt(row, "id");
                if (zct_slms::repo::ConfigRepo::get(
                        "staff_role:" + std::to_string(id),
                        "ADMIN"
                    ) != "SUPPORT")
                    continue;
                Json item;
                item["id"] = ::Json::Int64(id);
                item["username"] = zct_slms::repo::getStr(row, "username");
                item["nickname"] = zct_slms::repo::getStr(row, "display_name");
                item["status"] = zct_slms::repo::getInt(row, "status");
                out.append(item);
            }
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void moderationSettings(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            if (a.user_type != "ADMIN")
                throw std::runtime_error("需要管理员登录");
            if (req->method() == drogon::Post) {
                if (!adminPassword(req))
                    throw std::runtime_error("当前管理员密码错误");
                auto rules = common::paramStr(req, "rules");
                if (rules.size() > 1048576)
                    throw std::runtime_error("屏蔽词总长度不能超过 1048576 字节");
                std::istringstream in(rules);
                std::string line;
                int count = 0;
                size_t total = 0;
                while (std::getline(in, line)) {
                    if (line.empty())
                        continue;
                    if (line.size() > 256 || ++count > 20000 ||
                        (total += line.size()) > 1048576)
                        throw std::runtime_error("最多 20000 条屏蔽词，每条不超过 256 字节");
                }
                zct_slms::repo::ConfigRepo::set("moderation_rules", rules, now());
                zct_slms::repo::ConfigRepo::set(
                    "moderation_enabled",
                    common::paramStr(req, "enabled", "1") == "1" ? "1" : "0",
                    now()
                );
                zct_slms::moderation::matcher();
            }
            Json out;
            out["rules"] = zct_slms::repo::ConfigRepo::get("moderation_rules", "");
            out["enabled"] = zct_slms::repo::ConfigRepo::getBool("moderation_enabled", true);
            out["engine"] = "ZACLib";
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void review(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            if (a.user_type != "ADMIN" && a.user_type != "SUPPORT")
                throw std::runtime_error("需要管理员或支持账号登录");
            auto& db = zct_slms::db::Database::instance();
            Json out;
            out["users"] = Json(::Json::arrayValue);
            for (auto& row : db.queryParams(
                     "SELECT id,username FROM users ORDER BY id DESC LIMIT 1000"
                 )) {
                Json item;
                item["id"] = ::Json::Int64(zct_slms::repo::getInt(row, "id"));
                item["username"] = zct_slms::repo::getStr(row, "username");
                item["role"] = "USER";
                out["users"].append(item);
            }
            for (auto& row : db.queryParams(
                     "SELECT id,username FROM sub_users ORDER BY id DESC LIMIT 1000"
                 )) {
                Json item;
                item["id"] = ::Json::Int64(zct_slms::repo::getInt(row, "id"));
                item["username"] = zct_slms::repo::getStr(row, "username");
                item["role"] = "SUBUSER";
                out["users"].append(item);
            }
            out["apps"] = Json(::Json::arrayValue);
            auto matcher = zct_slms::moderation::matcher();
            for (auto& row : db.queryParams(
                     "SELECT a.id,a.appid,a.name,a.description,a.notice,u.username "
                     "FROM apps a JOIN users u ON u.id = a.owner_id ORDER BY a.id DESC "
                     "LIMIT 1000"
                 )) {
                Json item;
                item["id"] = ::Json::Int64(zct_slms::repo::getInt(row, "id"));
                for (auto key : {"appid", "name", "description", "notice", "username"})
                    item[key] = zct_slms::repo::getStr(row, key);
                item["flagged"] = matcher->Do(
                    zct_slms::moderation::lower(
                        item["name"].asString() + "\n" + item["description"].asString() +
                        "\n" + item["notice"].asString()
                    )
                );
                item["versions"] = Json(::Json::arrayValue);
                for (auto& version : db.queryParams(
                         "SELECT "
                         "v.version,v.changelog,v.minimum_version,v.download_url,v.file_"
                         "hash,v.hash_algorithm,v.release_time,c.channel FROM "
                         "update_versions v JOIN update_channels c ON c.id = "
                         "v.channel_id "
                         "WHERE c.app_id = ? ORDER BY v.id DESC LIMIT 100",
                         zct_slms::repo::getInt(row, "id")
                     )) {
                    Json v;
                    for (auto key : {
                             "version",
                             "changelog",
                             "minimum_version",
                             "channel",
                             "download_url",
                             "file_hash",
                             "hash_algorithm"
                         })
                        v[key] = zct_slms::repo::getStr(version, key);
                    v["release_time"] =
                        ::Json::Int64(zct_slms::repo::getInt(version, "release_time"));
                    item["versions"].append(v);
                }
                out["apps"].append(item);
            }
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }
} // namespace zct_slms::portal
