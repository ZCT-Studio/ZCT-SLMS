// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/account_lifecycle.hpp"
#include "services/ticket_mail.hpp"
#include <set>
#include <sstream>
#include <tuple>

namespace zct_slms::review {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    inline auto staff(const Req& req, bool sensitive = false) {
        auto a = zct_slms::factors::auth(req, sensitive);
        if (a.user_type != "ADMIN" && a.user_type != "SUPPORT")
            throw std::runtime_error("需要管理员或支持账号");
        return a;
    }

    inline Json document(int64_t id) {
        auto& db = zct_slms::db::Database::instance();
        auto rows = db.queryParams(
            "SELECT "
            "a.id,a.appid,a.owner_id,a.name,a.description,a.notice,a.dec_mode,a."
            "binding_mode,a.sign_enable,a.status,a.created_at,a.updated_at,u."
            "username FROM apps a JOIN users u ON u.id = a.owner_id WHERE a.id = ?",
            id
        );
        if (rows.empty())
            throw std::runtime_error("应用不存在");
        const auto& row = rows[0];
        Json out;
        out["id"] = ::Json::Int64(id);
        out["owner_id"] = ::Json::Int64(zct_slms::repo::getInt(row, "owner_id"));
        for (auto key : {"username", "name", "appid"})
            out[key] = zct_slms::repo::getStr(row, key);
        out["fields"] = Json(::Json::arrayValue);
        auto field = [&](
            const std::string& key,
            const std::string& label,
            const std::string& text
        ) {
            Json item;
            item["key"] = key;
            item["label"] = label;
            item["text"] = text;
            item["hash"] = zct_slms::crypto::sha256Hex(text);
            item["markable"] =
                key == "name" || key == "description" || key == "username" ||
                key == "notice" ||
                (key.starts_with("version:") && !key.ends_with(":release_time"));
            out["fields"].append(item);
        };
        for (const auto& [key, label] :
             std::vector<std::pair<std::string, std::string>>{
                 {"name", "应用名称"},
                 {"description", "应用介绍"},
                 {"username", "所有者用户名"},
                 {"notice", "公告"}
             })
            field(key, label, zct_slms::repo::getStr(row, key));
        out["_epoch"] =
            zct_slms::repo::ConfigRepo::get(
                "review_epoch:APP:USER:" + std::to_string(id),
                ""
            ) +
            zct_slms::repo::ConfigRepo::get(
                "review_epoch:USER:USER:" +
                std::to_string(out["owner_id"].asInt64()),
                ""
            );
        out["type"] = "APP";
        out["role"] = "USER";
        auto owner = zct_slms::repo::UserRepo::findById(out["owner_id"].asInt64());
        field(
            "owner_nickname",
            "所有者昵称",
            zct_slms::repo::ConfigRepo::get(
                "profile:USER:" + std::to_string(out["owner_id"].asInt64()) +
                ":nickname",
                owner ? owner->display_name : ""
            )
        );
        out["fields"][out["fields"].size() - 1]["markable"] = true;
        for (const auto& v : db.queryParams(
                 "SELECT "
                 "v.id,v.version,v.changelog,v.minimum_version,v.download_url,v.file_"
                 "hash,v.hash_algorithm,v.release_time,c.channel FROM "
                 "update_versions v JOIN update_channels c ON c.id = v.channel_id "
                 "WHERE c.app_id = ? ORDER BY v.id DESC LIMIT 500",
                 id
             )) {
            auto prefix = "version:" + std::to_string(zct_slms::repo::getInt(v, "id")) + ":";
            for (const auto& [key, label] :
                 std::vector<std::pair<std::string, std::string>>{
                     {"version", "版本号"},
                     {"changelog", "更新说明"},
                     {"minimum_version", "最低版本"},
                     {"download_url", "下载地址"},
                     {"file_hash", "文件哈希"}
                 })
                field(prefix + key, label, zct_slms::repo::getStr(v, key));
        }
        return out;
    }

    inline Json userDocument(int64_t id, const std::string& role) {
        if (role != "USER" && role != "SUBUSER")
            throw std::runtime_error("审查用户类型无效");
        auto rows = zct_slms::db::Database::instance().queryParams(
            "SELECT username,display_name FROM " + zct_slms::portal::table(role) +
            " WHERE id = ?",
            id
        );
        if (rows.empty())
            throw std::runtime_error("用户不存在");
        Json d;
        d["id"] = ::Json::Int64(id);
        d["owner_id"] = ::Json::Int64(id);
        d["_epoch"] = zct_slms::repo::ConfigRepo::get(
            "review_epoch:USER:" + role + ":" + std::to_string(id),
            ""
        );
        d["type"] = "USER";
        d["role"] = role;
        d["username"] = zct_slms::repo::getStr(rows[0], "username");
        d["name"] = d["username"];
        d["fields"] = Json(::Json::arrayValue);
        auto prefix = "profile:" + role + ":" + std::to_string(id) + ":";
        for (auto& [key, label, text] :
             std::vector<std::tuple<std::string, std::string, std::string>>{
                 {"username", "用户名", d["username"].asString()},
                 {
                     "nickname",
                     "昵称",
                     zct_slms::repo::ConfigRepo::get(
                         prefix + "nickname",
                         zct_slms::repo::getStr(rows[0], "display_name")
                     )
                 }
             }) {
            Json f;
            f["key"] = key;
            f["label"] = label;
            f["text"] = text;
            f["hash"] = zct_slms::crypto::sha256Hex(text);
            f["markable"] = true;
            d["fields"].append(f);
        }
        d["avatar"] = zct_slms::repo::ConfigRepo::get(prefix + "avatar", "");
        if (!d["avatar"].asString().empty()) {
            Json f;
            f["key"] = "avatar";
            f["label"] = "头像";
            f["text"] = "[头像违规]";
            f["hash"] = zct_slms::crypto::sha256Hex(d["avatar"].asString());
            f["markable"] = true;
            d["fields"].append(f);
        }
        return d;
    }

    inline Json requested(const Req& req, const std::string& idKey = "id") {
        auto type = common::paramStr(req, "type", "APP");
        if (type != "APP" && type != "USER")
            throw std::runtime_error("审查类型无效");
        return type == "USER"
                   ? userDocument(
                       common::paramI64(req, idKey),
                       common::paramStr(req, "role", "USER")
                   )
                   : document(common::paramI64(req, idKey));
    }

    inline std::string revision(const Json& d) {
        Json v;
        for (auto& f : d["fields"]) {
            Json a;
            a["key"] = f["key"];
            a["hash"] = f["hash"];
            v.append(a);
        }
        v.append(d.get("_epoch", ""));
        return zct_slms::crypto::sha256Hex(json(v));
    }

    inline void schema() {
        static std::once_flag once;
        std::call_once(
            once,
            [] {
                zct_slms::db::Database::instance().exec(
                    "CREATE TABLE IF NOT EXISTS content_reviews(subject_type VARCHAR(16) "
                    "NOT NULL,subject_role VARCHAR(16) NOT NULL,subject_id BIGINT NOT "
                    "NULL,approved_hash VARCHAR(64) NOT NULL,reviewer_role VARCHAR(16) NOT "
                    "NULL,reviewer_id BIGINT NOT NULL,reviewed_at BIGINT NOT NULL,PRIMARY "
                    "KEY(subject_type,subject_role,subject_id))"
                );
            }
        );
    }

    inline bool reviewed(const Json& d) {
        schema();
        auto rows = zct_slms::db::Database::instance().queryParams(
            "SELECT approved_hash FROM content_reviews WHERE subject_type = ? AND "
            "subject_role = ? AND subject_id = ?",
            d["type"].asString(),
            d["role"].asString(),
            d["id"].asInt64()
        );
        return !rows.empty() &&
               zct_slms::repo::getStr(rows[0], "approved_hash") == revision(d);
    }

    inline void approve(const Req& req, Callback&& cb) {
        try {
            auto a = staff(req);
            schema();
            auto& db = zct_slms::db::Database::instance();
            if (!db.transaction(
                [&] {
                    auto d = requested(req);
                    auto hash = revision(d);
                    if (common::paramStr(req, "revision") != hash)
                        throw std::runtime_error("内容已修改，请刷新后重新审查");
                    db.execParams(
                        "INSERT INTO "
                        "content_reviews(subject_type,subject_role,subject_id,approved_"
                        "hash,reviewer_role,reviewer_id,reviewed_at) VALUES "
                        "(?,?,?,?,?,?,?) ON "
                        "CONFLICT(subject_type,subject_role,subject_id) DO UPDATE SET "
                        "approved_hash = excluded.approved_hash,reviewer_role = "
                        "excluded.reviewer_role,reviewer_id = "
                        "excluded.reviewer_id,reviewed_at = excluded.reviewed_at",
                        d["type"].asString(),
                        d["role"].asString(),
                        d["id"].asInt64(),
                        hash,
                        a.user_type,
                        a.user_id,
                        now()
                    );
                    zct_slms::repo::AuditRepo::log(
                        a.user_type,
                        a.user_id,
                        "ApproveContent",
                        d["type"].asString(),
                        d["id"].asInt64(),
                        "",
                        "success",
                        common::clientIp(req),
                        "{}",
                        now()
                    );
                    return true;
                }
            ))
                throw std::runtime_error("审查保存失败");
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void queue(const Req& req, Callback&& cb) {
        try {
            staff(req);
            auto filter = common::paramStr(req, "status", "PENDING");
            std::set<std::string> states;
            std::stringstream ss(filter);
            std::string part;
            while (std::getline(ss, part, ',')) {
                if (part != "PENDING" && part != "REVIEWED" && part != "ALL")
                    throw std::runtime_error("审查状态无效");
                states.insert(part);
            }
            if (states.empty())
                throw std::runtime_error("请选择审查状态");
            Json out;
            out["apps"] = Json(::Json::arrayValue);
            out["users"] = Json(::Json::arrayValue);
            auto append = [&](Json d, const std::string& group) {
                bool done = reviewed(d);
                if (!states.contains("ALL") &&
                    !states.contains(done ? "REVIEWED" : "PENDING"))
                    return;
                Json item;
                for (auto k :
                     {"id", "owner_id", "name", "username", "appid", "type", "role"})
                    item[k] = d[k];
                item["review_status"] = done ? "REVIEWED" : "PENDING";
                item["revision"] = revision(d);
                std::string text;
                for (auto& f : d["fields"]) {
                    if (f["key"] == "nickname")
                        item["nickname"] = f["text"];
                    if (f["key"] == "description")
                        item["description"] = f["text"];
                    if (f["key"] != "avatar")text += f["text"].asString() + "\n";
                }
                item["flagged"] =
                    zct_slms::moderation::matcher()->Do(zct_slms::moderation::lower(text));
                out[group].append(item);
            };
            auto& db = zct_slms::db::Database::instance();
            for (auto& r : db.queryParams("SELECT id FROM apps ORDER BY id DESC"))
                append(document(zct_slms::repo::getInt(r, "id")), "apps");
            for (auto role : {"USER", "SUBUSER"})
                for (auto& r :
                     db.queryParams(
                         "SELECT id FROM " + zct_slms::portal::table(role) +
                         " ORDER BY id DESC"
                     ))
                    append(userDocument(zct_slms::repo::getInt(r, "id"), role), "users");
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void detail(const Req& req, Callback&& cb) {
        try {
            staff(req);
            auto d = requested(req);
            d["revision"] = revision(d);
            d["review_status"] = reviewed(d) ? "REVIEWED" : "PENDING";
            ok(cb, d);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void report(const Req& req, Callback&& cb) {
        try {
            auto a = staff(req);
            auto doc = requested(
                req,
                common::paramStr(req, "type", "APP") == "USER" ? "id" : "app_id"
            );
            auto body = req->getJsonObject();
            if (!body || !(*body)["marks"].isArray() || (*body)["marks"].empty() ||
                (*body)["marks"].size() > 30)
                throw std::runtime_error("请先标记1至30处疑似违规文字");
            Json marks(::Json::arrayValue);
            std::string message = "内容审查发现疑似违规信息，请核验并处理。\n";
            for (const auto& m : (*body)["marks"]) {
                auto key = m.get("field", "").asString(),
                     quote = m.get("quote", "").asString(),
                     hash = m.get("hash", "").asString();
                bool valid = false;
                if (quote.empty() || quote.size() > 1000)
                    throw std::runtime_error("单处标记最多1000字节");
                for (const auto& f : doc["fields"])
                    if (f.get("markable", false).asBool() && f["key"].asString() == key &&
                        f["hash"].asString() == hash &&
                        f["text"].asString().find(quote) != std::string::npos) {
                        Json mark;
                        mark["field"] = key;
                        mark["label"] = f["label"];
                        mark["quote"] = quote;
                        marks.append(mark);
                        message += f["label"].asString() + "：" + quote + "\n";
                        valid = true;
                        break;
                    }
                if (!valid)
                    throw std::runtime_error("应用文字已变化或标记无效，请刷新重新审查");
            }
            auto reason = common::paramStr(req, "reason");
            if (reason.size() > 3000)
                throw std::runtime_error("补充说明过长");
            message += "\n审查说明：" + reason;
            if (message.size() > 16000)
                throw std::runtime_error("标记内容过多");
            {
                std::lock_guard lock(mutex);
                prune();
                rate(
                    "review-report:" + a.user_type + std::to_string(a.user_id),
                    10,
                    3600
                );
            }
            zct_slms::tickets::schema();
            auto id = zct_slms::crypto::randomHex(16);
            Json metadata;
            metadata["app_id"] = doc["id"];
            metadata["app_name"] = doc["name"];
            metadata["marks"] = marks;
            auto& db = zct_slms::db::Database::instance();
            db.transaction(
                [&] {
                    db.execParams(
                        "INSERT INTO "
                        "support_tickets(id,category,owner_role,owner_id,title,"
                        "status,access_hash,contact_cipher,created_at,updated_at) "
                        "VALUES (?,'VIOLATION',?,?,?,'OPEN',?,?,?,?)",
                        id,
                        doc["role"].asString(),
                        doc["owner_id"].asInt64(),
                        "内容违规审查：" + doc["name"].asString(),
                        zct_slms::crypto::sha256Hex(zct_slms::crypto::randomHex(32)),
                        zct_slms::tickets::encrypted(metadata),
                        now(),
                        now()
                    );
                    db.execParams(
                        "INSERT INTO "
                        "ticket_messages(id,ticket_id,sender_role,sender_id,body,"
                        "created_at) VALUES (?,?,?,?,?,?)",
                        zct_slms::tickets::messageId(),
                        id,
                        a.user_type,
                        a.user_id,
                        message,
                        now()
                    );
                    return true;
                }
            );
            if (zct_slms::tickets::changed)
                zct_slms::tickets::changed(id, a.user_type, a.user_id);
            Json out;
            out["id"] = id;
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void act(const Req& req, Callback&& cb) {
        try {
            auto a = staff(req, true);
            if (a.user_type != "ADMIN" || common::paramStr(req, "reviewed") != "1")
                throw std::runtime_error("仅管理员核验后可处理违规工单");
            auto id = common::paramStr(req, "id"),
                 action = common::paramStr(req, "action"),
                 reason = common::paramStr(req, "reason");
            if (reason.empty() || reason.size() > 4000)
                throw std::runtime_error("请填写处理原因（最多4000字节）");
            if (action != "BAN" && action != "DELETE" && action != "WARN")
                throw std::runtime_error("处理方式无效");
            auto [row, ignored] = zct_slms::tickets::permitted(req, id, true);
            if (zct_slms::repo::getStr(row, "category") != "VIOLATION" ||
                (zct_slms::repo::getStr(row, "owner_role") != "USER" &&
                 zct_slms::repo::getStr(row, "owner_role") != "SUBUSER"))
                throw std::runtime_error("此工单不支持违规处置");
            auto uid = zct_slms::repo::getInt(row, "owner_id");
            if (zct_slms::repo::getStr(row, "owner_role") == "SUBUSER") {
                if (action == "BAN")
                    throw std::runtime_error("子用户仅支持警告或删除");
                auto& db = zct_slms::db::Database::instance();
                auto users =
                    db.queryParams("SELECT username FROM sub_users WHERE id = ?", uid);
                if (users.empty())
                    throw std::runtime_error("该子用户已删除");
                auto username = zct_slms::repo::getStr(users[0], "username");
                zct_slms::ticket_mail::schema();
                zct_slms::identity::contactsFor("SUBUSER", uid);
                zct_slms::vouchers::schema();
                if (!db.transaction(
                    [&] {
                        db.execParams(
                            "UPDATE support_tickets SET status = 'RESOLVED',updated_at = ? "
                            "WHERE id = ? AND status = 'OPEN'",
                            now(),
                            id
                        );
                        if (db.rowsChanged() != 1)
                            throw std::runtime_error("工单已被处理");
                        if (action == "WARN")
                            zct_slms::ticket_mail::enqueue(
                                zct_slms::ticket_mail::contact("SUBUSER", uid),
                                "ZCT-SLMS account warning\nAccount: " + username +
                                "\nTicket: " + id + "\nReason: " + reason
                            );
                        else {
                            if (common::paramStr(req, "confirm_username") != username)
                                throw std::runtime_error("请完整输入待删除账号的用户名确认");
                            zct_slms::accounts::erase("SUBUSER", uid);
                        }
                        db.execParams(
                            "INSERT INTO "
                            "ticket_status_events(id,ticket_id,status,created_at)"
                            " VALUES (?,?,'RESOLVED',?)",
                            zct_slms::crypto::randomHex(16),
                            id,
                            now()
                        );
                        db.execParams(
                            "INSERT INTO "
                            "ticket_messages(id,ticket_id,sender_role,sender_id,"
                            "body,created_at) VALUES (?,?,'ADMIN',?,?,?)",
                            zct_slms::tickets::messageId(),
                            id,
                            a.user_id,
                            "管理员已核验并处理子用户内容。\n处理原因：" + reason,
                            now()
                        );
                        return true;
                    }
                ))
                    throw std::runtime_error("处理失败");
                zct_slms::repo::AuditRepo::log(
                    a.user_type,
                    a.user_id,
                    "ReviewViolation:" + action,
                    "SUBUSER",
                    uid,
                    "",
                    "success",
                    common::clientIp(req),
                    "{}",
                    now()
                );
                if (zct_slms::tickets::changed)
                    zct_slms::tickets::changed(id, a.user_type, a.user_id);
                ok(cb);
                return;
            }
            auto owner = zct_slms::repo::UserRepo::findById(uid);
            if (!owner)
                throw std::runtime_error("该用户已删除");
            auto& db = zct_slms::db::Database::instance();
            if (!db.transaction(
                [&] {
                    db.execParams(
                        "UPDATE support_tickets SET status = 'RESOLVED',updated_at = ? "
                        "WHERE id = ? AND status = 'OPEN'",
                        now(),
                        id
                    );
                    if (db.rowsChanged() != 1)
                        throw std::runtime_error("工单状态已变化");
                    if (action == "WARN")
                        zct_slms::ticket_mail::enqueue(
                            zct_slms::ticket_mail::contact("USER", uid),
                            "ZCT-SLMS account warning\nAccount: " + owner->username +
                            "\nTicket: " + id + "\nReason: " + reason
                        );
                    else {
                        db.execParams(
                            "UPDATE sessions SET revoked = 1 WHERE (user_type = 'USER' AND "
                            "user_id = ?) OR (user_type = 'SUBUSER' AND user_id IN (SELECT "
                            "id FROM sub_users WHERE parent_id = ?))",
                            uid,
                            uid
                        );
                        if (action == "BAN") {
                            db.execParams(
                                "UPDATE users SET status = 0,updated_at = ? WHERE id = ?",
                                now(),
                                uid
                            );
                            db.execParams(
                                "UPDATE apps SET status = 0,updated_at = ? WHERE "
                                "owner_id = ?",
                                now(),
                                uid
                            );
                            db.execParams(
                                "UPDATE sub_users SET status = 0,updated_at = ? "
                                "WHERE parent_id = ?",
                                now(),
                                uid
                            );
                        } else {
                            if (common::paramStr(req, "confirm_username") != owner->username)
                                throw std::runtime_error("请完整输入待删除账号的用户名确认");
                            db.execParams(
                                "DELETE FROM ticket_mail_contacts WHERE "
                                "account_role = 'SUBUSER' AND user_id IN (SELECT "
                                "id FROM sub_users WHERE parent_id = ?)",
                                uid
                            );
                            db.execParams(
                                "DELETE FROM ticket_mail_contacts WHERE "
                                "account_role = 'USER' AND user_id = ?",
                                uid
                            );
                            db.execParams(
                                "DELETE FROM recovery_contacts WHERE (account_role = 'USER' "
                                "AND user_id = ?) OR (account_role = 'SUBUSER' AND user_id "
                                "IN (SELECT id FROM sub_users WHERE parent_id = ?))",
                                uid,
                                uid
                            );
                            db.execParams("DELETE FROM users WHERE id = ?", uid);
                        }
                    }
                    db.execParams(
                        "INSERT INTO "
                        "ticket_status_events(id,ticket_id,status,created_at) "
                        "VALUES (?,?,'RESOLVED',?)",
                        zct_slms::crypto::randomHex(16),
                        id,
                        now()
                    );
                    std::string message = action == "BAN"
                                              ? "管理员已封禁账号及所属应用。"
                                              : action == "DELETE"
                                              ? "管理员已删除账号及关联数据。"
                                              : "管理员已将警告邮件加入发送队列。";
                    db.execParams(
                        "INSERT INTO "
                        "ticket_messages(id,ticket_id,sender_role,sender_id,"
                        "body,created_at) VALUES (?,?,'ADMIN',?,?,?)",
                        zct_slms::tickets::messageId(),
                        id,
                        a.user_id,
                        message + "\n处理原因：" + reason,
                        now()
                    );
                    return true;
                }
            ))
                throw std::runtime_error("处理失败");
            zct_slms::repo::AuditRepo::log(
                a.user_type,
                a.user_id,
                "ReviewViolation:" + action,
                "USER",
                uid,
                "",
                "success",
                common::clientIp(req),
                "{}",
                now()
            );
            if (zct_slms::tickets::changed)
                zct_slms::tickets::changed(id, a.user_type, a.user_id);
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }
} // namespace zct_slms::review
