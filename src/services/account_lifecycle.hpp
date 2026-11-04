// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/authorization.hpp"
#include "services/ticket_mail.hpp"

namespace zct_slms::accounts {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;
    inline std::mutex guard;

    inline void revoke(const std::string& role, int64_t uid) {
        zct_slms::db::Database::instance().execParams(
            "UPDATE sessions SET revoked = 1 WHERE user_type = ? AND user_id = ?",
            role,
            uid
        );
    }

    inline void erase(const std::string& role, int64_t uid) {
        auto& db = zct_slms::db::Database::instance();
        if (role == "ADMIN") {
            auto rows = db.queryParams(
                "SELECT id FROM admins WHERE status = 1 AND id <> ?",
                uid
            );
            bool other = false;
            for (auto& r : rows)
                if (zct_slms::repo::ConfigRepo::get(
                        "staff_role:" + std::to_string(zct_slms::repo::getInt(r, "id")),
                        "ADMIN"
                    ) == "ADMIN")
                    other = true;
            if (!other)
                throw std::runtime_error("不能注销最后一个可用管理员账号");
        }
        if (role == "USER")
            for (auto& r :
                 db.queryParams("SELECT id FROM sub_users WHERE parent_id = ?", uid))
                zct_slms::accounts::erase("SUBUSER", zct_slms::repo::getInt(r, "id"));
        revoke(role, uid);
        db.execParams(
            "DELETE FROM recovery_contacts WHERE account_role = ? AND user_id = ?",
            role,
            uid
        );
        db.execParams(
            "DELETE FROM ticket_mail_contacts WHERE account_role = ? AND user_id = ?",
            role,
            uid
        );
        const auto key = role + ":" + std::to_string(uid);
        for (auto& k : {
                 "factors:" + key,
                 "force_password:" + key,
                 "profile:" + key + ":nickname",
                 "profile:" + key + ":avatar",
                 "ticket_mail_enabled:" + key
             })
            db.execParams("DELETE FROM system_config WHERE key = ?", k);
        db.execParams(
            "DELETE FROM voucher_codes WHERE issuer_role = ? AND issuer_id = ?",
            role,
            uid
        );
        db.execParams(
            "DELETE FROM " + zct_slms::portal::table(role) + " WHERE id = ?",
            uid
        );
        if (db.rowsChanged() != 1)
            throw std::runtime_error("账号不存在");
        if (role == "SUPPORT" || role == "ADMIN")
            db.execParams(
                "DELETE FROM system_config WHERE key = ?",
                "staff_role:" + std::to_string(uid)
            );
    }

    inline void manage(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req, true);
            auto role = common::paramStr(req, "role"),
                 action = common::paramStr(req, "action");
            auto uid = common::paramI64(req, "user_id", 0);
            if (role != "USER" && role != "SUBUSER" && role != "SUPPORT")
                throw std::runtime_error("目标账号类型无效");
            if (a.user_type != "ADMIN" &&
                !(a.user_type == "USER" && role == "SUBUSER" && action == "DELETE"))
                throw std::runtime_error("无权管理该账号");
            if (action != "DELETE" && action != "BAN" && action != "UNBAN")
                throw std::runtime_error("操作无效");
            if (role == "SUBUSER" && action != "DELETE")
                throw std::runtime_error("子用户列表仅允许删除操作");
            std::lock_guard lock(guard);
            auto& db = zct_slms::db::Database::instance();
            auto rows = db.queryParams(
                "SELECT * FROM " + zct_slms::portal::table(role) + " WHERE id = ?",
                uid
            );
            if (rows.empty())
                throw std::runtime_error("账号不存在");
            if (role == "SUPPORT" &&
                zct_slms::repo::ConfigRepo::get(
                    "staff_role:" + std::to_string(uid),
                    "ADMIN"
                ) != "SUPPORT")
                throw std::runtime_error("目标不是支持账号");
            if (a.user_type == role && a.user_id == uid)
                throw std::runtime_error("请使用注销申请处理自己的账号");
            if (a.user_type == "USER" &&
                zct_slms::repo::getInt(rows[0], "parent_id") != a.user_id)
                throw std::runtime_error("只能删除自己的子用户");
            if (action == "DELETE" && common::paramStr(req, "confirm_username") !=
                zct_slms::repo::getStr(rows[0], "username"))
                throw std::runtime_error("请完整输入目标用户名确认删除");
            zct_slms::vouchers::schema();
            zct_slms::ticket_mail::schema();
            zct_slms::recovery::contacts(zct_slms::authorization::sessionOf(req));
            if (!db.transaction(
                [&] {
                    if (action == "DELETE")
                        zct_slms::accounts::erase(role, uid);
                    else {
                        db.execParams(
                            "UPDATE " + zct_slms::portal::table(role) +
                            " SET status = ?,updated_at = ? WHERE id = ?",
                            action == "BAN" ? 0 : 1,
                            now(),
                            uid
                        );
                        revoke(role, uid);
                        if (role == "USER" && action == "BAN") {
                            for (auto& r : db.queryParams(
                                     "SELECT id FROM sub_users WHERE parent_id = ?",
                                     uid
                                 ))
                                revoke("SUBUSER", zct_slms::repo::getInt(r, "id"));
                            db.execParams(
                                "UPDATE sub_users SET status = 0,updated_at = ? "
                                "WHERE parent_id = ?",
                                now(),
                                uid
                            );
                            db.execParams(
                                "UPDATE apps SET status = 0,updated_at = ? WHERE "
                                "owner_id = ?",
                                now(),
                                uid
                            );
                        }
                    }
                    return true;
                }
            ))
                throw std::runtime_error("账号操作失败");
            zct_slms::repo::AuditRepo::log(
                a.user_type,
                a.user_id,
                "Account:" + action,
                role,
                uid,
                "",
                "success",
                common::clientIp(req),
                "{}",
                now()
            );
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void requestClosure(const Req& req, Callback&& cb) {
        try {
            auto s = zct_slms::authorization::sessionOf(req);
            auto role = s["user_type"].asString();
            if (role == "ADMIN") throw std::runtime_error("管理员账号禁止注销");
            auto uid = s["user_id"].asInt64();
            if (common::paramStr(req, "confirm_username") != s["username"].asString())
                throw std::runtime_error("请输入当前账号的完整用户名以确认注销申请");
            auto reason = common::paramStr(req, "reason");
            if (reason.size() < 10 || reason.size() > 4000)
                throw std::runtime_error("注销原因需10–4000字节");
            zct_slms::tickets::schema();
            std::lock_guard lock(guard);
            auto& db = zct_slms::db::Database::instance();
            std::string id = zct_slms::crypto::randomHex(16);
            Json contact;
            contact["fingerprint"] = zct_slms::authorization::accountFingerprint(s);
            contact["username"] = s["username"];
            {
                std::lock_guard lock(zct_slms::factors::guard);
                contact["factor_version"] =
                    zct_slms::factors::load(zct_slms::factors::accountKey(role, uid))
                   .get("version", 0);
            }
            if (!db.transaction(
                [&] {
                    if (!db.queryParams(
                                "SELECT id FROM support_tickets WHERE category = "
                                "'CLOSURE' AND owner_role = ? AND owner_id = ? "
                                "AND status = 'OPEN'",
                                role,
                                uid
                            )
                           .empty())
                        throw std::runtime_error("已有待审核的注销申请");
                    db.execParams(
                        "INSERT INTO "
                        "support_tickets(id,category,owner_role,owner_id,title,status,"
                        "access_hash,contact_cipher,created_at,updated_at) VALUES "
                        "(?,'CLOSURE',?,?,'账号注销申请','OPEN','',?,?,?)",
                        id,
                        role,
                        uid,
                        zct_slms::tickets::encrypted(contact),
                        now(),
                        now()
                    );
                    db.execParams(
                        "INSERT INTO "
                        "ticket_messages(id,ticket_id,sender_role,sender_id,"
                        "body,created_at) VALUES (?,?,?,?,?,?)",
                        zct_slms::tickets::messageId(),
                        id,
                        role,
                        uid,
                        "已输入本人用户名确认。注销原因：" + reason,
                        now()
                    );
                    return true;
                }
            ))
                throw std::runtime_error("申请提交失败");
            if (zct_slms::tickets::changed)
                zct_slms::tickets::changed(id, role, uid);
            Json out;
            out["id"] = id;
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void approveClosure(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req, true);
            if (a.user_type != "ADMIN" || common::paramStr(req, "reviewed") != "1")
                throw std::runtime_error("仅管理员核验后可批准注销");
            auto id = common::paramStr(req, "id");
            std::lock_guard lock(guard);
            auto [row, ignored] = zct_slms::tickets::permitted(req, id, true);
            const auto role = zct_slms::repo::getStr(row, "owner_role");
            const auto uid = zct_slms::repo::getInt(row, "owner_id");
            if (role == "ADMIN") throw std::runtime_error("管理员账号禁止注销");
            if (zct_slms::repo::getStr(row, "category") != "CLOSURE" ||
                (role == a.user_type && uid == a.user_id))
                throw std::runtime_error("不能审核自己的注销申请");
            Json s;
            s["user_type"] = role;
            s["user_id"] = ::Json::Int64(uid);
            auto c = zct_slms::tickets::decrypted(zct_slms::repo::getStr(row, "contact_cipher"));
            if (c.get("fingerprint", "").asString() !=
                zct_slms::authorization::accountFingerprint(s))
                throw std::runtime_error("账号安全信息已变化，请重新提交注销申请");
            {
                std::lock_guard lock(zct_slms::factors::guard);
                if (c["factor_version"] !=
                    zct_slms::factors::load(zct_slms::factors::accountKey(role, uid))
                   .get("version", 0))
                    throw std::runtime_error("账号登录方式已变化，请重新提交注销申请");
            }
            if (common::paramStr(req, "confirm_username") != c["username"].asString())
                throw std::runtime_error("请输入申请账号用户名确认注销");
            zct_slms::vouchers::schema();
            zct_slms::ticket_mail::schema();
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
                        throw std::runtime_error("工单已被处理");
                    zct_slms::accounts::erase(role, uid);
                    db.execParams(
                        "INSERT INTO "
                        "ticket_status_events(id,ticket_id,status,created_at) "
                        "VALUES (?,?,'RESOLVED',?)",
                        zct_slms::crypto::randomHex(16),
                        id,
                        now()
                    );
                    db.execParams(
                        "INSERT INTO "
                        "ticket_messages(id,ticket_id,sender_role,sender_id,body,created_"
                        "at) VALUES (?,?,'ADMIN',?,'管理员已审核并完成账号注销。',?)",
                        zct_slms::tickets::messageId(),
                        id,
                        a.user_id,
                        now()
                    );
                    return true;
                }
            ))
                throw std::runtime_error("注销失败");
            zct_slms::repo::AuditRepo::log(
                a.user_type,
                a.user_id,
                "ApproveAccountClosure",
                role,
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
} // namespace zct_slms::accounts
