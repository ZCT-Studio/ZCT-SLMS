// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/ticket_management.hpp"
#include <set>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace zct_slms::ticket_mail {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    inline std::string mailBody(std::string text) {
        size_t from = 0;
        while ((from = text.find("](data:image/", from)) != std::string::npos) {
            auto end = text.find(')', from);
            if (end == std::string::npos)break;
            auto begin = text.rfind("![", from);
            if (begin == std::string::npos) {
                from = end + 1;
                continue;
            }
            const std::string notice = "[图片：请登录工单查看]";
            text.replace(begin, end - begin + 1, notice);
            from = begin + notice.size();
        }
        return text;
    }

    inline std::string mailTime(int64_t timestamp) {
        const auto value = static_cast<std::time_t>(timestamp + 8 * 3600);
        std::tm tm{};
        #ifdef _WIN32
        gmtime_s(&tm, &value);
        #else
        gmtime_r(&value, &tm);
        #endif
        std::ostringstream out;
        out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC+8");
        return out.str();
    }

    inline Json config() { return zct_slms::factors::load("ticket_mail_config"); }

    inline void schema() {
        static std::once_flag once;
        std::call_once(
            once,
            [] {
                auto& db = zct_slms::db::Database::instance();
                db.exec(
                    "CREATE TABLE IF NOT EXISTS ticket_mail_contacts (account_role "
                    "VARCHAR(16) NOT NULL,user_id BIGINT NOT NULL,target TEXT NOT "
                    "NULL,PRIMARY KEY(account_role,user_id))"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS ticket_mail_outbox (id VARCHAR(32) "
                    "PRIMARY KEY,payload TEXT NOT NULL,status VARCHAR(16) NOT "
                    "NULL,attempts INTEGER NOT NULL DEFAULT 0,next_at BIGINT NOT "
                    "NULL,created_at BIGINT NOT NULL)"
                );
            }
        );
    }

    inline std::string account(const std::string& role, int64_t uid) {
        return role + ":" + std::to_string(uid);
    }

    inline std::string contact(const std::string& role, int64_t uid) {
        schema();
        auto row = zct_slms::db::Database::instance().queryParams(
            "SELECT target FROM ticket_mail_contacts WHERE account_role = ? AND "
            "user_id = ?",
            role,
            uid
        );
        if (!row.empty())
            return zct_slms::repo::getStr(row[0], "target");
        auto bound = contactsFor(role, uid);
        return bound.contains("email") ? bound["email"] : "";
    }

    inline bool enabled(const std::string& role, int64_t uid) {
        return zct_slms::repo::ConfigRepo::getBool(
            "ticket_mail_enabled:" + account(role, uid),
            false
        );
    }

    inline void enqueue(const std::string& target, const std::string& body, const std::string& subject = "ZCT-SLMS · 工单进度更新", const std::string& format = "plain") {
        schema();
        if (!config().get("enabled", false).asBool())
            throw std::runtime_error("管理员尚未启用独立工单邮箱");
        if (!validMail(target))
            throw std::runtime_error("该账号尚未绑定可用邮箱");
        Json payload;
        payload["target"] = target;
        payload["body"] = body;
        payload["subject"] = subject;
        payload["format"] = format;
        zct_slms::db::Database::instance().execParams(
            "INSERT INTO ticket_mail_outbox(id,payload,status,next_at,created_at) "
            "VALUES (?,?,'PENDING',?,?)",
            zct_slms::crypto::randomHex(16),
            zct_slms::tickets::encrypted(payload),
            now(),
            now()
        );
    }

    inline void notify(
        const std::string& id,
        const std::string& actor,
        int64_t actorId
    ) {
        try {
            if (!config().get("enabled", false).asBool())
                return;
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT owner_role,owner_id,status FROM support_tickets WHERE id = ?",
                id
            );
            if (rows.empty())
                return;
            std::map<std::string, Json> recipients;
            auto add = [&](const std::string& role, int64_t uid) {
                if (role == actor && uid == actorId || !enabled(role, uid))
                    return;
                auto mail = contact(role, uid);
                if (validMail(mail))
                    recipients.emplace(mail, mailAccount(role, uid, mail));
            };
            add(
                zct_slms::repo::getStr(rows[0], "owner_role"),
                zct_slms::repo::getInt(rows[0], "owner_id")
            );
            for (const auto& row : zct_slms::db::Database::instance().query(
                     "SELECT id FROM admins WHERE status = 1"
                 )) {
                auto uid = zct_slms::repo::getInt(row, "id");
                add(
                    zct_slms::repo::ConfigRepo::get(
                        "staff_role:" + std::to_string(uid),
                        "ADMIN"
                    ),
                    uid
                );
            }
            auto state = zct_slms::repo::getStr(rows[0], "status");
            const std::map<std::string, std::string> labels = {{"OPEN", "待处理"}, {"RESOLVED", "已处理"}, {"UNABLE", "无法处理"}, {"REJECTED", "已拒绝"}, {"PROCESSING", "处理中"}};
            auto chatRows = zct_slms::db::Database::instance().queryParams(
                "SELECT sender_role,sender_id,body,created_at FROM ticket_messages WHERE ticket_id=? ORDER BY created_at DESC,id DESC LIMIT 2001",
                id
            );
            std::reverse(chatRows.begin(), chatRows.end());
            Json messageCards(::Json::arrayValue);
            std::string fullChat, newChat;
            bool truncated = chatRows.size() > 2000;
            size_t bytes = 0;
            for (auto it = chatRows.rbegin(); it != chatRows.rend(); ++it) {
                auto senderRole = zct_slms::repo::getStr(*it, "sender_role");
                auto senderId = zct_slms::repo::getInt(*it, "sender_id");
                auto sender = mailAccount(senderRole, senderId);
                auto label = senderRole == "ADMIN" ? "管理员" : senderRole == "SUPPORT" ? "支持" : senderRole == "SUBUSER" ? "子用户" : "用户";
                auto message = std::string(label) + " · " + sender["nickname"].asString() + " @" + sender["username"].asString() + "\n" + mailTime(
                                   zct_slms::repo::getInt(*it, "created_at")
                               ) + "\n" + mailBody(zct_slms::repo::getStr(*it, "body"));
                if (newChat.empty())newChat = message;
                if (bytes + message.size() > 262144) {
                    truncated = true;
                    break;
                }
                Json card;
                card["sender"] = std::string(label) + " · " + sender["nickname"].asString() + " @" + sender["username"].asString();
                card["time"] = mailTime(zct_slms::repo::getInt(*it, "created_at"));
                card["body"] = mailBody(zct_slms::repo::getStr(*it, "body"));
                messageCards.append(card);
                fullChat = message + "\n\n" + fullChat;
                bytes += message.size();
            }
            if (truncated)fullChat = "[对话过长，邮件仅展示最近部分，请登录查看完整记录]\n\n" + fullChat;
            for (auto& [mail, values] : recipients) {
                values["new_chat"] = newChat;
                values["full_chat"] = fullChat;
                values["_chat_messages"] = messageCards;
                values["_chat_truncated"] = truncated;
                values["ticketid"] = id;
                values["status"] = labels.contains(state) ? labels.at(state) : state;
                auto rendered = renderMail("ticket_update", values);
                enqueue(mail, rendered["body"].asString(), rendered["subject"].asString(), rendered.get("format", "plain").asString());
            }
        } catch (...) {
            zct_slms::logger().WARN(
                "Ticket email notification could not be queued; check "
                "independent SMTP settings"
            );
        }
    }

    inline std::atomic<bool> sending{false};

    inline void flush() {
        if (sending.exchange(true))
            return;
        workers.runTaskInQueue(
            [] {
                try {
                    auto cfg = config();
                    if (cfg.get("enabled", false).asBool()) {
                        auto& db = zct_slms::db::Database::instance();
                        db.execParams(
                            "UPDATE ticket_mail_outbox SET status = 'PENDING' WHERE "
                            "status = 'SENDING' AND next_at < ?",
                            now()
                        );
                        for (const auto& row :
                             db.queryParams(
                                 "SELECT id,payload,attempts FROM "
                                 "ticket_mail_outbox WHERE status = 'PENDING' AND "
                                 "next_at <= ? ORDER BY created_at LIMIT 20",
                                 now()
                             )) {
                            auto id = zct_slms::repo::getStr(row, "id");
                            db.execParams(
                                "UPDATE ticket_mail_outbox SET status = 'SENDING',next_at = ? "
                                "WHERE id = ? AND status = 'PENDING'",
                                now() + 300,
                                id
                            );
                            if (db.rowsChanged() != 1)
                                continue;
                            try {
                                auto p = zct_slms::tickets::decrypted(zct_slms::repo::getStr(row, "payload"));
                                deliverEmail(
                                    cfg,
                                    p["target"].asString(),
                                    "",
                                    false,
                                    p.get("subject", "ZCT-SLMS · 工单进度更新").asString(),
                                    p["body"].asString(),
                                    "ticket_update",
                                    Json{},
                                    p.get("format", "plain").asString()
                                );
                                db.execParams(
                                    "UPDATE ticket_mail_outbox SET status = 'SENT' WHERE id = ?",
                                    id
                                );
                            } catch (...) {
                                auto attempts = zct_slms::repo::getInt(row, "attempts") + 1;
                                db.execParams(
                                    "UPDATE ticket_mail_outbox SET status = ?,attempts = ?,next_at "
                                    "= ? WHERE id = ?",
                                    attempts >= 5 ? "FAILED" : "PENDING",
                                    attempts,
                                    now() + std::min<int64_t>(3600, 30 * (1LL << attempts)),
                                    id
                                );
                            }
                        }
                    }
                } catch (...) {
                    zct_slms::logger().WARN(
                        "Ticket mail worker failed; pending messages retained"
                    );
                }
                sending = false;
            }
        );
    }

    inline void settings(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            if (a.user_type != "ADMIN")
                throw std::runtime_error("需要管理员登录");
            auto cfg = config();
            if (req->method() == drogon::Post) {
                if (!adminPassword(req))
                    throw std::runtime_error("请完成授权");
                auto body = req->getJsonObject();
                if (!body)
                    throw std::runtime_error("配置无效");
                for (auto key : {
                         "smtp_host",
                         "smtp_username",
                         "smtp_password",
                         "smtp_from",
                         "smtp_tls",
                         "smtp_auth"
                     })
                    if (body->isMember(key)) {
                        if (!(*body)[key].isString() || (*body)[key].asString().size() > 4096)
                            throw std::runtime_error("配置格式无效");
                        if (std::string(key) == "smtp_password" &&
                            (*body)[key].asString().empty())
                            continue;
                        cfg[key] = (*body)[key];
                    }
                if (body->isMember("smtp_port"))
                    cfg["smtp_port"] = (*body)["smtp_port"];
                if (body->isMember("enabled"))
                    cfg["enabled"] = (*body)["enabled"];
                if (!cfg.get("enabled", false).isBool() ||
                    !cfg.get("smtp_port", 465).isInt() ||
                    cfg.get("smtp_port", 465).asInt() < 1 ||
                    cfg.get("smtp_port", 465).asInt() > 65535)
                    throw std::runtime_error("邮箱开关或端口无效");
                if (cfg.get("enabled", false).asBool() &&
                    (!validMail(val(cfg, "smtp_from")) ||
                     !std::regex_match(
                         val(cfg, "smtp_host"),
                         std::regex("[A-Za-z0-9.-]+")
                     ) ||
                     val(cfg, "smtp_username").empty() ||
                     val(cfg, "smtp_password").empty() ||
                     (val(cfg, "smtp_tls") != "starttls" &&
                      val(cfg, "smtp_tls") != "implicit")))
                    throw std::runtime_error("请填写完整独立工单 SMTP 配置");
                smtpAuthMechanism(cfg);
                zct_slms::factors::store("ticket_mail_config", cfg);
            }
            cfg["password_configured"] = !val(cfg, "smtp_password").empty();
            cfg.removeMember("smtp_password");
            ok(cb, cfg);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void preferences(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            if (req->method() == drogon::Post) {
                auto on = common::paramStr(req, "enabled") == "1";
                if (on && contact(a.user_type, a.user_id).empty())
                    throw std::runtime_error("请先验证工单提醒邮箱");
                zct_slms::repo::ConfigRepo::set(
                    "ticket_mail_enabled:" +
                    account(a.user_type, a.user_id),
                    on ? "1" : "0",
                    now()
                );
            }
            Json out;
            out["enabled"] = enabled(a.user_type, a.user_id);
            out["email"] = contact(a.user_type, a.user_id);
            out["service_enabled"] = config().get("enabled", false);
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void sendCode(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto a = zct_slms::factors::auth(req, true);
                    auto target = common::paramStr(req, "email");
                    if (!validMail(target))
                        throw std::runtime_error("邮箱格式无效");
                    auto cfg = config();
                    if (!cfg.get("enabled", false).asBool())
                        throw std::runtime_error("独立工单邮箱尚未启用");
                    {
                        std::lock_guard lock(mutex);
                        prune();
                        rate("ticket-email:" + account(a.user_type, a.user_id), 3, 3600);
                    }
                    auto id = zct_slms::crypto::randomHex(24),
                         code = zct_slms::crypto::randomNumeric(6);
                    deliverEmail(cfg, target, code, false, "", "", "ticket_verify", mailAccount(a.user_type, a.user_id, target));
                    {
                        std::lock_guard lock(mutex);
                        challenges[id] = {
                                "email",
                                target,
                                zct_slms::crypto::hmacSha256Hex(id + ":" + code, otpSecret),
                                "ticket-email:" + account(a.user_type, a.user_id),
                                now() + 300
                            };
                    }
                    Json out;
                    out["challenge_id"] = id;
                    ok(cb, out);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void verifyCode(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req, true);
            auto challenge = consume(
                common::paramStr(req, "challenge_id"),
                common::paramStr(req, "code"),
                "ticket-email:" + account(a.user_type, a.user_id)
            );
            schema();
            zct_slms::db::Database::instance().execParams(
                "INSERT INTO ticket_mail_contacts(account_role,user_id,target) VALUES "
                "(?,?,?) ON CONFLICT(account_role,user_id) DO UPDATE SET target = "
                "excluded.target",
                a.user_type,
                a.user_id,
                challenge.target
            );
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void install() {
        schema();
        zct_slms::tickets::changed = notify;
        drogon::app().getLoop()->runEvery(30, flush);
    }
} // namespace zct_slms::ticket_mail
