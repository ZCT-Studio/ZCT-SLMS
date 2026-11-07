// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "services/recovery.hpp"
#include "services/object_storage.hpp"
#include <set>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace zct_slms::tickets {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    inline std::string messageId() {
        static std::atomic<int64_t> last{0};
        auto value = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto previous = last.load();
        while (!last.compare_exchange_weak(previous, std::max<int64_t>(value, previous + 1))) {}
        std::ostringstream out;
        out << std::hex << std::setw(16) << std::setfill('0') << std::max<int64_t>(value, previous + 1);
        return out.str() + zct_slms::crypto::randomHex(8);
    }

    inline void schema() {
        static std::once_flag once;
        std::call_once(
            once,
            [] {
                auto& db = zct_slms::db::Database::instance();
                db.exec(
                    "CREATE TABLE IF NOT EXISTS support_tickets (id VARCHAR(32) PRIMARY "
                    "KEY,category VARCHAR(16) NOT NULL,owner_role VARCHAR(16) NOT "
                    "NULL,owner_id BIGINT NOT NULL,title TEXT NOT NULL,status VARCHAR(16) "
                    "NOT NULL,access_hash VARCHAR(64) NOT NULL,contact_cipher TEXT NOT "
                    "NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL)"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS ticket_messages (id VARCHAR(32) PRIMARY "
                    "KEY,ticket_id VARCHAR(32) NOT NULL REFERENCES support_tickets(id) ON "
                    "DELETE CASCADE,sender_role VARCHAR(16) NOT NULL,sender_id BIGINT NOT "
                    "NULL,body TEXT NOT NULL,created_at BIGINT NOT NULL)"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS ticket_properties (ticket_id VARCHAR(32) "
                    "PRIMARY KEY REFERENCES support_tickets(id) ON DELETE CASCADE,priority "
                    "INTEGER NOT NULL DEFAULT 2,reopen_used INTEGER NOT NULL DEFAULT 0)"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS ticket_reads (ticket_id VARCHAR(32) NOT "
                    "NULL REFERENCES support_tickets(id) ON DELETE CASCADE,viewer_role "
                    "VARCHAR(16) NOT NULL,viewer_id BIGINT NOT NULL,seen_count BIGINT NOT "
                    "NULL DEFAULT 0,PRIMARY KEY(ticket_id,viewer_role,viewer_id))"
                );
                db.exec(
                    "CREATE TABLE IF NOT EXISTS ticket_status_events (id VARCHAR(32) "
                    "PRIMARY KEY,ticket_id VARCHAR(32) NOT NULL REFERENCES "
                    "support_tickets(id) ON DELETE CASCADE,status VARCHAR(16) NOT "
                    "NULL,created_at BIGINT NOT NULL)"
                );
                db.exec(
                    "UPDATE support_tickets SET status = 'REJECTED' WHERE status = "
                    "'CLOSED'"
                );
                db.exec(
                    "INSERT INTO ticket_status_events(id,ticket_id,status,created_at) "
                    "SELECT t.id,t.id,'RESOLVED',t.updated_at FROM support_tickets t "
                    "WHERE t.status = 'RESOLVED' AND NOT EXISTS (SELECT 1 FROM "
                    "ticket_status_events e WHERE e.ticket_id = t.id AND e.status = "
                    "'RESOLVED')"
                );
                db.exec(
                    "CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket_time ON "
                    "ticket_messages(ticket_id,created_at,id)"
                );
            }
        );
    }

    inline bool staff(const std::string& role) {
        return role == "ADMIN" || role == "SUPPORT";
    }

    inline std::function<void(const std::string &, const std::string &, int64_t)>
    changed;

    inline int64_t foreignMessages(
        const std::string& id,
        const std::string& role,
        int64_t uid
    ) {
        auto rows = zct_slms::db::Database::instance().queryParams(
            "SELECT COUNT(*) AS n FROM ticket_messages WHERE ticket_id = ? AND NOT "
            "(sender_role = ? AND sender_id = ?)",
            id,
            role,
            uid
        );
        return rows.empty() ? 0 : zct_slms::repo::getInt(rows[0], "n");
    }

    inline void decorate(
        Json& out,
        const std::string& id,
        const std::string& role,
        int64_t uid,
        bool markRead = false
    ) {
        auto& db = zct_slms::db::Database::instance();
        auto props = db.queryParams(
            "SELECT priority,reopen_used FROM ticket_properties WHERE ticket_id = ?",
            id
        );
        out["priority"] =
            props.empty()
                ? 2
                : static_cast<int>(zct_slms::repo::getInt(props[0], "priority"));
        out["reopen_used"] =
            !props.empty() && zct_slms::repo::getInt(props[0], "reopen_used") != 0;
        const auto total = foreignMessages(id, role, uid);
        auto seen =
            db.queryParams(
                "SELECT seen_count FROM ticket_reads WHERE ticket_id = ? "
                "AND viewer_role = ? AND viewer_id = ?",
                id,
                role,
                uid
            );
        out["unread_messages"] = ::Json::Int64(
            std::max<int64_t>(
                0,
                total - (seen.empty() ? 0 : zct_slms::repo::getInt(seen[0], "seen_count"))
            )
        );
        if (markRead) {
            db.execParams(
                "INSERT INTO ticket_reads(ticket_id,viewer_role,viewer_id,seen_count) "
                "VALUES (?,?,?,?) ON CONFLICT(ticket_id,viewer_role,viewer_id) DO "
                "UPDATE SET seen_count = excluded.seen_count",
                id,
                role,
                uid,
                total
            );
            out["unread_messages"] = 0;
        }
    }

    inline std::string encrypted(const Json& v) {
        return zct_slms::crypto::base64Encode(
            zct_slms::crypto::aes256GcmEncrypt(json(v), masterKey())
        );
    }

    inline Json decrypted(const std::string& v) {
        auto clear =
            zct_slms::crypto::aes256GcmDecrypt(zct_slms::crypto::base64Decode(v), masterKey());
        if (!clear)
            throw std::runtime_error("工单投递信息无法解密");
        return parse(*clear);
    }

    inline auto permitted(
        const Req& req,
        const std::string& id,
        bool write = false
    ) {
        schema();
        auto rows = zct_slms::db::Database::instance().queryParams(
            "SELECT * FROM support_tickets WHERE id = ?",
            id
        );
        if (rows.empty())
            throw std::runtime_error("工单不存在或无权访问");
        auto a =
            zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
        auto& row = rows[0];
        bool owner = a.success &&
                     a.user_type == zct_slms::repo::getStr(row, "owner_role") &&
                     a.user_id == zct_slms::repo::getInt(row, "owner_id");
        bool guest = false;
        auto token = common::paramStr(req, "access_token");
        if (!token.empty() && token.size() <= 128)
            guest = zct_slms::crypto::constantTimeEqual(
                zct_slms::crypto::sha256Hex(token),
                zct_slms::repo::getStr(row, "access_hash")
            );
        if (!(a.success && staff(a.user_type)) && !owner && !guest)
            throw std::runtime_error("工单不存在或无权访问");
        if (write && zct_slms::repo::getStr(row, "status") != "OPEN")
            throw std::runtime_error("工单已结束，不能继续回复");
        return std::make_pair(row, a);
    }

    inline void imageSchema() {
        schema();
        zct_slms::db::Database::instance().exec(
            "CREATE TABLE IF NOT EXISTS ticket_images(id VARCHAR(64) PRIMARY KEY,owner_role VARCHAR(16) NOT NULL,owner_id BIGINT NOT NULL,mime VARCHAR(32) NOT NULL,payload TEXT NOT NULL,created_at BIGINT NOT NULL)"
        );
    }

    // A failed write leaves the original encrypted database payload untouched.
    // A failed restart can safely retry; each object has an unpredictable name.
    inline void migrateImageStorage() {
        imageSchema();
        auto& db = zct_slms::db::Database::instance();
        const auto rows = db.queryParams("SELECT id,payload FROM ticket_images");
        for (const auto& row : rows) {
            const auto id = zct_slms::repo::getStr(row, "id");
            const auto payload = zct_slms::repo::getStr(row, "payload");
            if (payload.starts_with("local://") || payload.starts_with("s3://")) continue;
            // Authenticate the ciphertext before discarding the database copy.
            auto data = decrypted(payload);
            if (!data["data"].isString()) throw std::runtime_error("Invalid stored ticket image");
            const auto location = zct_slms::object_storage::put("tickets/" + zct_slms::crypto::randomHex(32), payload);
            if (zct_slms::object_storage::get(location) != payload) throw std::runtime_error("Ticket image storage verification failed");
            db.execParams("UPDATE ticket_images SET payload = ? WHERE id = ? AND payload = ?", location, id, payload);
        }
    }

    inline void migrateInlineImages() {
        auto& db = zct_slms::db::Database::instance();

        for (const auto& row : db.queryParams("SELECT id,sender_role,sender_id,body,created_at FROM ticket_messages WHERE body LIKE '%data:image/%'")) {
            auto body = zct_slms::repo::getStr(row, "body");
            const auto original = body;
            size_t position;
            while ((position = body.find("data:image/")) != std::string::npos) {
                const auto commaAt = body.find(',', position);
                if (commaAt == std::string::npos) throw std::runtime_error("Invalid inline image");
                const auto stop = body.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", commaAt + 1);
                const auto length = (stop == std::string::npos ? body.size() : stop) - position;
                const auto value = body.substr(position, length);
                const auto comma = value.find(',');
                const auto semicolon = value.find(';');
                const auto mime = value.substr(5, semicolon - 5);
                if ((mime != "image/png" && mime != "image/jpeg" && mime != "image/webp") || value.substr(semicolon, 8) != ";base64,") throw std::runtime_error(
                    "Invalid legacy image format"
                );
                const auto bytes = zct_slms::crypto::base64Decode(value.substr(comma + 1));
                if (bytes.empty() || bytes.size() > 1048576) throw std::runtime_error("Invalid legacy ticket image");
                Json image;
                image["data"] = zct_slms::crypto::base64Encode(bytes);
                const auto id = zct_slms::crypto::randomHex(32);
                const auto payload = encrypted(image);
                const auto location = zct_slms::object_storage::put("tickets/" + id, payload);
                if (zct_slms::object_storage::get(location) != payload) throw std::runtime_error("Legacy image verification failed");
                db.execParams(
                    "INSERT INTO ticket_images(id,owner_role,owner_id,mime,payload,created_at) VALUES(?,?,?,?,?,?)",
                    id,
                    zct_slms::repo::getStr(row, "sender_role"),
                    zct_slms::repo::getInt(row, "sender_id"),
                    mime,
                    location,
                    zct_slms::repo::getInt(row, "created_at")
                );
                body.replace(position, length, "/api/v1/tickets/image?image=" + id);
            }
            if (body != original) db.execParams("UPDATE ticket_messages SET body=? WHERE id=? AND body=?", body, zct_slms::repo::getStr(row, "id"), original);
        }
    }

    inline auto imageAuth(const Req& req) {
        auto a = zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
        if (a.success)return a;
        auto contact = req->getHeader("X-Ticket-Contact");
        if (!contact.empty()) {
            std::lock_guard lock(zct_slms::recovery::guard);
            auto it = zct_slms::recovery::grants.find(contact);
            if (it == zct_slms::recovery::grants.end() || it->second.expires < now() || (it->second.kind != "ticket" && it->second.kind != "security-ticket") || !
                zct_slms::recovery::allowed("ticket") || it->second.fingerprint != zct_slms::portal_auth::fingerprint(it->second.account))
                throw std::runtime_error("恢复授权已过期");
            a.success = true;
            a.user_type = "RECOVERY";
            a.user_id = std::stoll(zct_slms::crypto::sha256Hex(contact).substr(0, 15), nullptr, 16);
            return a;
        }
        auto ticket = common::paramStr(req, "id");
        if (!ticket.empty()) {
            auto [row,unused] = permitted(req, ticket);
            a.success = true;
            a.user_type = "GUEST";
            a.user_id = std::stoll(zct_slms::crypto::sha256Hex(ticket + common::paramStr(req, "access_token")).substr(0, 15), nullptr, 16);
        }
        return a;
    }

    inline void uploadImage(const Req& req, Callback&& cb) {
        try {
            imageSchema();
            auto a = imageAuth(req);
            if (!a.success)throw std::runtime_error("请先登录或验证恢复联系方式");
            auto data = std::string(req->body());
            if (data.empty() || data.size() > 262144)throw std::runtime_error("图片不能超过256 KB");
            std::string mime;
            if (data.size() > 8 && data.substr(0, 8) == std::string("\x89PNG\r\n\x1a\n", 8))mime = "image/png";
            else if (data.size() > 3 && (unsigned char)data[0] == 255 && (unsigned char)data[1] == 216 && (unsigned char)data[2] == 255)mime = "image/jpeg";
            else if (data.size() > 12 && data.substr(0, 4) == "RIFF" && data.substr(8, 4) == "WEBP")mime = "image/webp";
            else throw std::runtime_error("仅支持PNG、JPEG、WebP图片");
            auto& db = zct_slms::db::Database::instance();
            auto count = db.queryParams("SELECT COUNT(*) AS n FROM ticket_images WHERE owner_role=? AND owner_id=? AND created_at>?", a.user_type, a.user_id, now() - 3600);
            if (!count.empty() && zct_slms::repo::getInt(count[0], "n") >= 30)throw std::runtime_error("图片上传过于频繁，请稍后再试");
            auto id = zct_slms::crypto::randomHex(32);
            Json value;
            value["data"] = zct_slms::crypto::base64Encode(data);
            db.execParams(
                "INSERT INTO ticket_images(id,owner_role,owner_id,mime,payload,created_at) VALUES(?,?,?,?,?,?)",
                id,
                a.user_type,
                a.user_id,
                mime,
                zct_slms::object_storage::put("tickets/" + zct_slms::crypto::randomHex(32), encrypted(value)),
                now()
            );
            Json out;
            out["url"] = "/api/v1/tickets/image?image=" + id;
            ok(cb, out);
        } catch (const std::exception& e) { fail(cb, e.what()); }
    }

    inline void readImage(const Req& req, Callback&& cb) {
        try {
            imageSchema();
            auto id = common::paramStr(req, "image");
            if (!std::regex_match(id, std::regex("[a-f0-9]{64}")))throw std::runtime_error("图片不存在");
            auto& db = zct_slms::db::Database::instance();
            auto rows = db.queryParams("SELECT * FROM ticket_images WHERE id=?", id);
            if (rows.empty())throw std::runtime_error("图片不存在");
            auto a = imageAuth(req);
            bool allowed = a.success && a.user_type == zct_slms::repo::getStr(rows[0], "owner_role") && a.user_id == zct_slms::repo::getInt(rows[0], "owner_id");
            if (!allowed) {
                auto refs = db.queryParams("SELECT DISTINCT ticket_id FROM ticket_messages WHERE body LIKE ?", "%/api/v1/tickets/image?image=" + id + "%");
                for (auto& r : refs) {
                    try {
                        permitted(req, zct_slms::repo::getStr(r, "ticket_id"));
                        allowed = true;
                        break;
                    } catch (...) {}
                }
            }
            if (!allowed)throw std::runtime_error("无权查看图片");
            auto location = zct_slms::repo::getStr(rows[0], "payload");
            const auto encryptedData = (location.starts_with("local://") || location.starts_with("s3://")) ? zct_slms::object_storage::get(location) : location;
            auto data = zct_slms::crypto::base64Decode(decrypted(encryptedData)["data"].asString());
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setBody(data);
            response->setContentTypeString(zct_slms::repo::getStr(rows[0], "mime"));
            response->addHeader("Cache-Control", "private, no-store");
            response->addHeader("X-Content-Type-Options", "nosniff");
            cb(response);
        } catch (const std::exception& e) { fail(cb, e.what()); }
    }

    template <class Row> inline Json summary(const Row& row) {
        Json out;
        for (auto k : {"id", "category", "owner_role", "title", "status"})
            out[k] = zct_slms::repo::getStr(row, k);
        for (auto k : {"owner_id", "created_at", "updated_at"})
            out[k] = ::Json::Int64(zct_slms::repo::getInt(row, k));
        auto role = zct_slms::repo::getStr(row, "owner_role");
        auto uid = zct_slms::repo::getInt(row, "owner_id");
        auto name = zct_slms::db::Database::instance().queryScalar(
            "SELECT username FROM " + zct_slms::portal::table(role) + " WHERE id = ?",
            uid
        );
        out["username"] = name.value_or("已删除账号");
        return out;
    }

    inline Json securitySnapshot(const std::string& role, int64_t uid, const std::string& method, const std::string& keyId = "") {
        static const std::set<std::string> methods = {"email", "phone", "microsoft", "github", "google", "telegram", "gitlab", "discord", "totp", "passkey", "recovery"};
        if (!methods.contains(method)) throw std::runtime_error("安全方式无效");
        auto factors = zct_slms::factors::load(zct_slms::factors::accountKey(role, uid));
        Json out;
        out["method"] = method;
        out["key_id"] = keyId;
        out["factor_version"] = factors.get("version", 0);
        Json session;
        session["user_type"] = role;
        session["user_id"] = ::Json::Int64(uid);
        out["password_fingerprint"] = zct_slms::portal_auth::fingerprint(session);
        bool exists = false;
        if (method == "passkey") {
            if (keyId.empty()) {
                exists = !factors["keys"].empty();
                out["name"] = "全部通行密钥";
            }
            for (const auto& key : factors["keys"])
                if (key["id"].asString() == keyId) {
                    exists = true;
                    out["name"] = key["name"];
                    break;
                }
        } else if (method == "totp") exists = factors.get("totp_enabled", false).asBool();
        else if (method == "recovery") exists = !factors["recovery"].empty();
        else {
            Json bindings(::Json::arrayValue);
            if (role == "USER")
                for (const auto& row : zct_slms::db::Database::instance().queryParams(
                         "SELECT subject FROM auth_identities WHERE user_id = ? AND provider = ? ORDER BY subject",
                         uid,
                         method
                     ))
                    bindings.append(zct_slms::repo::getStr(row, "subject"));
            auto contacts = contactsFor(role, uid);
            if (contacts.contains(method))bindings.append(contacts[method]);
            exists = !bindings.empty();
            out["binding_hash"] = zct_slms::crypto::sha256Hex(json(bindings));
        }
        if (!exists)throw std::runtime_error("此登录方式尚未绑定或已被移除");
        return out;
    }

    inline void securityTargets(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            std::lock_guard lock(zct_slms::factors::guard);
            Json out(::Json::arrayValue);
            for (const auto& method : {"email", "phone", "microsoft", "github", "google", "telegram", "gitlab", "discord", "totp", "passkey", "recovery"}) {
                try {
                    auto item = securitySnapshot(a.user_type, a.user_id, method);
                    Json entry;
                    entry["method"] = method;
                    entry["key_id"] = "";
                    entry["name"] = item.get("name", "");
                    out.append(entry);
                } catch (const std::exception&) {}
            }
            ok(cb, out);
        } catch (const std::exception& e) { fail(cb, e.what()); }
    }

    inline void create(const Req& req, Callback&& cb) {
        try {
            schema();
            auto auth =
                zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
            auto category = common::paramStr(req, "category"),
                 title = common::paramStr(req, "title"),
                 body = common::paramStr(req, "body");
            if (category != "FORGOT" && category != "ACCOUNT" &&
                category != "GENERAL" && category != "PASSKEY" && category != "SECURITY")
                throw std::runtime_error("工单类型无效");
            if (title.empty() || title.size() > 180 || body.size() < 10 ||
                body.size() > 786432)
                throw std::runtime_error(
                    "标题最多 180 字节，申诉或问题描述为 10 字节至 768 KB（含图片）"
                );
            std::string role;
            int64_t uid;
            Json contact(::Json::objectValue);
            if (category == "FORGOT") {
                std::lock_guard lock(zct_slms::recovery::guard);
                auto flow = zct_slms::recovery::takeGrant(
                    common::paramStr(req, "contact_token"),
                    "ticket"
                );
                if (!zct_slms::recovery::allowed("ticket") ||
                    !zct_slms::recovery::contacts(flow.account).empty())
                    throw std::runtime_error("此账号请使用已绑定身份自助恢复");
                role = flow.account["user_type"].asString();
                uid = flow.account["user_id"].asInt64();
                contact["method"] = flow.method;
                contact["target"] = flow.target;
                contact["fingerprint"] = flow.fingerprint;
            } else {
                if (category == "SECURITY" && !auth.success) {
                    std::lock_guard lock(zct_slms::recovery::guard);
                    auto flow = zct_slms::recovery::takeGrant(common::paramStr(req, "contact_token"), "security-ticket");
                    if (!zct_slms::recovery::allowed("ticket"))throw std::runtime_error("人工恢复已关闭");
                    auth.success = true;
                    auth.user_type = flow.account["user_type"].asString();
                    auth.user_id = flow.account["user_id"].asInt64();
                }
                if (!auth.success)
                    throw std::runtime_error("请先登录后创建支持工单");
                role = auth.user_type;
                uid = auth.user_id;
                if (category == "SECURITY") {
                    auto method = common::paramStr(req, "security_method"), action = common::paramStr(req, "security_action", "UNBIND");
                    if (action != "UNBIND" && action != "RESET")throw std::runtime_error("安全工单操作无效");
                    std::lock_guard lock(zct_slms::factors::guard);
                    contact = securitySnapshot(role, uid, method, common::paramStr(req, "key_id"));
                    contact["action"] = action;
                }
                if (category == "PASSKEY") {
                    zct_slms::factors::auth(req, true);
                    std::lock_guard lock(zct_slms::factors::guard);
                    auto factors = zct_slms::factors::load(zct_slms::factors::accountKey(role, uid));
                    auto keyId = common::paramStr(req, "key_id");
                    bool found = false;
                    for (const auto& key : factors["keys"]) {
                        if (key["id"].asString() == keyId) {
                            contact["key_id"] = keyId;
                            contact["key_name"] = key["name"];
                            contact["factor_version"] = factors.get("version", 0);
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                        throw std::runtime_error("通行密钥不存在");
                }
            }
            {
                std::lock_guard limit(mutex);
                prune();
                rate("ticket-create-ip:" + common::clientIp(req), 5, 3600);
                rate("ticket-create-user:" + role + std::to_string(uid), 5, 3600);
            }
            auto id = zct_slms::crypto::randomHex(16), token = zct_slms::crypto::randomHex(32);
            auto& db = zct_slms::db::Database::instance();
            if (!db.transaction(
                [&] {
                    db.execParams(
                        "INSERT INTO "
                        "support_tickets(id,category,owner_role,owner_id,title,"
                        "status,access_hash,contact_cipher,created_at,updated_"
                        "at) VALUES (?,?,?,?,?,'OPEN',?,?,?,?)",
                        id,
                        category,
                        role,
                        uid,
                        title,
                        zct_slms::crypto::sha256Hex(token),
                        encrypted(contact),
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
                        body,
                        now()
                    );
                    return true;
                }
            ))
                throw std::runtime_error("工单创建失败");
            Json out;
            out["id"] = id;
            out["access_token"] = token;
            if (changed)
                changed(id, role, uid);
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void markAllRead(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req);
            auto& db = zct_slms::db::Database::instance();
            const std::string sql =
                "INSERT INTO ticket_reads(ticket_id,viewer_role,viewer_id,seen_count) SELECT t.id,?,?,SUM(CASE WHEN m.id IS NOT NULL AND NOT (m.sender_role=? AND m.sender_id=?) THEN 1 ELSE 0 END) FROM support_tickets t LEFT JOIN ticket_messages m ON m.ticket_id=t.id WHERE ";
            const std::string tail = " GROUP BY t.id ON CONFLICT(ticket_id,viewer_role,viewer_id) DO UPDATE SET seen_count=excluded.seen_count";
            if (staff(a.user_type))db.execParams(sql + "1=1" + tail, a.user_type, a.user_id, a.user_type, a.user_id);
            else db.execParams(sql + "t.owner_role=? AND t.owner_id=?" + tail, a.user_type, a.user_id, a.user_type, a.user_id, a.user_type, a.user_id);
            ok(cb);
        } catch (const std::exception& e) { fail(cb, e.what()); }
    }

    inline void list(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req);
            auto& db = zct_slms::db::Database::instance();
            auto filter = common::paramStr(req, "status", staff(a.user_type) ? "OPEN" : "ALL");
            std::set<std::string> states;
            std::stringstream stream(filter);
            std::string value;
            while (std::getline(stream, value, ',')) {
                if (value != "ALL" && value != "OPEN" && value != "RESOLVED" &&
                    value != "UNABLE" && value != "REJECTED" && value != "PROCESSING")
                    throw std::runtime_error("工单状态筛选无效");
                states.insert(value);
            }
            if (states.empty())
                throw std::runtime_error("工单状态筛选无效");
            std::string condition = "1=1";
            if (!states.contains("ALL")) {
                condition = "t.status IN (";
                for (auto& state : states) {
                    if (condition.back() != '(')
                        condition += ",";
                    condition += "'" + state + "'";
                }
                condition += ")";
            }
            auto categoryFilter = common::paramStr(req, "category", "ALL");
            std::set<std::string> categories;
            std::stringstream categoryStream(categoryFilter);
            while (std::getline(categoryStream, value, ',')) {
                if (value == "UNBIND") {
                    categories.insert("PASSKEY");
                    categories.insert("SECURITY");
                } else if (value == "ALL" || value == "FORGOT" || value == "ACCOUNT" || value == "GENERAL" || value == "PASSKEY" || value == "SECURITY" || value == "VIOLATION" ||
                           value == "CLOSURE")
                    categories.insert(value);
                else throw std::runtime_error("工单类型筛选无效");
            }
            if (categories.empty())throw std::runtime_error("工单类型筛选无效");
            if (!categories.contains("ALL")) {
                condition += " AND t.category IN (";
                bool first = true;
                for (const auto& category : categories) {
                    if (!first)condition += ",";
                    condition += "'" + category + "'";
                    first = false;
                }
                condition += ")";
            }
            auto sql = "SELECT t.* FROM support_tickets t LEFT JOIN ticket_properties "
                "p ON p.ticket_id = t.id WHERE ";
            auto order =
                " ORDER BY CASE WHEN t.status = 'OPEN' THEN 0 ELSE 1 END,COALESCE(p.priority,2) DESC,t.updated_at DESC,t.id DESC LIMIT 1000";
            auto rows =
                staff(a.user_type)
                    ? db.queryParams(std::string(sql) + condition + order)
                    : db.queryParams(
                        std::string(sql) +
                        "t.owner_role = ? AND t.owner_id = ? AND " +
                        condition + order,
                        a.user_type,
                        a.user_id
                    );
            Json out(::Json::arrayValue);
            for (auto& row : rows) {
                auto item = summary(row);
                decorate(item, zct_slms::repo::getStr(row, "id"), a.user_type, a.user_id);
                out.append(item);
            }
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void read(const Req& req, Callback&& cb) {
        try {
            Json out;
            auto& readDb = zct_slms::db::Database::instance();
            if (!readDb.transaction(
                [&] {
                    auto id = common::paramStr(req, "id");
                    auto [row, a] = permitted(req, id);
                    out = summary(row);
                    out["messages"] = Json(::Json::arrayValue);
                    std::map<std::string, Json> senderProfiles;
                    for (auto& message : zct_slms::db::Database::instance().queryParams(
                             "SELECT sender_role,sender_id,body,created_at FROM (SELECT "
                             "id,sender_role,sender_id,body,created_at FROM ticket_messages WHERE "
                             "ticket_id = ? ORDER BY created_at DESC,id DESC LIMIT 500) "
                             "recent "
                             "ORDER BY created_at,id",
                             id
                         )) {
                        Json m;
                        m["sender_role"] = zct_slms::repo::getStr(message, "sender_role");
                        auto senderId = zct_slms::repo::getInt(message, "sender_id");
                        auto senderKey = m["sender_role"].asString() + ":" + std::to_string(senderId);
                        if (!senderProfiles.contains(senderKey))senderProfiles[senderKey] = mailAccount(m["sender_role"].asString(), senderId);
                        m["sender_username"] = senderProfiles[senderKey]["username"];
                        m["sender_nickname"] = senderProfiles[senderKey]["nickname"];

                        m["body"] = zct_slms::repo::getStr(message, "body");
                        m["created_at"] =
                            ::Json::Int64(zct_slms::repo::getInt(message, "created_at"));
                        out["messages"].append(m);
                    }
                    out["can_reset_password"] =
                        a.success && staff(a.user_type) &&
                        zct_slms::repo::getStr(row, "category") == "FORGOT" &&
                        zct_slms::repo::getStr(row, "status") == "OPEN" &&
                        (a.user_type == "ADMIN" ||
                         zct_slms::repo::getStr(row, "owner_role") == "USER" ||
                         zct_slms::repo::getStr(row, "owner_role") == "SUBUSER");
                    out["can_remove_passkey"] =
                        a.success && staff(a.user_type) &&
                        zct_slms::repo::getStr(row, "category") == "PASSKEY" &&
                        zct_slms::repo::getStr(row, "status") == "OPEN" &&
                        !(a.user_type == zct_slms::repo::getStr(row, "owner_role") &&
                          a.user_id == zct_slms::repo::getInt(row, "owner_id")) &&
                        (a.user_type == "ADMIN" ||
                         zct_slms::repo::getStr(row, "owner_role") == "USER" ||
                         zct_slms::repo::getStr(row, "owner_role") == "SUBUSER");
                    if (zct_slms::repo::getStr(row, "category") == "PASSKEY")
                        out["passkey_name"] =
                            decrypted(zct_slms::repo::getStr(row, "contact_cipher"))["key_name"];
                    decorate(
                        out,
                        id,
                        a.success ? a.user_type : zct_slms::repo::getStr(row, "owner_role"),
                        a.success ? a.user_id : zct_slms::repo::getInt(row, "owner_id"),
                        true
                    );
                    out["can_manage"] = a.success && staff(a.user_type);
                    out["can_approve_closure"] =
                        a.success && a.user_type == "ADMIN" &&
                        zct_slms::repo::getStr(row, "category") == "CLOSURE" &&
                        zct_slms::repo::getStr(row, "status") == "OPEN" &&
                        !(a.user_type == zct_slms::repo::getStr(row, "owner_role") &&
                          a.user_id == zct_slms::repo::getInt(row, "owner_id"));
                    out["can_change_status"] =
                        a.success &&
                        (a.user_type == "ADMIN" ||
                         (staff(a.user_type) &&
                          zct_slms::repo::getStr(row, "category") != "VIOLATION" &&
                          zct_slms::repo::getStr(row, "category") != "CLOSURE"));
                    out["can_reset_security"] = a.success && staff(a.user_type) &&
                                                zct_slms::repo::getStr(row, "category") == "SECURITY" && zct_slms::repo::getStr(row, "status") == "OPEN" &&
                                                !(a.user_type == zct_slms::repo::getStr(row, "owner_role") && a.user_id == zct_slms::repo::getInt(row, "owner_id")) &&
                                                (a.user_type == "ADMIN" || zct_slms::repo::getStr(row, "owner_role") == "USER" || zct_slms::repo::getStr(row, "owner_role") ==
                                                 "SUBUSER");
                    if (zct_slms::repo::getStr(row, "category") == "SECURITY") {
                        auto request = decrypted(zct_slms::repo::getStr(row, "contact_cipher"));
                        out["security_method"] = request["method"];
                        out["security_action"] = request["action"];
                        out["security_name"] = request.get("name", "");
                    }
                    out["can_moderate"] =
                        a.success && a.user_type == "ADMIN" &&
                        zct_slms::repo::getStr(row, "category") == "VIOLATION" &&
                        zct_slms::repo::getStr(row, "status") == "OPEN";
                    if (zct_slms::repo::getStr(row, "category") == "VIOLATION")
                        out["violation"] =
                            decrypted(zct_slms::repo::getStr(row, "contact_cipher"));
                    out["can_reopen"] =
                        !out["reopen_used"].asBool() &&
                        zct_slms::repo::getStr(row, "status") != "OPEN" &&
                        zct_slms::repo::getStr(row, "status") != "PROCESSING" &&
                        (!a.success ||
                         (a.user_type == zct_slms::repo::getStr(row, "owner_role") &&
                          a.user_id == zct_slms::repo::getInt(row, "owner_id")));
                    return true;
                }
            ))
                throw std::runtime_error("工单阅读状态保存失败");
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void reply(const Req& req, Callback&& cb) {
        try {
            auto id = common::paramStr(req, "id"), body = common::paramStr(req, "body");
            auto [row, a] = permitted(req, id, true);
            if (body.empty() || body.size() > 786432)
                throw std::runtime_error("回复不能为空或超过 768 KB（含图片）");
            auto role = a.success ? a.user_type : zct_slms::repo::getStr(row, "owner_role");
            auto uid = a.success ? a.user_id : zct_slms::repo::getInt(row, "owner_id");
            auto& db = zct_slms::db::Database::instance();
            db.execParams(
                "INSERT INTO "
                "ticket_messages(id,ticket_id,sender_role,sender_id,body,"
                "created_at) VALUES (?,?,?,?,?,?)",
                zct_slms::tickets::messageId(),
                id,
                role,
                uid,
                body,
                now()
            );
            db.execParams(
                "UPDATE support_tickets SET updated_at = ? WHERE id = ?",
                now(),
                id
            );
            if (changed)
                changed(id, role, uid);
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void close(const Req& req, Callback&& cb) {
        try {
            auto id = common::paramStr(req, "id");
            auto [row, a] = permitted(req, id);
            if (!a.success || !staff(a.user_type))
                throw std::runtime_error("需要管理员或支持账号登录");
            if ((zct_slms::repo::getStr(row, "category") == "VIOLATION" ||
                 zct_slms::repo::getStr(row, "category") == "CLOSURE") &&
                a.user_type != "ADMIN")
                throw std::runtime_error("违规工单仅由管理员处理");
            zct_slms::db::Database::instance().execParams(
                "UPDATE support_tickets SET status = 'REJECTED',updated_at = ? WHERE "
                "id "
                "= ? AND status = 'OPEN'",
                now(),
                id
            );
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline std::mutex resetGuard;

    inline void removePasskey(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto a = zct_slms::factors::auth(req, true);
                    if (!staff(a.user_type) || common::paramStr(req, "reviewed") != "1")
                        throw std::runtime_error("请先核验账号归属及删除申请");
                    std::scoped_lock lock(resetGuard, zct_slms::factors::guard);
                    auto id = common::paramStr(req, "id");
                    auto [row, ignored] = permitted(req, id, true);
                    auto role = zct_slms::repo::getStr(row, "owner_role");
                    auto uid = zct_slms::repo::getInt(row, "owner_id");
                    if (zct_slms::repo::getStr(row, "category") != "PASSKEY" ||
                        (a.user_type == role && a.user_id == uid) ||
                        (a.user_type == "SUPPORT" && role != "USER" && role != "SUBUSER"))
                        throw std::runtime_error("无权处理此通行密钥删除申请");
                    auto request = decrypted(zct_slms::repo::getStr(row, "contact_cipher"));
                    auto account = zct_slms::factors::accountKey(role, uid);
                    auto factors = zct_slms::factors::load(account);
                    if (request["factor_version"] != factors.get("version", 0))
                        throw std::runtime_error("账号安全设置已变化，请用户重新提交申请");
                    zct_slms::factors::removeKey(factors, request["key_id"].asString());
                    factors["version"] = factors.get("version", 0).asInt() + 1;
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
                            zct_slms::factors::store(account, factors);
                            db.execParams(
                                "UPDATE sessions SET revoked = 1 WHERE user_type = ? "
                                "AND user_id = ?",
                                role,
                                uid
                            );
                            db.execParams(
                                "INSERT INTO "
                                "ticket_messages(id,ticket_id,sender_role,sender_id,"
                                "body,created_at) VALUES (?,?,?,?,?,?)",
                                zct_slms::tickets::messageId(),
                                id,
                                a.user_type,
                                a.user_id,
                                "已核验账号归属并删除申请中的通行密钥。原登录会话已失"
                                "效，请重新登录。",
                                now()
                            );
                            return true;
                        }
                    ))
                        throw std::runtime_error("删除处理失败");
                    zct_slms::repo::AuditRepo::log(
                        a.user_type,
                        a.user_id,
                        "RemovePasskeyByReviewedTicket",
                        role,
                        uid,
                        "",
                        "success",
                        common::clientIp(req),
                        "{}",
                        now()
                    );
                    db.execParams(
                        "INSERT INTO ticket_status_events(id,ticket_id,status,created_at) "
                        "VALUES (?,?,'RESOLVED',?)",
                        zct_slms::crypto::randomHex(16),
                        id,
                        now()
                    );
                    if (changed)
                        changed(id, a.user_type, a.user_id);
                    ok(cb);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void resetSecurity(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto a = zct_slms::factors::auth(req, true);
                    if (!staff(a.user_type) || common::paramStr(req, "reviewed") != "1")throw std::runtime_error("请先核验账号归属和安全申请");
                    std::scoped_lock lock(resetGuard, zct_slms::factors::guard);
                    auto id = common::paramStr(req, "id");
                    auto [row,ignored] = permitted(req, id, true);
                    auto role = zct_slms::repo::getStr(row, "owner_role");
                    auto uid = zct_slms::repo::getInt(row, "owner_id");
                    if (zct_slms::repo::getStr(row, "category") != "SECURITY" || (a.user_type == role && a.user_id == uid) || (
                            a.user_type == "SUPPORT" && role != "USER" && role != "SUBUSER"))
                        throw std::runtime_error("无权处理此账号安全申请");
                    auto request = decrypted(zct_slms::repo::getStr(row, "contact_cipher"));
                    auto method = request["method"].asString();
                    auto snapshot = request;
                    snapshot.removeMember("action");
                    auto key = zct_slms::factors::accountKey(role, uid);
                    auto factors = zct_slms::factors::load(key);
                    auto& db = zct_slms::db::Database::instance();
                    if (!db.transaction(
                        [&] {
                            if (json(snapshot) != json(securitySnapshot(role, uid, method, request["key_id"].asString())))throw std::runtime_error("账号安全信息已变化，请重新提交申请");
                            db.execParams("UPDATE support_tickets SET status='RESOLVED',updated_at=? WHERE id=? AND status='OPEN'", now(), id);
                            if (db.rowsChanged() != 1)throw std::runtime_error("工单已被处理");
                            if (method == "totp") {
                                factors["totp_enabled"] = false;
                                for (auto field : {"totp_secret", "pending_totp", "last_step"})factors.removeMember(field);
                            } else if (method == "passkey") {
                                if (request["key_id"].asString().empty()) {
                                    factors["keys"] = Json(::Json::arrayValue);
                                    factors["passkey_required"] = false;
                                    factors.removeMember("pending_passkey");
                                } else zct_slms::factors::removeKey(factors, request["key_id"].asString());
                            } else if (method == "recovery") {
                                factors["recovery"] = Json(::Json::arrayValue);
                                factors["recovery_reset_pending"] = request["action"] == "RESET";
                            } else {
                                if (role == "USER")db.execParams("DELETE FROM auth_identities WHERE user_id=? AND provider=?", uid, method);
                                db.execParams("DELETE FROM recovery_contacts WHERE account_role=? AND user_id=? AND provider=?", role, uid, method);
                            }
                            factors["version"] = factors.get("version", 0).asInt() + 1;
                            zct_slms::factors::store(key, factors);
                            db.execParams("UPDATE sessions SET revoked=1 WHERE user_type=? AND user_id=?", role, uid);
                            db.execParams(
                                "INSERT INTO ticket_messages(id,ticket_id,sender_role,sender_id,body,created_at) VALUES (?,?,?,?,?,?)",
                                zct_slms::tickets::messageId(),
                                id,
                                a.user_type,
                                a.user_id,
                                "账号安全申请已审核通过，指定登录方式已移除，旧会话已撤销。请重新登录并自行绑定新身份或生成新恢复码。",
                                now()
                            );
                            db.execParams("INSERT INTO ticket_status_events(id,ticket_id,status,created_at) VALUES (?,?,'RESOLVED',?)", zct_slms::crypto::randomHex(16), id, now());
                            return true;
                        }
                    ))
                        throw std::runtime_error("安全申请处理失败");
                    zct_slms::repo::AuditRepo::log(a.user_type, a.user_id, "ResetSecurityByReviewedTicket", role, uid, "", "success", common::clientIp(req), "{}", now());
                    if (changed)changed(id, a.user_type, a.user_id);
                    ok(cb);
                } catch (const std::exception& e) { fail(cb, e.what()); }
            }
        );
    }

    inline void resetPassword(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                std::string claimed;
                try {
                    auto a = zct_slms::factors::auth(req, true);
                    if (!staff(a.user_type) || common::paramStr(req, "reviewed") != "1")
                        throw std::runtime_error("请先核验申诉材料和账号归属");
                    if (!zct_slms::recovery::allowed("ticket"))
                        throw std::runtime_error("人工恢复已关闭");
                    auto id = common::paramStr(req, "id");
                    auto [row, unused] = permitted(req, id, true);
                    auto role = zct_slms::repo::getStr(row, "owner_role");
                    auto uid = zct_slms::repo::getInt(row, "owner_id");
                    if (zct_slms::repo::getStr(row, "category") != "FORGOT" ||
                        a.user_type == "SUPPORT" && (role == "ADMIN" || role == "SUPPORT"))
                        throw std::runtime_error("无权重置此账号");
                    Json account;
                    account["user_type"] = role;
                    account["user_id"] = ::Json::Int64(uid);
                    if (!zct_slms::portal_auth::active(account) ||
                        !zct_slms::recovery::contacts(account).empty())
                        throw std::runtime_error("账号不可用或已有自助恢复方式");
                    auto contact = decrypted(zct_slms::repo::getStr(row, "contact_cipher"));
                    if (contact.get("fingerprint", "").asString() !=
                        zct_slms::portal_auth::fingerprint(account))
                        throw std::runtime_error("账号密码已变更，请重新提交工单");
                    auto method = contact["method"].asString(),
                         target = contact["target"].asString();
                    auto cfg = zct_slms::recovery::transport(method);
                    auto password = zct_slms::vouchers::generate(true).substr(0, 24);
                    auto hp = zct_slms::service::hashPassword(password);
                    {
                        std::lock_guard lock(resetGuard);
                        auto current = zct_slms::db::Database::instance().queryParams(
                            "SELECT status FROM support_tickets WHERE id = ?",
                            id
                        );
                        if (current.empty() ||
                            zct_slms::repo::getStr(current[0], "status") != "OPEN")
                            throw std::runtime_error("工单已在处理或已结束");
                        zct_slms::db::Database::instance().execParams(
                            "UPDATE support_tickets SET status = 'PROCESSING',updated_at = ? "
                            "WHERE id = ?",
                            now(),
                            id
                        );
                        claimed = id;
                    }
                    try {
                        if (method == "email")
                            deliverEmail(cfg, target, password, true, "", "", "temporary_password", mailAccount(role, uid, target));
                        else
                            deliverPhone(cfg, target, password, true);
                    } catch (...) {
                        zct_slms::db::Database::instance().execParams(
                            "UPDATE support_tickets SET status = 'OPEN' WHERE id = ?",
                            id
                        );
                        claimed.clear();
                        throw;
                    }
                    auto& db = zct_slms::db::Database::instance();
                    const auto success = db.transaction(
                        [&] {
                            if (contact.get("fingerprint", "").asString() !=
                                zct_slms::portal_auth::fingerprint(account))
                                throw std::runtime_error("账号凭据在处理期间发生变化");
                            if (role == "USER" && identityUser(method, target) == 0)
                                attach(uid, method, target);
                            db.execParams(
                                "INSERT INTO "
                                "recovery_contacts(account_role,user_id,provider,target) VALUES "
                                "(?,?,?,?) ON CONFLICT(account_role,user_id,provider) DO UPDATE "
                                "SET target = excluded.target",
                                role,
                                uid,
                                method,
                                target
                            );
                            db.execParams(
                                "UPDATE " + zct_slms::portal::table(role) +
                                " SET password_hash = ?,salt = ?,updated_at = ? WHERE id = ?",
                                hp.hash,
                                hp.salt,
                                now(),
                                uid
                            );
                            db.execParams(
                                "UPDATE sessions SET revoked = 1 WHERE user_type = ? AND "
                                "user_id = ?",
                                role,
                                uid
                            );
                            zct_slms::repo::ConfigRepo::set(
                                "force_password:" + role + ":" + std::to_string(uid),
                                "1",
                                now()
                            );
                            db.execParams(
                                "UPDATE support_tickets SET status = "
                                "'RESOLVED',updated_at = ? WHERE id = ?",
                                now(),
                                id
                            );
                            db.execParams(
                                "INSERT INTO "
                                "ticket_messages(id,ticket_id,sender_role,sender_id,body,created_"
                                "at) VALUES (?,?,?,?,?,?)",
                                zct_slms::tickets::messageId(),
                                id,
                                a.user_type,
                                a.user_id,
                                "临时密码已发送至申诉时验证的联系方式。首次登录后须设置新密码。",
                                now()
                            );
                            return true;
                        }
                    );
                    if (!success)
                        throw std::runtime_error("重置处理失败");
                    claimed.clear();
                    zct_slms::repo::AuditRepo::log(
                        a.user_type,
                        a.user_id,
                        "ResetPasswordByVerifiedTicket",
                        role,
                        uid,
                        "",
                        "success",
                        common::clientIp(req),
                        "{}",
                        now()
                    );
                    db.execParams(
                        "INSERT INTO ticket_status_events(id,ticket_id,status,created_at) "
                        "VALUES (?,?,'RESOLVED',?)",
                        zct_slms::crypto::randomHex(16),
                        id,
                        now()
                    );
                    if (changed)
                        changed(id, a.user_type, a.user_id);
                    ok(cb);
                } catch (const std::exception& e) {
                    if (!claimed.empty())
                        zct_slms::db::Database::instance().execParams(
                            "UPDATE support_tickets SET status = 'OPEN' WHERE id = ?",
                            claimed
                        );
                    fail(cb, e.what());
                }
            }
        );
    }
} // namespace zct_slms::tickets
