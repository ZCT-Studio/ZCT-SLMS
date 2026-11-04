// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "services/tickets.hpp"

namespace zct_slms::tickets {
    inline void status(const Req& req, Callback&& cb) {
        try {
            auto id = common::paramStr(req, "id"),
                 state = common::paramStr(req, "status");
            if (state != "OPEN" && state != "RESOLVED" && state != "UNABLE" &&
                state != "REJECTED")
                throw std::runtime_error("工单状态无效");
            auto [row, a] = permitted(req, id);
            auto role = zct_slms::repo::getStr(row, "owner_role");
            auto uid = zct_slms::repo::getInt(row, "owner_id");
            auto& db = zct_slms::db::Database::instance();
            const auto previous = zct_slms::repo::getStr(row, "status");
            const bool operatorStaff = a.success && staff(a.user_type);
            if (zct_slms::repo::getStr(row, "category") == "CLOSURE" &&
                ((operatorStaff && a.user_type != "ADMIN") || state == "RESOLVED"))
                throw std::runtime_error(
                    "注销工单由管理员专门审核，批准后才能标记已处理"
                );
            if (operatorStaff && zct_slms::repo::getStr(row, "category") == "VIOLATION" &&
                a.user_type != "ADMIN")
                throw std::runtime_error("违规工单仅由管理员处理状态");
            if (previous == "PROCESSING")
                throw std::runtime_error("工单正在执行安全操作，请稍后再试");
            if (state == previous)
                throw std::runtime_error("工单已处于此状态");
            if (!db.transaction(
                [&] {
                    db.execParams(
                        "INSERT INTO ticket_properties(ticket_id,priority,reopen_used) "
                        "VALUES (?,2,0) ON CONFLICT(ticket_id) DO NOTHING",
                        id
                    );
                    if (!operatorStaff) {
                        if (state != "OPEN" || previous == "OPEN")
                            throw std::runtime_error("仅可申请重新标记为待处理");
                        db.execParams(
                            "UPDATE ticket_properties SET reopen_used = 1 WHERE "
                            "ticket_id = ? AND reopen_used = 0",
                            id
                        );
                        if (db.rowsChanged() != 1)
                            throw std::runtime_error("每个工单仅能申请重新处理一次");
                    }
                    db.execParams(
                        "UPDATE support_tickets SET status = ?,updated_at = ? "
                        "WHERE id = ? AND status = ?",
                        state,
                        now(),
                        id,
                        previous
                    );
                    if (db.rowsChanged() != 1)
                        throw std::runtime_error("工单状态已变化，请刷新");
                    db.execParams(
                        "INSERT INTO "
                        "ticket_status_events(id,ticket_id,status,created_at) "
                        "VALUES (?,?,?,?)",
                        zct_slms::crypto::randomHex(16),
                        id,
                        state,
                        now()
                    );
                    std::string label = state == "OPEN"
                                            ? "待处理"
                                            : state == "RESOLVED"
                                            ? "已处理"
                                            : state == "UNABLE"
                                            ? "无法处理"
                                            : "已拒绝";
                    db.execParams(
                        "INSERT INTO "
                        "ticket_messages(id,ticket_id,sender_role,sender_id,body,created_"
                        "at) VALUES (?,?,?,?,?,?)",
                        zct_slms::tickets::messageId(),
                        id,
                        a.success ? a.user_type : role,
                        a.success ? a.user_id : uid,
                        "工单状态已更新为：" + label,
                        now()
                    );
                    return true;
                }
            ))
                throw std::runtime_error("状态更新失败");
            if (changed)
                changed(id, a.success ? a.user_type : role, a.success ? a.user_id : uid);
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void priority(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::factors::auth(req);
            if (!staff(a.user_type))
                throw std::runtime_error("仅管理员或支持人员可设置优先级");
            auto id = common::paramStr(req, "id");
            auto [row, unused] = permitted(req, id);
            auto p = common::paramI64(req, "priority", 2);
            if (p < 0 || p > 4)
                throw std::runtime_error("优先级无效");
            zct_slms::db::Database::instance().execParams(
                "INSERT INTO ticket_properties(ticket_id,priority,reopen_used) VALUES "
                "(?,?,0) ON CONFLICT(ticket_id) DO UPDATE SET priority = "
                "excluded.priority",
                id,
                p
            );
            ok(cb);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void dashboard(const Req& req, Callback&& cb) {
        try {
            schema();
            auto a = zct_slms::factors::auth(req);
            auto& db = zct_slms::db::Database::instance();
            Json out;
            out["unread_messages"] = 0;
            out["pending_types"] = Json(::Json::objectValue);
            out["days"] = Json(::Json::arrayValue);
            const std::string aggregate =
                "SELECT t.category,SUM(CASE WHEN t.status = 'OPEN' THEN 1 ELSE 0 END) "
                "AS pending,SUM(CASE WHEN COALESCE(m.n,0) > COALESCE(r.seen_count,0) "
                "THEN COALESCE(m.n,0) - COALESCE(r.seen_count,0) ELSE 0 END) AS unread "
                "FROM support_tickets t LEFT JOIN (SELECT ticket_id,COUNT(*) AS n FROM "
                "ticket_messages WHERE NOT (sender_role = ? AND sender_id = ?) GROUP "
                "BY ticket_id) m ON m.ticket_id = t.id LEFT JOIN ticket_reads r ON "
                "r.ticket_id = t.id AND r.viewer_role = ? AND r.viewer_id = ? ";
            auto rows =
                staff(a.user_type)
                    ? db.queryParams(
                        aggregate + "GROUP BY t.category",
                        a.user_type,
                        a.user_id,
                        a.user_type,
                        a.user_id
                    )
                    : db.queryParams(
                        aggregate + "WHERE t.owner_role = ? AND "
                        "t.owner_id = ? GROUP BY t.category",
                        a.user_type,
                        a.user_id,
                        a.user_type,
                        a.user_id,
                        a.user_type,
                        a.user_id
                    );
            int64_t unread = 0;
            for (const auto& r : rows) {
                unread += zct_slms::repo::getInt(r, "unread");
                out["pending_types"][zct_slms::repo::getStr(r, "category")] =
                    ::Json::Int64(zct_slms::repo::getInt(r, "pending"));
            }
            out["unread_messages"] = ::Json::Int64(unread);
            const auto today = now() / 86400 * 86400;
            if (staff(a.user_type))
                for (int i = 13; i >= 0; --i) {
                    auto day = today - i * 86400;
                    Json item;
                    item["day"] = ::Json::Int64(day);
                    auto created =
                        db.queryParams(
                            "SELECT COUNT(*) AS n FROM support_tickets WHERE "
                            "created_at >= ? AND created_at < ?",
                            day,
                            day + 86400
                        );
                    auto solved = db.queryParams(
                        "SELECT COUNT(DISTINCT ticket_id) AS n FROM ticket_status_events "
                        "WHERE status = 'RESOLVED' AND created_at >= ? AND created_at < ?",
                        day,
                        day + 86400
                    );
                    item["created"] = ::Json::Int64(zct_slms::repo::getInt(created[0], "n"));
                    auto total = db.queryParams(
                        "SELECT COUNT(*) AS n FROM support_tickets WHERE created_at < ?",
                        day + 86400
                    );
                    item["total"] = ::Json::Int64(zct_slms::repo::getInt(total[0], "n"));
                    item["resolved"] = ::Json::Int64(zct_slms::repo::getInt(solved[0], "n"));
                    out["days"].append(item);
                }
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }
} // namespace zct_slms::tickets
