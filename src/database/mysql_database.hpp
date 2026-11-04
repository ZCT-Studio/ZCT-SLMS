// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "database/idatabase.hpp"
#include <mysql.h>
#include <cstring>
#include <string>
#include <vector>

namespace zct_slms::db {
    class MysqlDatabase : public IDatabase {
    public:
        const char* backendName() const override { return "mysql"; }

        void open(const std::string& conninfo) override {
            // conninfo 格式: host:port:user:password:dbname:connect_timeout
            auto parts = splitColon(conninfo);
            if (parts.size() < 5) throw SQLException(std::format("mysql bad conninfo: {}", conninfo));
            const char* host = parts[0].c_str();
            unsigned int port = 3306;
            try { port = std::stoul(parts[1]); } catch (...) {}
            const char* user = parts[2].c_str();
            const char* pwd = parts[3].c_str();
            const char* db = parts[4].c_str();
            unsigned int timeout = parts.size() > 5 ? static_cast<unsigned>(std::stoul(parts[5])) : 10;

            std::unique_lock lock(mtx_);
            closeLocked();

            MYSQL* m = mysql_init(nullptr);
            if (!m) throw SQLException("mysql_init failed");

            unsigned int opt_timeout = timeout;
            mysql_options(m, MYSQL_OPT_CONNECT_TIMEOUT, &opt_timeout);
            unsigned int opt_read_timeout = 30;
            mysql_options(m, MYSQL_OPT_READ_TIMEOUT, &opt_read_timeout);

            if (!mysql_real_connect(m, host, user, pwd, db, port, nullptr, 0)) {
                auto msg = mysql_error(m);
                mysql_close(m);
                throw SQLException(std::format("mysql connect failed: {}", msg ? msg : "unknown"));
            }
            mysql_set_character_set(m, "utf8mb4");
            mysql_ = m;
            open_ = true;
        }

        void close() override {
            std::unique_lock lock(mtx_);
            closeLocked();
        }

        bool isOpen() const override { return open_ && mysql_ != nullptr; }

        int64_t lastInsertId() const override { return mysql_ ? static_cast<int64_t>(mysql_insert_id(mysql_)) : 0; }
        int rowsChanged() const override { return static_cast<int>(lastRows_); }

        void exec(const std::string& sql) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            if (mysql_real_query(mysql_, sql.c_str(), static_cast<unsigned long>(sql.size())) != 0) {
                auto msg = mysql_error(mysql_);
                throw SQLException(std::format("mysql exec: {} | sql: {}", msg ? msg : "unknown", sql));
            }
            MYSQL_RES* res = mysql_store_result(mysql_);
            if (res) { mysql_free_result(res); }
            lastRows_ = mysql_affected_rows(mysql_);
        }

        void execParams(const std::string& sql, const std::vector<std::string>& params) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            MYSQL_STMT* stmt = mysql_stmt_init(mysql_);
            if (!stmt) throw SQLException("mysql_stmt_init failed");
            if (mysql_stmt_prepare(stmt, sql.c_str(), static_cast<unsigned long>(sql.size())) != 0) {
                auto msg = mysql_stmt_error(stmt);
                mysql_stmt_close(stmt);
                throw SQLException(std::format("mysql_stmt_prepare: {}", msg ? msg : "unknown"));
            }
            if (!params.empty()) bindAndExec(stmt, params);
            else {
                if (mysql_stmt_execute(stmt) != 0) {
                    auto msg = mysql_stmt_error(stmt);
                    mysql_stmt_close(stmt);
                    throw SQLException(std::format("mysql_stmt_execute: {}", msg ? msg : "unknown"));
                }
            }
            lastRows_ = mysql_stmt_affected_rows(stmt);
            mysql_stmt_close(stmt);
        }

        ResultSet query(const std::string& sql) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            if (mysql_real_query(mysql_, sql.c_str(), static_cast<unsigned long>(sql.size())) != 0) {
                auto msg = mysql_error(mysql_);
                throw SQLException(std::format("mysql query: {}", msg ? msg : "unknown"));
            }
            auto* res = mysql_store_result(mysql_);
            if (!res) throw SQLException(std::format("mysql store_result: {}", mysql_error(mysql_)));
            auto rows = collectRes(res);
            mysql_free_result(res);
            return rows;
        }

        ResultSet queryParams(const std::string& sql, const std::vector<std::string>& params) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            MYSQL_STMT* stmt = mysql_stmt_init(mysql_);
            if (!stmt) throw SQLException("mysql_stmt_init failed");
            if (mysql_stmt_prepare(stmt, sql.c_str(), static_cast<unsigned long>(sql.size())) != 0) {
                auto msg = mysql_stmt_error(stmt);
                mysql_stmt_close(stmt);
                throw SQLException(std::format("mysql_stmt_prepare: {}", msg ? msg : "unknown"));
            }
            if (!params.empty()) bindAndExec(stmt, params);
            else {
                if (mysql_stmt_execute(stmt) != 0) {
                    auto msg = mysql_stmt_error(stmt);
                    mysql_stmt_close(stmt);
                    throw SQLException(std::format("mysql_stmt_execute: {}", msg ? msg : "unknown"));
                }
            }
            if (mysql_stmt_store_result(stmt) != 0) {
                auto msg = mysql_stmt_error(stmt);
                mysql_stmt_close(stmt);
                throw SQLException(std::format("mysql_stmt_store_result: {}", msg ? msg : "unknown"));
            }
            auto rows = collectStmtRes(stmt);
            lastRows_ = mysql_stmt_affected_rows(stmt);
            mysql_stmt_close(stmt);
            return rows;
        }

        std::optional<std::string> queryScalar(
            const std::string& sql,
            const std::vector<std::string>& params
        ) override {
            auto rs = queryParams(sql, params);
            if (!rs.empty() && !rs[0].empty()) return rs[0][0].second;
            return std::nullopt;
        }

    protected:
        void beginTransaction() override { exec("START TRANSACTION"); }
        void commitTransaction() override { exec("COMMIT"); }
        void rollbackTransaction() override { exec("ROLLBACK"); }

    private:
        MYSQL* mysql_ = nullptr;
        bool open_ = false;
        uint64_t lastRows_ = 0;

        void closeLocked() {
            if (mysql_) {
                mysql_close(mysql_);
                mysql_ = nullptr;
            }
            open_ = false;
        }

        void checkOpen() const {
            if (!mysql_) throw SQLException("mysql connection not open");
        }

        static std::vector<std::string> splitColon(const std::string& s) {
            std::vector<std::string> out;
            size_t p = 0;
            while (p < s.size()) {
                auto q = s.find(':', p);
                if (q == std::string::npos) q = s.size();
                out.push_back(s.substr(p, q - p));
                p = q + 1;
            }
            return out;
        }

        static void bindAndExec(MYSQL_STMT* stmt, const std::vector<std::string>& params) {
            std::vector<MYSQL_BIND> binds(params.size(), MYSQL_BIND{});
            // 每个 bind 用一个对应的 string 持有 buffer，避免生命周期问题
            // 但 bind 只保留指针 —— 所以我们在函数内部创建 holder 数组
            // 用 MYSQL_TYPE_STRING + buffer = const_cast<char*>(v.c_str())
            std::vector<std::string> holders = params;
            for (size_t i = 0; i < params.size(); ++i) {
                auto& b = binds[i];
                b.buffer_type = MYSQL_TYPE_STRING;
                b.buffer = const_cast<char*>(holders[i].data());
                b.buffer_length = static_cast<unsigned long>(holders[i].size());
                b.is_null = new my_bool(0);
            }
            if (mysql_stmt_bind_param(stmt, binds.data()) != 0) {
                throw SQLException(std::format("mysql_stmt_bind_param: {}", mysql_stmt_error(stmt)));
            }
            if (mysql_stmt_execute(stmt) != 0) {
                throw SQLException(std::format("mysql_stmt_execute: {}", mysql_stmt_error(stmt)));
            }
            for (auto& b : binds) delete static_cast<my_bool*>(b.is_null);
        }

        static ResultSet collectRes(MYSQL_RES* res) {
            ResultSet out;
            const unsigned ncols = mysql_num_fields(res);
            MYSQL_FIELD* fields = mysql_fetch_fields(res);
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res))) {
                Row r;
                r.reserve(ncols);
                unsigned long* lens = mysql_fetch_lengths(res);
                for (unsigned i = 0; i < ncols; ++i) {
                    std::string col_name = fields[i].name ? fields[i].name : std::to_string(i);
                    std::string val = row[i] ? std::string(row[i], lens[i]) : "";
                    r.emplace_back(std::move(col_name), std::move(val));
                }
                out.push_back(std::move(r));
            }
            return out;
        }

        static ResultSet collectStmtRes(MYSQL_STMT* stmt) {
            auto* meta = mysql_stmt_result_metadata(stmt);
            if (!meta) return {}; // 无结果集
            const unsigned ncols = mysql_num_fields(meta);
            MYSQL_FIELD* fields = mysql_fetch_fields(meta);

            struct Col {
                std::string name;
                std::vector<char> buf;
                MYSQL_BIND bind{nullptr};
                my_bool is_null = 0;
                unsigned long length = 0;
            };
            std::vector<Col> cols(ncols);
            std::vector<MYSQL_BIND> binds(ncols);

            for (unsigned i = 0; i < ncols; ++i) {
                cols[i].name = fields[i].name ? fields[i].name : std::to_string(i);
                cols[i].buf.resize(65536); // 足够大
                binds[i].buffer_type = MYSQL_TYPE_STRING;
                binds[i].buffer = cols[i].buf.data();
                binds[i].buffer_length = static_cast<unsigned long>(cols[i].buf.size());
                binds[i].is_null = &cols[i].is_null;
                binds[i].length = &cols[i].length;
            }
            if (mysql_stmt_bind_result(stmt, binds.data()) != 0) {
                mysql_free_result(meta);
                throw SQLException(std::format("mysql_stmt_bind_result: {}", mysql_stmt_error(stmt)));
            }

            ResultSet out;
            while (mysql_stmt_fetch(stmt) == 0) {
                Row r;
                r.reserve(ncols);
                for (unsigned i = 0; i < ncols; ++i) {
                    std::string val;
                    if (!cols[i].is_null) val.assign(cols[i].buf.data(), cols[i].length);
                    r.emplace_back(cols[i].name, std::move(val));
                }
                out.push_back(std::move(r));
            }
            mysql_free_result(meta);
            return out;
        }
    };
}

