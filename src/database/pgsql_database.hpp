// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include "database/idatabase.hpp"
#include <libpq-fe.h>
#include <algorithm>
#include <string>
#include <vector>

namespace zct_slms::db {
    class PgsqlDatabase : public IDatabase {
    public:
        const char* backendName() const override { return "postgresql"; }

        void open(const std::string& conninfo) override {
            std::unique_lock lock(mtx_);
            closeLocked();
            PGconn* c = PQconnectdb(conninfo.c_str());
            if (!c) throw SQLException("libpq: PQconnectdb returned null");
            if (PQstatus(c) != CONNECTION_OK) {
                auto msg = PQerrorMessage(c);
                PQfinish(c);
                throw SQLException(std::format("pgsql connect failed: {}", msg ? msg : "unknown"));
            }
            // 强制 UTF-8
            PQsetClientEncoding(c, "UTF8");
            // 关闭 DATESTYLE，避免 timestamp 显示干扰
            pg_ = c;
            open_ = true;
        }

        void close() override {
            std::unique_lock lock(mtx_);
            closeLocked();
        }

        bool isOpen() const override { return open_ && pg_ != nullptr; }

        int64_t lastInsertId() const override {
            // PostgreSQL 的 SERIAL/IDENTITY 可以用 currval() 或 lastval() 取值
            auto r = runScalar("SELECT lastval()");
            if (r) { try { return std::stoll(*r); } catch (...) {} }
            return 0;
        }

        int rowsChanged() const override { return rows_changed_; }

        void exec(const std::string& sql) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            PGresult* res = PQexec(pg_, sql.c_str());
            if (!res) throw SQLException("pgsql PQexec failed (null result)");
            auto st = PQresultStatus(res);
            if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
                auto msg = PQresultErrorMessage(res);
                PQclear(res);
                throw SQLException(std::format("pgsql exec: {}", msg ? msg : "unknown"));
            }
            rows_changed_ = PQcmdTuples(res) ? std::atoi(PQcmdTuples(res)) : 0;
            PQclear(res);
        }

        void execParams(const std::string& sql, const std::vector<std::string>& params) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            const auto adapted = adaptParams(sql);
            auto res = PQexecParams(
                pg_,
                adapted.c_str(),
                static_cast<int>(params.size()),
                nullptr,
                // paramTypes
                vectorParamCstr(params).data(),
                nullptr,
                nullptr,
                // paramLens, paramFormats
                0 // resultFormat: 0=text
            );
            if (!res) throw SQLException("pgsql PQexecParams failed (null result)");
            auto st = PQresultStatus(res);
            if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
                auto msg = PQresultErrorMessage(res);
                PQclear(res);
                throw SQLException(std::format("pgsql execParams: {}", msg ? msg : "unknown"));
            }
            rows_changed_ = PQcmdTuples(res) ? std::atoi(PQcmdTuples(res)) : 0;
            PQclear(res);
        }

        ResultSet query(const std::string& sql) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            PGresult* res = PQexec(pg_, sql.c_str());
            return collectRows(res);
        }

        ResultSet queryParams(const std::string& sql, const std::vector<std::string>& params) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            const auto adapted = adaptParams(sql);
            auto res = PQexecParams(
                pg_,
                adapted.c_str(),
                static_cast<int>(params.size()),
                nullptr,
                vectorParamCstr(params).data(),
                nullptr,
                nullptr,
                0
            );
            return collectRows(res);
        }

        std::optional<std::string> queryScalar(
            const std::string& sql,
            const std::vector<std::string>& params
        ) override {
            std::unique_lock lock(mtx_);
            checkOpen();
            if (params.empty()) {
                PGresult* res = PQexec(pg_, sql.c_str());
                return pickScalar(res);
            }
            const auto adapted = adaptParams(sql);
            auto res = PQexecParams(
                pg_,
                adapted.c_str(),
                static_cast<int>(params.size()),
                nullptr,
                vectorParamCstr(params).data(),
                nullptr,
                nullptr,
                0
            );
            return pickScalar(res);
        }

        // PostgreSQL 把 ? 占位符改成 $1 $2 ...
        std::string adaptParams(const std::string& sql) const override {
            std::string out;
            out.reserve(sql.size() + 32);
            int idx = 1;
            bool in_single = false, in_double = false, in_line_comment = false, in_block_comment = false;
            for (size_t i = 0; i < sql.size(); ++i) {
                const char c = sql[i];
                if (in_line_comment) {
                    out += c;
                    if (c == '\n') in_line_comment = false;
                    continue;
                }
                if (in_block_comment) {
                    out += c;
                    if (c == '*' && i + 1 < sql.size() && sql[i + 1] == '/') {
                        out += '/';
                        ++i;
                        in_block_comment = false;
                    }
                    continue;
                }
                if (c == '-' && i + 1 < sql.size() && sql[i + 1] == '-') {
                    in_line_comment = true;
                    out += "--";
                    ++i;
                    continue;
                }
                if (c == '/' && i + 1 < sql.size() && sql[i + 1] == '*') {
                    in_block_comment = true;
                    out += "/*";
                    ++i;
                    continue;
                }
                if (!in_double && c == '\'') {
                    in_single = !in_single;
                    out += c;
                    continue;
                }
                if (!in_single && c == '"') {
                    in_double = !in_double;
                    out += c;
                    continue;
                }
                if (c == '?' && !in_single && !in_double) {
                    out += '$';
                    out += std::to_string(idx++);
                } else {
                    out += c;
                }
            }
            return out;
        }

    protected:
        void beginTransaction() override { exec("BEGIN"); }
        void commitTransaction() override { exec("COMMIT"); }
        void rollbackTransaction() override { exec("ROLLBACK"); }

    private:
        PGconn* pg_ = nullptr;
        bool open_ = false;
        mutable int rows_changed_ = 0;

        void closeLocked() {
            if (pg_) {
                PQfinish(pg_);
                pg_ = nullptr;
            }
            open_ = false;
        }

        void checkOpen() const {
            if (!pg_) throw SQLException("pgsql connection not open");
        }

        static std::vector<const char*> vectorParamCstr(const std::vector<std::string>& params) {
            std::vector<const char*> out;
            out.reserve(params.size());
            for (const auto& p : params) out.push_back(p.c_str());
            return out;
        }

        ResultSet collectRows(PGresult* res) const {
            if (!res) throw SQLException("pgsql: null result");
            auto st = PQresultStatus(res);
            if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
                auto msg = PQresultErrorMessage(res);
                PQclear(res);
                throw SQLException(std::format("pgsql query: {}", msg ? msg : "unknown"));
            }
            rows_changed_ = PQcmdTuples(res) ? std::atoi(PQcmdTuples(res)) : 0;
            ResultSet out;
            const int ncols = PQnfields(res);
            const int nrows = PQntuples(res);
            for (int r = 0; r < nrows; ++r) {
                Row row;
                row.reserve(ncols);
                for (int c = 0; c < ncols; ++c) {
                    const char* col_name = PQfname(res, c);
                    const char* val = PQgetvalue(res, r, c);
                    row.emplace_back(
                        col_name ? col_name : std::to_string(c),
                        val ? val : (PQgetisnull(res, r, c) ? "" : std::string{})
                    );
                }
                out.push_back(std::move(row));
            }
            PQclear(res);
            return out;
        }

        std::optional<std::string> pickScalar(PGresult* res) const {
            if (!res) return std::nullopt;
            auto st = PQresultStatus(res);
            if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
                PQclear(res);
                return std::nullopt;
            }
            std::optional<std::string> v;
            if (PQntuples(res) > 0 && PQnfields(res) > 0) {
                const char* val = PQgetvalue(res, 0, 0);
                if (val) v = val;
            }
            PQclear(res);
            return v;
        }

        std::optional<std::string> runScalar(const std::string& sql) const {
            std::unique_lock lock(mtx_);
            PGresult* res = PQexec(pg_, sql.c_str());
            auto v = pickScalar(res);
            return v;
        }
    };
}

