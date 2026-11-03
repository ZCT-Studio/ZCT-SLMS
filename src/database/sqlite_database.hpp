// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_DATABASE_SQLITE_DATABASE
#define ZCT_SLMS_DATABASE_SQLITE_DATABASE

#include "database/idatabase.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

namespace zct_slms::db {

    class SqliteDatabase : public IDatabase {
    public:
        const char* backendName() const override { return "sqlite"; }

        void open(const std::string& path) override {
            std::unique_lock lock(mtx_);
            if (db_) sqlite3_close_v2(db_);
            db_ = nullptr;
            constexpr int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
            if (sqlite3_open_v2(path.c_str(), &db_, flags, nullptr) != SQLITE_OK) {
                auto msg = db_ ? sqlite3_errmsg(db_) : "unknown";
                if (db_) { sqlite3_close_v2(db_); db_ = nullptr; }
                throw SQLException(std::format("sqlite open [{}] failed: {}", path, msg));
            }
            sqlite3_exec(db_, "PRAGMA journal_mode=DELETE;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
            open_ = true;
        }

        void close() override {
            std::unique_lock lock(mtx_);
            if (db_) { sqlite3_close_v2(db_); db_ = nullptr; }
            open_ = false;
        }

        bool isOpen() const override { return open_; }

        int64_t lastInsertId() const override { return sqlite3_last_insert_rowid(db_); }
        int rowsChanged() const override { return sqlite3_changes(db_); }

        void exec(const std::string& sql) override {
            std::unique_lock lock(mtx_);
            char* err = nullptr;
            if (const int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err); rc != SQLITE_OK) {
                std::string msg = err ? err : "unknown";
                sqlite3_free(err);
                throw SQLException(std::format("sqlite exec: {} | sql: {}", msg, sql));
            }
        }

        void execParams(const std::string& sql, const std::vector<std::string>& params) override {
            std::unique_lock lock(mtx_);
            sqlite3_stmt* stmt = compile(sql);
            bindAll(stmt, params);
            stepFinalize(stmt);
        }

        ResultSet query(const std::string& sql) override {
            std::unique_lock lock(mtx_);
            sqlite3_stmt* stmt = compile(sql);
            return fetchAll(stmt);
        }

        ResultSet queryParams(const std::string& sql, const std::vector<std::string>& params) override {
            std::unique_lock lock(mtx_);
            sqlite3_stmt* stmt = compile(sql);
            bindAll(stmt, params);
            return fetchAll(stmt);
        }

        std::optional<std::string> queryScalar(
            const std::string& sql,
            const std::vector<std::string>& params
        ) override {
            std::unique_lock lock(mtx_);
            sqlite3_stmt* stmt = compile(sql);
            bindAll(stmt, params);
            if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_count(stmt) > 0) {
                const auto ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                std::string val = ptr ? ptr : "";
                sqlite3_finalize(stmt);
                return val;
            }
            sqlite3_finalize(stmt);
            return std::nullopt;
        }

    protected:
        void beginTransaction() override { exec("BEGIN IMMEDIATE"); }
        void commitTransaction() override { exec("COMMIT"); }
        void rollbackTransaction() override {
            if (!sqlite3_get_autocommit(db_)) exec("ROLLBACK");
        }

    private:
        sqlite3* db_ = nullptr;
        bool open_ = false;

        sqlite3_stmt* compile(const std::string& sql) const {
            sqlite3_stmt* stmt = nullptr;
            if (const int rc = sqlite3_prepare_v2(db_, sql.c_str(), static_cast<int>(sql.size()), &stmt, nullptr); rc != SQLITE_OK) {
                throw SQLException(std::format("sqlite prepare: {} | sql: {}", sqlite3_errmsg(db_), sql));
            }
            return stmt;
        }

        void stepFinalize(sqlite3_stmt* stmt) const {
            const int rc = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (rc != SQLITE_DONE) {
                throw SQLException(std::format("sqlite step: {}", sqlite3_errmsg(db_)));
            }
        }

        ResultSet fetchAll(sqlite3_stmt* stmt) const {
            ResultSet out;
            const int cols = sqlite3_column_count(stmt);
            std::vector<std::string> col_names(static_cast<size_t>(cols));
            for (int i = 0; i < cols; ++i) col_names[i] = sqlite3_column_name(stmt, i);

            int rc;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                Row row;
                row.reserve(cols);
                for (int i = 0; i < cols; ++i) {
                    auto v = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                    row.emplace_back(col_names[i], v ? v : "");
                }
                out.push_back(std::move(row));
            }
            sqlite3_finalize(stmt);
            if (rc != SQLITE_DONE) {
                throw SQLException(std::format("sqlite fetch: {}", sqlite3_errmsg(db_)));
            }
            return out;
        }

        static void bindAll(sqlite3_stmt* stmt, const std::vector<std::string>& params) {
            for (size_t i = 0; i < params.size(); ++i) {
                const auto& v = params[i];
                sqlite3_bind_text(stmt, static_cast<int>(i + 1), v.data(),
                                  static_cast<int>(v.size()), SQLITE_TRANSIENT);
            }
        }
    };
}

#endif // ZCT_SLMS_DATABASE_SQLITE_DATABASE
