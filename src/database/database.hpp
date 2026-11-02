// Copyright 2026 ZCT-Studio
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
// Created by wanjiangzhi on 2026/10/3.
//

#ifndef ZCT_SLMS_DATABASE_DATABASE
#define ZCT_SLMS_DATABASE_DATABASE

#include <cstddef>
#include <ctime>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <utility>
#include <string>
#include <vector>

#include "database/idatabase.hpp"
#include "config/app_config.hpp"
#include "common/logger.hpp"

// 三个具体后端实现
#include "database/sqlite_database.hpp"
#ifdef ZCT_SLMS_HAS_PGSQL
#include "database/pgsql_database.hpp"
#endif
#ifdef ZCT_SLMS_HAS_MYSQL
#include "database/mysql_database.hpp"
#endif

namespace zct_slms::db {

    // ── 门面类：持有一个 IDatabase 实例，repo/service 层零改动 ──
    class Database {
    public:
        static Database& instance() {
            static Database inst;
            return inst;
        }

        // 根据 config 创建后端
        void open(const zct_slms::DatabaseConfig& cfg) {
            std::unique_lock lock(mtx_);
            if (impl_) { impl_->close(); impl_.reset(); }

            auto type = cfg.type;
            if (type == "sqlite") {
                auto p = std::filesystem::path(cfg.sqlite_path);
                if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path());
                auto s = std::make_unique<SqliteDatabase>();
                s->open(cfg.sqlite_path);
                impl_ = std::move(s);
                zct_slms::logger().INFO("Database opened: SQLite {}", std::filesystem::absolute(cfg.sqlite_path).string());
            } else if (type == "postgresql") {
#ifdef ZCT_SLMS_HAS_PGSQL
                auto& pg = cfg.pgsql;
                std::string conninfo = std::format(
                    "host={} port={} dbname={} user={} password={} sslmode={} application_name=ZCT_SLMS",
                    pg.host, pg.port, pg.dbname, pg.user,
                    pg.password.empty() ? "" : ("password=" + pg.password),
                    pg.sslmode
                );
                auto s = std::make_unique<PgsqlDatabase>();
                s->open(conninfo);
                impl_ = std::move(s);
                zct_slms::logger().INFO("Database opened: PostgreSQL {}@{}:{}/{}", pg.user, pg.host, pg.port, pg.dbname);
#else
                throw SQLException("ZCT_SLMS was compiled without PostgreSQL support (ZCT_SLMS_HAS_PGSQL not defined)");
#endif
            } else if (type == "mysql") {
#ifdef ZCT_SLMS_HAS_MYSQL
                auto& my = cfg.mysql;
                std::string conninfo = std::format(
                    "{}:{}:{}:{}:{}:{}",
                    my.host, my.port, my.user, my.password, my.dbname, my.connect_timeout_sec
                );
                auto s = std::make_unique<MysqlDatabase>();
                s->open(conninfo);
                impl_ = std::move(s);
                zct_slms::logger().INFO("Database opened: MySQL {}@{}:{}/{}", my.user, my.host, my.port, my.dbname);
#else
                throw SQLException("ZCT_SLMS was compiled without MySQL support (ZCT_SLMS_HAS_MYSQL not defined)");
#endif
            } else {
                throw SQLException(std::format("Unsupported database.type: {}", type));
            }
        }

        void close() {
            std::unique_lock lock(mtx_);
            if (impl_) { impl_->close(); impl_.reset(); }
        }

        const char* backendName() const {
            return impl_ ? impl_->backendName() : "none";
        }

        int64_t lastInsertId() const { return impl_ ? impl_->lastInsertId() : 0; }
        int rowsChanged() const { return impl_ ? impl_->rowsChanged() : 0; }

        void exec(const std::string& sql) const {
            if (!impl_) throw SQLException("database not open");
            impl_->exec(sql);
        }

        template <typename... Args>
        void execParams(const std::string& sql, Args&&... args) {
            if (!impl_) throw SQLException("database not open");
            std::vector<std::string> params;
            detail::packVec(params, std::forward<Args>(args)...);
            impl_->execParams(impl_->adaptParams(sql), params);
        }

        ResultSet query(const std::string& sql) const {
            if (!impl_) throw SQLException("database not open");
            return impl_->query(sql);
        }

        template <typename... Args>
        ResultSet queryParams(const std::string& sql, Args&&... args) {
            if (!impl_) throw SQLException("database not open");
            std::vector<std::string> params;
            detail::packVec(params, std::forward<Args>(args)...);
            return impl_->queryParams(impl_->adaptParams(sql), params);
        }

        template <typename... Args>
        std::optional<std::string> queryScalar(const std::string& sql, Args&&... args) {
            if (!impl_) throw SQLException("database not open");
            std::vector<std::string> params;
            detail::packVec(params, std::forward<Args>(args)...);
            return impl_->queryScalar(impl_->adaptParams(sql), params);
        }

        template <typename F>
        bool transaction(F&& fn) {
            if (!impl_) throw SQLException("database not open");
            return impl_->transaction(std::forward<F>(fn));
        }

        void execSqlFile(const std::string& path) {
            if (!impl_) throw SQLException("database not open");
            impl_->execSqlFile(path);
        }

        Database(const Database&) = delete;
        Database& operator=(const Database&) = delete;

    private:
        Database() = default;
        ~Database() { close(); }

        std::unique_ptr<IDatabase> impl_;
        mutable std::recursive_mutex mtx_;
    };

    // ── MigrationRunner ──
    class MigrationRunner {
    public:
        // 根据当前 Database 类型决定跑哪个目录下的 SQL
        // 目录规则: {migrations}/{backend}/  (sqlite / postgresql / mysql)
        static void runAll(const std::string& migrationsDir) {
            auto& db = Database::instance();
            const char* backend = db.backendName();

            std::string backend_dir = backendDirName(backend);
            std::string target_dir = (std::filesystem::path(migrationsDir) / backend_dir).string();

            // 兼容旧目录: 如果 migrationsDir 本身就是 sqlite 风格的（001_initial.sql），
            // 且不存在 migrations/sqlite/ 目录，直接用 migrationsDir
            std::filesystem::path p(migrationsDir);
            bool use_plain = false;
            if (!std::filesystem::exists(target_dir)) {
                // 检查是否有 001_initial.sql 等直接文件
                if (std::filesystem::exists(p / "001_initial.sql")) {
                    zct_slms::logger().WARN(
                        "No backend-specific migrations/{}/ dir found, "
                        "falling back to plain {} (all SQLs must be cross-DB compatible).",
                        backend_dir, migrationsDir);
                    target_dir = migrationsDir;
                    use_plain = true;
                } else {
                    throw SQLException(std::format(
                        "Migration dir not found: {}. Expected migrations/{}/001_initial.sql",
                        target_dir, backend_dir));
                }
            }

            // 建 schema_migrations 表（不同后端不同方言）
            db.exec(schemaMigrationsCreate(backend));

            std::vector<std::filesystem::path> files;
            if (std::filesystem::exists(target_dir)) {
                for (auto& f : std::filesystem::directory_iterator(target_dir)) {
                    if (f.path().extension() == ".sql") files.push_back(f.path());
                }
                std::ranges::sort(files);
            }

            for (auto& fp : files) {
                std::string f_name = fp.filename().string();
                int version = 0;
                if (auto pos = f_name.find('_'); pos != std::string::npos) {
                    try { version = std::stoi(f_name.substr(0, pos)); } catch (...) {}
                }
                auto applied = db.queryScalar(
                    "SELECT version FROM schema_migrations WHERE version = ?",
                    version
                );
                if (applied.has_value()) continue;

                try {
                    db.execSqlFile(fp.string());
                    int64_t now = std::time(nullptr);
                    db.execParams(
                        "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                        version, f_name, now
                    );
                    zct_slms::logger().INFO("[{}] Migration applied: {}", backend, f_name);
                } catch (const std::exception& e) {
                    zct_slms::logger().ERROR("[{}] Migration FAILED {}: {}", backend, f_name, e.what());
                    throw;
                }
            }

            if (use_plain) {
                zct_slms::logger().WARN(
                    "Consider splitting migrations into migrations/{}/ for full backend-specific control.",
                    backend_dir);
            }
        }

    private:
        static std::string backendDirName(const char* backend) {
            if (std::string_view(backend) == "postgresql") return "pgsql";
            if (std::string_view(backend) == "mysql")      return "mysql";
            return "sqlite";
        }

        static std::string schemaMigrationsCreate(const char* backend) {
            // 三种后端各自的建表方言
            if (std::string_view(backend) == "postgresql") {
                return "CREATE TABLE IF NOT EXISTS schema_migrations ("
                       "version BIGSERIAL PRIMARY KEY, "
                       "name TEXT NOT NULL UNIQUE, "
                       "applied_at BIGINT NOT NULL)";
            } else if (std::string_view(backend) == "mysql") {
                return "CREATE TABLE IF NOT EXISTS schema_migrations ("
                       "version BIGINT PRIMARY KEY AUTO_INCREMENT, "
                       "name VARCHAR(255) NOT NULL UNIQUE, "
                       "applied_at BIGINT NOT NULL) "
                       "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
            }
            // sqlite 默认
            return "CREATE TABLE IF NOT EXISTS schema_migrations ("
                   "version INTEGER PRIMARY KEY, "
                   "name TEXT NOT NULL UNIQUE, "
                   "applied_at INTEGER NOT NULL)";
        }
    };
}

#endif // ZCT_SLMS_DATABASE_DATABASE
