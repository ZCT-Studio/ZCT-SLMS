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

#ifndef ZCT_SLMS_DATABASE_IDATABASE
#define ZCT_SLMS_DATABASE_IDATABASE

#include <exception>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace zct_slms::db {

    class SQLException : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    using Row = std::vector<std::pair<std::string, std::string>>;
    using ResultSet = std::vector<Row>;

    // ── 纯虚接口：SQLite / PostgreSQL / MySQL 三后端公共 API ──
    class IDatabase {
    public:
        virtual ~IDatabase() = default;

        virtual const char* backendName() const = 0;

        // 生命周期
        virtual void open(const std::string& conn_str) = 0;
        virtual void close() = 0;
        virtual bool isOpen() const = 0;

        // 基本信息
        virtual int64_t lastInsertId() const = 0;
        virtual int rowsChanged() const = 0;

        // 直接执行（无参数）
        virtual void exec(const std::string& sql) = 0;

        // 参数化执行（占位符 ? / $1 / ?）
        virtual void execParams(const std::string& sql, const std::vector<std::string>& params) = 0;

        // 参数化查询
        virtual ResultSet query(const std::string& sql) = 0;
        virtual ResultSet queryParams(const std::string& sql, const std::vector<std::string>& params) = 0;

        // 标量查询（取第一行第一列）
        virtual std::optional<std::string> queryScalar(
            const std::string& sql,
            const std::vector<std::string>& params
        ) = 0;

        // 事务
        template <typename F>
        bool transaction(F&& fn) {
            std::unique_lock lock(mtx_);
            beginTransaction();
            bool committed = false;
            try {
                if (fn()) {
                    commitTransaction();
                    committed = true;
                } else {
                    rollbackTransaction();
                }
            } catch (...) {
                rollbackTransaction();
                throw;
            }
            return committed;
        }

        // SQL 文件直接执行
        virtual void execSqlFile(const std::string& path) {
            std::ifstream f(path);
            if (!f.is_open()) throw SQLException(std::format("cannot open sql file: {}", path));
            std::ostringstream ss;
            ss << f.rdbuf();
            exec(ss.str());
        }

        // 将通用 SQL 适配到当前后端方言（可选 override）
        // SQLite / MySQL: 原样
        // PostgreSQL: 把 ? 替换成 $1 $2 ...
        virtual std::string adaptParams(const std::string& sql) const { return sql; }

    protected:
        virtual void beginTransaction() = 0;
        virtual void commitTransaction() = 0;
        virtual void rollbackTransaction() = 0;
        mutable std::recursive_mutex mtx_;
    };

    // ── 内部辅助：把任意参数打包成 vector<string> ──
    namespace detail {
        template <typename T>
        std::string anyToString(T&& v) {
            if constexpr (std::is_same_v<std::decay_t<T>, std::string> ||
                          std::is_same_v<std::decay_t<T>, std::string_view>) {
                return std::string(v);
            } else if constexpr (std::is_same_v<std::decay_t<T>, const char*> ||
                                 std::is_same_v<std::decay_t<T>, char*>) {
                return v ? std::string(v) : std::string{};
            } else if constexpr (std::is_same_v<std::decay_t<T>, std::nullptr_t>) {
                return std::string{};
            } else if constexpr (std::is_same_v<std::decay_t<T>, std::optional<std::string>>) {
                return v.value_or(std::string{});
            } else if constexpr (std::is_same_v<std::decay_t<T>, std::optional<int64_t>>) {
                return v ? std::to_string(*v) : std::string{};
            } else {
                return std::to_string(v);
            }
        }

        inline void packVec(std::vector<std::string>& /*out*/) {}
        template <typename T, typename... Rest>
        void packVec(std::vector<std::string>& out, T&& v, Rest&&... rest) {
            out.push_back(anyToString(std::forward<T>(v)));
            packVec(out, std::forward<Rest>(rest)...);
        }
    }
}

#endif // ZCT_SLMS_DATABASE_IDATABASE
