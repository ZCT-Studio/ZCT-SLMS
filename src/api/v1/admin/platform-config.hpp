// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "api/v1/auth/identity.hpp"
#include <fstream>
#ifdef _WIN32
#include <windows.h>
#endif
namespace zct_slms::platform {
    using namespace zct_slms::identity;
    namespace common = zct_slms::inside::api::v1::common;

    struct Field {
        const char* path;
        const char* label;
        const char* type;
        const char* fallback;
        int min = 0, max = 0;
        const char* options = "";
    };

    inline const std::vector<Field> fields = {
            {"server.ipv4_host", "IPv4 监听地址", "text", "0.0.0.0"},
            {"server.ipv6_host", "IPv6 监听地址", "text", "::"},
            {"server.port", "监听端口", "number", "17112", 1, 65535},
            {
                "database.type",
                "数据库类型",
                "select",
                "sqlite",
                0,
                0,
                "sqlite,postgresql,mysql"
            },
            {"database.sqlite_path", "SQLite 文件路径", "text", "./zct_slms.db"},
            {"database.postgresql.host", "PostgreSQL 主机", "text", "127.0.0.1"},
            {"database.postgresql.port", "PostgreSQL 端口", "number", "5432", 1, 65535},
            {"database.postgresql.dbname", "PostgreSQL 数据库", "text", "zct_slms"},
            {"database.postgresql.user", "PostgreSQL 用户", "text", "zct_slms"},
            {"database.postgresql.password", "PostgreSQL 密码", "password", ""},
            {
                "database.postgresql.sslmode",
                "PostgreSQL SSL 模式",
                "select",
                "prefer",
                0,
                0,
                "disable,prefer,require,verify-ca,verify-full"
            },
            {"database.mysql.host", "MySQL 主机", "text", "127.0.0.1"},
            {"database.mysql.port", "MySQL 端口", "number", "3306", 1, 65535},
            {"database.mysql.dbname", "MySQL 数据库", "text", "zct_slms"},
            {"database.mysql.user", "MySQL 用户", "text", "zct_slms"},
            {"database.mysql.password", "MySQL 密码", "password", ""},
            {
                "database.mysql.connect_timeout_sec",
                "MySQL 连接超时（秒）",
                "number",
                "10",
                1,
                300
            },
            {
                "security.admin_security_level",
                "管理接口访问范围",
                "select",
                "LAN",
                0,
                0,
                "LOCAL,LAN,PUBLIC"
            },
            {
                "security.app_secret_reveal_allowed",
                "允许验证密码后重复查看 APPSECRET",
                "bool",
                "true"
            },
            {
                "security.replay_window_seconds",
                "重放保护窗口（秒）",
                "number",
                "60",
                1,
                3600
            },
            {
                "security.session_ttl_seconds",
                "会话闲置有效期（秒）",
                "number",
                "259200",
                60,
                2592000
            },
            {
                "security.temp_token_ttl_seconds",
                "临时令牌有效期（秒）",
                "number",
                "3600",
                60,
                86400
            },
            {
                "security.password_hasher",
                "密码哈希算法",
                "select",
                "argon2id",
                0,
                0,
                "argon2id"
            },
            {"rate_limit.enabled", "启用限流", "bool", "true"},
            {"rate_limit.ip_per_sec", "每 IP 每秒请求数", "number", "100", 1, 100000},
            {"rate_limit.app_per_sec", "每应用每秒请求数", "number", "500", 1, 100000},
            {
                "rate_limit.license_per_sec",
                "每卡密每秒请求数",
                "number",
                "10",
                1,
                100000
            },
            {
                "rate_limit.login_fail_lock_threshold",
                "登录失败锁定次数",
                "number",
                "5",
                1,
                100
            },
            {
                "rate_limit.login_fail_lock_seconds",
                "登录锁定时长（秒）",
                "number",
                "300",
                1,
                86400
            },
            {
                "logging.level",
                "全局最低日志等级",
                "select",
                "INFO",
                0,
                0,
                "TRACE,DEBUG,INFO,WARN,ERROR,FATAL,OFF"
            },
            {
                "logging.api_level",
                "API 访问日志等级（立即生效）",
                "select",
                "DEBUG",
                0,
                0,
                "TRACE,DEBUG,INFO,WARN,ERROR,OFF"
            },
            {"logging.async", "异步日志", "bool", "true"},
            {"logging.file_path", "日志文件路径", "text", "./logs/zct_slms.log"}
        };

    inline YAML::Node node(YAML::Node root, const std::string& path) {
        auto p = path.find('.');
        auto q = path.find('.', p + 1);
        if (q == std::string::npos)
            return root[path.substr(0, p)][path.substr(p + 1)];
        return root[path.substr(0, p)][path.substr(p + 1, q - p - 1)]
            [path.substr(q + 1)];
    }

    inline std::mutex configMutex;

    inline void handle(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto auth = zct_slms::service::AuthService::authenticateSession(
                        common::authBearer(req)
                    );
                    if (!auth.success || auth.user_type != "ADMIN")
                        throw std::runtime_error("需要管理员登录");
                    std::lock_guard lock(configMutex);
                    const auto path =
                        std::filesystem::u8path(zct_slms::AppConfig::instance().configPath());
                    if (path.empty() || !std::filesystem::exists(path))
                        throw std::runtime_error("运行配置文件不存在");
                    auto root = YAML::LoadFile(path.string());
                    if (req->method() == drogon::Post) {
                        if (!adminPassword(req))
                            throw std::runtime_error("当前管理员密码错误");
                        auto body = req->getJsonObject();
                        if (!body || !(*body)["values"].isObject())
                            throw std::runtime_error("配置格式错误");
                        const auto& values = (*body)["values"];
                        for (auto& key : values.getMemberNames())
                            if (std::none_of(
                                fields.begin(),
                                fields.end(),
                                [&](auto& f) { return key == f.path; }
                            ))
                                throw std::runtime_error("未知配置项");
                        for (auto& f : fields) {
                            if (!values.isMember(f.path))
                                continue;
                            const auto& value = values[f.path];
                            const std::string type = f.type;
                            if (type == "bool") {
                                if (!value.isBool())
                                    throw std::runtime_error("开关格式错误");
                                node(root, f.path) = value.asBool();
                            } else if (type == "number") {
                                if (!value.isIntegral() || value.asInt64() < f.min ||
                                    value.asInt64() > f.max)
                                    throw std::runtime_error(std::string(f.label) + "超出范围");
                                node(root, f.path) = value.asInt();
                            } else {
                                if (!value.isString() || value.asString().size() > 4096 ||
                                    value.asString().find('\0') != std::string::npos)
                                    throw std::runtime_error("文本格式错误");
                                auto text = value.asString();
                                if (type == "password" && text.empty())
                                    continue;
                                if (type == "select" &&
                                    (std::string(",") + f.options + ",").find("," + text + ",") ==
                                    std::string::npos)
                                    throw std::runtime_error("选项无效");
                                node(root, f.path) = text;
                            }
                        }
                        #ifndef ZCT_SLMS_HAS_PGSQL
                        if (node(root, "database.type").as<std::string>("sqlite") ==
                            "postgresql")
                            throw std::runtime_error(
                                "当前 Core 未编译 PostgreSQL 支持，请先构建对应可选后端"
                            );
                        #endif
                        #ifndef ZCT_SLMS_HAS_MYSQL
                        if (node(root, "database.type").as<std::string>("sqlite") == "mysql")
                            throw std::runtime_error(
                                "当前 Core 未编译 MySQL 支持，请先构建对应可选后端"
                            );
                        #endif
                        if (node(root, "server.ipv4_host").as<std::string>("").empty() &&
                            node(root, "server.ipv6_host").as<std::string>("").empty())
                            throw std::runtime_error("至少保留一个监听地址");
                        auto temp = path;
                        temp += ".tmp";
                        auto backup = path;
                        backup += ".previous";
                        YAML::Emitter out;
                        out << root;
                        if (!out.good())
                            throw std::runtime_error("配置序列化失败");
                        {
                            std::ofstream file(temp, std::ios::binary | std::ios::trunc);
                            file << out.c_str() << '\n';
                            file.close();
                            if (!file)
                                throw std::runtime_error("配置写入失败");
                        }
                        std::filesystem::copy_file(
                            path,
                            backup,
                            std::filesystem::copy_options::overwrite_existing
                        );
                        #ifdef _WIN32
                        if (!MoveFileExW(
                            temp.c_str(),
                            path.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
                        ))
                            throw std::runtime_error("无法替换配置文件");
                        #else
                        std::filesystem::rename(temp, path);
                        #endif
                        zct_slms::apiLogLevel.store(
                            zct_slms::logLevelFromString(
                                node(root, "logging.api_level").as<std::string>("DEBUG")
                            )
                        );
                        zct_slms::repo::ConfigRepo::set(
                            "app_secret_reveal_allowed",
                            node(root, "security.app_secret_reveal_allowed").as<bool>(true)
                                ? "1"
                                : "0",
                            now()
                        );
                        zct_slms::repo::AuditRepo::log(
                            "ADMIN",
                            auth.user_id,
                            "UpdatePlatformConfig",
                            "SYSTEM",
                            0,
                            "",
                            "success",
                            common::clientIp(req),
                            "{}",
                            now()
                        );
                    }
                    Json result;
                    result["database_backends"] = Json(::Json::arrayValue);
                    result["database_backends"].append("sqlite");
                    #ifdef ZCT_SLMS_HAS_PGSQL
                    result["database_backends"].append("postgresql");
                    #endif
                    #ifdef ZCT_SLMS_HAS_MYSQL
                    result["database_backends"].append("mysql");
                    #endif
                    result["path"] = path.string();
                    result["fields"] = Json(::Json::arrayValue);
                    for (auto& f : fields) {
                        auto n = node(root, f.path);
                        Json item;
                        item["path"] = f.path;
                        item["label"] = f.label;
                        item["type"] = f.type;
                        item["min"] = f.min;
                        item["max"] = f.max;
                        item["options"] = f.options;
                        const std::string type = f.type;
                        if (type == "password") {
                            item["value"] = "";
                            item["configured"] = !n.as<std::string>(f.fallback).empty();
                        } else if (type == "bool")
                            item["value"] = n.as<bool>(std::string(f.fallback) == "true");
                        else if (type == "number")
                            item["value"] = n.as<int>(std::stoi(f.fallback));
                        else
                            item["value"] = n.as<std::string>(f.fallback);
                        result["fields"].append(item);
                    }
                    result["restart_required"] = req->method() == drogon::Post;
                    ok(cb, result);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }
} // namespace zct_slms::platform
