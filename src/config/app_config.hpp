// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#include <exception>
#include <filesystem>
#include <string>
#include <yaml-cpp/yaml.h>
#include "common/logger.hpp"

namespace zct_slms {
    struct DatabaseConfig {
        // sqlite | postgresql | mysql
        std::string type = "sqlite";

        // ── SQLite ──
        std::string sqlite_path = "./zct_slms.db";

        // ── PostgreSQL ──
        struct Pgsql {
            std::string host = "127.0.0.1";
            int port = 5432;
            std::string dbname = "zct_slms";
            std::string user = "zct_slms";
            std::string password;
            // 可选: SSL 模式 disable / prefer / require / verify-ca / verify-full
            std::string sslmode = "prefer";
        } pgsql;

        // ── MySQL ──
        struct Mysql {
            std::string host = "127.0.0.1";
            int port = 3306;
            std::string dbname = "zct_slms";
            std::string user = "zct_slms";
            std::string password;
            int connect_timeout_sec = 10;
        } mysql;
    };

    struct SecurityConfig {
        bool app_secret_reveal_allowed = true;
        std::string admin_security_level = "LAN"; // LOCAL/LAN/PUBLIC
        int replay_window_seconds = 60;
        int session_ttl_seconds = 259200;
        int temp_token_ttl_seconds = 3600;
        std::string password_hasher = "argon2id";
    };

    struct RateLimitConfig {
        bool enabled = true;
        int ip_per_sec = 100;
        int app_per_sec = 500;
        int license_per_sec = 10;
        int login_fail_lock_threshold = 5;
        int login_fail_lock_seconds = 300;
    };

    struct LoggingConfig {
        std::string api_level = "DEBUG";
        std::string level = "INFO";
        bool async = true;
        std::string file_path = "./logs/zct_slms.log";
    };

    struct ServerConfig {
        // IPv4 监听地址, "" 表示不监听 IPv4
        std::string ipv4_host = "0.0.0.0";
        // IPv6 监听地址, "" 表示不监听 IPv6
        std::string ipv6_host = "::";
        // 监听端口 (IPv4/IPv6 共用)
        int port = 17112;
    };

    struct LicenseConfig {
        bool timer_paused = false;
    };

    class AppConfig {
    public:
        static AppConfig& instance() {
            static AppConfig inst;
            return inst;
        }

        bool load(const std::string& path) {
            config_path_ = std::filesystem::absolute(path).string();
            try {
                YAML::Node root = YAML::LoadFile(path);

                if (auto n = root["server"]) {
                    server_.port = n["port"].as<int>(server_.port);

                    // 新字段: ipv4_host / ipv6_host
                    bool has_v4 = n["ipv4_host"].IsDefined();
                    bool has_v6 = n["ipv6_host"].IsDefined();

                    // 旧字段 host 兼容 (当作 ipv4_host)
                    bool has_old_host = n["host"].IsDefined() && !has_v4;

                    if (has_v4) {
                        server_.ipv4_host = n["ipv4_host"].as<std::string>();
                    } else if (has_old_host) {
                        server_.ipv4_host = n["host"].as<std::string>();
                    }

                    if (has_v6) {
                        server_.ipv6_host = n["ipv6_host"].as<std::string>();
                    }

                    // 校验: ipv4_host 和 ipv6_host 至少一个非空
                    if (server_.ipv4_host.empty() && server_.ipv6_host.empty()) {
                        throw std::runtime_error(
                            "server.ipv4_host and server.ipv6_host cannot both be empty; "
                            "at least one listen address is required"
                        );
                    }
                }

                if (auto n = root["database"]) {
                    db_.type = n["type"].as<std::string>(db_.type);
                    if (db_.type == "sqlite" && n["sqlite_path"])
                        db_.sqlite_path = n["sqlite_path"].as<std::string>();

                    if (auto pg = n["postgresql"]) {
                        db_.pgsql.host = pg["host"].as<std::string>(db_.pgsql.host);
                        db_.pgsql.port = pg["port"].as<int>(db_.pgsql.port);
                        db_.pgsql.dbname = pg["dbname"].as<std::string>(db_.pgsql.dbname);
                        db_.pgsql.user = pg["user"].as<std::string>(db_.pgsql.user);
                        db_.pgsql.password = pg["password"].as<std::string>(db_.pgsql.password);
                        db_.pgsql.sslmode = pg["sslmode"].as<std::string>(db_.pgsql.sslmode);
                    }

                    if (auto my = n["mysql"]) {
                        db_.mysql.host = my["host"].as<std::string>(db_.mysql.host);
                        db_.mysql.port = my["port"].as<int>(db_.mysql.port);
                        db_.mysql.dbname = my["dbname"].as<std::string>(db_.mysql.dbname);
                        db_.mysql.user = my["user"].as<std::string>(db_.mysql.user);
                        db_.mysql.password = my["password"].as<std::string>(db_.mysql.password);
                        db_.mysql.connect_timeout_sec = my["connect_timeout_sec"].as<int>(db_.mysql.connect_timeout_sec);
                    }
                }

                if (auto n = root["security"]) {
                    sec_.app_secret_reveal_allowed = n["app_secret_reveal_allowed"].as<bool>(true);
                    sec_.admin_security_level = n["admin_security_level"].as<std::string>(sec_.admin_security_level);
                    sec_.replay_window_seconds = n["replay_window_seconds"].as<int>(sec_.replay_window_seconds);
                    sec_.session_ttl_seconds = n["session_ttl_seconds"].as<int>(sec_.session_ttl_seconds);
                    sec_.temp_token_ttl_seconds = n["temp_token_ttl_seconds"].as<int>(sec_.temp_token_ttl_seconds);
                    sec_.password_hasher = n["password_hasher"].as<std::string>(sec_.password_hasher);
                }

                if (auto n = root["rate_limit"]) {
                    rl_.enabled = n["enabled"].as<bool>(rl_.enabled);
                    rl_.ip_per_sec = n["ip_per_sec"].as<int>(rl_.ip_per_sec);
                    rl_.app_per_sec = n["app_per_sec"].as<int>(rl_.app_per_sec);
                    rl_.license_per_sec = n["license_per_sec"].as<int>(rl_.license_per_sec);
                    rl_.login_fail_lock_threshold = n["login_fail_lock_threshold"].as<int>(rl_.login_fail_lock_threshold);
                    rl_.login_fail_lock_seconds = n["login_fail_lock_seconds"].as<int>(rl_.login_fail_lock_seconds);
                }

                if (auto n = root["logging"]) {
                    log_.api_level = n["api_level"].as<std::string>(log_.api_level);
                    log_.level = n["level"].as<std::string>(log_.level);
                    log_.async = n["async"].as<bool>(log_.async);
                    log_.file_path = n["file_path"].as<std::string>(log_.file_path);
                }

                if (auto n = root["license"]) {
                    lic_.timer_paused = n["timer_paused"].as<bool>(lic_.timer_paused);
                }

                return true;
            } catch (const std::exception& e) {
                zct_slms::logger().ERROR("Failed to load config from {}: {}", path, e.what());
                return false;
            }
        }

        AppConfig() = default;

        [[nodiscard]] const ServerConfig& server() const { return server_; }
        [[nodiscard]] const DatabaseConfig& database() const { return db_; }
        [[nodiscard]] const SecurityConfig& security() const { return sec_; }
        [[nodiscard]] const RateLimitConfig& rateLimit() const { return rl_; }
        [[nodiscard]] const LoggingConfig& logging() const { return log_; }
        [[nodiscard]] const std::string& configPath() const { return config_path_; }
        [[nodiscard]] const LicenseConfig& license() const { return lic_; }

    private:
        std::string config_path_;
        ServerConfig server_;
        DatabaseConfig db_;
        SecurityConfig sec_;
        RateLimitConfig rl_;
        LoggingConfig log_;
        LicenseConfig lic_;
    };
}

