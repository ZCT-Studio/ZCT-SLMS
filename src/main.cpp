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
// Created by wanjiangzhi on 2026/9/25.
//

#include <exception>
#include <filesystem>
#include <string>
#include <thread>
#include <drogon/drogon.h>
#include "constants.hpp"
#include "common/logger.hpp"
#include "config/app_config.hpp"
#include "database/database.hpp"
#include "api/v1/register_all.hpp"
#include "middleware/middlewares.hpp"

namespace {
    void ensureDirectory(const std::filesystem::path& path) {
        try { std::filesystem::create_directories(path); } catch (...) {}
    }

    bool bootstrapDatabase() {
        try {
            const auto& cfg = zct_slms::AppConfig::instance();
            auto& db = zct_slms::db::Database::instance();
            db.open(cfg.database());

            std::string migrations = "migrations";
            if (!std::filesystem::exists(migrations)) {
                migrations = (std::filesystem::current_path() / "migrations").string();
            }
            zct_slms::db::MigrationRunner::runAll(migrations);
            zct_slms::logger().INFO("Migrations applied from: {}", migrations);
            const auto count = db.queryScalar("SELECT COUNT(*) FROM admins");
            if (!count) throw std::runtime_error("Cannot inspect administrator accounts");
            if (*count == "0") {
                const auto password = zct_slms::crypto::randomHex(24);
                const auto hp = zct_slms::service::hashPassword(password);
                if (hp.hash.empty()) throw std::runtime_error("Cannot hash initial administrator password");
                const auto id=zct_slms::repo::AdminRepo::insert("admin", hp.hash, hp.salt, "Administrator", std::time(nullptr));
                zct_slms::repo::ConfigRepo::set("admin_initial_setup_done:"+std::to_string(id),"0",std::time(nullptr));
                zct_slms::logger().WARN("Initial administrator: username=admin password={}. Change it immediately.", password);
            }
            return true;
        } catch (const std::exception& e) {
            zct_slms::logger().ERROR("Database bootstrap FAILED: {}", e.what());
            return false;
        }
    }
}

int main(const int argc, char** argv) {
    try {
        zct_slms::logger().INFO("Server \"{}\" is starting, version {}", zct_slms::constants::PROJECT_NAME, zct_slms::constants::PROJECT_VERSION);

        const std::filesystem::path config_path = argc > 1 ? argv[1] : "config/config.yaml";

        zct_slms::logger().INFO("Config path: \"{}\"", std::filesystem::absolute(config_path).string());

        if (!std::filesystem::exists(config_path)) {
            zct_slms::logger().FATAL("Config file not found");
            return 1;
        }

        zct_slms::logger().INFO("Loading config...");
        zct_slms::AppConfig::instance().load(config_path.string());

        const auto& cfg = zct_slms::AppConfig::instance();
        zct_slms::initLogger(cfg.logging().level, cfg.logging().file_path, cfg.logging().async);
        zct_slms::apiLogLevel.store(zct_slms::logLevelFromString(cfg.logging().api_level));
        zct_slms::logger().INFO("Logger initialized from config");

        zct_slms::logger().INFO("Bootstrapping database...");
        if (!bootstrapDatabase()) {
            zct_slms::logger().FATAL("Cannot start: database bootstrap failed. Check ZCT_SLMS was compiled with the requested backend.");
            return 1;
        }
        zct_slms::repo::ConfigRepo::set("app_secret_reveal_allowed",cfg.security().app_secret_reveal_allowed?"1":"0",std::time(nullptr));
        zct_slms::repo::ConfigRepo::set("admin_security_level",cfg.security().admin_security_level,std::time(nullptr));
        try{auto identity=zct_slms::identity::config();const auto url=zct_slms::identity::val(identity,"public_url");if(url=="http://localhost:8088"||url=="http://127.0.0.1:8088"){identity["public_url"]=url.substr(0,url.rfind(':')+1)+"17316";zct_slms::identity::saveConfig(identity);}}catch(const std::exception&){zct_slms::logger().WARN("Local public URL migration skipped; check identity configuration master key");}
        if(!zct_slms::repo::ConfigRepo::getBool("license_timer_initialized",false)){if(cfg.license().timer_paused)zct_slms::repo::GlobalTimer::pause(std::time(nullptr));zct_slms::repo::ConfigRepo::set("license_timer_initialized","1",std::time(nullptr));}

        zct_slms::logger().INFO("Registering routes...");
        zct_slms::middleware::registerAllMiddlewares(drogon::app());
        zct_slms::api::registerAllV1Routes(drogon::app());

        auto nthreads = std::thread::hardware_concurrency();
        if (nthreads == 0) nthreads = 4;

        auto& svr = drogon::app();

        if (const auto& [ipv4_host, ipv6_host, port] = cfg.server(); !ipv4_host.empty() && !ipv6_host.empty()) {
            zct_slms::logger().INFO("Listening IPv4 {}:{} and IPv6 [{}]:{}, {} threads", ipv4_host, port, ipv6_host, port, nthreads);
            svr.addListener(ipv4_host, port);
            svr.addListener(ipv6_host, port);
        } else {
            if (!ipv4_host.empty()) {
                zct_slms::logger().INFO("Listening IPv4 {}:{}, {} threads", ipv4_host, port, nthreads);
                svr.addListener(ipv4_host, port);
            }
            if (!ipv6_host.empty()) {
                zct_slms::logger().INFO("Listening IPv6 [{}]:{}, {} threads", ipv6_host, port, nthreads);
                svr.addListener(ipv6_host, port);
            }
        }

        svr.setClientMaxBodySize(4 * 1024 * 1024);
        svr.setThreadNum(nthreads)
           .enableServerHeader(false)
           .setDocumentRoot("./zct_slms_web")
           .run();
    } catch (const std::exception& e) {
        zct_slms::logger().FATAL("FATAL exception: {}", e.what());
        return 1;
    } catch (...) {
        zct_slms::logger().FATAL("FATAL unknown exception");
        return 2;
    }
    return 0;
}
