// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio
#pragma once

#pragma push_macro("ALL")
#pragma push_macro("ERROR")
#pragma push_macro("NO_ERROR")
#pragma push_macro("FATAL")
#pragma push_macro("DELETE")
#include "constants.hpp"
#ifdef ALL
#undef ALL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef NO_ERROR
#undef NO_ERROR
#endif
#ifdef FATAL
#undef FATAL
#endif
#ifdef DELETE
#undef DELETE
#endif

#include <cctype>
#include <atomic>
#include <format>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include "ZCLibLog/logger_sync.hpp"
#include "ZCLibLog/logger_async.hpp"
#include "common/formatters.hpp"
#include "common/executors.hpp"

namespace zct_slms {
    using LoogerFormatter = logging::zct_slms_formatter;
    using LoggerSyncT = ZCLibLog::LoggerSync<LoogerFormatter>;
    using LoggerAsyncT = ZCLibLog::LoggerAsync<LoogerFormatter>;

    inline ZCLibLog::LogLevel logLevelFromString(std::string_view s) {
        std::string up;
        up.reserve(s.size());
        for (const char c : s) {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
            }
        }
        if (up == "ALL") return ZCLibLog::LogLevel::ALL;
        else if (up == "TRACE") return ZCLibLog::LogLevel::TRACE;
        else if (up == "DEBUG") return ZCLibLog::LogLevel::DEBUG;
        else if (up == "INFO") return ZCLibLog::LogLevel::INFO;
        else if (up == "WARN") return ZCLibLog::LogLevel::WARN;
        else if (up == "ERROR") return ZCLibLog::LogLevel::ERROR;
        else if (up == "FATAL") return ZCLibLog::LogLevel::FATAL;
        else if (up == "OFF") return ZCLibLog::LogLevel::OFF;
        return ZCLibLog::LogLevel::INFO;
    }

    using LoggerVariant = std::variant<LoggerSyncT, LoggerAsyncT>;

    inline std::optional<LoggerVariant>& loggerStorage() {
        static std::optional<LoggerVariant> s;
        return s;
    }

    inline std::mutex& loggerMutex() {
        static std::mutex m;
        return m;
    }

    /**
     * @brief 类型擦除 wrapper——把 Sync / Async 统一成一个调用接口
     *
     * 内部持有 variant 指针，每个日志方法模板 std::visit 转发。
     */
    class Logger {
    public:
        explicit Logger(LoggerVariant* impl) : impl_(impl) {}

        template <typename... Args>
        void ALL(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.ALL(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        template <typename... Args>
        void TRACE(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.TRACE(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        template <typename... Args>
        void DEBUG(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.DEBUG(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        template <typename... Args>
        void INFO(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.INFO(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        template <typename... Args>
        void WARN(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.WARN(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        template <typename... Args>
        void ERROR(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.ERROR(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        template <typename... Args>
        void FATAL(std::format_string<Args...> fmt, Args&&... args) {
            std::visit([&](auto& lg) { lg.FATAL(fmt, std::forward<Args>(args)...); }, *impl_);
        }

        [[nodiscard]] const std::string& name() const {
            return std::visit([](auto& lg) -> const std::string& { return lg.name(); }, *impl_);
        }

        ZCLibLog::LogLevelCfg& config() {
            return std::visit([](auto& lg) -> ZCLibLog::LogLevelCfg& { return lg.config(); }, *impl_);
        }

        [[nodiscard]] bool hasExecutor() const {
            return std::visit([](auto& lg) { return lg.has_executor(); }, *impl_);
        }

        size_t bindExecutor(const ZCLibLog::executor& ex) {
            return std::visit([&](auto& lg) { return lg.bind_executor(ex); }, *impl_);
        }

    private:
        LoggerVariant* impl_;
    };

    inline void initLogger(const std::string& level, const std::string& file_path, const bool async = true) {
        std::lock_guard lk(loggerMutex());

        const auto lv = logLevelFromString(level);
        ZCLibLog::LogLevelCfg level_cfg(lv, ZCLibLog::LogLevel::OFF);

        auto ex = ZCLibLog::executor::make<zct_slms::logging::zct_slms_executor>(file_path, false);
        std::initializer_list<ZCLibLog::executor> executors{std::move(ex)};

        if (async) {
            loggerStorage().emplace(std::in_place_index < 1 >, zct_slms::constants::PROJECT_NAME, executors, level_cfg);
        } else {
            loggerStorage().emplace(std::in_place_index < 0 >, zct_slms::constants::PROJECT_NAME, executors, level_cfg);
        }
    }

    inline Logger logger() {
        std::lock_guard lk(loggerMutex());
        auto& s = loggerStorage();
        if (!s) {
            s.emplace(
                std::in_place_index < 0 >,
                zct_slms::constants::PROJECT_NAME,
                std::initializer_list<ZCLibLog::executor>{
                    ZCLibLog::executor::make<zct_slms::logging::zct_slms_executor>(std::string{}, true)
                }
            );
        }
        return Logger(&*s);
    }

    inline std::atomic<ZCLibLog::LogLevel> apiLogLevel{ZCLibLog::LogLevel::DEBUG};

    template <class... Args> inline void apiLog(std::format_string<Args...> format, Args&&... args) {
        switch (apiLogLevel.load()) {
            case ZCLibLog::LogLevel::TRACE: logger().TRACE(format, std::forward<Args>(args)...);
                break;
            case ZCLibLog::LogLevel::INFO: logger().INFO(format, std::forward<Args>(args)...);
                break;
            case ZCLibLog::LogLevel::WARN: logger().WARN(format, std::forward<Args>(args)...);
                break;
            case ZCLibLog::LogLevel::ERROR: logger().ERROR(format, std::forward<Args>(args)...);
                break;
            case ZCLibLog::LogLevel::OFF: break;
            default: logger().DEBUG(format, std::forward<Args>(args)...);
                break;
        }
    }
}

