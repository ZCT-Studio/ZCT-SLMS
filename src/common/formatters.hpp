// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include <array>
#include <ctime>
#include <format>
#include <string>
#include <thread>

#include "ZCLibLog/formatters/format_apis/stdcxx20format.hpp"

namespace zct_slms::logging {
    struct zct_slms_formatter : ZCLibLog::format_apis::stdcxx20format {
        template <typename... Args>
        static std::string do_format(
            ZCLibLog::FLogPack pack,
            const std::format_string<Args...>& fmt,
            Args&&... args
        ) {
            std::string f_msg = std::format(fmt, std::forward<Args>(args)...);

            auto t = static_cast<std::time_t>(pack.time / 1000);
            const auto ms = static_cast<short>(pack.time % 1000);
            std::tm tm{};
            #if defined(_WIN32)
            localtime_s(&tm, &t);
            #elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
            localtime_r(&t, &tm);
            #else
            tm = *std::localtime(&t);
            #endif

            thread_local std::array<char, 64> time_buf;
            std::strftime(time_buf.data(), time_buf.size(), "%Y-%m-%d %H:%M:%S", &tm);

            auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());

            auto level = "OUT";
            switch (pack.level) {
                case ZCLibLog::LogLevel::TRACE: level = "TRACE";
                    break;
                case ZCLibLog::LogLevel::DEBUG: level = "DEBUG";
                    break;
                case ZCLibLog::LogLevel::INFO: level = "INFO";
                    break;
                case ZCLibLog::LogLevel::WARN: level = "WARN";
                    break;
                case ZCLibLog::LogLevel::ERROR: level = "ERROR";
                    break;
                case ZCLibLog::LogLevel::FATAL: level = "FATAL";
                    break;
                default: break;
            }

            return std::format(
                "{}.{:03d} [T{}] [{}] [{}] {}",
                time_buf.data(),
                ms,
                tid,
                level,
                *pack.name,
                f_msg
            );
        }
    };
}

