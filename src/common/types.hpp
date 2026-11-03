// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT-Studio

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_COMMON_TYPES
#define ZCT_SLMS_COMMON_TYPES

#include <cstdint>
#include <utility>
#include <optional>
#include <string>

namespace zct_slms::common {
    using i32 = std::int32_t;
    using i64 = std::int64_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;

    // 通用角色
    enum class Role {
        Admin,
        Owner,   // 主用户
        SubUser, // 子用户
        Anonymous,
        Client // 第三方 APP / 卡密持有者
    };

    // 卡密状态
    enum class LicenseStatus {
        Unused,  // 未激活
        Active,  // 激活中
        Expired, // 已过期
        Banned,  // 已封禁（也可能同时 active）
        Deleted  // 已删除（逻辑删除）
    };

    // 绑定模式
    enum class BindingMode {
        None,
        Ip,
        Device,
        IpAndDevice
    };

    // 卡密存储模式
    enum class LicenseStorageMode {
        Plain,
        Base64,
        Hex,
        Hash
    };

    // 解绑消耗策略
    enum class UnbindCost {
        None,
        Count,
        Time,
        CountAndTime
    };

    // 管理接口安全等级
    enum class AdminSecurityLevel {
        Local, // 仅 127.0.0.1 / ::1
        Lan,   // 本机 + 局域网
        Public // 公网（需 IP 白名单）
    };

    // 操作结果（不包含值）
    struct Result {
        bool success = false;
        int code = 0;
        std::string message;

        static Result ok() { return {true, 0, "OK"}; }
        static Result fail(int c, std::string msg) { return {false, c, std::move(msg)}; }
    };

    // 带值的操作结果
    template <typename T>
    struct ResultOf {
        bool success = false;
        int code = 0;
        std::string message;
        std::optional<T> value;

        static ResultOf<T> ok(T v) { return {true, 0, "OK", std::move(v)}; }
        static ResultOf<T> fail(int c, std::string msg) { return {false, c, std::move(msg), std::nullopt}; }
    };
}

#endif // ZCT_SLMS_COMMON_TYPES
