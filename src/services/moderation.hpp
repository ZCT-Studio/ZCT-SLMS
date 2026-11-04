// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once
#include "ZACLib/ZACLib.hpp"
#include "api/v1/uih.h"
#include <memory>
#include <mutex>

namespace zct_slms::moderation {
    inline std::mutex mutex;

    inline std::string lower(std::string text) {
        for (auto& c : text)
            if (static_cast<unsigned char>(c) < 128)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return text;
    }

    inline std::shared_ptr<const ZACLib::Has> matcher() {
        static std::string previous;
        static std::shared_ptr<const ZACLib::Has> cached;
        auto rules = zct_slms::repo::ConfigRepo::get("moderation_rules", "");
        std::lock_guard lock(mutex);
        if (cached && previous == rules)
            return cached;
        auto next = std::make_shared<ZACLib::Has>();
        std::istringstream stream(rules);
        std::string line;
        size_t count = 0, total = 0;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line.empty())
                continue;
            if (line.size() > 256 || ++count > 20000 || (total += line.size()) > 1048576)
                throw std::runtime_error("屏蔽词数量或长度超出限制");
            next->AddRule(lower(line));
        }
        next->Build();
        previous = rules;
        cached = next;
        return cached;
    }

    inline void check(const std::string& text) {
        if (zct_slms::repo::ConfigRepo::getBool("moderation_enabled", true) &&
            matcher()->Do(lower(text)))
            throw std::invalid_argument("内容包含平台屏蔽词，请修改后重试");
    }
} // namespace zct_slms::moderation
