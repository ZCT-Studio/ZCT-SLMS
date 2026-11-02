// Licensed under the Apache License, Version 2.0

//
// Created by wanjiangzhi on 2026/2/24.
//

#ifndef ZACLIB_HPP
#define ZACLIB_HPP
#include "ZACLib_Constants.hpp"

#include <array>
#include <vector>
#include <string>
#include "ZACLib_Types.hpp"

namespace ZACLib {
    class Replace {
    public:
        Replace();
        void AddRule(const ZAC_SV& from);
        void AddRule(const ZAC_SV& from, const ZAC_SV& to);
        void AddReplaceRule(const ZAC_SV& from, const ZAC_SV& to);
        void AddRemoveRule(const ZAC_SV& from);
        void Build();
        std::string Do(const ZAC_SV& input) const;

    private:
        std::vector<Node> trie;
        std::vector<std::string> outputs;
        size_t max_rule_len = 0;
    };

    class Search {
    public:
        struct Match {
            size_t pos;
            size_t len;
            size_t ruleId;
        };

        Search();
        void AddRule(const ZAC_SV& from);
        void Build();
        std::vector<Match> Do(const ZAC_SV& input) const;

    private:
        std::vector<Node> trie;
        std::vector<std::string> outputs;
        size_t max_rule_len = 0;
    };

    class Has {
    public:
        Has();
        void AddRule(const ZAC_SV& from);
        void Build();
        bool Do(const ZAC_SV& input) const;

    private:
        std::vector<Node> trie;
    };

} // namespace ZACLIB

#endif // ZACLIB_HPP