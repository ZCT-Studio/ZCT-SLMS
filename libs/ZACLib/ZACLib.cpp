// Licensed under the Apache License, Version 2.0

//
// Created by wanjiangzhi on 2026/2/24.
//

#include "ZACLib.hpp"
#include <array>
#include <queue>

namespace ZACLib {
    Replace::Replace() {
        trie.emplace_back();
    }

    void Replace::AddRule(const ZAC_SV& from) {
        AddRule(from, ZAC_SV(""));
    }

    void Replace::AddRule(const ZAC_SV& from, const ZAC_SV& to) {
        if (from.empty()) return;
        if (from.size() > max_rule_len) max_rule_len = from.size();
        int node = 0;
        for (const ZAC_CHAR i : from) {
            const auto c = static_cast<unsigned char>(i);
            if (trie[node].next[c] == -1) {
                trie[node].next[c] = Node::ToIndexOrThrow(trie.size());
                trie.emplace_back();
            }
            node = trie[node].next[c];
        }

        if (from.size() > trie[node].match_len) {
            trie[node].output_id = outputs.size();
            trie[node].match_len = from.size();
            outputs.emplace_back(reinterpret_cast<const char*>(to.data()), to.size());
        }
    }

    void Replace::AddReplaceRule(const ZAC_SV& from, const ZAC_SV& to) {
        AddRule(from, to);
    }

    void Replace::AddRemoveRule(const ZAC_SV& from) {
        AddRule(from);
    }

    void Replace::Build() {
        std::queue<int> q;
        for (int c = 0; c < 256; ++c) {
            int nxt = trie[0].next[c];
            if (nxt != -1) {
                trie[nxt].fail = 0;
                q.push(nxt);
            } else trie[0].next[c] = 0;
        }

        while (!q.empty()) {
            const int u = q.front();
            q.pop();
            for (int c = 0; c < 256; ++c) {
                int v = trie[u].next[c];
                if (v != -1) {
                    trie[v].fail = trie[trie[u].fail].next[c];

                    const int f = trie[v].fail;
                    if (trie[f].match_len > trie[v].match_len) {
                        trie[v].match_len = trie[f].match_len;
                        trie[v].output_id = trie[f].output_id;
                    }

                    q.push(v);
                } else {
                    trie[u].next[c] = trie[trie[u].fail].next[c];
                }
            }
        }
    }

    std::string Replace::Do(const ZAC_SV& input) const {
        std::string result;
        result.reserve(input.size());

        if (input.empty()) return result;
        if (max_rule_len == 0) {
            result.append(reinterpret_cast<const char*>(input.data()), input.size());
            return result;
        }

        constexpr auto invalid_output = Node::kInvalidOutput;
        const size_t ring_size = max_rule_len + 1;
        std::vector<size_t> pending_start(ring_size, invalid_output);
        std::vector<size_t> pending_len(ring_size, 0);
        std::vector<size_t> pending_output(ring_size, invalid_output);

        auto get_best = [&](const size_t start, size_t& best_len, size_t& best_output) {
            const size_t idx = start % ring_size;
            if (pending_start[idx] == start) {
                best_len = pending_len[idx];
                best_output = pending_output[idx];
            } else {
                best_len = 0;
                best_output = invalid_output;
            }
        };

        auto set_best = [&](const size_t start, const size_t len, const size_t output_id) {
            const size_t idx = start % ring_size;
            if (pending_start[idx] != start) {
                pending_start[idx] = start;
                pending_len[idx] = 0;
                pending_output[idx] = invalid_output;
            }
            if (len > pending_len[idx]) {
                pending_len[idx] = len;
                pending_output[idx] = output_id;
            }
        };

        int state = 0;
        size_t last_pos = 0;
        size_t cursor = 0;

        auto emit_until = [&](const size_t upper_bound) {
            while (cursor < upper_bound) { // NOLINT
                size_t best_len = 0;
                size_t best_output = invalid_output;
                get_best(cursor, best_len, best_output);
                if (best_len == 0) {
                    ++cursor;
                    continue;
                }
                result.append(reinterpret_cast<const char*>(input.data() + last_pos), cursor - last_pos);
                result.append(outputs[best_output]);
                cursor += best_len;
                last_pos = cursor;
            }
        };

        for (size_t i = 0; i < input.size(); ++i) {
            const auto c = static_cast<unsigned char>(input[i]);
            state = trie[state].next[c];

            if (trie[state].output_id != invalid_output) {
                const size_t match_len = trie[state].match_len;
                const size_t match_start = i + 1 - match_len;
                set_best(match_start, match_len, trie[state].output_id);
            }

            const size_t finalize_before = (i + 1 > max_rule_len) ? (i + 1 - max_rule_len) : 0;
            emit_until(finalize_before);
        }

        emit_until(input.size());

        if (last_pos < input.size()) {
            result.append(reinterpret_cast<const char*>(input.data() + last_pos), input.size() - last_pos);
        }

        return result;
    }


    Search::Search() {
        trie.emplace_back();
    }

    void Search::AddRule(const ZAC_SV& from) {
        if (from.empty()) return;
        int node = 0;
        for (const ZAC_CHAR i : from) {
            const auto c = static_cast<unsigned char>(i);
            if (trie[node].next[c] == -1) {
                trie[node].next[c] = Node::ToIndexOrThrow(trie.size());
                trie.emplace_back();
            }
            node = trie[node].next[c];
        }

        if (from.size() > trie[node].match_len) {

            trie[node].output_id = outputs.size();
            trie[node].match_len = from.size();
            outputs.emplace_back(reinterpret_cast<const char*>(from.data()), from.size());
        }
    }

    void Search::Build() {
        std::queue<int> q;
        for (int c = 0; c < 256; ++c) {
            int nxt = trie[0].next[c];
            if (nxt != -1) {
                trie[nxt].fail = 0;
                q.push(nxt);
            } else trie[0].next[c] = 0;
        }

        while (!q.empty()) {
            const int u = q.front();
            q.pop();
            for (int c = 0; c < 256; ++c) {
                int v = trie[u].next[c];
                if (v != -1) {
                    trie[v].fail = trie[trie[u].fail].next[c];

                    int f = trie[v].fail;
                    if (trie[f].match_len > trie[v].match_len) {
                        trie[v].match_len = trie[f].match_len;
                        trie[v].output_id = trie[f].output_id;
                    }

                    q.push(v);
                } else {
                    trie[u].next[c] = trie[trie[u].fail].next[c];
                }
            }
        }
    }

    std::vector<Search::Match> Search::Do(const ZAC_SV& input) const {
        std::vector<Match> result;
        if (trie.empty()) return result;

        int state = 0;
        for (size_t i = 0; i < input.size(); ++i) {
            const auto c = static_cast<unsigned char>(input[i]);
            while (state != 0 && trie[state].next[c] == -1) {
                state = trie[state].fail;
            }
            if (trie[state].next[c] != -1) {
                state = trie[state].next[c];
            } else {
                state = 0;
            }

            if (trie[state].output_id != Node::kInvalidOutput) {
                result.push_back(
                    Match{
                        i + 1 - trie[state].match_len,
                        trie[state].match_len,
                        trie[state].output_id
                    }
                );
            }
        }
        return result;
    }


    Has::Has() { trie.emplace_back(); }

    void Has::AddRule(const ZAC_SV& from) {
        if (from.empty()) return;
        int node = 0;
        for (const unsigned char c : from) {
            if (trie[node].next[c] == -1) {
                trie[node].next[c] = Node::ToIndexOrThrow(trie.size());
                trie.emplace_back();
            }
            node = trie[node].next[c];
        }
        trie[node].output_id = 0;
    }

    void Has::Build() {
        std::queue<int> q;
        for (int c = 0; c < 256; ++c) {
            int nxt = trie[0].next[c];
            if (nxt != -1) {
                trie[nxt].fail = 0;
                q.push(nxt);
            } else {
                trie[0].next[c] = 0;
            }
        }

        while (!q.empty()) {
            const int u = q.front(); q.pop();
            for (int c = 0; c < 256; ++c) {
                int v = trie[u].next[c];
                if (v != -1) {
                    trie[v].fail = trie[trie[u].fail].next[c];
                    q.push(v);
                } else {
                    trie[u].next[c] = trie[trie[u].fail].next[c];
                }
            }
        }
    }

    bool Has::Do(const ZAC_SV& input) const {
        int state = 0;
        for (const unsigned char c : input) {
            state = trie[state].next[c];

            int s = state;
            while (s != 0) {
                if (trie[s].output_id != Node::kInvalidOutput) return true;
                s = trie[s].fail;
            }
        }
        return false;
    }
} // namespace ZACLIB
