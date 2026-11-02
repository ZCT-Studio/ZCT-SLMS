// Licensed under the Apache License, Version 2.0

//
// Created by wanjiangzhi on 2026/2/24.
//

// ReSharper disable CppNonExplicitConvertingConstructor
#ifndef ZACLIB_TYPES_HPP
#define ZACLIB_TYPES_HPP

#if __cplusplus >= 201703L
#define HAS_STRING_VIEW
#endif

#ifdef HAS_STRING_VIEW
#include <string_view>
#else
#include <cstring>
#endif

#include <string>
#include <array>
#include <limits>
#include <stdexcept>

#if defined(__CHAR_UNSIGNED__) || (defined(_CHAR_UNSIGNED) && _CHAR_UNSIGNED)
#define CHAR_UNSIGNED
#endif

namespace ZACLib {
    #ifdef CHAR_UNSIGNED
    #define ArmCastChar(ptr) reinterpret_cast<const ZAC_CHAR*>(ptr)
    using ZAC_CHAR = unsigned char;
    #else
    using ZAC_CHAR = char;
    #define ArmCastChar(ptr) (ptr)
    #endif

    #if __cplusplus >= 201703L
    class ZAC_SV : public std::basic_string_view<ZAC_CHAR> {
    public:
        using std::basic_string_view<ZAC_CHAR>::basic_string_view;
        ZAC_SV() = default;

        ZAC_SV(const std::string& s) noexcept
            : std::basic_string_view<ZAC_CHAR>(reinterpret_cast<const ZAC_CHAR*>(s.data()), s.size()) {}

    #ifdef CHAR_UNSIGNED
    ZAC_SV(const char* s, const size_t n)
        : std::basic_string_view<ZAC_CHAR>(reinterpret_cast<const ZAC_CHAR*>(s), n) {}

    ZAC_SV(const char* s)
        : std::basic_string_view<ZAC_CHAR>(
            reinterpret_cast<const ZAC_CHAR*>(s),
            s ? std::char_traits<char>::length(s) : 0
        ) {}
    #endif
    };
    #else
    class ZAC_SV {
        const ZAC_CHAR* m_data;
        const std::size_t m_size;

    public:
        ZAC_SV() : m_data(nullptr),
                   m_size(0) {}

        ZAC_SV(const ZAC_CHAR* d, const std::size_t s) : m_data(d),
                                                    m_size(s) {}

        #ifdef CHAR_UNSIGNED
        ZAC_SV(const char* d, const size_t s) : m_data(reinterpret_cast<const ZAC_CHAR*>(d)),
                                                m_size(s) {}
        #endif

        ZAC_SV(const std::string& s) noexcept : m_data(ArmCastChar(s.data())),
                                                m_size(s.size()) {}

        ZAC_SV(const ZAC_CHAR* d) : m_data(d),
                                    m_size(d ? std::strlen(reinterpret_cast<const char*>(d)) : 0) {}

        #ifdef CHAR_UNSIGNED
        ZAC_SV(const char* d) : m_data(reinterpret_cast<const ZAC_CHAR*>(d)),
                                m_size(d ? std::strlen(d) : 0) {}
        #endif

        const ZAC_CHAR* data() const noexcept {
            return m_data;
        }

        std::size_t size() const noexcept {
            return m_size;
        }

        bool empty() const noexcept {
            return m_size == 0;
        }

        const ZAC_CHAR* begin() const { return m_data; }
        const ZAC_CHAR* end() const { return m_data + m_size; }
        const ZAC_CHAR* cbegin() const { return m_data; }
        const ZAC_CHAR* cend() const { return m_data + m_size; }

        const ZAC_CHAR& operator[](const size_t i) const { return m_data[i]; }
    };
    #endif

    struct Node {
        using value_type = int;
        using next_type = std::array<value_type, 256>;
        using size_type = std::size_t;
        next_type next{};
        value_type fail;
        size_type output_id;
        size_type match_len;
        static constexpr auto kInvalidOutput = std::numeric_limits<size_type>::max();

        static value_type ToIndexOrThrow(const size_type value) {
            if (value > static_cast<size_type>(std::numeric_limits<value_type>::max())) {
                throw std::overflow_error("Trie node count exceeds Node::value_type range");
            }
            return static_cast<value_type>(value);
        }

        Node() : fail(0),
                 output_id(kInvalidOutput),
                 match_len(0) { next.fill(-1); }
    };
}

#endif //ZACLIB_TYPES_HPP
// ReSharper enable CppNonExplicitConvertingConstructor
