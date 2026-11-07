// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include <curl/curl.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <memory>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include "crypto/crypto.hpp"

namespace zct_slms::object_storage {
    inline std::string env(const char* name, const char* fallback = "") {
        const auto* value = std::getenv(name);
        return value && *value ? value : fallback;
    }

    inline void validateKey(const std::string& key) {
        const auto slash = key.find('/');
        const auto prefix = key.substr(0, slash);
        if (slash == std::string::npos || (prefix != "avatars" && prefix != "tickets") || key.size() != slash + 65 ||
            !std::all_of(key.begin() + slash + 1, key.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))
            throw std::runtime_error("Invalid storage key");
    }

    inline std::filesystem::path localPath(const std::string& key) {
        validateKey(key);
        return std::filesystem::path(env("ZCT_SLMS_CORE_STORAGE_DIRECTORY", "./data/media")) / key;
    }

    inline std::string s3Endpoint() {
        auto endpoint = env("ZCT_SLMS_CORE_STORAGE_S3_ENDPOINT");
        while (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();
        if (!(endpoint.starts_with("https://") || endpoint.starts_with("http://127.0.0.1:") || endpoint.starts_with("http://localhost:")) ||
            endpoint.find_first_of("?#@\\\r\n\t ") != std::string::npos)
            throw std::runtime_error("S3 endpoint must be an HTTPS origin (HTTP is permitted for localhost)");
        return endpoint;
    }

    inline size_t append(char* data, size_t size, size_t count, void* target) {
        auto* out = static_cast<std::string*>(target);
        const auto bytes = size * count;
        if (out->size() + bytes > 8 * 1024 * 1024) return 0;
        out->append(data, bytes);
        return bytes;
    }

    inline std::string s3(const std::string& method, const std::string& key, std::string_view body = {}) {
        validateKey(key);
        const auto bucket = env("ZCT_SLMS_CORE_STORAGE_S3_BUCKET");
        const auto access = env("ZCT_SLMS_CORE_STORAGE_S3_ACCESS_KEY");
        const auto secret = env("ZCT_SLMS_CORE_STORAGE_S3_SECRET_KEY");
        const auto region = env("ZCT_SLMS_CORE_STORAGE_S3_REGION", "us-east-1");
        if (!std::regex_match(bucket, std::regex("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")) || access.empty() || secret.empty() ||
            !std::regex_match(region, std::regex("[a-z0-9-]{1,64}")))
            throw std::runtime_error("Invalid or incomplete S3 storage configuration");
        const auto url = s3Endpoint() + "/" + bucket + "/" + key;
        const auto credentials = access + ":" + secret;
        const auto signature = "aws:amz:" + region + ":s3";
        std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
        if (!curl) throw std::runtime_error("Cannot initialize S3 client");
        std::string response;
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_USERPWD, credentials.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_AWS_SIGV4, signature.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 60L);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, append);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, method.c_str());
        if (method == "PUT") {
            curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.data());
            curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
        }
        const auto result = curl_easy_perform(curl.get());
        long status = 0;
        curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
        if (result != CURLE_OK || status < 200 || status >= 300)
            throw std::runtime_error("S3 storage request failed (HTTP " + std::to_string(status) + ", curl " + std::to_string(result) + ")");
        return response;
    }

    inline std::string put(const std::string& key, std::string_view data) {
        validateKey(key);
        const auto mode = env("ZCT_SLMS_CORE_STORAGE_MODE", "local");
        if (mode == "s3") {
            s3("PUT", key, data);
            return "s3://" + env("ZCT_SLMS_CORE_STORAGE_S3_BUCKET") + "/" + key;
        }
        if (mode != "local") throw std::runtime_error("Invalid storage mode");
        const auto path = localPath(key);
        std::filesystem::create_directories(path.parent_path());
        auto temp = path;
        temp += "." + zct_slms::crypto::randomHex(8) + ".tmp";
        try {
            std::ofstream out(temp, std::ios::binary | std::ios::trunc);
            if (!out.write(data.data(), static_cast<std::streamsize>(data.size())) || !out.flush())
                throw std::runtime_error("Cannot write storage object");
            out.close();
            std::filesystem::rename(temp, path);
        } catch (...) {
            std::error_code ec;
            std::filesystem::remove(temp, ec);
            throw;
        }
        return "local://" + key;
    }

    inline std::string get(const std::string& location) {
        if (location.starts_with("local://")) {
            auto path = localPath(location.substr(8));
            std::ifstream in(path, std::ios::binary);
            if (!in) throw std::runtime_error("Storage object not found");
            return std::string(std::istreambuf_iterator<char>(in), {});
        }
        if (location.starts_with("s3://")) {
            const auto prefix = "s3://" + env("ZCT_SLMS_CORE_STORAGE_S3_BUCKET") + "/";
            if (!location.starts_with(prefix)) throw std::runtime_error("Storage bucket does not match configuration");
            return s3("GET", location.substr(prefix.size()));
        }
        throw std::runtime_error("Invalid storage location");
    }
}
