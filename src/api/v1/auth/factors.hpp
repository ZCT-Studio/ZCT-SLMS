#pragma once
#include "services/security_identity.hpp"
namespace zct_slms::human {
using namespace zct_slms::identity;
namespace common = zct_slms::inside::api::v1::common;
inline std::mutex guard;
struct Challenge {
  std::string answer, ip;
  int64_t expires;
  int attempts = 0;
};
inline std::map<std::string, Challenge> challenges;
inline std::map<std::string, int64_t> tokens;
inline void clean() {
  for (auto it = challenges.begin(); it != challenges.end();)
    if (it->second.expires < now())
      it = challenges.erase(it);
    else
      ++it;
  for (auto it = tokens.begin(); it != tokens.end();)
    if (it->second < now())
      it = tokens.erase(it);
    else
      ++it;
  if (challenges.size() > 10000 || tokens.size() > 10000)
    throw std::runtime_error("人机验证服务繁忙");
}
inline std::vector<std::pair<std::filesystem::path, std::string>> images() {
  const auto dir = std::filesystem::weakly_canonical("captcha/static");
  std::ifstream file(dir / "answer.json", std::ios::binary);
  if (!file)
    throw std::runtime_error("请配置 captcha/static/answer.json");
  std::string raw((std::istreambuf_iterator<char>(file)), {});
  if (raw.size() > 1048576)
    throw std::runtime_error("静态题配置过大");
  auto answers = parse(raw);
  if (!answers.isObject() || answers.empty() || answers.size() > 10000)
    throw std::runtime_error("静态题答案格式无效");
  std::vector<std::pair<std::filesystem::path, std::string>> result;
  for (auto &name : answers.getMemberNames()) {
    auto path = std::filesystem::u8path(name);
    if (path.has_parent_path() || !answers[name].isString() ||
        answers[name].asString().empty() ||
        answers[name].asString().size() > 128)
      throw std::runtime_error("静态题只允许文件名与文本答案");
    auto ext = path.extension().string();
    if (ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".webp")
      throw std::runtime_error("静态题仅支持 PNG JPEG WebP");
    path = std::filesystem::weakly_canonical(dir / path);
    if (path.parent_path() != dir || !std::filesystem::is_regular_file(path) ||
        std::filesystem::file_size(path) > 524288)
      throw std::runtime_error("静态题文件路径或大小无效");
    result.emplace_back(path, answers[name].asString());
  }
  return result;
}
inline void options(const Req &req, Callback &&cb) {
  try {
    auto cfg = zct_slms::factors::settings();
    auto provider = cfg.get("captcha_provider", "none").asString();
    Json out;
    out["provider"] = provider;
    out["site_key"] = cfg.get("captcha_site_key", "");
    if (provider == "static") {
      std::string answer;
      auto rnd = zct_slms::crypto::randomBytes(4);
      uint32_t n = 0;
      for (unsigned char c : rnd)
        n = (n << 8) | c;
      if (cfg.get("static_mode", "arithmetic").asString() == "image") {
        auto list = images();
        auto &item = list[n % list.size()];
        answer = item.second;
        std::ifstream f(item.first, std::ios::binary);
        std::string bytes((std::istreambuf_iterator<char>(f)), {});
        auto ext = item.first.extension().string();
        out["image"] = "data:image/" +
                       std::string(ext == ".png"    ? "png"
                                   : ext == ".webp" ? "webp"
                                                    : "jpeg") +
                       ";base64," + zct_slms::crypto::base64Encode(bytes);
      } else {
        int a = n % 90 + 10, b = (n / 90) % 9 + 1;
        bool multiply = (n / 810) % 2;
        out["question"] = std::to_string(a) + (multiply ? " × " : " + ") +
                          std::to_string(b) + " = ?";
        answer = std::to_string(multiply ? a * b : a + b);
      }
      auto id = zct_slms::crypto::randomHex(24);
      {
        std::lock_guard lock(mutex);
        prune();
        rate("captcha:" + common::clientIp(req), 30, 60);
      }
      std::lock_guard lock(guard);
      clean();
      challenges[id] = {
          zct_slms::crypto::hmacSha256Hex(id + ":" + answer, otpSecret),
          common::clientIp(req), now() + 120};
      out["challenge_id"] = id;
    }
    ok(cb, out);
  } catch (const std::exception &e) {
    fail(cb, e.what());
  }
}
inline void validate(const Req &req) {
  auto cfg = zct_slms::factors::settings();
  auto provider = cfg.get("captcha_provider", "none").asString();
  if (provider == "none")
    return;
  const auto ip = common::clientIp(req);
  if (provider == "static") {
    std::lock_guard lock(guard);
    clean();
    auto id = common::paramStr(req, "captcha_id");
    auto it = challenges.find(id);
    if (it == challenges.end() || it->second.ip != ip ||
        it->second.expires < now())
      throw std::runtime_error("请完成人机验证，题目已过期时请刷新");
    if (++it->second.attempts > 5) {
      challenges.erase(it);
      throw std::runtime_error("人机验证次数过多，请刷新题目");
    }
    if (!zct_slms::crypto::constantTimeEqual(
            it->second.answer,
            zct_slms::crypto::hmacSha256Hex(
                id + ":" + common::paramStr(req, "captcha_answer"), otpSecret)))
      throw std::runtime_error("人机验证答案错误");
    challenges.erase(it);
    return;
  }
  auto token = common::paramStr(req, "captcha_token");
  if (token.empty() || token.size() > 8192)
    throw std::runtime_error("请先完成人机验证");
  {
    std::lock_guard lock(guard);
    clean();
    auto key = zct_slms::crypto::sha256Hex(token);
    if (tokens.contains(key))
      throw std::runtime_error("人机验证已使用，请重新验证");
    tokens[key] = now() + 600;
  }
  std::string url =
      provider == "recaptcha"
          ? "https://www.google.com/recaptcha/api/siteverify"
      : provider == "hcaptcha" ? "https://api.hcaptcha.com/siteverify"
      : provider == "turnstile"
          ? "https://challenges.cloudflare.com/turnstile/v0/siteverify"
          : "";
  if (url.empty())
    throw std::runtime_error("人机验证配置无效");
  auto r = http(url,
                form({{"secret", cfg.get("captcha_secret", "").asString()},
                      {"response", token},
                      {"remoteip", ip}}),
                {"Content-Type: application/x-www-form-urlencoded"});
  if (!r.get("success", false).asBool() ||
      r.get("hostname", "").asString() !=
          cfg.get("captcha_hostname", "").asString())
    throw std::runtime_error("人机验证失败，请重新验证");
}
template <class Fn> inline auto secured(Fn fn) {
  return [fn](const Req &req, Callback &&callback) {
    background(req, std::move(callback), [fn](auto req, const Callback &cb) {
      try {
        if (req->path().ends_with("/login")) {
          std::lock_guard lock(mutex);
          prune();
          rate("password-ip:" + common::clientIp(req), 60, 60);
        }
        validate(req);
        auto next = cb;
        fn(req, std::move(next));
      } catch (const std::exception &e) {
        fail(cb, e.what());
      }
    });
  };
}
inline void adminSettings(const Req &req, Callback &&callback) {
  background(req, std::move(callback), [](auto req, const Callback &cb) {
    try {
      auto user = zct_slms::factors::auth(req);
      if (user.user_type != "ADMIN")
        throw std::runtime_error("需要管理员登录");
      if (req->method() == drogon::Post && !adminPassword(req))
        throw std::runtime_error("当前授权无效，请重新验证");
      std::lock_guard lock(zct_slms::factors::guard);
      auto cfg = zct_slms::factors::settings();
      if (req->method() == drogon::Post) {
        auto body = req->getJsonObject();
        if (!body)
          throw std::runtime_error("配置无效");
        for (auto key : {"captcha_provider", "captcha_site_key",
                         "captcha_secret", "captcha_hostname", "static_mode"})
          if (body->isMember(key)) {
            if (!(*body)[key].isString() ||
                (*body)[key].asString().size() > 4096)
              throw std::runtime_error("配置格式无效");
            if (std::string(key) == "captcha_secret" &&
                (*body)[key].asString().empty())
              continue;
            cfg[key] = (*body)[key];
          }
        for (auto key : {"two_factor_enabled", "totp_enabled", "passkey_enabled", "recovery_email_enabled", "recovery_phone_enabled", "recovery_totp_enabled", "recovery_passkey_enabled", "recovery_ticket_enabled"})
          if (body->isMember(key)) {
            if (!(*body)[key].isBool())
              throw std::runtime_error("开关格式无效");
            cfg[key] = (*body)[key];
          }
        auto provider = cfg.get("captcha_provider", "none").asString();
        if (provider != "none" && provider != "static" &&
            provider != "recaptcha" && provider != "hcaptcha" &&
            provider != "turnstile")
          throw std::runtime_error("人机验证类型无效");
        if (provider == "static") {
          auto mode = cfg.get("static_mode", "arithmetic").asString();
          if (mode != "image" && mode != "arithmetic")
            throw std::runtime_error("静态题类型无效");
          if (mode == "image")
            images();
        } else if (provider != "none") {
          if (val(cfg, "captcha_site_key").empty() ||
              val(cfg, "captcha_secret").empty() ||
              !std::regex_match(val(cfg, "captcha_hostname"),
                                std::regex("[A-Za-z0-9.-]+")))
            throw std::runtime_error("请填写 Site Key、Secret 与本站主机名");
        }
        if (cfg.get("passkey_enabled", false).asBool())
          zct_slms::factors::origin();
        zct_slms::factors::store("factor_settings", cfg);
        zct_slms::repo::AuditRepo::log("ADMIN", user.user_id, "UpdateFactorSettings",
                                  "SYSTEM", 0, "", "success",
                                  common::clientIp(req), "{}", now());
      }
      cfg["captcha_secret_configured"] = !val(cfg, "captcha_secret").empty();
      cfg["captcha_secret"] = "";
      ok(cb, cfg);
    } catch (const std::exception &e) {
      fail(cb, e.what());
    }
  });
}
} // namespace zct_slms::human
