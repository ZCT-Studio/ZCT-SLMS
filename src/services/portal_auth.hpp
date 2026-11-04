#pragma once
#include "services/portal_accounts.hpp"
namespace zct_slms::portal_auth {
using namespace zct_slms::identity;
namespace common = zct_slms::inside::api::v1::common;
inline std::mutex guard;
inline std::string roleName(std::string role) {
  for (auto &c : role)
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  if (role == "OWNER")
    role = "USER";
  zct_slms::portal::table(role);
  return role;
}
inline Json findAccount(const std::string &role, const std::string &username) {
  auto rows = zct_slms::db::Database::instance().queryParams(
      "SELECT id,username,password_hash,salt,status FROM " +
          zct_slms::portal::table(role) + " WHERE username = ?",
      username);
  if (rows.empty())
    throw std::runtime_error("账号或验证信息不正确");
  auto &r = rows[0];
  auto id = zct_slms::repo::getInt(r, "id");
  auto actual = (role == "ADMIN" || role == "SUPPORT")
                    ? zct_slms::repo::ConfigRepo::get(
                          "staff_role:" + std::to_string(id), "ADMIN")
                    : role;
  if (role == "SUPPORT" && actual != "SUPPORT" ||
      zct_slms::repo::getInt(r, "status") != 1)
    throw std::runtime_error("账号或验证信息不正确");
  Json out;
  out["user_type"] = actual;
  out["user_id"] = ::Json::Int64(id);
  out["username"] = zct_slms::repo::getStr(r, "username");
  return out;
}
inline bool active(const Json &session) {
  auto role = session["user_type"].asString();
  auto id = session["user_id"].asInt64();
  auto rows = zct_slms::db::Database::instance().queryParams(
      "SELECT status FROM " + zct_slms::portal::table(role) + " WHERE id = ?", id);
  if (rows.empty() || zct_slms::repo::getInt(rows[0], "status") != 1)
    return false;
  if (role == "USER" || role == "SUBUSER") {
    auto expiry = zct_slms::db::Database::instance().queryScalar(
        "SELECT expires_at FROM " + zct_slms::portal::table(role) + " WHERE id = ?",
        id);
    if (!expiry || (*expiry != "-1" && std::stoll(*expiry) < now()))
      return false;
  }
  return true;
}
inline std::string fingerprint(const Json &session) {
  auto value = zct_slms::db::Database::instance().queryScalar(
      "SELECT password_hash FROM " +
          zct_slms::portal::table(session["user_type"].asString()) + " WHERE id = ?",
      session["user_id"].asInt64());
  return value ? zct_slms::crypto::sha256Hex(*value) : "";
}
inline Json issue(Json session, const std::string &ip, const std::string &ua) {
  if (!active(session))
    throw std::runtime_error("账号不可用");
  auto token = zct_slms::crypto::randomHex(32);
  zct_slms::repo::SessionRepo::insert(
      session["user_type"].asString(), session["user_id"].asInt64(),
      zct_slms::crypto::sha256Hex(token),
      now() + zct_slms::AppConfig::instance().security().session_ttl_seconds, now(),
      ip, ua);
  session["token"] = token;
  session.removeMember("_fingerprint");
  session.removeMember("_factor_version");
  session.removeMember("auth_method");
  session.removeMember("_verified_method");
  if (zct_slms::portal::forceRequired(session["user_type"].asString(),
                                 session["user_id"].asInt64()))
    session["force_password_change"] = true;
  return session;
}
inline std::vector<std::string> methods(const Json &session, const Json &a) {
  std::vector<std::string> out;
  if (!zct_slms::repo::ConfigRepo::getBool(
          "identity_password_pending:" +
              std::to_string(session["user_id"].asInt64()),
          false) ||
      session["user_type"].asString() != "USER")
    out.push_back("password");
  if (a.get("totp_enabled", false).asBool())
    out.push_back("totp");
  if (!a["keys"].empty()) {
    try {
      zct_slms::factors::origin();
      out.push_back("passkey");
    } catch (...) {
    }
  }
  if (session["user_type"].asString() == "USER") {
    zct_slms::identity::schema();
    auto cfg = config();
    for (auto &row : zct_slms::db::Database::instance().queryParams(
             "SELECT provider FROM auth_identities WHERE user_id = ?",
             session["user_id"].asInt64())) {
      auto p = zct_slms::repo::getStr(row, "provider");
      if ((p == "github" || p == "microsoft" || p == "google" || p == "telegram" || p == "gitlab" || p == "discord") && ready(cfg, p))
        out.push_back(p);
    }
  }
  auto cfg = config();
  for (auto &[provider, target] : contactsFor(session["user_type"].asString(),
                                              session["user_id"].asInt64()))
    if (ready(cfg, provider))
      out.push_back(provider);
  return out;
}
inline Json publicKey(const Json &a, const std::string &challenge) {
  auto origin = zct_slms::factors::origin();
  Json pk;
  pk["challenge"] = challenge;
  pk["rpId"] = origin.second;
  pk["userVerification"] = "required";
  pk["timeout"] = 120000;
  pk["allowCredentials"] = Json(::Json::arrayValue);
  for (auto &key : a["keys"]) {
    Json v;
    v["type"] = "public-key";
    v["id"] = key["id"];
    pk["allowCredentials"].append(v);
  }
  return pk;
}
struct Challenge {
  Json session;
  std::string account, primary, challenge, origin, rp, ip, ua, kind;
  int64_t expires;
  int attempts = 0;
};
inline std::map<std::string, Challenge> challenges;
inline std::function<Json(const std::string &, Challenge &, Json)>
    authorizationComplete;
inline std::function<void(const Json &, const Json &)> twoFactorCompleted;
inline void pruneChallenges() {
  for (auto it = challenges.begin(); it != challenges.end();)
    if (it->second.expires < now())
      it = challenges.erase(it);
    else
      ++it;
  if (challenges.size() > 10000)
    throw std::runtime_error("认证服务繁忙");
}
inline Json gateLocked(Json session, const std::string &ip,
                       const std::string &ua) {
  auto key = zct_slms::factors::accountKey(session["user_type"].asString(),
                                      session["user_id"].asInt64());
  auto a = zct_slms::factors::load(key), settings = zct_slms::factors::settings();
  auto enrolled = methods(session, a);
  auto primary = session.get("auth_method", "password").asString();
  if (!settings.get("two_factor_enabled", false).asBool() ||
      zct_slms::portal::forceRequired(session["user_type"].asString(),
                                 session["user_id"].asInt64()) ||
      enrolled.size() < 2) {
    session["second_factor_needed"] =
        settings.get("two_factor_enabled", false).asBool() &&
        enrolled.size() < 2;
    session.removeMember("auth_method");
    return session;
  }
  if (session.isMember("token"))
    zct_slms::repo::SessionRepo::revokeByHash(
        zct_slms::crypto::sha256Hex(session["token"].asString()));
  session.removeMember("token");
  session["_fingerprint"] = fingerprint(session);
  session["_factor_version"] = a.get("version", 0);
  pruneChallenges();
  auto id = zct_slms::crypto::randomHex(32),
       challenge = b64url(zct_slms::crypto::randomBytes(32));
  std::string origin, rp;
  if (std::find(enrolled.begin(), enrolled.end(), "passkey") !=
      enrolled.end()) {
    auto o = zct_slms::factors::origin();
    origin = o.first;
    rp = o.second;
  }
  challenges[id] = {session, key, primary, challenge,   origin,
                    rp,      ip,  ua,      "secondary", now() + 180};
  Json out;
  out["mfa_required"] = true;
  out["recovery_available"] = !a["recovery"].empty();
  out["challenge_id"] = id;
  out["primary_method"] = primary;
  out["methods"] = Json(::Json::arrayValue);
  for (auto &method : enrolled)
    if (method != primary)
      out["methods"].append(method);
  if (!rp.empty())
    out["public_key"] = publicKey(a, challenge);
  return out;
}
inline Json gate(Json session, const std::string &ip, const std::string &ua) {
  std::scoped_lock lock(guard, zct_slms::factors::guard);
  return gateLocked(session, ip, ua);
}
inline Challenge &pending(const std::string &id, const std::string &ip,
                          const std::string &ua, bool count = true) {
  auto it = challenges.find(id);
  if (it == challenges.end() || it->second.expires < now() ||
      it->second.ip != ip || it->second.ua != ua)
    throw std::runtime_error("验证已过期或登录环境改变，请重新登录");
  auto &p = it->second;
  if (count && ++p.attempts > 5) {
    challenges.erase(it);
    throw std::runtime_error("验证次数过多，请重新登录");
  }
  if (!active(p.session) ||
      fingerprint(p.session) != p.session["_fingerprint"].asString())
    throw std::runtime_error("账号凭据已变更，请重新登录");
  return p;
}
inline Json completeLocked(const std::string &id, Challenge &p, Json a) {
  if (a.get("version", 0) != p.session.get("_factor_version", 0))
    throw std::runtime_error("账号安全设置已变更，请重新登录");
  zct_slms::factors::store(p.account, a);
  if (p.kind == "authorize")
    return authorizationComplete(id, p, a);
  auto result = issue(p.session, p.ip, p.ua);
  if (twoFactorCompleted)
    twoFactorCompleted(result, a);
  result["second_factor_needed"] = false;
  challenges.erase(id);
  return result;
}
inline void primaryStart(const Req &req, Callback &&cb) {
  try {
    std::scoped_lock lock(guard, zct_slms::factors::guard);
    auto session = findAccount(roleName(common::paramStr(req, "role", "USER")),
                               common::paramStr(req, "username"));
    auto key = zct_slms::factors::accountKey(session["user_type"].asString(),
                                        session["user_id"].asInt64());
    auto a = zct_slms::factors::load(key);
    if (a["keys"].empty())
      throw std::runtime_error("账号或验证信息不正确");
    pruneChallenges();
    auto id = zct_slms::crypto::randomHex(32),
         challenge = b64url(zct_slms::crypto::randomBytes(32));
    auto origin = zct_slms::factors::origin();
    session["_fingerprint"] = fingerprint(session);
    session["_factor_version"] = a.get("version", 0);
    challenges[id] = {session,
                      key,
                      "passkey",
                      challenge,
                      origin.first,
                      origin.second,
                      common::clientIp(req),
                      common::clientUa(req),
                      "primary",
                      now() + 180};
    Json out;
    out["challenge_id"] = id;
    out["public_key"] = publicKey(a, challenge);
    ok(cb, out);
  } catch (const std::exception &e) {
    fail(cb, e.what());
  }
}
inline void primaryFinish(const Req &req, Callback &&cb) {
  try {
    std::scoped_lock lock(guard, zct_slms::factors::guard);
    auto method = common::paramStr(req, "method");
    Json session;
    if (method == "totp") {
      session = findAccount(roleName(common::paramStr(req, "role", "USER")),
                            common::paramStr(req, "username"));
      auto key = zct_slms::factors::accountKey(session["user_type"].asString(),
                                          session["user_id"].asInt64());
      auto a = zct_slms::factors::load(key);
      {
        std::lock_guard limit(mutex);
        prune();
        rate("totp-login:" + key, 6, 60);
        rate("totp-login-ip:" + common::clientIp(req), 30, 60);
      }
      if (!a.get("totp_enabled", false).asBool() ||
          !zct_slms::factors::checkTotp(a, common::paramStr(req, "code")))
        throw std::runtime_error("账号或动态验证码不正确");
      zct_slms::factors::store(key, a);
    } else if (method == "passkey") {
      auto id = common::paramStr(req, "challenge_id");
      auto &p = pending(id, common::clientIp(req), common::clientUa(req));
      if (p.kind != "primary")
        throw std::runtime_error("验证用途不匹配");
      auto a = zct_slms::factors::load(p.account);
      if (a.get("version", 0) != p.session.get("_factor_version", 0))
        throw std::runtime_error("安全设置已改变，请重新登录");
      auto body = req->getJsonObject();
      if (!body)
        throw std::runtime_error("凭据数据无效");
      zct_slms::factors::assertion(a, (*body)["credential"], p.challenge, p.origin,
                              p.rp);
      session = p.session;
      session.removeMember("_factor_version");
      session.removeMember("_fingerprint");
      zct_slms::factors::store(p.account, a);
      challenges.erase(id);
    } else
      throw std::runtime_error("登录方式无效");
    auto login = issue(session, common::clientIp(req), common::clientUa(req));
    login["auth_method"] = method;
    ok(cb, gateLocked(login, common::clientIp(req), common::clientUa(req)));
  } catch (const std::exception &e) {
    fail(cb, e.what());
  }
}
inline void sendCode(const Req &req, Callback &&callback) {
  background(req, std::move(callback), [](auto req, const Callback &cb) {
    try {
      std::unique_lock lock(guard);
      auto id = common::paramStr(req, "challenge_id"),
           method = common::paramStr(req, "method");
      auto &p =
          pending(id, common::clientIp(req), common::clientUa(req), false);
      if ((p.kind != "secondary" && p.kind != "authorize") ||
          p.primary == method || (method != "email" && method != "phone"))
        throw std::runtime_error("不能使用此验证方式");
      auto uid = p.session["user_id"].asInt64();
      auto bound = contactsFor(p.session["user_type"].asString(), uid);
      auto cfg = config();
      if (!bound.contains(method) || !ready(cfg, method))
        throw std::runtime_error("此验证方式不可用");
      auto target = bound[method], challenge = zct_slms::crypto::randomHex(24),
           code = zct_slms::crypto::randomNumeric(6);
      {
        std::lock_guard limit(mutex);
        prune();
        rate("mfa-code:" + id + method, 1, 60);
        rate("mfa-send:" + common::clientIp(req), 10, 3600);
      }
      const auto mailValues=mailAccount(p.session["user_type"].asString(),uid,target);
      lock.unlock();
      if (method == "email")
        deliverEmail(cfg, target, code, false, "", "", "security", mailValues);
      else
        deliverPhone(cfg, target, code);
      {
        std::lock_guard limit(mutex);
        zct_slms::identity::challenges[challenge] = {
            method,
            target,
            zct_slms::crypto::hmacSha256Hex(challenge + ":" + code, otpSecret),
            "mfa:" + id,
            now() + 180,
            0};
      }
      Json out;
      out["code_challenge_id"] = challenge;
      ok(cb, out);
    } catch (const std::exception &e) {
      fail(cb, e.what());
    }
  });
}
inline void finish(const Req &req, Callback &&cb) {
  try {
    std::scoped_lock lock(guard, zct_slms::factors::guard);
    auto id = common::paramStr(req, "challenge_id"),
         method = common::paramStr(req, "method");
    auto &p = pending(id, common::clientIp(req), common::clientUa(req));
    if (p.kind != "secondary" && p.kind != "authorize")
      throw std::runtime_error("验证用途不匹配");
    auto a = zct_slms::factors::load(p.account);
    if (method == "recovery") {
      if (p.session.get("_closure", false).asBool())
        throw std::runtime_error("注销需要两种登录方式，不能使用恢复码代替");
      if (p.kind == "authorize" && p.primary.empty())
        throw std::runtime_error("请先验证一种已绑定的登录方式");
      if (!zct_slms::factors::recovery(a, common::paramStr(req, "recovery_code")))
        throw std::runtime_error("恢复码无效或已使用");
    } else {
      auto available = methods(p.session, a);
      if (method == p.primary || std::find(available.begin(), available.end(),
                                           method) == available.end())
        throw std::runtime_error("请选择另一种已绑定的登录方式");
      if (method == "totp") {
        if (!zct_slms::factors::checkTotp(a, common::paramStr(req, "code")))
          throw std::runtime_error("动态验证码错误或已使用");
      } else if (method == "passkey") {
        auto body = req->getJsonObject();
        if (!body)
          throw std::runtime_error("通行密钥数据无效");
        zct_slms::factors::assertion(a, (*body)["credential"], p.challenge, p.origin,
                                p.rp);
      } else if (method == "password") {
        auto row = zct_slms::db::Database::instance().queryParams(
            "SELECT password_hash,salt FROM " +
                zct_slms::portal::table(p.session["user_type"].asString()) +
                " WHERE id = ?",
            p.session["user_id"].asInt64());
        if (row.empty() || !zct_slms::service::verifyPassword(
                               common::paramStr(req, "password"),
                               zct_slms::repo::getStr(row[0], "password_hash"),
                               zct_slms::repo::getStr(row[0], "salt")))
          throw std::runtime_error("密码不正确");
      } else if (method == "email" || method == "phone") {
        auto code = consume(common::paramStr(req, "code_challenge_id"),
                            common::paramStr(req, "code"), "mfa:" + id);
        if (code.method != method ||
            contactsFor(p.session["user_type"].asString(),
                        p.session["user_id"].asInt64())[method] != code.target)
          throw std::runtime_error("验证码用途或身份不匹配");
      } else
        throw std::runtime_error("请通过对应授权入口验证");
    }
    p.session["_verified_method"] = method;
    ok(cb, completeLocked(id, p, a));
  } catch (const std::exception &e) {
    fail(cb, e.what());
  }
}
inline int64_t oauthOwner(const Req &req) {
  std::scoped_lock lock(guard, zct_slms::factors::guard);
  auto &p = pending(common::paramStr(req, "challenge_id"),
                    common::clientIp(req), common::clientUa(req), false);
  auto provider = common::paramStr(req, "provider");
  auto a = zct_slms::factors::load(p.account);
  auto available = methods(p.session, a);
  if ((p.kind != "secondary" && p.kind != "authorize") ||
      p.primary == provider || p.session["user_type"].asString() != "USER" ||
      std::find(available.begin(), available.end(), provider) ==
          available.end())
    throw std::runtime_error("不能使用此授权方式");
  return p.session["user_id"].asInt64();
}
inline Json oauthComplete(const std::string &id, const std::string &provider,
                          int64_t uid, const std::string &ip,
                          const std::string &ua) {
  std::scoped_lock lock(guard, zct_slms::factors::guard);
  auto &p = pending(id, ip, ua);
  if ((p.kind != "secondary" && p.kind != "authorize") ||
      p.primary == provider || p.session["user_type"].asString() != "USER" ||
      p.session["user_id"].asInt64() != uid)
    throw std::runtime_error("授权账号不匹配");
  p.session["_verified_method"] = provider;
  return completeLocked(id, p, zct_slms::factors::load(p.account));
}
inline void status(const Req &req, Callback &&cb) {
  try {
    auto auth = zct_slms::factors::auth(req);
    std::scoped_lock lock(guard, zct_slms::factors::guard);
    Json s;
    s["user_type"] = auth.user_type;
    s["user_id"] = ::Json::Int64(auth.user_id);
    auto a = zct_slms::factors::load(
        zct_slms::factors::accountKey(auth.user_type, auth.user_id));
    auto list = methods(s, a);
    auto cfg = zct_slms::factors::settings();
    Json out;
    out["two_factor_enabled"] = cfg.get("two_factor_enabled", false);
    out["needs_second_method"] =
        cfg.get("two_factor_enabled", false).asBool() && list.size() < 2;
    out["method_count"] = static_cast<int>(list.size());
    ok(cb, out);
  } catch (const std::exception &e) {
    fail(cb, e.what());
  }
}
} // namespace zct_slms::portal_auth
