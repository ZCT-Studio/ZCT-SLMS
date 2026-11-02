#pragma once
#include "api/v1/auth/identity.hpp"
#include <openssl/core_names.h>
#include <openssl/x509.h>
namespace zct_slms::factors {
using namespace zct_slms::identity;
namespace common = zct_slms::inside::api::v1::common;
inline std::mutex guard;
inline Json load(const std::string &key) {
  auto raw = zct_slms::repo::ConfigRepo::get(key, "");
  if (raw.empty())
    return Json(::Json::objectValue);
  auto plain = zct_slms::crypto::aes256GcmDecrypt(zct_slms::crypto::base64Decode(raw),
                                             masterKey());
  if (!plain)
    throw std::runtime_error("安全配置无法解密");
  return parse(*plain);
}
inline void store(const std::string &key, const Json &value) {
  zct_slms::repo::ConfigRepo::set(
      key,
      zct_slms::crypto::base64Encode(
          zct_slms::crypto::aes256GcmEncrypt(json(value), masterKey())),
      now());
}
inline Json settings() { return load("factor_settings"); }
inline std::string accountKey(const std::string &role, int64_t id) {
  return "factors:" + role + ":" + std::to_string(id);
}
inline std::string decode64(std::string value) {
  if (value.size() > 131072 ||
      !std::regex_match(value, std::regex("[A-Za-z0-9_-]*")))
    throw std::runtime_error("无效认证数据");
  std::replace(value.begin(), value.end(), '-', '+');
  std::replace(value.begin(), value.end(), '_', '/');
  while (value.size() % 4)
    value += '=';
  return zct_slms::crypto::base64Decode(value);
}
inline std::string base32(std::string_view bytes) {
  const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  unsigned int acc = 0;
  int bits = 0;
  std::string out;
  for (unsigned char b : bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(acc >> bits) & 31];
    }
  }
  if (bits)
    out += alphabet[(acc << (5 - bits)) & 31];
  return out;
}
inline std::string unbase32(const std::string &text) {
  unsigned int acc = 0;
  int bits = 0;
  std::string out;
  for (char c : text) {
    auto p = std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").find(c);
    if (p == std::string::npos)
      throw std::runtime_error("动态令牌密钥无效");
    acc = (acc << 5) | static_cast<unsigned>(p);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out += static_cast<char>((acc >> bits) & 255);
    }
  }
  return out;
}
inline std::string totp(const std::string &secret, int64_t counter) {
  std::string input(8, '\0');
  for (int i = 7; i >= 0; --i) {
    input[i] = static_cast<char>(counter & 255);
    counter >>= 8;
  }
  auto hash = hmacSha1(unbase32(secret), input);
  int off = static_cast<unsigned char>(hash.back()) & 15;
  uint32_t n = 0;
  for (int i = 0; i < 4; ++i)
    n = (n << 8) | static_cast<unsigned char>(hash[off + i]);
  auto code = std::to_string((n & 0x7fffffff) % 1000000);
  return std::string(6 - code.size(), '0') + code;
}
inline bool checkTotp(Json &a, const std::string &code) {
  if (code.size() != 6 || val(a, "totp_secret").empty())
    return false;
  auto counter = now() / 30,
       last = a.get("last_step", ::Json::Int64(-1)).asInt64();
  for (int delta = -1; delta <= 1; ++delta) {
    auto step = counter + delta;
    if (step > last && zct_slms::crypto::constantTimeEqual(
                           totp(val(a, "totp_secret"), step), code)) {
      a["last_step"] = ::Json::Int64(step);
      return true;
    }
  }
  return false;
}
inline bool recovery(Json &a, const std::string &code) {
  if (code.empty())
    return false;
  auto hash = zct_slms::crypto::sha256Hex(code);
  auto &list = a["recovery"];
  for (::Json::ArrayIndex i = 0; i < list.size(); ++i)
    if (zct_slms::crypto::constantTimeEqual(list[i].asString(), hash)) {
      list.removeIndex(i, nullptr);
      return true;
    }
  return false;
}
inline Json recoveryCodes(Json &a) {
  Json result(::Json::arrayValue);
  a["recovery"] = Json(::Json::arrayValue);
  for (int i = 0; i < 8; ++i) {
    auto raw = zct_slms::crypto::randomHex(10);
    result.append(raw);
    a["recovery"].append(zct_slms::crypto::sha256Hex(raw));
  }
  return result;
}
inline auto auth(const Req &req, bool password = false) {
  auto a =
      zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
  if (!a.success)
    throw std::runtime_error("请先登录");
  if (password && common::paramStr(req, "password").starts_with("zct_slms-auth:")) {
    if (!common::sensitiveAuthorization(req, common::paramStr(req, "password")))
      throw std::runtime_error("授权已失效，请重新验证");
    return a;
  }
  if (password) {
    std::lock_guard lock(mutex);
    prune();
    rate("factor-password:" + a.user_type + std::to_string(a.user_id), 10, 60);
    std::string hash, salt;
    bool found = false;
    if (a.user_type == "ADMIN" || a.user_type == "SUPPORT") {
      auto u = zct_slms::repo::AdminRepo::findById(a.user_id);
      if (u) {
        hash = u->password_hash;
        salt = u->salt;
        found = true;
      }
    } else if (a.user_type == "USER") {
      auto u = zct_slms::repo::UserRepo::findById(a.user_id);
      if (u) {
        hash = u->password_hash;
        salt = u->salt;
        found = true;
      }
    } else {
      auto rows = zct_slms::db::Database::instance().queryParams(
          "SELECT password_hash,salt FROM sub_users WHERE id = ?", a.user_id);
      if (!rows.empty()) {
        hash = zct_slms::repo::getStr(rows[0], "password_hash");
        salt = zct_slms::repo::getStr(rows[0], "salt");
        found = true;
      }
    }
    if (!found || !zct_slms::service::verifyPassword(
                      common::paramStr(req, "password"), hash, salt))
      throw std::runtime_error("当前密码错误");
  }
  if (password &&
      !common::sensitiveAuthorization(req, common::paramStr(req, "password")))
    throw std::runtime_error("请完成统一授权验证");
  return a;
}
// Only the small, definite-length CBOR subset used by WebAuthn is accepted.
struct Cbor {
  const std::string &s;
  size_t p = 0;
  uint64_t head(int &major) {
    if (p >= s.size())
      throw std::runtime_error("无效 CBOR");
    unsigned b = static_cast<unsigned char>(s[p++]);
    major = b >> 5;
    unsigned v = b & 31;
    if (v < 24)
      return v;
    int n = v == 24 ? 1 : v == 25 ? 2 : v == 26 ? 4 : v == 27 ? 8 : 0;
    if (!n || p + n > s.size())
      throw std::runtime_error("无效 CBOR");
    uint64_t out = 0;
    for (int i = 0; i < n; ++i)
      out = (out << 8) | static_cast<unsigned char>(s[p++]);
    if (out > 131072)
      throw std::runtime_error("CBOR 过大");
    return out;
  }
  Json read(int depth = 0) {
    if (depth > 8)
      throw std::runtime_error("CBOR 过深");
    int major;
    auto n = head(major);
    if (major == 0)
      return Json(::Json::Int64(n));
    if (major == 1)
      return Json(::Json::Int64(-1 - static_cast<int64_t>(n)));
    if (major == 2 || major == 3) {
      if (p + n > s.size())
        throw std::runtime_error("无效 CBOR 长度");
      auto out = s.substr(p, n);
      p += n;
      return out;
    }
    if (major == 4) {
      if (n > 64)
        throw std::runtime_error("CBOR 数组过大");
      Json out(::Json::arrayValue);
      for (uint64_t i = 0; i < n; ++i)
        out.append(read(depth + 1));
      return out;
    }
    if (major == 5) {
      if (n > 32)
        throw std::runtime_error("CBOR 映射过大");
      Json out(::Json::objectValue);
      for (uint64_t i = 0; i < n; ++i) {
        auto k = read(depth + 1);
        auto key = k.isString() ? k.asString() : std::to_string(k.asInt64());
        if (out.isMember(key))
          throw std::runtime_error("重复 CBOR 键");
        out[key] = read(depth + 1);
      }
      return out;
    }
    if (major == 7 && (n == 20 || n == 21))
      return Json(n == 21);
    throw std::runtime_error("不支持的 CBOR 类型");
  }
};
inline std::string publicDer(const Json &cose) {
  if (cose.get("1", 0).asInt() != 2 || cose.get("3", 0).asInt() != -7 ||
      cose.get("-1", 0).asInt() != 1)
    throw std::runtime_error("仅支持 ES256 通行密钥");
  auto x = val(cose, "-2"), y = val(cose, "-3");
  if (x.size() != 32 || y.size() != 32)
    throw std::runtime_error("公钥格式无效");
  auto prefix = zct_slms::crypto::fromHex(
      "3059301306072a8648ce3d020106082a8648ce3d03010703420004");
  return prefix + x + y;
}
inline bool signature(const std::string &der, const std::string &data,
                      const std::string &sig) {
  const unsigned char *p = reinterpret_cast<const unsigned char *>(der.data());
  EVP_PKEY *key = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
  if (!key)
    return false;
  auto ctx = EVP_MD_CTX_new();
  bool valid =
      ctx &&
      EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
      EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(sig.data()),
                       sig.size(),
                       reinterpret_cast<const unsigned char *>(data.data()),
                       data.size()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return valid;
}
inline std::pair<std::string, std::string> origin() {
  auto origin = baseUrl(config());
  auto rp = origin.substr(origin.find("://") + 3);
  auto colon = rp.find(':');
  if (colon != std::string::npos)
    rp = rp.substr(0, colon);
  return {origin, rp};
}
inline uint32_t counter(const std::string &data) {
  if (data.size() < 37)
    throw std::runtime_error("认证数据过短");
  uint32_t out = 0;
  for (int i = 33; i < 37; ++i)
    out = (out << 8) | static_cast<unsigned char>(data[i]);
  return out;
}
inline void client(const Json &credential, const std::string &challenge,
                   const std::string &type, const std::string &expectedOrigin) {
  auto c = parse(
      decode64(credential["response"].get("clientDataJSON", "").asString()));
  if (c.get("type", "").asString() != type ||
      !zct_slms::crypto::constantTimeEqual(c.get("challenge", "").asString(),
                                      challenge) ||
      c.get("origin", "").asString() != expectedOrigin ||
      c.get("crossOrigin", false).asBool())
    throw std::runtime_error("通行密钥来源或挑战无效");
}
inline void authenticator(const std::string &data, const std::string &rp,
                          bool registration) {
  if (data.size() < 37 || !zct_slms::crypto::constantTimeEqual(
                              data.substr(0, 32), zct_slms::crypto::sha256(rp)))
    throw std::runtime_error("通行密钥 RP 无效");
  auto flags = static_cast<unsigned char>(data[32]);
  if ((flags & 5) != 5 || ((flags & 0x10) && !(flags & 8)))
    throw std::runtime_error("通行密钥必须完成用户验证");
  if (registration && !(flags & 64))
    throw std::runtime_error("通行密钥注册格式无效");
}
inline Json registerKey(const Json &credential, const std::string &challenge,
                        const std::string &expectedOrigin,
                        const std::string &rp) {
  client(credential, challenge, "webauthn.create", expectedOrigin);
  auto bytes =
      decode64(credential["response"].get("attestationObject", "").asString());
  Cbor c{bytes};
  auto att = c.read();
  if (c.p != bytes.size() || att.get("fmt", "").asString() != "none" ||
      !att["attStmt"].isObject() || !att["attStmt"].empty())
    throw std::runtime_error("仅接受 none attestation");
  auto data = val(att, "authData");
  authenticator(data, rp, true);
  if (data.size() < 55)
    throw std::runtime_error("通行密钥注册数据无效");
  unsigned n = (static_cast<unsigned char>(data[53]) << 8) |
               static_cast<unsigned char>(data[54]);
  if (n == 0 || n > 1024 || 55 + n >= data.size())
    throw std::runtime_error("凭据 ID 无效");
  auto id = b64url(data.substr(55, n));
  if (credential.get("id", "").asString() != id ||
      credential.get("type", "").asString() != "public-key")
    throw std::runtime_error("凭据 ID 不匹配");
  auto coseBytes = data.substr(55 + n);
  Cbor key{coseBytes};
  auto cose = key.read();
  if (static_cast<unsigned char>(data[32]) & 128) {
    auto extensions = key.read();
    if (!extensions.isObject())
      throw std::runtime_error("凭据扩展格式无效");
  }
  if (key.p != coseBytes.size())
    throw std::runtime_error("多余凭据数据");
  Json out;
  out["id"] = id;
  auto der = publicDer(cose);
  const unsigned char *point =
      reinterpret_cast<const unsigned char *>(der.data());
  auto pub = d2i_PUBKEY(nullptr, &point, static_cast<long>(der.size()));
  auto ctx = pub ? EVP_PKEY_CTX_new(pub, nullptr) : nullptr;
  const bool valid = ctx && EVP_PKEY_public_check(ctx) == 1;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pub);
  if (!valid)
    throw std::runtime_error("凭据公钥无效");
  out["public_key"] = b64url(der);
  out["sign_count"] = counter(data);
  out["created_at"] = ::Json::Int64(now());
  out["backup_eligible"] = (static_cast<unsigned char>(data[32]) & 8) != 0;
  return out;
}
inline void assertion(Json &a, const Json &credential,
                      const std::string &challenge,
                      const std::string &expectedOrigin,
                      const std::string &rp) {
  client(credential, challenge, "webauthn.get", expectedOrigin);
  auto id = credential.get("id", "").asString();
  for (auto &key : a["keys"]) {
    if (key["id"].asString() != id)
      continue;
    auto data = decode64(
        credential["response"].get("authenticatorData", "").asString());
    authenticator(data, rp, false);
    if (credential.get("type", "").asString() != "public-key" ||
        ((static_cast<unsigned char>(data[32]) & 8) != 0) !=
            key.get("backup_eligible", false).asBool())
      throw std::runtime_error("凭据属性不匹配");
    auto count = counter(data), last = key.get("sign_count", 0).asUInt();
    if ((count || last) && count <= last)
      throw std::runtime_error("通行密钥计数异常");
    auto clientData =
        decode64(credential["response"].get("clientDataJSON", "").asString());
    auto handle = credential["response"].get("userHandle", Json{});
    if (!handle.isNull() &&
        (!handle.isString() ||
         !zct_slms::crypto::constantTimeEqual(
             decode64(handle.asString()),
             zct_slms::crypto::sha256(a.get("account_handle", "").asString()))))
      throw std::runtime_error("通行密钥用户标识无效");
    if (!signature(
            decode64(val(key, "public_key")),
            data + zct_slms::crypto::sha256(clientData),
            decode64(credential["response"].get("signature", "").asString())))
      throw std::runtime_error("通行密钥签名无效");
    key["sign_count"] = count;
    return;
  }
  throw std::runtime_error("未找到已绑定的通行密钥");
}
struct Pending {
  Json session;
  std::string ip, ua, challenge, origin, rp, account, action;
  int64_t expires;
  int attempts = 0;
};
inline std::map<std::string, Pending> pending;
inline void clean() {
  for (auto it = pending.begin(); it != pending.end();)
    if (it->second.expires < now())
      it = pending.erase(it);
    else
      ++it;
  if (pending.size() > 10000)
    throw std::runtime_error("认证服务繁忙");
}
inline Json gate(Json session, const std::string &ip, const std::string &ua) {
  std::lock_guard lock(guard);
  auto key =
      accountKey(session["user_type"].asString(), session["user_id"].asInt64());
  auto a = load(key);
  if (!a.get("totp_enabled", false).asBool() &&
      !a.get("passkey_required", false).asBool())
    return session;
  zct_slms::repo::SessionRepo::revokeByHash(
      zct_slms::crypto::sha256Hex(session["token"].asString()));
  session.removeMember("token");
  session["_factor_version"] = a.get("version", 0);
  const auto table = (session["user_type"].asString() == "ADMIN" ||
                      session["user_type"].asString() == "SUPPORT")
                         ? "admins"
                     : session["user_type"].asString() == "USER" ? "users"
                                                                 : "sub_users";
  auto fingerprint = zct_slms::db::Database::instance().queryScalar(
      std::string("SELECT password_hash FROM ") + table + " WHERE id = ?",
      session["user_id"].asInt64());
  session["_password_fingerprint"] =
      fingerprint ? zct_slms::crypto::sha256Hex(*fingerprint) : "";
  clean();
  const auto id = zct_slms::crypto::randomHex(32),
             challenge = b64url(zct_slms::crypto::randomBytes(32));
  std::string url, rp;
  if (a.get("passkey_required", false).asBool()) {
    auto o = origin();
    url = o.first;
    rp = o.second;
  }
  pending[id] = {session, ip,  ua,      challenge,  url,
                 rp,      key, "login", now() + 180};
  Json out;
  out["mfa_required"] = true;
  out["challenge_id"] = id;
  out["totp_required"] = a.get("totp_enabled", false);
  out["passkey_required"] = a.get("passkey_required", false);
  out["public_key"]["challenge"] = challenge;
  out["public_key"]["rpId"] = rp;
  out["public_key"]["userVerification"] = "required";
  out["public_key"]["timeout"] = 120000;
  out["public_key"]["allowCredentials"] = Json(::Json::arrayValue);
  for (auto &key : a["keys"]) {
    Json k;
    k["id"] = key["id"];
    k["type"] = "public-key";
    out["public_key"]["allowCredentials"].append(k);
  }
  return out;
}
inline void finish(const Req &req, Callback &&cb) {
  try {
    std::lock_guard lock(guard);
    auto id = common::paramStr(req, "challenge_id");
    auto it = pending.find(id);
    if (it == pending.end() || it->second.expires < now() ||
        it->second.action != "login")
      throw std::runtime_error("验证已过期，请重新登录");
    auto &p = it->second;
    if (p.ip != common::clientIp(req) || p.ua != common::clientUa(req))
      throw std::runtime_error("登录环境已改变");
    if (++p.attempts > 5) {
      pending.erase(it);
      throw std::runtime_error("验证次数过多，请重新登录");
    }
    auto a = load(p.account);
    if (a.get("version", 0) != p.session.get("_factor_version", 0)) {
      pending.erase(it);
      throw std::runtime_error("账号安全设置已变更，请重新登录");
    }
    const auto table = (p.session["user_type"].asString() == "ADMIN" ||
                        p.session["user_type"].asString() == "SUPPORT")
                           ? "admins"
                       : p.session["user_type"].asString() == "USER"
                           ? "users"
                           : "sub_users";
    auto fingerprint = zct_slms::db::Database::instance().queryScalar(
        std::string("SELECT password_hash FROM ") + table + " WHERE id = ?",
        p.session["user_id"].asInt64());
    if (!fingerprint || !zct_slms::crypto::constantTimeEqual(
                            zct_slms::crypto::sha256Hex(*fingerprint),
                            p.session["_password_fingerprint"].asString())) {
      pending.erase(it);
      throw std::runtime_error("账号密码已变更，请重新登录");
    }
    auto body = req->getJsonObject();
    if (!body)
      throw std::runtime_error("验证数据无效");
    bool recovered = recovery(a, common::paramStr(req, "recovery_code"));
    if (!recovered) {
      if (a.get("totp_enabled", false).asBool() &&
          !checkTotp(a, common::paramStr(req, "code")))
        throw std::runtime_error("动态验证码错误或已使用");
      if (a.get("passkey_required", false).asBool())
        assertion(a, (*body)["credential"], p.challenge, p.origin, p.rp);
    }
    auto session = p.session;
    auto role = session["user_type"].asString();
    auto uid = session["user_id"].asInt64();
    bool valid = false;
    if (role == "ADMIN" || role == "SUPPORT") {
      auto u = zct_slms::repo::AdminRepo::findById(uid);
      valid = u && u->status == 1;
    } else if (role == "USER") {
      auto u = zct_slms::repo::UserRepo::findById(uid);
      valid = u && u->status == 1 &&
              (u->expires_at == -1 || u->expires_at >= now());
    } else {
      auto rows = zct_slms::db::Database::instance().queryParams(
          "SELECT status,expires_at FROM sub_users WHERE id = ?", uid);
      valid = !rows.empty() && zct_slms::repo::getInt(rows[0], "status") == 1 &&
              (zct_slms::repo::getInt(rows[0], "expires_at") == -1 ||
               zct_slms::repo::getInt(rows[0], "expires_at") >= now());
    }
    if (!valid) {
      pending.erase(it);
      throw std::runtime_error("账号不可用");
    }
    store(p.account, a);
    auto token = zct_slms::crypto::randomHex(32);
    zct_slms::repo::SessionRepo::insert(
        role, uid, zct_slms::crypto::sha256Hex(token),
        now() + zct_slms::AppConfig::instance().security().session_ttl_seconds,
        now(), p.ip, p.ua);
    session["token"] = token;
    session.removeMember("_factor_version");
    session.removeMember("_password_fingerprint");
    pending.erase(it);
    ok(cb, session);
  } catch (const std::exception &e) {
    fail(cb, e.what());
  }
}
inline void removeKey(Json &a, const std::string &id) {
  auto &keys = a["keys"];
  for (::Json::ArrayIndex i = 0; i < keys.size(); ++i) {
    if (keys[i]["id"].asString() == id) {
      keys.removeIndex(i, nullptr);
      if (keys.empty())
        a["passkey_required"] = false;
      return;
    }
  }
  throw std::runtime_error("通行密钥不存在");
}
inline void account(const Req &req, Callback &&callback) {
  background(req, std::move(callback), [](auto req, const Callback &cb) {
    try {
      auto action = common::paramStr(req, "action");
      auto user = auth(req, req->method() == drogon::Post);
      std::lock_guard lock(guard);
      const auto key = accountKey(user.user_type, user.user_id);
      auto a = load(key), s = settings();
      a["account_handle"] = key;
      Json out;
      if (req->method() == drogon::Post) {
        if (action == "totp-start") {
          if (!s.get("totp_enabled", false).asBool())
            throw std::runtime_error("平台尚未开放动态令牌");
          if (a.get("totp_enabled", false).asBool())
            throw std::runtime_error("请先解除现有动态令牌");
          const auto secret = base32(zct_slms::crypto::randomBytes(20));
          a["pending_totp"] = secret;
          a["pending_expires"] = ::Json::Int64(now() + 300);
          out["secret"] = secret;
          out["uri"] = "otpauth://totp/ZCT-SLMS:" +
                       escape(user.user_type + "-" + user.username) +
                       "?secret=" + secret +
                       "&issuer=ZCT-SLMS&algorithm=SHA1&digits=6&period=30";
        } else if (action == "totp-confirm") {
          if (a.get("pending_expires", 0).asInt64() < now() ||
              val(a, "pending_totp").empty())
            throw std::runtime_error("绑定已过期");
          Json candidate;
          candidate["totp_secret"] = a["pending_totp"];
          if (!checkTotp(candidate, common::paramStr(req, "code")))
            throw std::runtime_error("动态验证码无效");
          a["totp_secret"] = a["pending_totp"];
          a["last_step"] = candidate["last_step"];
          a["totp_enabled"] = true;
          a.removeMember("pending_totp");
          a.removeMember("pending_expires");
          out["recovery_codes"] = recoveryCodes(a);
        } else if (action == "totp-disable") {
          if (!checkTotp(a, common::paramStr(req, "code")) &&
              !recovery(a, common::paramStr(req, "recovery_code")))
            throw std::runtime_error("请输入动态验证码或恢复码");
          a["totp_enabled"] = false;
          a.removeMember("totp_secret");
        } else if (action == "passkey-start") {
          if (!s.get("passkey_enabled", false).asBool())
            throw std::runtime_error("平台尚未开放通行密钥");
          if (a["keys"].size() >= 5)
            throw std::runtime_error("最多绑定 5 个通行密钥");
          auto o = origin();
          clean();
          auto id = zct_slms::crypto::randomHex(32),
               challenge = b64url(zct_slms::crypto::randomBytes(32));
          pending[id] = {Json{},
                         common::clientIp(req),
                         common::clientUa(req),
                         challenge,
                         o.first,
                         o.second,
                         key,
                         "register",
                         now() + 180};
          out["challenge_id"] = id;
          auto &pk = out["public_key"];
          pk["challenge"] = challenge;
          pk["rp"]["id"] = o.second;
          pk["rp"]["name"] = "ZCT-SLMS";
          pk["user"]["id"] = b64url(zct_slms::crypto::sha256(key));
          pk["user"]["name"] = user.user_type + "-" + user.username;
          pk["user"]["displayName"] = pk["user"]["name"];
          Json alg;
          alg["type"] = "public-key";
          alg["alg"] = -7;
          pk["pubKeyCredParams"].append(alg);
          pk["authenticatorSelection"]["residentKey"] = "preferred";
          pk["authenticatorSelection"]["userVerification"] = "required";
          pk["attestation"] = "none";
          pk["timeout"] = 120000;
          pk["excludeCredentials"] = Json(::Json::arrayValue);
          for (auto &k : a["keys"]) {
            Json item;
            item["type"] = "public-key";
            item["id"] = k["id"];
            pk["excludeCredentials"].append(item);
          }
        } else if (action == "passkey-confirm") {
          auto it = pending.find(common::paramStr(req, "challenge_id"));
          if (it == pending.end() || it->second.action != "register" ||
              it->second.account != key || it->second.expires < now() ||
              it->second.ip != common::clientIp(req))
            throw std::runtime_error("注册挑战无效");
          auto p = it->second;
          pending.erase(it);
          auto body = req->getJsonObject();
          if (!body)
            throw std::runtime_error("注册数据无效");
          auto credential =
              registerKey((*body)["credential"], p.challenge, p.origin, p.rp);
          auto name = common::paramStr(req, "name", "我的通行密钥");
          if (name.size() > 96)
            throw std::runtime_error("名称过长");
          credential["name"] = name;
          for (auto &k : a["keys"])
            if (k["id"] == credential["id"])
              throw std::runtime_error("此通行密钥已绑定");
          a["keys"].append(credential);
          if (a["recovery"].empty())
            out["recovery_codes"] = recoveryCodes(a);
        } else if (action == "passkey-require") {
          auto enable = common::paramStr(req, "enabled") == "1";
          if (enable) {
            if (a["keys"].empty() || !s.get("passkey_enabled", false).asBool())
              throw std::runtime_error("请先绑定通行密钥");
          } else if (a.get("passkey_required", false).asBool() &&
                     !recovery(a, common::paramStr(req, "recovery_code")))
            throw std::runtime_error("关闭通行密钥验证需要恢复码");
          a["passkey_required"] = enable;
        } else if (action == "passkey-remove-start") {
          auto id = common::paramStr(req, "id");
          bool found = false;
          for (const auto &item : a["keys"])
            if (item["id"].asString() == id)
              found = true;
          if (!found)
            throw std::runtime_error("通行密钥不存在");
          auto o = origin();
          clean();
          auto challengeId = zct_slms::crypto::randomHex(32);
          auto challenge = b64url(zct_slms::crypto::randomBytes(32));
          Json proof;
          proof["key_id"] = id;
          proof["version"] = a.get("version", 0);
          proof["session_hash"] =
              zct_slms::crypto::sha256Hex(common::authBearer(req));
          pending[challengeId] = {proof,
                                  common::clientIp(req),
                                  common::clientUa(req),
                                  challenge,
                                  o.first,
                                  o.second,
                                  key,
                                  "remove",
                                  now() + 180};
          out["challenge_id"] = challengeId;
          auto &pk = out["public_key"];
          pk["challenge"] = challenge;
          pk["rpId"] = o.second;
          pk["userVerification"] = "required";
          pk["timeout"] = 120000;
          pk["allowCredentials"] = Json(::Json::arrayValue);
          for (const auto &item : a["keys"]) {
            Json credential;
            credential["type"] = "public-key";
            credential["id"] = item["id"];
            pk["allowCredentials"].append(credential);
          }
        } else if (action == "passkey-remove") {
          auto id = common::paramStr(req, "id");
          auto method = common::paramStr(req, "method", "recovery");
          // Validate the target before consuming a one-time recovery code.
          bool found = false;
          for (const auto &item : a["keys"])
            if (item["id"].asString() == id)
              found = true;
          if (!found)
            throw std::runtime_error("通行密钥不存在");
          if (method == "passkey") {
            auto it = pending.find(common::paramStr(req, "challenge_id"));
            if (it == pending.end() || it->second.action != "remove" ||
                it->second.account != key || it->second.expires < now() ||
                it->second.ip != common::clientIp(req) ||
                it->second.ua != common::clientUa(req) ||
                it->second.session["key_id"].asString() != id ||
                it->second.session["version"] != a.get("version", 0) ||
                it->second.session["session_hash"].asString() !=
                    zct_slms::crypto::sha256Hex(common::authBearer(req)))
              throw std::runtime_error("删除验证已失效，请重新开始");
            auto proof = it->second;
            pending.erase(it);
            auto body = req->getJsonObject();
            if (!body)
              throw std::runtime_error("通行密钥验证数据无效");
            assertion(a, (*body)["credential"], proof.challenge, proof.origin,
                      proof.rp);
          } else if (method == "recovery") {
            if (!recovery(a, common::paramStr(req, "recovery_code")))
              throw std::runtime_error("恢复码无效或已使用");
          } else
            throw std::runtime_error("删除验证方式无效");
          removeKey(a, id);
        } else if (action == "recovery-regenerate") {
          if (!a.get("recovery_reset_pending",false).asBool() && !checkTotp(a, common::paramStr(req, "code")) &&
              !recovery(a, common::paramStr(req, "recovery_code")))
            throw std::runtime_error("请输入动态验证码或恢复码");
          out["recovery_codes"] = recoveryCodes(a);
          a.removeMember("recovery_reset_pending");
        } else
          throw std::runtime_error("未知操作");
        if (action != "totp-start" && action != "passkey-start" &&
            action != "passkey-remove-start")
          a["version"] = a.get("version", 0).asInt() + 1;
        store(key, a);
        zct_slms::repo::AuditRepo::log(
            user.user_type, user.user_id, "UpdateAccountFactors", "ACCOUNT",
            user.user_id, "", "success", common::clientIp(req), "{}", now());
      }
      out["totp_enabled"] = a.get("totp_enabled", false);
      out["passkey_required"] = a.get("passkey_required", false);
      out["totp_available"] = s.get("totp_enabled", false);
      out["passkey_available"] = s.get("passkey_enabled", false);
      out["recovery_reset_pending"] = a.get("recovery_reset_pending",false);
      out["recovery_remaining"] = a["recovery"].size();
      out["keys"] = Json(::Json::arrayValue);
      for (auto &k : a["keys"]) {
        Json item;
        item["id"] = k["id"];
        item["name"] = k["name"];
        item["created_at"] = k["created_at"];
        out["keys"].append(item);
      }
      ok(cb, out);
    } catch (const std::exception &e) {
      fail(cb, e.what());
    }
  });
}
} // namespace zct_slms::factors
