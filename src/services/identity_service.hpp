#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "api/v1/uih.h"
#include <atomic>
#include <set>
#include <curl/curl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <regex>
#include <trantor/utils/ConcurrentTaskQueue.h>

namespace zct_slms::identity {
using Json = ::Json::Value;
inline std::string json(const Json &value) {
  ::Json::StreamWriterBuilder w;
  w["indentation"] = "";
  return ::Json::writeString(w, value);
}
inline Json parse(const std::string &value) {
  ::Json::CharReaderBuilder b;
  Json out;
  std::string error;
  std::istringstream in(value);
  if (!::Json::parseFromStream(b, in, &out, &error))
    throw std::runtime_error("服务返回了无效数据");
  return out;
}
inline std::mutex mutex;
inline int64_t now() { return std::time(nullptr); }
inline std::string b64url(std::string_view s) {
  auto out = zct_slms::crypto::base64Encode(s);
  std::replace(out.begin(), out.end(), '+', '-');
  std::replace(out.begin(), out.end(), '/', '_');
  while (!out.empty() && out.back() == '=')
    out.pop_back();
  return out;
}
inline std::string escape(std::string_view value) {
  std::string out;
  const char *hex = "0123456789ABCDEF";
  for (unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
      out += c;
    else {
      out += '%';
      out += hex[c >> 4];
      out += hex[c & 15];
    }
  }
  return out;
}
inline std::string form(const std::map<std::string, std::string> &values) {
  std::string out;
  for (const auto &[k, v] : values) {
    if (!out.empty())
      out += '&';
    out += escape(k) + "=" + escape(v);
  }
  return out;
}
inline const std::vector<std::string> secrets = {
    "smtp_password", "aliyun_secret", "twilio_token", "github_secret",
    "microsoft_secret"};
inline std::string masterKey() {
  static const std::string key = []() {
    const auto env = std::getenv("ZCT_SLMS_CORE_AUTH_MASTER_KEY");
    if (env && *env) {
      auto raw = zct_slms::crypto::fromHex(env);
      if (raw.size() != 32)
        throw std::runtime_error(
            "ZCT_SLMS_CORE_AUTH_MASTER_KEY 必须为 64 位十六进制字符");
      return raw;
    }
    const std::filesystem::path file = "data/auth-master.key";
    std::filesystem::create_directories(file.parent_path());
    std::ifstream in(file, std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(in)), {});
    if (!raw.empty()) {
      if (raw.size() != 32)
        throw std::runtime_error("认证配置主密钥无效");
      return raw;
    }
    raw = zct_slms::crypto::randomBytes(32);
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out.write(raw.data(), raw.size());
    out.close();
    if (!out)
      throw std::runtime_error("无法保存认证配置主密钥");
    std::error_code ec;
    std::filesystem::permissions(file,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return raw;
  }();
  return key;
}
inline Json config() {
  auto raw = zct_slms::repo::ConfigRepo::get("identity_config", "");
  if (raw.empty()) {
    Json v;
    v["registration_enabled"] = true;
    v["sms_provider"] = "aliyun";
    v["smtp_port"] = 465;
    v["smtp_tls"] = "implicit";
    v["microsoft_tenant"] = "common";
    return v;
  }
  auto value = zct_slms::crypto::aes256GcmDecrypt(zct_slms::crypto::base64Decode(raw),
                                             masterKey());
  if (!value)
    throw std::runtime_error("认证配置无法解密，请检查主密钥");
  return parse(*value);
}
inline bool enabled(const Json &cfg, const std::string &method) {
  return cfg.get(method + "_enabled", false).asBool();
}
inline std::string val(const Json &cfg, const char *key) {
  return cfg.get(key, "").asString();
}
inline bool ready(const Json &c, const std::string &method) {
  if (!enabled(c, method))
    return false;
  if (method == "email")
    return !val(c, "smtp_host").empty() && !val(c, "smtp_from").empty() &&
           !val(c, "smtp_username").empty() &&
           !val(c, "smtp_password").empty();
  if (method == "phone")
    return val(c, "sms_provider") == "aliyun"
               ? !val(c, "aliyun_key").empty() &&
                     !val(c, "aliyun_secret").empty() &&
                     !val(c, "aliyun_sign").empty() &&
                     !val(c, "aliyun_template").empty()
               : !val(c, "twilio_sid").empty() &&
                     !val(c, "twilio_token").empty() &&
                     !val(c, "twilio_from").empty();
  return !c.get(method + "_client", "").asString().empty() &&
         !c.get(method + "_secret", "").asString().empty() &&
         !val(c, "public_url").empty();
}
inline void saveConfig(Json value) {
  auto blob = zct_slms::crypto::aes256GcmEncrypt(json(value), masterKey());
  if (blob.empty())
    throw std::runtime_error("保存配置失败");
  zct_slms::repo::ConfigRepo::set("identity_config", zct_slms::crypto::base64Encode(blob),
                             now());
}
inline size_t writeData(char *data, size_t size, size_t count, void *pointer) {
  auto &out = *static_cast<std::string *>(pointer);
  if (out.size() + size * count > 1048576)
    return 0;
  out.append(data, size * count);
  return size * count;
}
inline void curlInit() {
  static const auto initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (initialized != CURLE_OK)
    throw std::runtime_error("网络组件初始化失败");
}
struct Curl {
  CURL *h;
  curl_slist *headers = nullptr;
  Curl() {
    curlInit();
    h = curl_easy_init();
    if (!h)
      throw std::runtime_error("网络组件不可用");
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "ZCT-SLMS/1.0");
    curl_easy_setopt(h, CURLOPT_SSL_OPTIONS,
                     static_cast<long>(CURLSSLOPT_NATIVE_CA));
    if (const auto ca = std::getenv("ZCT_SLMS_CORE_AUTH_CA_BUNDLE"); ca && *ca)
      curl_easy_setopt(h, CURLOPT_CAINFO, ca);
  }
  ~Curl() {
    curl_slist_free_all(headers);
    curl_easy_cleanup(h);
  }
  void header(const std::string &s) {
    headers = curl_slist_append(headers, s.c_str());
  }
};
inline Json http(const std::string &url, const std::string &body = "",
                 const std::vector<std::string> &headers = {},
                 const std::string &basic = "") {
  Curl c;
  std::string response;
  curl_easy_setopt(c.h, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c.h, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(c.h, CURLOPT_WRITEFUNCTION, writeData);
  curl_easy_setopt(c.h, CURLOPT_WRITEDATA, &response);
  for (auto &h : headers)
    c.header(h);
  curl_easy_setopt(c.h, CURLOPT_HTTPHEADER, c.headers);
  if (!basic.empty()) {
    curl_easy_setopt(c.h, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(c.h, CURLOPT_USERPWD, basic.c_str());
  }
  if (!body.empty()) {
    curl_easy_setopt(c.h, CURLOPT_POST, 1L);
    curl_easy_setopt(c.h, CURLOPT_POSTFIELDS, body.c_str());
  }
  auto result = curl_easy_perform(c.h);
  long status = 0;
  curl_easy_getinfo(c.h, CURLINFO_RESPONSE_CODE, &status);
  if (result != CURLE_OK || status < 200 || status >= 300)
    throw std::runtime_error("外部服务请求失败，请检查平台配置与网络");
  return parse(response);
}
struct Payload {
  std::string text;
  size_t offset = 0;
};
inline size_t readMail(char *buffer, size_t size, size_t count, void *pointer) {
  auto &p = *static_cast<Payload *>(pointer);
  auto n = std::min(size * count, p.text.size() - p.offset);
  std::memcpy(buffer, p.text.data() + p.offset, n);
  p.offset += n;
  return n;
}
inline bool validMail(const std::string &target) {
  return target.size() <= 254 &&
         std::regex_match(
             target,
             std::regex("[A-Za-z0-9.!#$%&'*+/"
                        "=?^_`{|}~-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+"));
}
inline std::string normalize(std::string method, std::string target) {
  if (method == "email") {
    std::transform(target.begin(), target.end(), target.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (!validMail(target))
      throw std::runtime_error("邮箱格式无效");
  } else if (method == "phone") {
    if (std::regex_match(target, std::regex("1[3-9][0-9]{9}")))
      target = "+86" + target;
    if (!std::regex_match(target, std::regex("\\+[1-9][0-9]{7,14}")))
      throw std::runtime_error("请输入带国际区号的手机号，例如 +8613800000000");
  } else
    throw std::runtime_error("不支持的验证方式");
  return target;
}

inline Json defaultMailTemplates() {
  Json out;
  const std::vector<std::pair<std::string,std::string>> types = {
    {"register","注册账号"},{"login","登录账号"},{"bind","绑定身份"},
    {"security","安全验证"},{"recovery","恢复账号"},{"ticket_verify","验证工单提醒邮箱"},
    {"general","验证身份"}};
  auto card=[](const std::string &title,const std::string &content){return
    "<!doctype html><html lang=\"zh-CN\"><body style=\"margin:0;padding:32px 12px;background:#f5f6fb;font-family:Arial,Microsoft YaHei,sans-serif;color:#28304a\"><div style=\"max-width:560px;margin:auto;background:#fff;border:1px solid #e9eaf2;border-radius:20px;padding:32px\"><div style=\"font-size:13px;letter-spacing:2px;color:#8170df;font-weight:bold\">ZCT-SLMS</div><h1 style=\"font-size:24px;margin:24px 0 18px\">"+title+"</h1>"+content+"<p style=\"text-align:center;margin:26px 0 0\"><a href=\"{siteurl}\" style=\"display:inline-block;padding:13px 28px;border-radius:12px;background:#7968df;color:#fff;text-decoration:none;font-size:14px;font-weight:bold\">前往平台</a></p><div style=\"border-top:1px solid #edf0f6;margin-top:28px;padding-top:18px;font-size:12px;color:#969bad;line-height:1.8\">此邮件由 ZCT-SLMS 自动发送，请勿直接回复。<br>© ZCT-SLMS</div></div></body></html>";};
  for(const auto &[key,label]:types) {
    out[key]["subject"]="ZCT-SLMS · "+label+"验证码";out[key]["format"]="html";
    auto greeting=key=="login"?"您好，{username}：":"您好：";
    out[key]["body"]=card(label,"<p style=\"line-height:1.8\">"+std::string(greeting)+"<br>您正在"+label+"，请使用以下验证码完成验证。</p><div style=\"background:#f2efff;border:1px solid #e2dcff;border-radius:14px;padding:22px;text-align:center;margin:24px 0\"><div style=\"font-size:12px;color:#8172bb;margin-bottom:10px\">验证码</div><strong style=\"font-size:34px;letter-spacing:8px;color:#7160ce\">{code}</strong></div><p style=\"font-size:13px;line-height:1.9;color:#7b8297\">验证码 5 分钟内有效。请勿将验证码提供给他人。<br>如非本人操作，请忽略此邮件。</p>");
  }
  out["temporary_password"]["subject"]="ZCT-SLMS · 账号密码已重置";out["temporary_password"]["format"]="html";
  out["temporary_password"]["body"]=card("请设置新的密码","<p>您好，{username}：</p><p>账号密码重置申请已通过审核，您的临时密码为：</p><pre style=\"padding:18px;background:#f2efff;border-radius:12px;text-align:center;font-size:20px;white-space:pre-wrap\">{code}</pre><p>请登录后立即设置新密码。临时密码仅发送给您，请勿转发。</p>");
  out["ticket_update"]["subject"]="ZCT-SLMS · 工单进度更新";out["ticket_update"]["format"]="html";
  out["ticket_update"]["body"]=card("工单有新的进展","<p>您好，{nickname}：</p><p style=\"color:#81889a;font-size:13px\">工单 {ticketid} · {status}</p><h2 style=\"font-size:16px\">最新消息</h2><div style=\"background:#f2efff;padding:18px;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.8\">{new_chat}</div><h2 style=\"font-size:16px;margin-top:26px\">完整对话</h2><div style=\"background:#f8f9fc;padding:18px;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.8\">{full_chat}</div><p style=\"font-size:13px;color:#9298a9\">请登录平台继续回复或查看工单详情。</p>");
  auto ticketBody=out["ticket_update"]["body"].asString();
  auto link=ticketBody.find("{siteurl}");if(link!=std::string::npos)ticketBody.replace(link,9,"{ticketurl}");
  auto label=ticketBody.find("前往平台");if(label!=std::string::npos)ticketBody.replace(label,std::string("前往平台").size(),"查看并回复工单");out["ticket_update"]["body"]=ticketBody;
  return out;
}
inline void validateMailText(const std::string &text) {
  static const std::set<std::string> keys = {"code","username","nickname","userid","email","ticketid","status","full_chat","new_chat","siteurl","ticketurl"};
  for (size_t i = 0; i < text.size();) {
    if (text[i] == '}') throw std::runtime_error("邮件模板占位符格式无效");
    if (text[i] != '{') { ++i; continue; }
    auto end = text.find('}', i + 1);
    if (end == std::string::npos || !keys.contains(text.substr(i + 1, end-i-1)))
      throw std::runtime_error("邮件模板含不支持的占位符");
    i = end + 1;
  }
}
inline Json mailTemplates() {
  auto out = defaultMailTemplates();
  auto saved = config()["mail_templates"];
  if (saved.isObject()) for (const auto &key : out.getMemberNames())
    if (saved[key].isObject()) out[key] = saved[key];
  return out;
}
inline Json mailAccount(const std::string &role, int64_t uid, const std::string &email = "") {
  Json values;
  values["email"] = email; values["username"] = ""; values["nickname"] = "用户"; values["userid"] = "";
  auto table = role == "USER" ? "users" : role == "SUBUSER" ? "sub_users" : (role == "ADMIN" || role == "SUPPORT") ? "admins" : "";
  if (uid > 0 && std::string(table).size()) {
    auto rows = zct_slms::db::Database::instance().queryParams(std::string("SELECT username,display_name FROM ") + table + " WHERE id = ?", uid);
    if (!rows.empty()) {
      values["userid"] = std::to_string(uid);
      values["username"] = zct_slms::repo::getStr(rows[0], "username");
      values["nickname"] = zct_slms::repo::ConfigRepo::get("profile:" + role + ":" + std::to_string(uid) + ":nickname", zct_slms::repo::getStr(rows[0], "display_name").empty() ? values["username"].asString() : zct_slms::repo::getStr(rows[0], "display_name"));
    }
  }
  return values;
}
inline std::string renderMailText(const std::string &text, const Json &values) {
  std::string out;
  for (size_t i=0;i<text.size();) {
    if(text[i]!='{') {out+=text[i++];continue;}
    auto end=text.find('}',i+1);
    if(end==std::string::npos) throw std::runtime_error("邮件模板无效");
    auto key=text.substr(i+1,end-i-1);
    out+=values.get(key, "").asString(); i=end+1;
  }
  return out;
}

inline std::string escapeMailHtml(const std::string &value) {
  std::string out;for(char ch:value) switch(ch){case '&':out+="&amp;";break;case '<':out+="&lt;";break;case '>':out+="&gt;";break;case '"':out+="&quot;";break;case '\'':out+="&#39;";break;default:out+=ch;}
  return out;
}
inline Json renderMail(const std::string &kind, Json values) {
  auto site=config().get("public_url","").asString();
  if(!site.starts_with("https://") && !site.starts_with("http://"))site.clear();
  while(!site.empty() && site.back()=='/')site.pop_back();
  values["siteurl"]=site.empty()?"":site+"/";
  auto ticket=values.get("ticketid","").asString();
  values["ticketurl"]=site.empty()?"":site+"/tickets"+(ticket.empty()?"":"?ticket="+ticket);
  auto templates = mailTemplates();
  if (!templates.isMember(kind)) throw std::runtime_error("邮件模板类型无效");
  auto chatCards=values["_chat_messages"];auto chatTruncated=values.get("_chat_truncated",false).asBool();values.removeMember("_chat_messages");values.removeMember("_chat_truncated");
  Json out;
  out["subject"] = renderMailText(templates[kind]["subject"].asString(), values);
  out["format"]=templates[kind].get("format","plain");
  if(out["format"].asString()=="html")for(const auto &key:values.getMemberNames()) {
    auto escaped=escapeMailHtml(values[key].asString());
    if(key=="new_chat" || key=="full_chat") {
      std::string lines;
      for(char ch:escaped) { if(ch=='\n') lines+="<br>"; else if(ch!='\r') lines+=ch; }
      escaped=std::move(lines);
    }
    values[key]=escaped;
  }
  if(kind=="ticket_update" && out["format"].asString()=="html" && chatCards.isArray()) {
    std::string cards;
    if(chatTruncated)cards="<p>对话过长，邮件仅展示最近部分，请登录查看完整记录。</p>";
    for(auto index=chatCards.size();index>0;--index) {
      const auto &card=chatCards[index-1];auto body=escapeMailHtml(card.get("body","").asString());std::string lines;
      for(char ch:body){if(ch=='\n')lines+="<br>";else if(ch!='\r')lines+=ch;}
      cards+="<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin-bottom:12px;border:1px solid #e5e7ef;border-radius:12px;background:#ffffff\"><tr><td style=\"padding:16px;overflow-wrap:anywhere;word-break:break-word\"><div style=\"font-weight:700;color:#30364a;font-size:14px\">"+escapeMailHtml(card.get("sender","").asString())+"</div><div style=\"color:#9298a9;font-size:12px;margin-top:4px;margin-bottom:12px\">"+escapeMailHtml(card.get("time","").asString())+"</div><div style=\"color:#50586c;line-height:1.8;font-size:14px\">"+lines+"</div></td></tr></table>";
    }
    values["full_chat"]=cards;
  }
  out["body"] = renderMailText(templates[kind]["body"].asString(), values);
  if(site.empty() && out["format"].asString()=="html")out["body"]=std::regex_replace(out["body"].asString(),std::regex("<a[^>]*href=\"\"[^>]*>[^<]*</a>"),"");
  return out;
}


inline std::string mimeSubject(const std::string &value) {
  std::string out;
  for(size_t start=0;start<value.size();) {
    auto end=std::min(start+size_t(42),value.size());
    while(end<value.size() && end>start && (static_cast<unsigned char>(value[end])&0xc0)==0x80)--end;
    if(end==start)throw std::runtime_error("邮件主题编码无效");
    if(!out.empty())out+="\r\n ";
    out+="=?UTF-8?B?"+zct_slms::crypto::base64Encode(value.substr(start,end-start))+"?=";start=end;
  }
  return out;
}

inline std::string smtpAuthMechanism(const Json &c) {
  const auto mode = c.get("smtp_auth", "auto").asString();
  if (mode != "auto" && mode != "login" && mode != "plain")
    throw std::runtime_error("SMTP 认证方式无效");
  auto host = val(c, "smtp_host");
  std::transform(host.begin(), host.end(), host.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  if (mode == "login" || (mode == "auto" && host == "smtp.qq.com"))
    return "LOGIN";
  return mode == "plain" ? "PLAIN" : "AUTO";
}
inline void deliverEmail(const Json &c, const std::string &target,
                         const std::string &code, bool temporary = false,
                         const std::string &subjectOverride = "",
                         const std::string &bodyOverride = "",
                         const std::string &purpose = "general", Json values = Json{}, const std::string &formatOverride = "") {
  const auto host = val(c, "smtp_host"), from = val(c, "smtp_from");
  if (!std::regex_match(host, std::regex("[A-Za-z0-9.-]+")) ||
      !validMail(from) || !validMail(target) ||
      subjectOverride.find_first_of("\r\n") != std::string::npos)
    throw std::runtime_error("SMTP 配置无效");
  auto port = c.get("smtp_port", 465).asInt();
  if (port < 1 || port > 65535)
    throw std::runtime_error("SMTP 端口无效");
  Curl curl;
  const auto url = (val(c, "smtp_tls") == "starttls" ? "smtp://" : "smtps://") +
                   host + ":" + std::to_string(port);
  curl_easy_setopt(curl.h, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl.h, CURLOPT_PROTOCOLS_STR, "smtp,smtps");
  curl_easy_setopt(curl.h, CURLOPT_USE_SSL, static_cast<long>(CURLUSESSL_ALL));
  const auto username = val(c, "smtp_username"),
             password = val(c, "smtp_password");
  if (username.empty() || password.empty())
    throw std::runtime_error("SMTP 用户名和密码或授权码不能为空");
  curl_easy_setopt(curl.h, CURLOPT_USERNAME, username.c_str());
  curl_easy_setopt(curl.h, CURLOPT_PASSWORD, password.c_str());
  const auto mechanism = smtpAuthMechanism(c);
  if (mechanism != "AUTO") {
    const auto options = "AUTH=" + mechanism;
    if (curl_easy_setopt(curl.h, CURLOPT_LOGIN_OPTIONS, options.c_str()) != CURLE_OK)
      throw std::runtime_error("当前网络组件不支持指定 SMTP 认证方式");
  }
  curl_easy_setopt(curl.h, CURLOPT_SASL_IR, 0L);

  const auto envelope = "<" + from + ">", recipient = "<" + target + ">";
  curl_easy_setopt(curl.h, CURLOPT_MAIL_FROM, envelope.c_str());
  curl.header(recipient);
  curl_easy_setopt(curl.h, CURLOPT_MAIL_RCPT, curl.headers);
  values["email"] = target; values["code"] = code;
  if (!values.isMember("nickname") || values["nickname"].asString().empty()) values["nickname"] = "用户";
  const auto rendered = renderMail(temporary ? "temporary_password" : purpose, values);
  const auto subject = subjectOverride.empty() ? rendered["subject"].asString() : subjectOverride;
  const auto body = bodyOverride.empty() ? rendered["body"].asString() : bodyOverride;
  if (subject.find_first_of("\r\n") != std::string::npos || subject.size() > 4096)
    throw std::runtime_error("邮件主题格式无效");
  const auto format = bodyOverride.empty() ? rendered.get("format","plain").asString() : formatOverride;
  std::string safeBody;
  for (char ch : body) { if (ch == '\n') safeBody += "\r\n"; else if (ch != '\r') safeBody += ch; }
  const auto encodedBody=zct_slms::crypto::base64Encode(safeBody);
  std::string wireBody;for(size_t i=0;i<encodedBody.size();i+=76)wireBody+=encodedBody.substr(i,76)+"\r\n";
  Payload payload{"From: " + from + "\r\nTo: " + target +
                  "\r\nSubject: " + mimeSubject(subject) +
                  "\r\nMIME-Version: 1.0\r\nContent-Type: " + std::string(format=="html"?"text/html":"text/plain") + "; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wireBody + "\r\n"};
  curl_easy_setopt(curl.h, CURLOPT_READFUNCTION, readMail);
  curl_easy_setopt(curl.h, CURLOPT_READDATA, &payload);
  curl_easy_setopt(curl.h, CURLOPT_UPLOAD, 1L);
  std::string smtpPhase="连接或问候";
  curl_easy_setopt(curl.h,CURLOPT_VERBOSE,1L);
  curl_easy_setopt(curl.h,CURLOPT_DEBUGDATA,&smtpPhase);
  curl_easy_setopt(curl.h,CURLOPT_DEBUGFUNCTION,+[](CURL*,curl_infotype type,char *data,size_t length,void *context)->int {
    if(type==CURLINFO_HEADER_OUT){std::string_view command(data,length);auto &phase=*static_cast<std::string*>(context);
      if(command.starts_with("EHLO ")||command.starts_with("HELO "))phase="EHLO";
      else if(command.starts_with("AUTH "))phase="AUTH";
      else if(command.starts_with("MAIL FROM:"))phase="MAIL FROM";
      else if(command.starts_with("RCPT TO:"))phase="RCPT TO";
      else if(command.starts_with("DATA"))phase="DATA或正文提交";
    }
    return 0;
  });
  const auto status = curl_easy_perform(curl.h);
  if (status != CURLE_OK) {
    long response = 0;
    curl_easy_getinfo(curl.h, CURLINFO_RESPONSE_CODE, &response);
    const auto detail = "（curl " + std::to_string(static_cast<int>(status)) +
                        "，SMTP " + std::to_string(response) + "，认证 " + mechanism + "，阶段 " + smtpPhase + "）";
    if (status == CURLE_LOGIN_DENIED && response == 334)
      throw std::runtime_error(
          "SMTP 认证交互未完成 " + detail +
          "：认证挑战交互未完成，尚不能判定密码错误。请核对 SMTP 主机、TLS 模式、完整邮箱账号和授权码，并按服务商要求选择认证方式。");
    if (status == CURLE_LOGIN_DENIED)
      throw std::runtime_error(
          "SMTP 认证被拒绝 " + detail +
          "：请检查完整邮箱用户名、SMTP 授权码或应用密码，以及邮箱后台是否已开启 SMTP。" 
          "部分服务商禁止密码认证，需要 OAuth；重复重试不会解决。注册邮件与工单邮件使用独立配置。");
    throw std::runtime_error(std::string("SMTP 邮件发送失败：") +
                             curl_easy_strerror(status) + detail);
  }
}
inline std::string hmacSha1(const std::string &key, const std::string &text) {
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int n;
  HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char *>(text.data()), text.size(), out,
       &n);
  return std::string(reinterpret_cast<char *>(out), n);
}
inline void deliverPhone(const Json &c, const std::string &target,
                         const std::string &code, bool temporary = false) {
  if (val(c, "sms_provider") == "twilio") {
    const auto sid = val(c, "twilio_sid");
    if (!std::regex_match(sid, std::regex("AC[a-fA-F0-9]{32}")))
      throw std::runtime_error("Twilio Account SID 无效");
    auto r = http(
        "https://api.twilio.com/2010-04-01/Accounts/" + sid + "/Messages.json",
        form({{"To", target},
              {"From", val(c, "twilio_from")},
              {"Body", temporary
                           ? "Your ZCT-SLMS temporary password is " + code +
                                 ". Sign in and set a new password immediately."
                           : "Your ZCT-SLMS verification code is " + code +
                                 ". Valid for 5 minutes."}}),
        {"Content-Type: application/x-www-form-urlencoded"},
        sid + ":" + val(c, "twilio_token"));
    if (!r.isMember("sid"))
      throw std::runtime_error("短信服务未接受请求");
  } else {
    if (target.rfind("+86", 0) != 0)
      throw std::runtime_error("阿里云国内短信当前仅支持 +86 手机号");
    std::time_t timestamp = now();
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &timestamp);
#else
    gmtime_r(&timestamp, &utc);
#endif
    char date[32];
    std::strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%SZ", &utc);
    Json params;
    params[temporary ? "password" : "code"] = code;
    if (temporary && val(c, "aliyun_reset_template").empty())
      throw std::runtime_error(
          "请先配置阿里云临时密码短信模板（变量 password）");
    std::map<std::string, std::string> values = {
        {"AccessKeyId", val(c, "aliyun_key")},
        {"Action", "SendSms"},
        {"Format", "JSON"},
        {"Version", "2017-05-25"},
        {"SignatureMethod", "HMAC-SHA1"},
        {"SignatureVersion", "1.0"},
        {"SignatureNonce", zct_slms::crypto::randomHex(16)},
        {"Timestamp", date},
        {"PhoneNumbers", target.substr(3)},
        {"SignName", val(c, "aliyun_sign")},
        {"TemplateCode",
         val(c, temporary ? "aliyun_reset_template" : "aliyun_template")},
        {"TemplateParam", json(params)}};
    values["Signature"] = zct_slms::crypto::base64Encode(hmacSha1(
        val(c, "aliyun_secret") + "&", "POST&%2F&" + escape(form(values))));
    auto r = http("https://dysmsapi.aliyuncs.com/", form(values),
                  {"Content-Type: application/x-www-form-urlencoded"});
    if (r.get("Code", "").asString() != "OK")
      throw std::runtime_error(
          "阿里云短信发送失败，请检查签名、模板与服务状态");
  }
}
inline void schema() {
  static std::once_flag once;
  std::call_once(once, [] {
    zct_slms::db::Database::instance().exec(
        "CREATE TABLE IF NOT EXISTS auth_identities (provider VARCHAR(32) NOT "
        "NULL, subject VARCHAR(320) NOT NULL, user_id BIGINT NOT NULL "
        "REFERENCES users(id) ON DELETE CASCADE, created_at BIGINT NOT NULL, "
        "PRIMARY KEY(provider,subject), UNIQUE(provider,user_id))");
  });
}
inline int64_t identityUser(const std::string &provider,
                            const std::string &subject) {
  schema();
  auto rows = zct_slms::db::Database::instance().queryParams(
      "SELECT user_id FROM auth_identities WHERE provider = ? AND subject = ?",
      provider, subject);
  return rows.empty() ? 0 : zct_slms::repo::getInt(rows[0], "user_id");
}
inline std::map<std::string, std::string> contactsFor(const std::string &role,
                                                      int64_t uid) {
  schema();
  static std::once_flag once;
  std::call_once(once, [] {
    zct_slms::db::Database::instance().exec(
        "CREATE TABLE IF NOT EXISTS recovery_contacts (account_role "
        "VARCHAR(16) NOT NULL,user_id BIGINT NOT NULL,provider VARCHAR(16) NOT "
        "NULL,target VARCHAR(320) NOT NULL,PRIMARY "
        "KEY(account_role,user_id,provider))");
  });
  std::map<std::string, std::string> out;
  if (role == "USER")
    for (auto &row : zct_slms::db::Database::instance().queryParams(
             "SELECT provider,subject FROM auth_identities WHERE user_id = ?",
             uid)) {
      auto p = zct_slms::repo::getStr(row, "provider");
      if (p == "email" || p == "phone")
        out[p] = zct_slms::repo::getStr(row, "subject");
    }
  for (auto &row : zct_slms::db::Database::instance().queryParams(
           "SELECT provider,target FROM recovery_contacts WHERE account_role = "
           "? AND user_id = ?",
           role, uid))
    if (!out.contains(zct_slms::repo::getStr(row, "provider")))
      out[zct_slms::repo::getStr(row, "provider")] =
          zct_slms::repo::getStr(row, "target");
  return out;
}
inline void attach(int64_t uid, const std::string &provider,
                   const std::string &subject) {
  schema();
  zct_slms::db::Database::instance().execParams(
      "INSERT INTO auth_identities(provider, subject, user_id, created_at) "
      "VALUES (?, ?, ?, ?)",
      provider, subject, uid, now());
}
inline Json session(int64_t uid, const std::string &ip, const std::string &ua,
                    const std::string &method = "password") {
  auto user = zct_slms::repo::UserRepo::findById(uid);
  if (!user || user->status != 1 ||
      (user->expires_at != -1 && user->expires_at < now()))
    throw std::runtime_error("账号不可用");
  auto token = zct_slms::crypto::randomHex(32);
  zct_slms::repo::SessionRepo::insert(
      "USER", uid, zct_slms::crypto::sha256Hex(token),
      now() + zct_slms::AppConfig::instance().security().session_ttl_seconds, now(),
      ip, ua);
  Json out;
  out["token"] = token;
  out["user_type"] = "USER";
  out["user_id"] = static_cast<::Json::Int64>(uid);
  out["username"] = user->username;
  out["auth_method"] = method;
  return zct_slms::inside::api::v1::common::gateLogin(out, ip, ua);
}
struct Challenge {
  std::string method, target, digest, action;
  int64_t expires;
  int attempts = 0;
};
struct Flow {
  std::string provider, verifier, browser, publicUrl;
  int64_t user, expires;
  std::string mfa_id;
  std::string backendUrl;
};
struct Ticket {
  Json result;
  std::string browser;
  int64_t expires;
};
inline std::map<std::string, Challenge> challenges;
inline std::map<std::string, Flow> flows;
inline std::map<std::string, Ticket> tickets;
inline std::map<std::string, std::vector<int64_t>> limits;
inline std::string otpSecret = zct_slms::crypto::randomBytes(32);
inline void rate(const std::string &key, int count, int seconds) {
  auto &stamps = limits[key];
  const auto cutoff = now() - seconds;
  stamps.erase(std::remove_if(stamps.begin(), stamps.end(),
                              [&](auto t) { return t < cutoff; }),
               stamps.end());
  if (static_cast<int>(stamps.size()) >= count)
    throw std::runtime_error("请求过于频繁，请稍后再试");
  stamps.push_back(now());
}
inline void prune() {
  auto t = now();
  for (auto it = challenges.begin(); it != challenges.end();)
    if (it->second.expires < t)
      it = challenges.erase(it);
    else
      ++it;
  for (auto it = flows.begin(); it != flows.end();)
    if (it->second.expires < t)
      it = flows.erase(it);
    else
      ++it;
  for (auto it = tickets.begin(); it != tickets.end();)
    if (it->second.expires < t)
      it = tickets.erase(it);
    else
      ++it;
  for (auto it = limits.begin(); it != limits.end();)
    if (it->second.empty() || it->second.back() < t - 3600)
      it = limits.erase(it);
    else
      ++it;
  if (challenges.size() > 10000 || flows.size() > 10000 ||
      limits.size() > 50000)
    throw std::runtime_error("服务繁忙，请稍后再试");
}
inline Challenge consume(const std::string &id, const std::string &code,
                         const std::string &action) {
  std::lock_guard lock(mutex);
  auto it = challenges.find(id);
  if (it == challenges.end())
    throw std::runtime_error("验证码错误或已过期");
  auto &c = it->second;
  if (c.expires < now() || ++c.attempts > 5) {
    challenges.erase(it);
    throw std::runtime_error("验证码错误或已过期");
  }
  if (c.action != action ||
      !zct_slms::crypto::constantTimeEqual(
          c.digest, zct_slms::crypto::hmacSha256Hex(id + ":" + code, otpSecret)))
    throw std::runtime_error("验证码错误或已过期");
  auto result = c;
  challenges.erase(it);
  return result;
}
inline std::string baseUrl(const Json &c) {
  auto url = val(c, "public_url");
  while (!url.empty() && url.back() == '/')
    url.pop_back();
  if (!std::regex_match(url,
                        std::regex("https://[A-Za-z0-9.-]+(:[0-9]+)?|http://"
                                   "(localhost|127\\.0\\.0\\.1)(:[0-9]+)?")))
    throw std::runtime_error(
        "可访问地址必须为 HTTPS 源地址，本机调试允许 HTTP localhost");
  std::transform(url.begin()+url.find("://")+3,url.end(),url.begin()+url.find("://")+3,[](unsigned char ch){return static_cast<char>(std::tolower(ch));});
  if((url.starts_with("https://")&&url.ends_with(":443"))||(url.starts_with("http://")&&url.ends_with(":80")))url.erase(url.rfind(':'));
  return url;
}
inline std::string backendBaseUrl(const Json &c) {
  if(val(c,"backend_url").empty())return baseUrl(c);
  auto backend=c;backend["public_url"]=c["backend_url"];return baseUrl(backend);
}
inline std::string callback(const std::string &origin,
                            const std::string &provider) {
  return origin + "/api/v1/auth/connect/callback/" + provider;
}
inline std::string tenant(const Json &c) {
  auto value = c.get("microsoft_tenant", "common").asString();
  if (!std::regex_match(value, std::regex("[A-Za-z0-9.-]+")))
    throw std::runtime_error("Microsoft 租户无效");
  return value;
}
inline trantor::ConcurrentTaskQueue workers{4, "identity"};
inline std::atomic<int> jobs{0};
using Req = drogon::HttpRequestPtr;
using Resp = drogon::HttpResponsePtr;
using Callback = std::function<void(const Resp &)>;
template <class F> inline void background(Req req, Callback cb, F fn) {
  if (jobs.fetch_add(1) >= 32) {
    jobs.fetch_sub(1);
    cb(drogon::HttpResponse::newHttpJsonResponse(
        zct_slms::api::makeFail(1003, "服务繁忙")));
    return;
  }
  workers.runTaskInQueue([req, cb = std::move(cb), fn]() {
    try {
      fn(req, cb);
    } catch (const std::exception &) {
      cb(drogon::HttpResponse::newHttpJsonResponse(
          zct_slms::api::makeFail(1003, "认证服务处理失败，请检查配置")));
    }
    jobs.fetch_sub(1);
  });
}
inline void ok(const Callback &cb, Json data = Json{}) {
  auto response =
      drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(data));
  response->addHeader("Cache-Control", "no-store");
  cb(response);
}
inline void fail(const Callback &cb, const std::string &msg) {
  auto response =
      drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(1003, msg));
  response->addHeader("Cache-Control", "no-store");
  cb(response);
}
namespace common = zct_slms::inside::api::v1::common;
inline auto owner(const Req &req) {
  auto auth =
      zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
  if (!auth.success || auth.user_type != "USER")
    throw std::runtime_error("需要用户登录");
  {
    std::lock_guard lock(mutex);
    prune();
    rate("bind-password:" + std::to_string(auth.user_id), 10, 60);
  }
  auto u = zct_slms::repo::UserRepo::findById(auth.user_id);
  if (!u ||
      !common::sensitiveAuthorization(req, common::paramStr(req, "password")))
    throw std::runtime_error("当前密码错误");
  return auth;
}
} // namespace zct_slms::identity
