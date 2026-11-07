// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 ZCT Studio

#pragma once

#include "services/identity_service.hpp"
#include "services/telegram_oidc.hpp"
#include "services/oauth_profile.hpp"
#include "services/moderation.hpp"

namespace zct_slms::identity {
    struct PendingSignup {
        std::string provider, subject, browser, userAgent;
        Json profile;
        int64_t expires;
        bool working = false;
    };

    inline std::map<std::string, PendingSignup> pendingSignups;

    inline void pruneSignups() {
        const auto t = now();
        for (auto i = pendingSignups.begin(); i != pendingSignups.end();)
            if (i->second.expires < t && !i->second.working) i = pendingSignups.erase(i);
            else ++i;
        if (pendingSignups.size() >= 5000) throw std::runtime_error("注册服务繁忙，请稍后再试");
    }

    inline bool adminPassword(const Req& req) {
        auto a =
            zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
        if (!a.success || a.user_type != "ADMIN")
            return false;
        {
            std::lock_guard lock(mutex);
            prune();
            rate("admin-auth:" + std::to_string(a.user_id), 10, 60);
        }
        auto user = zct_slms::repo::AdminRepo::findById(a.user_id);
        return user &&
               common::sensitiveAuthorization(req, common::paramStr(req, "current_password"));
    }

    inline void templatesSettings(const Req& req, Callback&& cb) {
        try {
            auto a = zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
            if (!a.success || a.user_type != "ADMIN") throw std::runtime_error("需要管理员登录");
            if (req->method() == drogon::Post) {
                if (!adminPassword(req)) throw std::runtime_error("请完成管理员授权");
                auto body = req->getJsonObject();
                auto defaults = defaultMailTemplates();
                if (!body || !(*body)["templates"].isObject()) throw std::runtime_error("邮件模板格式无效");
                auto input = (*body)["templates"];
                for (const auto& key : input.getMemberNames()) {
                    if (!defaults.isMember(key) || !input[key].isObject()) throw std::runtime_error("邮件模板类型无效");
                    auto subject = input[key]["subject"], text = input[key]["body"];
                    if (!subject.isString() || !text.isString() || subject.asString().empty() || subject.asString().size() > 180 || text.asString().empty() || text.asString().
                        size() > 16000 || subject.asString().find_first_of("\r\n") != std::string::npos)
                        throw std::runtime_error("邮件主题最多180字节、正文最多16000字节，且不能为空");
                    if (input[key].get("format", "plain") != "plain" && input[key].get("format", "plain") != "html")throw std::runtime_error("邮件格式无效");
                    validateMailText(subject.asString());
                    validateMailText(text.asString());
                    if (key != "ticket_update" && text.asString().find("{code}") == std::string::npos) throw std::runtime_error("验证码和临时密码模板必须包含 {code}");
                }
                auto c = config();
                auto merged = mailTemplates();
                for (const auto& key : input.getMemberNames())merged[key] = input[key];
                c["mail_templates"] = merged;
                saveConfig(c);
                zct_slms::repo::AuditRepo::log("ADMIN", a.user_id, "UpdateMailTemplates", "SYSTEM", 0, "", "success", common::clientIp(req), "{}", now());
            }
            Json out;
            out["templates"] = mailTemplates();
            out["defaults"] = defaultMailTemplates();
            ok(cb, out);
        } catch (const std::exception& e) { fail(cb, e.what()); }
    }

    inline void options(const Req&, Callback&& cb) {
        try {
            auto c = config();
            Json out;
            out["registration_enabled"] = c.get("registration_enabled", true);
            out["invite_registration_enabled"] =
                c.get("invite_registration_enabled", true);
            for (auto m : {"phone", "email", "microsoft", "github", "google", "telegram", "gitlab", "discord"})
                out[std::string(m) + "_enabled"] = ready(c, m);
            ok(cb, out);
        } catch (...) {
            fail(cb, "认证配置不可用");
        }
    }

    inline void settings(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto auth = zct_slms::service::AuthService::authenticateSession(
                        common::authBearer(req)
                    );
                    if (!auth.success || auth.user_type != "ADMIN") {
                        fail(cb, "需要管理员登录");
                        return;
                    }
                    auto c = config();
                    if (req->method() == drogon::Post) {
                        if (!adminPassword(req)) {
                            fail(cb, "管理员操作授权无效或已过期，请重新验证身份");
                            return;
                        }
                        auto body = req->getJsonObject();
                        if (!body)
                            throw std::runtime_error("无效配置");
                        if (body->get("action", "").asString() == "reveal") {
                            ok(cb, c);
                            return;
                        }
                        const std::vector<std::string> keys = {
                                "public_url",
                                "backend_url",
                                "smtp_host",
                                "smtp_username",
                                "smtp_password",
                                "smtp_from",
                                "smtp_tls",
                                "smtp_auth",
                                "sms_provider",
                                "aliyun_key",
                                "aliyun_secret",
                                "aliyun_sign",
                                "aliyun_template",
                                "aliyun_reset_template",
                                "twilio_sid",
                                "twilio_token",
                                "twilio_from",
                                "github_client",
                                "github_secret",
                                "microsoft_client",
                                "microsoft_secret",
                                "microsoft_tenant",
                                "google_client",
                                "google_secret",
                                "telegram_client",
                                "telegram_secret",
                                "gitlab_client",
                                "gitlab_secret",
                                "discord_client",
                                "discord_secret"
                            };
                        for (auto& key : keys) {
                            if (!body->isMember(key))
                                continue;
                            if (!(*body)[key].isString() || (*body)[key].asString().size() > 4096)
                                throw std::runtime_error("配置字段格式无效");
                            const auto text = (*body)[key].asString();
                            if (std::find(secrets.begin(), secrets.end(), key) != secrets.end() &&
                                text.empty())
                                continue;
                            c[key] = text;
                        }
                        for (auto k : {
                                 "registration_enabled",
                                 "invite_registration_enabled",
                                 "phone_enabled",
                                 "email_enabled",
                                 "github_enabled",
                                 "microsoft_enabled",
                                 "google_enabled",
                                 "telegram_enabled",
                                 "gitlab_enabled",
                                 "discord_enabled"
                             })
                            if (body->isMember(k)) {
                                if (!(*body)[k].isBool())
                                    throw std::runtime_error("开关格式无效");
                                c[k] = (*body)[k];
                            }
                        if (body->isMember("smtp_port")) {
                            const auto p = (*body)["smtp_port"].asInt();
                            if (p < 1 || p > 65535)
                                throw std::runtime_error("SMTP 端口无效");
                            c["smtp_port"] = p;
                        }
                        if (val(c, "sms_provider") != "aliyun" &&
                            val(c, "sms_provider") != "twilio")
                            throw std::runtime_error("请选择阿里云或 Twilio");
                        if (!val(c, "smtp_tls").empty() && val(c, "smtp_tls") != "implicit" &&
                            val(c, "smtp_tls") != "starttls")
                            throw std::runtime_error("SMTP 必须启用 TLS");
                        if (!val(c, "public_url").empty())
                            baseUrl(c);
                        if (!val(c, "backend_url").empty()) backendBaseUrl(c);
                        tenant(c);
                        for (auto method : {"phone", "email", "github", "microsoft", "google", "telegram", "gitlab", "discord"})
                            if (enabled(c, method) && !ready(c, method))
                                throw std::runtime_error("启用前请先填写完整的服务配置");
                        smtpAuthMechanism(c);
                        saveConfig(c);
                        zct_slms::repo::AuditRepo::log(
                            "ADMIN",
                            auth.user_id,
                            "UpdateRegistrationConfig",
                            "SYSTEM",
                            0,
                            "",
                            "success",
                            common::clientIp(req),
                            "{}",
                            now()
                        );
                    }
                    for (auto& key : secrets) {
                        c[key + "_configured"] = !c.get(key, "").asString().empty();
                        c[key] = "";
                    }
                    ok(cb, c);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void sendCode(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    auto c = config();
                    const auto method = common::paramStr(req, "method"),
                               action = common::paramStr(req, "action");
                    if (!ready(c, method) || (method != "email" && method != "phone"))
                        throw std::runtime_error("此验证方式尚未开放");
                    if (action != "login" && action != "register" && action != "bind")
                        throw std::runtime_error("无效验证用途");
                    if (action == "register" &&
                        !c.get("registration_enabled", true).asBool())
                        throw std::runtime_error("注册尚未开放");
                    if (action == "bind")
                        owner(req);
                    auto target = normalize(method, common::paramStr(req, "target"));
                    const auto id = zct_slms::crypto::randomHex(24),
                               code = zct_slms::crypto::randomNumeric(6);
                    {
                        std::lock_guard lock(mutex);
                        prune();
                        rate("send-ip:" + common::clientIp(req), 10, 3600);
                        rate("send-target-minute:" + method + target, 1, 60);
                        rate("send-target-hour:" + method + target, 5, 3600);
                    }
                    if (method == "email") {
                        Json values = mailAccount("", 0, target);
                        if (action == "bind") {
                            auto u = owner(req);
                            values = mailAccount(u.user_type, u.user_id, target);
                        } else if (action == "login") values = mailAccount("USER", identityUser(method, target), target);
                        else {
                            values["username"] = common::paramStr(req, "username").substr(0, 64);
                            values["nickname"] = common::paramStr(req, "nickname").substr(0, 96);
                        }
                        deliverEmail(c, target, code, false, "", "", action, values);
                    } else
                        deliverPhone(c, target, code);
                    {
                        std::lock_guard lock(mutex);
                        challenges[id] = {
                                method,
                                target,
                                zct_slms::crypto::hmacSha256Hex(id + ":" + code, otpSecret),
                                action,
                                now() + 300,
                                0
                            };
                    }
                    Json out;
                    out["challenge_id"] = id;
                    out["expires_in"] = 300;
                    out["retry_after"] = 60;
                    ok(cb, out);
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void verifyCode(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                try {
                    const auto action = common::paramStr(req, "action");
                    auto c = config();
                    if (action != "login" && action != "register" && action != "bind")
                        throw std::runtime_error("无效操作");
                    if (action == "register" &&
                        !c.get("registration_enabled", true).asBool())
                        throw std::runtime_error("注册尚未开放");
                    auto ch = consume(
                        common::paramStr(req, "challenge_id"),
                        common::paramStr(req, "code"),
                        action
                    );
                    if (!ready(c, ch.method))
                        throw std::runtime_error("此验证方式已关闭");
                    if (action == "bind") {
                        auto user = owner(req);
                        try {
                            attach(user.user_id, ch.method, ch.target);
                        } catch (...) {
                            throw std::runtime_error("此身份已绑定，或当前账号已有该类型身份");
                        }
                        ok(cb);
                        return;
                    }
                    auto uid = identityUser(ch.method, ch.target);
                    if (action == "register") {
                        auto username = common::paramStr(req, "username"),
                             password = common::paramStr(req, "password"),
                             nickname = common::paramStr(req, "nickname");
                        if (!std::regex_match(username, std::regex("[A-Za-z0-9_.-]{3,64}")) ||
                            password.size() < 12 || password.size() > 256 ||
                            nickname.size() > 96)
                            throw std::runtime_error(
                                "用户名须为 3–64 位字母数字或 _ . -；密码至少 12 位"
                            );
                        if (uid || zct_slms::repo::UserRepo::findByUsername(username))
                            throw std::runtime_error("该身份或用户名已注册，请登录");
                        auto hp = zct_slms::service::hashPassword(password);
                        bool success = zct_slms::db::Database::instance().transaction(
                            [&] {
                                uid = zct_slms::repo::UserRepo::insert(
                                    username,
                                    hp.hash,
                                    hp.salt,
                                    nickname,
                                    now(),
                                    0
                                );
                                attach(uid, ch.method, ch.target);
                                return true;
                            }
                        );
                        if (!success)
                            throw std::runtime_error("注册失败，请重试");
                    }
                    if (!uid)
                        throw std::runtime_error("登录验证失败，请确认账号已注册");
                    ok(
                        cb,
                        session(uid, common::clientIp(req), common::clientUa(req), ch.method)
                    );
                } catch (const std::exception& e) {
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void bindings(const Req& req, Callback&& cb) {
        try {
            auto auth =
                zct_slms::service::AuthService::authenticateSession(common::authBearer(req));
            if (!auth.success || auth.user_type != "USER")
                throw std::runtime_error("需要用户登录");
            schema();
            auto rows = zct_slms::db::Database::instance().queryParams(
                "SELECT provider, subject FROM auth_identities WHERE user_id = ?",
                auth.user_id
            );
            Json out(::Json::arrayValue);
            for (auto& row : rows) {
                Json item;
                auto provider = zct_slms::repo::getStr(row, "provider"),
                     subject = zct_slms::repo::getStr(row, "subject");
                item["provider"] = provider;
                item["label"] =
                    (provider == "phone" || provider == "email")
                        ? (subject.size() > 6
                               ? subject.substr(0, 2) + "***" +
                                 subject.substr(subject.size() - 3)
                               : "***")
                        : "已绑定";
                out.append(item);
            }
            ok(cb, out);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline std::function<int64_t(const Req &)> mfaOwner =
        [](const Req&) -> int64_t { throw std::runtime_error("登录验证不可用"); };
    inline std::function<Json(
                         const std::string&,
                         const std::string&,
                         int64_t,
                         const std::string&, const std::string&
    )
    >
    mfaComplete;

    inline void oauthStart(const Req& req, Callback&& cb) {
        try {
            auto c = config();
            auto provider = common::paramStr(req, "provider");
            if ((provider != "github" && provider != "microsoft" && provider != "google" && provider != "telegram" && provider != "gitlab" && provider != "discord") ||
                !ready(c, provider))
                throw std::runtime_error("此账号登录方式尚未配置");
            auto intent = common::paramStr(req, "action", "login");
            int64_t uid = 0;
            if (intent == "bind")
                uid = owner(req).user_id;
            else if (intent == "mfa")
                uid = mfaOwner(req);
            else if (intent != "login")
                throw std::runtime_error("无效登录操作");
            const auto origin = baseUrl(c), state = zct_slms::crypto::randomHex(32),
                       browser = common::paramStr(req, "browser_challenge"),
                       verifier = b64url(zct_slms::crypto::randomBytes(32));
            if (!std::regex_match(browser, std::regex("[a-f0-9]{64}")))throw std::runtime_error("登录浏览器校验信息无效，请刷新前端后重试");
            {
                std::lock_guard lock(mutex);
                prune();
                rate("oauth:" + common::clientIp(req), 20, 60);
                flows[zct_slms::crypto::sha256Hex(state)] = {
                        provider,
                        verifier,
                        browser,
                        origin,
                        uid,
                        now() + 600
                    };
                flows[zct_slms::crypto::sha256Hex(state)].backendUrl = backendBaseUrl(c);
                if (intent == "mfa")
                    flows[zct_slms::crypto::sha256Hex(state)].mfa_id =
                        common::paramStr(req, "challenge_id");
            }
            std::map<std::string, std::string> params = {
                    {"client_id", c[provider + "_client"].asString()},
                    {"redirect_uri", callback(backendBaseUrl(c), provider)},
                    {"state", state},
                    {"response_type", "code"},
                    {"code_challenge", b64url(zct_slms::crypto::sha256(verifier))},
                    {"code_challenge_method", "S256"},
                    {"scope", provider == "github" ? "read:user" : provider == "discord" ? "identify" : provider == "microsoft" ? "openid profile User.Read" : "openid profile"}
                };
            if (provider == "telegram") params["nonce"] = b64url(zct_slms::crypto::sha256(verifier));
            const auto endpoint = provider == "github"
                                      ? "https://github.com/login/oauth/authorize"
                                      : provider == "google"
                                      ? "https://accounts.google.com/o/oauth2/v2/auth"
                                      : provider == "telegram"
                                      ? "https://oauth.telegram.org/auth"
                                      : provider == "gitlab"
                                      ? "https://gitlab.com/oauth/authorize"
                                      : provider == "discord"
                                      ? "https://discord.com/oauth2/authorize"
                                      : "https://login.microsoftonline.com/" + tenant(c) + "/oauth2/v2.0/authorize";
            const auto url = endpoint + "?" + form(params);
            Json out;
            out["url"] = url;
            auto resp =
                drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(out));
            resp->addHeader("Cache-Control", "no-store");
            cb(resp);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }

    inline void oauthCallback(const Req& req, Callback&& callbackFn) {
        background(
            req,
            std::move(callbackFn),
            [](auto req, const Callback& cb) {
                std::string origin;
                try {
                    const auto state = req->getParameter("state");
                    Flow flow;
                    {
                        std::lock_guard lock(mutex);
                        auto it = flows.find(zct_slms::crypto::sha256Hex(state));
                        if (it == flows.end() || it->second.expires < now())
                            throw std::runtime_error("登录请求无效或已过期，请重新发起");
                        flow = it->second;
                        flows.erase(it);
                    }
                    origin = flow.publicUrl;
                    auto provider = flow.provider;
                    const auto suffix = "/" + provider;
                    if (req->path().size() < suffix.size() ||
                        req->path().substr(req->path().size() - suffix.size()) != suffix ||
                        req->getParameter("code").empty())
                        throw std::runtime_error("第三方登录已取消或失败");
                    auto c = config();
                    if (!ready(c, provider) || baseUrl(c) != origin || backendBaseUrl(c) != flow.backendUrl)
                        throw std::runtime_error("登录配置已变更，请重试");
                    const auto tokenUrl = provider == "github"
                                              ? "https://github.com/login/oauth/access_token"
                                              : provider == "google"
                                              ? "https://oauth2.googleapis.com/token"
                                              : provider == "telegram"
                                              ? "https://oauth.telegram.org/token"
                                              : provider == "gitlab"
                                              ? "https://gitlab.com/oauth/token"
                                              : provider == "discord"
                                              ? "https://discord.com/api/oauth2/token"
                                              : "https://login.microsoftonline.com/" + tenant(c) + "/oauth2/v2.0/token";
                    std::map<std::string, std::string> fields = {
                            {"client_id", c[provider + "_client"].asString()},
                            {"client_secret", c[provider + "_secret"].asString()},
                            {"code", req->getParameter("code")},
                            {"code_verifier", flow.verifier},
                            {"grant_type", "authorization_code"},
                            {"redirect_uri", callback(backendBaseUrl(c), provider)}
                        };
                    std::vector<std::string> headers{"Accept: application/json", "Content-Type: application/x-www-form-urlencoded"};
                    if (provider == "telegram") {
                        fields.erase("client_secret");
                        headers.push_back(
                            "Authorization: Basic " + zct_slms::crypto::base64Encode(escape(c[provider + "_client"].asString()) + ":" + escape(c[provider + "_secret"].asString()))
                        );
                    }
                    auto token = http(tokenUrl, form(fields), headers);
                    Json profile;
                    if (provider == "telegram") {
                        profile = telegramClaims(
                            token.get("id_token", "").asString(),
                            http("https://oauth.telegram.org/.well-known/jwks.json"),
                            c["telegram_client"].asString(),
                            b64url(zct_slms::crypto::sha256(flow.verifier))
                        );
                    } else {
                        auto access = token.get("access_token", "").asString();
                        if (access.empty() || access.find_first_of("\r\n") != std::string::npos) throw std::runtime_error("第三方授权失败");
                        profile = http(
                            provider == "github"
                                ? "https://api.github.com/user"
                                : provider == "google"
                                ? "https://openidconnect.googleapis.com/v1/userinfo"
                                : provider == "gitlab"
                                ? "https://gitlab.com/oauth/userinfo"
                                : provider == "discord"
                                ? "https://discord.com/api/v10/users/@me"
                                : "https://graph.microsoft.com/oidc/userinfo",
                            "",
                            {"Authorization: Bearer " + access, "Accept: application/json"}
                        );
                    }
                    std::string subject = (provider == "github" || provider == "discord")
                                              ? profile["id"].asString()
                                              : profile.get("sub", "").asString();
                    if (subject.empty())
                        throw std::runtime_error("第三方身份无效");
                    auto uid = identityUser(provider, subject);
                    if (provider == "microsoft" && flow.mfa_id.empty() && !flow.user && (!uid || !zct_slms::repo::ConfigRepo::getBool(
                                                                                             "identity_profile_done:" + std::to_string(uid),
                                                                                             false
                                                                                         ))) {
                        const auto access = token.get("access_token", "").asString();
                        try {
                            auto details = http("https://graph.microsoft.com/v1.0/me?$select=displayName,mailNickname,userPrincipalName", "", {"Authorization: Bearer " + access});
                            profile["preferred_username"] = profileText(details, {"mailNickname", "userPrincipalName"});
                            if (profileText(profile, {"name"}).empty()) profile["name"] = profileText(details, {"displayName"});
                        } catch (const std::exception&) { /* Optional profile fields must not prevent login. */ }
                        profile["_avatar"] = microsoftAvatar(access);
                    }
                    Json result;
                    if (!flow.mfa_id.empty()) {
                        if (!uid || uid != flow.user)
                            throw std::runtime_error("授权账号不匹配");
                        result = mfaComplete(
                            flow.mfa_id,
                            provider,
                            uid,
                            common::clientIp(req),
                            common::clientUa(req)
                        );
                    } else if (flow.user) {
                        if (uid)
                            throw std::runtime_error("此第三方账号已经绑定");
                        attach(flow.user, provider, subject);
                        result["bound"] = true;
                    } else {
                        if (!uid) {
                            if (!c.get("registration_enabled", true).asBool()) throw std::runtime_error("此身份尚未注册，平台当前未开放注册");
                            const auto setupToken = zct_slms::crypto::randomHex(32);
                            auto suggested = oauthProfile(provider, profile);
                            {
                                std::lock_guard lock(mutex);
                                pruneSignups();
                                pendingSignups[zct_slms::crypto::sha256Hex(setupToken)] = {provider, subject, flow.browser, common::clientUa(req), suggested, now() + 600};
                            }
                            result["setup_required"] = true;
                            result["setup_token"] = setupToken;
                            result["profile"] = suggested;
                            result["max_avatar_bytes"] = ::Json::Int64(zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes", 1048576));
                        } else {
                            // Legacy unfinished registrations can still complete their existing onboarding.
                            if (!zct_slms::repo::ConfigRepo::getBool("identity_profile_done:" + std::to_string(uid), false) && zct_slms::repo::ConfigRepo::getBool(
                                    "identity_password_pending:" + std::to_string(uid),
                                    false
                                )) {
                                const auto suggested = oauthProfile(provider, profile);
                                for (auto field : {"username", "nickname", "avatar"})
                                    zct_slms::repo::ConfigRepo::set(
                                        "identity_profile_" + std::string(field) + ":" + std::to_string(uid),
                                        suggested[field].asString(),
                                        now()
                                    );
                            }
                            result = session(uid, common::clientIp(req), common::clientUa(req), provider);
                        }
                    }
                    const auto ticket = zct_slms::crypto::randomHex(32);
                    {
                        std::lock_guard lock(mutex);
                        tickets[zct_slms::crypto::sha256Hex(ticket)] = {
                                result,
                                flow.browser,
                                now() + 60
                            };
                    }
                    auto response = drogon::HttpResponse::newRedirectionResponse(
                        origin + "/?auth_ticket=" + escape(ticket) + "&auth_binding=" + escape(flow.browser)
                    );
                    response->addHeader("Cache-Control", "no-store");
                    response->addHeader("Referrer-Policy", "no-referrer");
                    cb(response);
                } catch (const std::exception&) {
                    auto response = drogon::HttpResponse::newHttpResponse();
                    response->setStatusCode(drogon::k400BadRequest);
                    response->setContentTypeCode(drogon::CT_TEXT_HTML);
                    response->setBody(
                        "<!doctype html><meta "
                        "charset=utf-8><title>登录失败</"
                        "title><p>"
                        "第三方登录未完成。请返回登录页面重新发起，或联系管理员"
                        "检查配置。</p>"
                    );
                    response->addHeader("Cache-Control", "no-store");
                    cb(response);
                }
            }
        );
    }

    inline void signup(const Req& req, Callback&& callback) {
        background(
            req,
            std::move(callback),
            [](auto req, const Callback& cb) {
                std::string key;
                bool reserved = false;
                try {
                    const auto raw = common::paramStr(req, "setup_token");
                    if (!std::regex_match(raw, std::regex("[a-f0-9]{64}"))) throw std::runtime_error("注册信息已过期，请重新登录");
                    key = zct_slms::crypto::sha256Hex(raw);
                    PendingSignup pending;
                    {
                        std::lock_guard lock(mutex);
                        auto it = pendingSignups.find(key);
                        if (it == pendingSignups.end() || it->second.expires < now() || it->second.working || it->second.browser != zct_slms::crypto::sha256Hex(
                                common::paramStr(req, "browser_verifier")
                            ) || it->second.userAgent !=
                            common::clientUa(req))
                            throw std::runtime_error("注册信息已过期或登录环境改变，请重新登录");
                        rate("oauth-signup:" + common::clientIp(req), 30, 60);
                        if (common::paramStr(req, "action") == "cancel") {
                            pendingSignups.erase(it);
                            Json out;
                            out["cancelled"] = true;
                            ok(cb, out);
                            return;
                        }
                        it->second.working = true;
                        reserved = true;
                        pending = it->second;
                    }
                    const auto username = common::paramStr(req, "username"), nickname = common::paramStr(req, "nickname"), password = common::paramStr(req, "new_password"), avatar
                                   = common::paramStr(req, "avatar", pending.profile.get("avatar", "").asString());
                    if (!std::regex_match(username, std::regex("[A-Za-z0-9_.-]{3,64}")) || nickname.empty() || nickname.size() > 96) throw std::runtime_error("请设置有效的用户名和昵称");
                    if (!password.empty() && (password.size() < 12 || password.size() > 256)) throw std::runtime_error("密码须为 12–256 字节，或留空暂不设置");
                    if (!profileAvatarAllowed(avatar, pending.profile.get("avatar", "").asString())) throw std::runtime_error("头像超过大小限制或格式不支持");
                    zct_slms::moderation::check(username);
                    zct_slms::moderation::check(nickname);
                    const auto cfg = config();
                    if (!cfg.get("registration_enabled", true).asBool() || !ready(cfg, pending.provider)) throw std::runtime_error("此登录方式或注册已关闭");
                    const auto hp = password.empty() ? zct_slms::service::HashedPassword{} : zct_slms::service::hashPassword(password);
                    auto& db = zct_slms::db::Database::instance();
                    int64_t uid = 0;
                    if (!db.transaction(
                        [&] {
                            if (identityUser(pending.provider, pending.subject)) throw std::runtime_error("此第三方账号已注册，请直接登录");
                            if (zct_slms::repo::UserRepo::findByUsername(username)) throw std::runtime_error("用户名已存在");
                            uid = zct_slms::repo::UserRepo::insert(username, hp.hash, hp.salt, nickname, now(), 0);
                            attach(uid, pending.provider, pending.subject);
                            zct_slms::repo::ConfigRepo::set("identity_password_pending:" + std::to_string(uid), password.empty() ? "1" : "0", now());
                            zct_slms::repo::ConfigRepo::set("identity_profile_done:" + std::to_string(uid), "1", now());
                            zct_slms::repo::ConfigRepo::set("profile:USER:" + std::to_string(uid) + ":nickname", nickname, now());
                            zct_slms::repo::ConfigRepo::set("profile:USER:" + std::to_string(uid) + ":avatar", zct_slms::identity::persistAvatar(avatar), now());
                            return true;
                        }
                    ))
                        throw std::runtime_error("注册失败，请重试");
                    {
                        std::lock_guard lock(mutex);
                        pendingSignups.erase(key);
                        reserved = false;
                    }
                    ok(cb, session(uid, common::clientIp(req), common::clientUa(req), pending.provider));
                } catch (const std::exception& e) {
                    if (reserved) {
                        std::lock_guard lock(mutex);
                        auto it = pendingSignups.find(key);
                        if (it != pendingSignups.end())it->second.working = false;
                    }
                    fail(cb, e.what());
                }
            }
        );
    }

    inline void exchange(const Req& req, Callback&& cb) {
        try {
            const auto key = zct_slms::crypto::sha256Hex(common::paramStr(req, "ticket")),
                       browser = zct_slms::crypto::sha256Hex(common::paramStr(req, "browser_verifier"));
            Json result;
            {
                std::lock_guard lock(mutex);
                auto it = tickets.find(key);
                if (it == tickets.end() || it->second.expires < now() ||
                    !zct_slms::crypto::constantTimeEqual(it->second.browser, browser))
                    throw std::runtime_error("登录结果已过期，请重试");
                result = it->second.result;
                tickets.erase(it);
            }
            ok(cb, result);
        } catch (const std::exception& e) {
            fail(cb, e.what());
        }
    }
} // namespace zct_slms::identity
