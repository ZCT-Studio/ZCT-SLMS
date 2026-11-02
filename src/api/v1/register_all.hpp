// Copyright 2026 ZCT-Studio
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
// Created by wanjiangzhi on 2026/9/25.
//

#ifndef ZCT_SLMS_API_V1_REGISTER_ALL
#define ZCT_SLMS_API_V1_REGISTER_ALL

#include "api/v1/common.hpp"
#include "common/logger.hpp"
#include "middleware/middlewares.hpp"
#include <drogon/drogon.h>

#include "api/v1/ping.hpp"

// --- system ---
#include "api/v1/system/configs.hpp"
#include "api/v1/system/ping.hpp"

// --- auth ---
#include "api/v1/admin/account.hpp"
#include "api/v1/admin/avatar-limit.hpp"
#include "api/v1/admin/encoding-policy.hpp"
#include "api/v1/admin/license-types.hpp"
#include "api/v1/admin/platform-config.hpp"
#include "api/v1/app/subusers.hpp"
#include "api/v1/app/update.hpp"
#include "api/v1/auth/admin/login.hpp"
#include "api/v1/auth/factors.hpp"
#include "api/v1/auth/identity.hpp"
#include "api/v1/auth/initial-password.hpp"
#include "api/v1/auth/logout.hpp"
#include "api/v1/auth/owner/login.hpp"
#include "api/v1/auth/password.hpp"
#include "api/v1/auth/profile.hpp"
#include "api/v1/auth/balance.hpp"
#include "api/v1/auth/subuser/login.hpp"
#include "services/moderation.hpp"
#include "services/portal_accounts.hpp"
#include "services/portal_auth.hpp"
#include "services/authorization.hpp"
#include "services/tickets.hpp"
#include "services/ticket_management.hpp"
#include "services/ticket_mail.hpp"
#include "services/review.hpp"
#include "services/heartbeat.hpp"
#include "services/account_lifecycle.hpp"
#include "services/vouchers.hpp"

// --- admin ---
#include "admin/audit/list.hpp"
#include "api/v1/admin/license-timer/pause.hpp"
#include "api/v1/admin/license-timer/resume.hpp"
#include "api/v1/admin/owner/balance.hpp"
#include "api/v1/admin/owner/create.hpp"
#include "api/v1/admin/owner/list.hpp"

// --- app ---
#include "api/v1/app/binding.hpp"
#include "api/v1/app/channel/list.hpp"
#include "api/v1/app/create.hpp"
#include "api/v1/app/delete.hpp"
#include "api/v1/app/list.hpp"
#include "api/v1/app/notice.hpp"
#include "api/v1/app/secret/regenerate.hpp"
#include "api/v1/app/secret/view.hpp"
#include "api/v1/app/set-decode.hpp"
#include "api/v1/app/sign-enable.hpp"
#include "api/v1/app/version/create.hpp"
#include "api/v1/app/version/latest.hpp"

// --- license ---
#include "api/v1/license/add-time.hpp"
#include "api/v1/license/ban.hpp"
#include "api/v1/license/create.hpp"
#include "api/v1/license/delete.hpp"
#include "api/v1/license/list.hpp"
#include "api/v1/license/set-time.hpp"
#include "api/v1/license/set-type.hpp"
#include "api/v1/license/unban.hpp"
#include "api/v1/license/unbind-info.hpp"
#include "api/v1/license/unbind.hpp"

// --- client ---
#include "api/v1/client/app/channels.hpp"
#include "api/v1/client/app/notice.hpp"
#include "api/v1/client/app/version.hpp"
#include "api/v1/client/license/remaining.hpp"
#include "api/v1/client/license/status.hpp"
#include "api/v1/client/license/verify.hpp"

namespace zct_slms::api {
inline void registerAllV1Routes(drogon::HttpAppFramework &app) {
  using zct_slms::inside::api::v1::common::wrap;
  using namespace drogon;
  zct_slms::repo::validatePublicText=&zct_slms::moderation::check;
  zct_slms::authorization::install();
  zct_slms::ticket_mail::install();
  zct_slms::inside::api::v1::common::reviewContentChanged=[](const std::string &type,const std::string &role,int64_t id){zct_slms::repo::ConfigRepo::set("review_epoch:"+type+":"+role+":"+std::to_string(id),zct_slms::crypto::randomHex(16),std::time(nullptr));};
  app.registerHandler("/api/v1/app/heartbeat",wrap(&zct_slms::heartbeat::settings),{Get,Post});
  app.registerHandler("/api/v1/support/review/detail",wrap(&zct_slms::review::detail),{Post});
  app.registerHandler("/api/v1/support/review/report",wrap(&zct_slms::review::report),{Post});
  app.registerHandler("/api/v1/admin/review/action",wrap(&zct_slms::review::act),{Post});
  app.registerHandler("/api/v1/admin/ticket-mail",wrap(&zct_slms::ticket_mail::settings),{Get,Post});
  app.registerHandler("/api/v1/tickets/notifications",wrap(&zct_slms::ticket_mail::preferences),{Get,Post});
  app.registerHandler("/api/v1/tickets/notifications/code",wrap(&zct_slms::ticket_mail::sendCode),{Post});
  app.registerHandler("/api/v1/tickets/notifications/verify",wrap(&zct_slms::ticket_mail::verifyCode),{Post});
  app.registerHandler("/api/v1/auth/authorize/start",wrap(&zct_slms::authorization::start),{Post});
  app.registerHandler("/api/v1/auth/recovery/options",wrap(zct_slms::human::secured(&zct_slms::recovery::options)),{Post});
  app.registerHandler("/api/v1/auth/recovery/code",wrap(zct_slms::human::secured(&zct_slms::recovery::sendCode)),{Post});
  app.registerHandler("/api/v1/auth/recovery/verify",wrap(&zct_slms::recovery::verifyCode),{Post});
  app.registerHandler("/api/v1/auth/recovery/totp",wrap(zct_slms::human::secured(&zct_slms::recovery::verifyTotp)),{Post});
  app.registerHandler("/api/v1/auth/recovery/passkey/start",wrap(zct_slms::human::secured(&zct_slms::recovery::passkeyStart)),{Post});
  app.registerHandler("/api/v1/auth/recovery/passkey/finish",wrap(&zct_slms::recovery::passkeyFinish),{Post});
  app.registerHandler("/api/v1/auth/recovery/reset",wrap(&zct_slms::recovery::reset),{Post});
  app.registerHandler("/api/v1/tickets/create",wrap(&zct_slms::tickets::create),{Post});
  app.registerHandler("/api/v1/tickets/list",wrap(&zct_slms::tickets::list),{Get});
  app.registerHandler("/api/v1/tickets/image-upload",wrap(&zct_slms::tickets::uploadImage),{Post});
  app.registerHandler("/api/v1/tickets/image",wrap(&zct_slms::tickets::readImage),{Get});
  app.registerHandler("/api/v1/tickets/read",wrap(&zct_slms::tickets::read),{Post});
  app.registerHandler("/api/v1/tickets/reply",wrap(&zct_slms::tickets::reply),{Post});
  app.registerHandler("/api/v1/tickets/close",wrap(&zct_slms::tickets::close),{Post});
  app.registerHandler("/api/v1/tickets/reset-password",wrap(&zct_slms::tickets::resetPassword),{Post});
  app.registerHandler("/api/v1/tickets/mark-all-read",wrap(&zct_slms::tickets::markAllRead),{Post});
  app.registerHandler("/api/v1/tickets/security-targets",wrap(&zct_slms::tickets::securityTargets),{Get});
  app.registerHandler("/api/v1/tickets/reset-security",wrap(&zct_slms::tickets::resetSecurity),{Post});
  app.registerHandler("/api/v1/tickets/remove-passkey",wrap(&zct_slms::tickets::removePasskey),{Post});
  app.registerHandler("/api/v1/tickets/status",wrap(&zct_slms::tickets::status),{Post});
  app.registerHandler("/api/v1/tickets/priority",wrap(&zct_slms::tickets::priority),{Post});
  app.registerHandler("/api/v1/tickets/dashboard",wrap(&zct_slms::tickets::dashboard),{Get});
  app.registerHandler("/api/v1/vouchers/reveal",wrap(&zct_slms::vouchers::reveal),{Post});
  app.registerHandler("/api/v1/vouchers/delete",wrap(&zct_slms::vouchers::remove),{Post});
  app.registerHandler("/api/v1/vouchers/create", wrap(&zct_slms::vouchers::create),
                      {Post});
  app.registerHandler("/api/v1/vouchers/list", wrap(&zct_slms::vouchers::list),
                      {Get});
  app.registerHandler("/api/v1/vouchers/status", wrap(&zct_slms::vouchers::status),
                      {Get});
  app.registerHandler("/api/v1/vouchers/redeem", wrap(&zct_slms::vouchers::redeem),
                      {Post});
  app.registerHandler("/api/v1/auth/invite/register",
                      wrap(zct_slms::human::secured(&zct_slms::vouchers::registerInvite)),
                      {Post});
  app.registerHandler("/api/v1/app/update",
                      wrap(&zct_slms::inside::api::v1::app::update::handle), {Post});
  zct_slms::inside::api::v1::common::forcePassword = &zct_slms::portal::forceRequired;
  zct_slms::inside::api::v1::common::gateLogin =
      [](Json::Value data, const std::string &ip, const std::string &ua) {
        if (zct_slms::portal::forceRequired(data["user_type"].asString(),
                                       data["user_id"].asInt64())) {
          data["force_password_change"] = true;
          return data;
        }
        return zct_slms::portal_auth::gate(data, ip, ua);
      };
  zct_slms::identity::mfaOwner = &zct_slms::portal_auth::oauthOwner;
  zct_slms::identity::mfaComplete = &zct_slms::portal_auth::oauthComplete;
  app.registerHandler("/api/v1/auth/factors/status",
                      wrap(&zct_slms::portal_auth::status), {Get});
  app.registerHandler(
      "/api/v1/auth/factors/passkey/start",
      wrap(zct_slms::human::secured(&zct_slms::portal_auth::primaryStart)), {Post});
  app.registerHandler(
      "/api/v1/auth/factors/primary",
      wrap([](const drogon::HttpRequestPtr &req, zct_slms::identity::Callback &&cb) {
        if (zct_slms::inside::api::v1::common::paramStr(req, "method") == "totp")
          zct_slms::human::secured (&zct_slms::portal_auth::primaryFinish)(req,
                                                                 std::move(cb));
        else
          zct_slms::portal_auth::primaryFinish(req, std::move(cb));
      }),
      {Post});
  app.registerHandler("/api/v1/auth/factors/code",
                      wrap(&zct_slms::portal_auth::sendCode), {Post});
  app.registerHandler("/api/v1/auth/factors/oauth/start",
                      wrap([](const drogon::HttpRequestPtr& req,zct_slms::identity::Callback&& cb){if(zct_slms::inside::api::v1::common::paramStr(req,"action")!="mfa"){zct_slms::identity::fail(cb,"此入口仅用于二次验证");return;}zct_slms::identity::oauthStart(req,std::move(cb));}), {Post});
  app.registerHandler("/api/v1/auth/onboarding", wrap(&zct_slms::portal::onboarding),
                      {Get, Post});
  app.registerHandler("/api/v1/admin/support/users", wrap(&zct_slms::portal::staff),
                      {Get, Post});
  app.registerHandler("/api/v1/admin/moderation",
                      wrap(&zct_slms::portal::moderationSettings), {Get, Post});
  app.registerHandler("/api/v1/support/review/approve",wrap(&zct_slms::review::approve),{Post});
  app.registerHandler("/api/v1/support/review", wrap(&zct_slms::review::queue),
                      {Get});
  zct_slms::inside::api::v1::common::contentGuard =
      [](const drogon::HttpRequestPtr &req) {
        if (req->method() != drogon::Post)
          return;
        const auto &path = req->path();
        if (path == "/api/v1/app/create" || path == "/api/v1/app/notice" ||
            path == "/api/v1/app/version/create" ||
            path == "/api/v1/auth/profile" || path == "/api/v1/admin/account" ||
            path == "/api/v1/auth/connect/verify" ||
            path == "/api/v1/admin/owner/create" ||
            path == "/api/v1/app/subusers")
          for (auto field : {"name", "description", "notice", "version",
                             "changelog", "minimum_version", "download_url", "nickname",
                             "display_name", "username", "new_username"})
            zct_slms::moderation::check(
                zct_slms::inside::api::v1::common::paramStr(req, field));
      };
  app.registerHandler("/api/v1/admin/factors/settings",
                      wrap(&zct_slms::human::adminSettings), {Get, Post});
  app.registerHandler("/api/v1/auth/captcha", wrap(&zct_slms::human::options),
                      {Get});
  app.registerHandler("/api/v1/auth/factors", wrap(&zct_slms::factors::account),
                      {Get, Post});
  app.registerHandler("/api/v1/auth/factors/verify",
                      wrap(&zct_slms::portal_auth::finish), {Post});
  app.registerHandler("/api/v1/admin/platform-config",
                      wrap(&zct_slms::platform::handle), {Get, Post});
  app.registerHandler("/api/v1/auth/balance",wrap(&zct_slms::inside::api::v1::auth::balance::handle),{Get});
  app.registerHandler("/api/v1/admin/mail-templates", wrap(&zct_slms::identity::templatesSettings), {Get, Post});
  app.registerHandler("/api/v1/admin/identity/settings",
                      wrap(&zct_slms::identity::settings), {Get, Post});
  app.registerHandler("/api/v1/auth/connect/options",
                      wrap(&zct_slms::identity::options), {Get});
  app.registerHandler("/api/v1/auth/connect/initial-password",
                      wrap(&zct_slms::identity::initialPassword), {Get, Post});
  app.registerHandler("/api/v1/auth/connect/code",
                      wrap(zct_slms::human::secured(&zct_slms::identity::sendCode)),
                      {Post});
  app.registerHandler("/api/v1/auth/connect/verify",
                      wrap(&zct_slms::identity::verifyCode), {Post});
  app.registerHandler("/api/v1/auth/connect/bindings",
                      wrap(&zct_slms::identity::bindings), {Get});
  app.registerHandler("/api/v1/auth/connect/start",
                      wrap(zct_slms::human::secured(&zct_slms::identity::oauthStart)),
                      {Post});
  app.registerHandler("/api/v1/auth/connect/callback/github",
                      wrap(&zct_slms::identity::oauthCallback), {Get});
  app.registerHandler("/api/v1/auth/connect/callback/microsoft",
                      wrap(&zct_slms::identity::oauthCallback), {Get});
  app.registerHandler("/api/v1/auth/connect/exchange",
                      wrap(&zct_slms::identity::exchange), {Post});

  app.registerHandler("/api/v1/ping", wrap(&zct_slms::inside::api::v1::ping::handle),
                      {Get});

  app.registerHandler("/api/v1/system/ping",
                      wrap(&zct_slms::inside::api::v1::system::ping::handle), {Get});
  app.registerHandler("/api/v1/system/configs",
                      wrap(&zct_slms::inside::api::v1::system::configs::handle),
                      {Get});

  app.registerHandler("/api/v1/auth/admin/login",
                      wrap(zct_slms::human::secured(
                          &zct_slms::inside::api::v1::auth::admin::login::handle)),
                      {Post});
  app.registerHandler("/api/v1/accounts/manage",wrap(&zct_slms::accounts::manage),{Post});
  app.registerHandler("/api/v1/accounts/closure",wrap(&zct_slms::accounts::requestClosure),{Post});
  app.registerHandler("/api/v1/tickets/approve-closure",wrap(&zct_slms::accounts::approveClosure),{Post});
  app.registerHandler("/api/v1/auth/owner/login",
                      wrap(zct_slms::human::secured(
                          &zct_slms::inside::api::v1::auth::owner::login::handle)),
                      {Post});
  app.registerHandler("/api/v1/auth/subuser/login",
                      wrap(zct_slms::human::secured(
                          &zct_slms::inside::api::v1::auth::subuser::login::handle)),
                      {Post});
  app.registerHandler("/api/v1/auth/logout",
                      wrap(&zct_slms::inside::api::v1::auth::logout::handle),
                      {Post});
  app.registerHandler("/api/v1/app/subuser-access",
                      wrap(&zct_slms::inside::api::v1::app::subuser_access::handle),
                      {Post});
  app.registerHandler("/api/v1/app/subusers",
                      wrap(&zct_slms::inside::api::v1::app::subusers::handle),
                      {Get, Post});
  app.registerHandler(
      "/api/v1/admin/subuser-policy",
      wrap(&zct_slms::inside::api::v1::admin::subuser_policy::handle), {Post});
  app.registerHandler("/api/v1/auth/password",
                      wrap(&zct_slms::inside::api::v1::auth::password::handle),
                      {Post});
  app.registerHandler("/api/v1/auth/profile",
                      wrap(&zct_slms::inside::api::v1::auth::profile::handle),
                      {Get, Post});
  app.registerHandler("/api/v1/admin/license-types",
                      wrap(&zct_slms::inside::api::v1::admin::license_types::handle),
                      {Post});
  app.registerHandler("/api/v1/app/secret/view",
                      wrap(&zct_slms::inside::api::v1::app::secret::view::handle),
                      {Post});
  app.registerHandler("/api/v1/admin/account",
                      wrap(&zct_slms::inside::api::v1::admin::account::handle),
                      {Post});
  app.registerHandler("/api/v1/admin/avatar-limit",
                      wrap(&zct_slms::inside::api::v1::admin::avatar_limit::handle),
                      {Post});
  app.registerHandler(
      "/api/v1/admin/encoding-policy",
      wrap(&zct_slms::inside::api::v1::admin::encoding_policy::handle), {Post});

  app.registerHandler("/api/v1/admin/owner/list",
                      wrap(&zct_slms::inside::api::v1::admin::owner::list::handle),
                      {Get});
  app.registerHandler("/api/v1/admin/owner/create",
                      wrap(&zct_slms::inside::api::v1::admin::owner::create::handle),
                      {Post});
  app.registerHandler(
      "/api/v1/admin/owner/balance",
      wrap(&zct_slms::inside::api::v1::admin::owner::balance::handle), {Post});
  app.registerHandler(
      "/api/v1/admin/license-timer/pause",
      wrap(&zct_slms::inside::api::v1::admin::license_timer::pause::handle), {Post});
  app.registerHandler(
      "/api/v1/admin/license-timer/resume",
      wrap(&zct_slms::inside::api::v1::admin::license_timer::resume::handle),
      {Post});
  app.registerHandler("/api/v1/admin/audit/list",
                      wrap(&zct_slms::inside::api::v1::admin::audit::list::handle),
                      {Get});

  app.registerHandler("/api/v1/app/create",
                      wrap(&zct_slms::inside::api::v1::app::create::handle), {Post});
  app.registerHandler("/api/v1/app/list",
                      wrap(&zct_slms::inside::api::v1::app::list::handle), {Get});
  app.registerHandler(
      "/api/v1/app/secret/regenerate",
      wrap(&zct_slms::inside::api::v1::app::secret::regenerate::handle), {Post});
  app.registerHandler("/api/v1/app/delete",
                      wrap(&zct_slms::inside::api::v1::app::delete_::handle),
                      {Post});

  app.registerHandler("/api/v1/app/binding",
                      wrap(&zct_slms::inside::api::v1::app::binding::handle),
                      {Post});
  app.registerHandler("/api/v1/app/set-decode",
                      wrap(&zct_slms::inside::api::v1::app::set_decode::handle),
                      {Post});
  app.registerHandler("/api/v1/app/sign-enable",
                      wrap(&zct_slms::inside::api::v1::app::sign_enable::handle),
                      {Post});
  app.registerHandler("/api/v1/app/notice",
                      wrap(&zct_slms::inside::api::v1::app::notice::handle), {Post});
  app.registerHandler(
      "/api/v1/app/version/create",
      wrap(&zct_slms::inside::api::v1::app::version::create_::handle), {Post});
  app.registerHandler("/api/v1/app/version/latest",
                      wrap(&zct_slms::inside::api::v1::app::version::latest::handle),
                      {Get});
  app.registerHandler("/api/v1/app/channel/list",
                      wrap(&zct_slms::inside::api::v1::app::channel::list_::handle),
                      {Get});

  app.registerHandler("/api/v1/license/create",
                      wrap(&zct_slms::inside::api::v1::license::create::handle),
                      {Post});
  app.registerHandler("/api/v1/license/delete",
                      wrap(&zct_slms::inside::api::v1::license::delete_::handle),
                      {Post});
  app.registerHandler("/api/v1/license/ban",
                      wrap(&zct_slms::inside::api::v1::license::ban::handle),
                      {Post});
  app.registerHandler("/api/v1/license/unban",
                      wrap(&zct_slms::inside::api::v1::license::unban::handle),
                      {Post});
  app.registerHandler("/api/v1/license/add-time",
                      wrap(&zct_slms::inside::api::v1::license::add_time::handle),
                      {Post});
  app.registerHandler("/api/v1/license/set-time",
                      wrap(&zct_slms::inside::api::v1::license::set_time::handle),
                      {Post});
  app.registerHandler("/api/v1/license/set-type",
                      wrap(&zct_slms::inside::api::v1::license::set_type::handle),
                      {Post});
  app.registerHandler("/api/v1/license/unbind",
                      wrap(&zct_slms::inside::api::v1::license::unbind::handle),
                      {Post});
  app.registerHandler("/api/v1/license/list",
                      wrap(&zct_slms::inside::api::v1::license::list::handle),
                      {Get});

  app.registerHandler("/api/v1/license/unbind-info",
                      wrap(&zct_slms::inside::api::v1::license::unbind_info::handle),
                      {Get, Post});

  app.registerHandler(
      "/api/v1/client/license/verify",
      wrap(&zct_slms::inside::api::v1::client::license::verify::handle),
      {Post, Get});
  // Heartbeats revalidate expiry, ban and binding.
  app.registerHandler(
      "/api/v1/client/license/heartbeat",
      wrap(&zct_slms::inside::api::v1::client::license::verify::handle), {Post});
  app.registerHandler(
      "/api/v1/client/license/remaining",
      wrap(&zct_slms::inside::api::v1::client::license::remaining::handle), {Get});
  app.registerHandler(
      "/api/v1/client/license/status",
      wrap(&zct_slms::inside::api::v1::client::license::status::handle), {Get});
  app.registerHandler("/api/v1/client/app/notice",
                      wrap(&zct_slms::inside::api::v1::client::app::notice::handle),
                      {Get});
  app.registerHandler("/api/v1/client/app/version",
                      wrap(&zct_slms::inside::api::v1::client::app::version::handle),
                      {Get});
  app.registerHandler(
      "/api/v1/client/app/channels",
      wrap(&zct_slms::inside::api::v1::client::app::channels::handle), {Get});

  zct_slms::logger().INFO("All /api/v1 routes registered");
}
} // namespace zct_slms::api

#endif // ZCT_SLMS_API_V1_REGISTER_ALL
