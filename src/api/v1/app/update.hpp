#pragma once
#include "api/v1/uih.h"
#include "services/moderation.hpp"
namespace zct_slms::inside::api::v1::app::update {
inline void handle(const drogon::HttpRequestPtr &req,
                   std::function<void(const drogon::HttpResponsePtr &)> &&cb) {
  namespace c = zct_slms::inside::api::v1::common;
  try {
    auto a = zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
    auto app = zct_slms::repo::AppRepo::findByAppid(c::paramStr(req, "app_id"));
    if (!a.success || !app ||
        (a.user_type != "ADMIN" &&
         (a.user_type != "USER" || app->owner_id != a.user_id)))
      throw std::runtime_error("无权编辑此应用");
    auto name = c::paramStr(req, "name"),
         description = c::paramStr(req, "description");
    if (name.empty() || name.size() > 128 || description.size() > 4096)
      throw std::runtime_error("应用名称或介绍长度无效");
    zct_slms::moderation::check(name);
    zct_slms::moderation::check(description);
    zct_slms::db::Database::instance().execParams(
        "UPDATE apps SET name = ?,description = ?,updated_at = ? WHERE id = ?",
        name, description, static_cast<int64_t>(std::time(nullptr)), app->id);
    c::reviewContentChanged("APP","USER",app->id);
    zct_slms::repo::AuditRepo::log(a.user_type, a.user_id, "UpdateAppDetails", "APP",
                              app->id, "", "success", c::clientIp(req), "{}",
                              std::time(nullptr));
    cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
  } catch (const std::exception &e) {
    cb(drogon::HttpResponse::newHttpJsonResponse(
        zct_slms::api::makeFail(1004, e.what())));
  }
}
} // namespace zct_slms::inside::api::v1::app::update
