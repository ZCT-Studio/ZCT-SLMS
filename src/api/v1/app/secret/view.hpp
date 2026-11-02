#ifndef ZCT_SLMS_API_V1_APP_SECRET_VIEW
#define ZCT_SLMS_API_V1_APP_SECRET_VIEW
#include "api/v1/uih.h"
#include "services/app_secret_policy.hpp"
namespace zct_slms::inside::api::v1::app::secret::view {
inline void handle(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
    namespace c=zct_slms::inside::api::v1::common;
    const auto type=c::currentUserType(req); const auto uid=c::currentUserId(req);
    auto app=zct_slms::repo::AppRepo::findByAppid(c::paramStr(req,"app_id"));
    auto fail=[&](int code,const char* message){cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code,message)));};
    if(!app){fail(zct_slms::api::ErrorCode::APP_NOT_FOUND,"应用不存在");return;}
    if(type!="ADMIN" && (type!="USER" || app->owner_id!=uid)){fail(zct_slms::api::ErrorCode::UNAUTHORIZED,"无权查看此应用密钥");return;}
    const auto password=c::paramStr(req,"password"); bool valid=false;
    if(type=="ADMIN"){auto u=zct_slms::repo::AdminRepo::findById(uid);valid=u && c::sensitiveAuthorization(req,password);}
    else {auto u=zct_slms::repo::UserRepo::findById(uid);valid=u && c::sensitiveAuthorization(req,password);}
    if(!valid){fail(zct_slms::api::ErrorCode::UNAUTHORIZED,"密码错误");return;}
    if(!zct_slms::service::claimAppSecret(*app)){fail(zct_slms::api::ErrorCode::UNAUTHORIZED,"平台已限制密钥只能查看一次，此密钥已展示过；如遗失请重置密钥");return;}
    Json::Value result;result["secret"]=app->secret;
    auto response=drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(result));
    response->addHeader("Cache-Control","no-store");cb(response);
}
}
#endif
