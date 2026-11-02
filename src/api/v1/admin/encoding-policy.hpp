#pragma once
#include <sstream>
#include "api/v1/uih.h"
namespace zct_slms::inside::api::v1::admin::encoding_policy {
inline void handle(const drogon::HttpRequestPtr& req,std::function<void(const drogon::HttpResponsePtr&)>&& cb){
 const auto auth=zct_slms::service::AuthService::authenticateSession(zct_slms::inside::api::v1::common::authBearer(req));
 if(!auth.success||auth.user_type!="ADMIN"){cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::UNAUTHORIZED,"需要管理员登录")));return;}
 auto raw=zct_slms::inside::api::v1::common::paramStr(req,"modes");std::string cleaned;std::istringstream input(raw);std::string mode;
 while(std::getline(input,mode,',')){if(mode!="NONE"&&mode!="BASE64"&&mode!="HEX"&&mode!="AES128-GCM"&&mode!="AES256-GCM"&&mode!="CHACHA20-POLY1305"){cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(zct_slms::api::ErrorCode::VALIDATION,"无效加密方式")));return;}if(!cleaned.empty())cleaned+=",";cleaned+=mode;}
 if(cleaned.empty())cleaned="NONE";zct_slms::repo::ConfigRepo::set("allowed_encoding_modes",cleaned,std::time(nullptr));cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk()));
}}
