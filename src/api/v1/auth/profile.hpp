#ifndef ZCT_SLMS_API_V1_AUTH_PROFILE
#define ZCT_SLMS_API_V1_AUTH_PROFILE
#include "api/v1/uih.h"
namespace zct_slms::inside::api::v1::auth::profile {
inline void handle(const drogon::HttpRequestPtr& req,std::function<void(const drogon::HttpResponsePtr&)>&& cb){
 namespace c=zct_slms::inside::api::v1::common;
 const auto auth=zct_slms::service::AuthService::authenticateSession(c::authBearer(req));
 auto fail=[&](int code,const char* m){cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeFail(code,m)));};
 if(!auth.success || (auth.user_type!="ADMIN" && auth.user_type!="SUPPORT" && auth.user_type!="USER" && auth.user_type!="SUBUSER")){fail(zct_slms::api::ErrorCode::UNAUTHORIZED,"未登录或登录已过期");return;}
 const auto prefix=std::string("profile:")+auth.user_type+":"+std::to_string(auth.user_id)+":";
 if(req->method()==drogon::Post){
  const auto name=c::paramStr(req,"nickname"); const auto avatar=c::paramStr(req,"avatar");
  if(name.empty()||name.size()>96){fail(zct_slms::api::ErrorCode::VALIDATION,"昵称不能为空或过长");return;}
  const auto max_avatar=zct_slms::repo::ConfigRepo::getI64("max_avatar_bytes",1048576);
  const auto max_encoded=static_cast<size_t>(max_avatar*4/3+256);
  if(avatar.size()>max_encoded || (!avatar.empty() && avatar.rfind("data:image/png;base64,",0)!=0 && avatar.rfind("data:image/jpeg;base64,",0)!=0 && avatar.rfind("data:image/webp;base64,",0)!=0)){fail(zct_slms::api::ErrorCode::VALIDATION,"头像超过管理员设置的大小上限或格式不支持");return;}
  if(!avatar.empty()){auto pos=avatar.find(','); if(avatar.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",pos+1)!=std::string::npos){fail(zct_slms::api::ErrorCode::VALIDATION,"头像数据无效");return;}}
  const auto now=std::time(nullptr);zct_slms::repo::ConfigRepo::set(prefix+"nickname",name,now);zct_slms::repo::ConfigRepo::set(prefix+"avatar",avatar,now);c::reviewContentChanged("USER",auth.user_type,auth.user_id);
 }
 std::string default_name=auth.username;if(auth.user_type=="USER"){auto user=zct_slms::repo::UserRepo::findById(auth.user_id);if(user&&!user->display_name.empty())default_name=user->display_name;}else if(auth.user_type=="ADMIN"||auth.user_type=="SUPPORT"){auto user=zct_slms::repo::AdminRepo::findById(auth.user_id);if(user&&!user->display_name.empty())default_name=user->display_name;}else{auto rows=zct_slms::db::Database::instance().queryParams("SELECT display_name FROM sub_users WHERE id = ?",auth.user_id);if(!rows.empty()&&!zct_slms::repo::getStr(rows[0],"display_name").empty())default_name=zct_slms::repo::getStr(rows[0],"display_name");}
 Json::Value v;v["nickname"]=zct_slms::repo::ConfigRepo::get(prefix+"nickname",default_name);v["avatar"]=zct_slms::repo::ConfigRepo::get(prefix+"avatar","");v["user_id"]=static_cast<Json::Int64>(auth.user_id);v["username"]=auth.username;v["user_type"]=auth.user_type;
 cb(drogon::HttpResponse::newHttpJsonResponse(zct_slms::api::makeOk(v)));
}
}
#endif
