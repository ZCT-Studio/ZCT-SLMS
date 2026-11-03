#pragma once
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
namespace zct_slms::dotenv {
inline std::string_view trim(std::string_view text) {
  const auto start=text.find_first_not_of(" \t\r");if(start==text.npos)return {};
  const auto end=text.find_last_not_of(" \t\r");return text.substr(start,end-start+1);
}
inline bool keyChar(char ch,bool first=false) {
 return (ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||ch=='_'||(!first&&ch>='0'&&ch<='9');
}
inline size_t load(const std::filesystem::path& file=".env") {
 std::error_code ec;const bool exists=std::filesystem::exists(file,ec);
 if(ec)throw std::runtime_error("Cannot inspect .env file");if(!exists)return 0;
 const auto size=std::filesystem::file_size(file,ec);if(ec||size>1024*1024)throw std::runtime_error("Cannot read .env file or file exceeds 1 MiB");
 std::ifstream input(file,std::ios::binary);if(!input)throw std::runtime_error("Cannot read .env file");
 std::map<std::string,std::string> values;std::string line;size_t number=0;
 while(std::getline(input,line)) {
  ++number;const auto fail=[&](){throw std::runtime_error("Invalid .env syntax at line "+std::to_string(number));};
  if(number==1&&line.starts_with("\xEF\xBB\xBF"))line.erase(0,3);
  if(line.find('\0')!=line.npos||line.size()>65536)fail();
  auto text=trim(line);if(text.empty()||text.front()=='#')continue;
  if(text.starts_with("export ")||text.starts_with("export\t"))text=trim(text.substr(7));
  auto equal=text.find('=');if(equal==text.npos)fail();auto key=trim(text.substr(0,equal));
  if(key.empty()||!keyChar(key.front(),true))fail();for(char ch:key)if(!keyChar(ch))fail();
  text=trim(text.substr(equal+1));std::string value;
  if(!text.empty()&&(text.front()=='\''||text.front()=='"')) {
   const auto quote=text.front();size_t i=1;bool closed=false;
   for(;i<text.size();++i){char ch=text[i];if(ch==quote){closed=true;++i;break;}
    if(quote=='"'&&ch=='\\'&&i+1<text.size()){
     char next=text[++i];switch(next){case 'n':value+='\n';break;case 'r':value+='\r';break;case 't':value+='\t';break;case '\\':value+='\\';break;case '"':value+='"';break;default:value+='\\';value+=next;break;}
    }else value+=ch;
   }
   if(!closed)fail();auto rest=trim(text.substr(i));if(!rest.empty()&&rest.front()!='#')fail();
  }else{
   size_t end=text.size();for(size_t i=0;i<text.size();++i)if(text[i]=='#'&&(i==0||text[i-1]==' '||text[i-1]=='\t')){end=i;break;}
   value=std::string(trim(text.substr(0,end)));
  }
  values.insert_or_assign(std::string(key),std::move(value));
 }
 if(input.bad())throw std::runtime_error("Cannot read .env file");
 size_t loaded=0;for(const auto& [key,value]:values){if(std::getenv(key.c_str())!=nullptr)continue;
#ifdef _WIN32
  if(_putenv_s(key.c_str(),value.c_str())!=0)throw std::runtime_error("Cannot set environment from .env file");
#else
  if(setenv(key.c_str(),value.c_str(),0)!=0)throw std::runtime_error("Cannot set environment from .env file");
#endif
  ++loaded;
 }
 return loaded;
}
}
