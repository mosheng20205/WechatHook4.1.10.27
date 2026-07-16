#pragma once
#include <string>

namespace WeixinSend
{
    bool SendImage(const std::string& wxid, const std::string& imgPath);
    bool SendText(const std::string& wxidorgid, const std::string& msg);
    bool DecodePic(const std::string& enc_pic_path, const std::string& dec_pic_path);
}
