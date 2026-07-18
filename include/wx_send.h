#pragma once
#include <string>

namespace WeixinSend
{
    bool SendImage(const std::string& wxid, const std::string& imgPath);
    bool SendText(const std::string& wxidorgid, const std::string& msg);
    bool DecodePic(const std::string& enc_pic_path, const std::string& dec_pic_path);

    // appmsg/XML (msgtype 49) send on the VERIFIED sendappmsg CGI submit path
    // (WeChat 4.1.10.27).  Natively default-constructs the nested protobuf
    // SendAppMsgRequest{ BaseRequest, AppMsg } via the IDA-verified ctors
    // (offset::sendappmsg_req_ctor / appmsg_msg_ctor / sendappmsg_base_ctor),
    // injects fromusername(self)/tousername/type/content(XML)/clientmsgid as
    // ArenaStringPtr members with the correct has-bits, then replays the CGI
    // through the passively-captured network manager (g_AppMsgSubmitManager)
    // via offset::appmsg_submit.  The manager deep-copies (reads) the request,
    // so the constructed objects are intentionally leaked (no allocator
    // mismatch).  Requires one prior real card send/forward to capture the
    // manager for the current login.  type defaults to 5 (link appmsg).
    bool SendAppMsg(const std::string& to_wxid, const std::string& xml,
                    uint64_t type);
}
