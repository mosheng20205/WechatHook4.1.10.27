#pragma once
#include <string>

namespace WeixinSend
{
    bool SendImage(const std::string& wxid, const std::string& imgPath);
    bool SendText(const std::string& wxidorgid, const std::string& msg);
    bool DecodePic(const std::string& enc_pic_path, const std::string& dec_pic_path,
                   uint32_t mode = 1, bool wide_path = true);

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

    // Experimental: insert a LOCAL system-tip message (e.g. the recall notice
    // "<name> 撤回了一条消息") into the conversation `talker` via the native
    // local-sysmsg inserter (offset::revoke_tip_insert / sub_184C280B0).  This
    // does NOT touch the network -- it only writes a local message + refreshes
    // the UI, so it is used to add the recall notice on top of an anti-revoke
    // preserved bubble.  Must be called from a worker thread (never inside a
    // receive hook).  SEH-guarded: a layout/type mismatch faults inside Weixin
    // and is translated to false rather than terminating the host.  NOTE: the
    // native inserter hard-codes sysmsg type="paymsg", so the rendered result
    // is UNVERIFIED until confirmed on a real client.
    bool InsertLocalSysTip(const std::string& talker, const std::string& text);
}
