#include "json.hpp"
#include "httplib.h"

#include <windows.h>
#include "global.h"
#include "wx_send_xml.h"
#include "wx_send.h"

#include "ForwardXMLMsg.h"



using json = nlohmann::json;

void Route_ForwardXMLMsg(httplib::Server& svr)
{
    svr.Post("/ForwardXMLMsg", [](const httplib::Request& req, httplib::Response& res)
        {
            json reqJson;
            json resp;

            try
            {
                reqJson = json::parse(req.body);
            }
            catch (...)
            {
                resp["ret"] = -1;
                resp["msg"] = "invalid json";
                res.set_content(resp.dump(), "application/json");
                return;
            }

            std::string wxid = reqJson.value("to_wxid", "");
            std::string xml = reqJson.value("content", "");

            // appmsg "type" carried by the sendappmsg CGI request (int field @
            // AppMsg+0x24).  Defaults to 5 (link/article appmsg, matches the
            // captured real send); overridable per-request for other appmsg
            // subtypes without recompiling.
            uint64_t typeVal = reqJson.value("type", (uint64_t)5);

            res.set_header("Content-Type", "application/json; charset=utf-8");
            if (!g_IsLogin) {
                resp["ret"] = -2;
                resp["msg"] = "not logged in";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }
            if (wxid.empty() || xml.empty() || xml.size() > 1024 * 1024 ||
                wxid.find('\0') != std::string::npos ||
                xml.find('\0') != std::string::npos) {
                resp["ret"] = -1;
                resp["msg"] = "to_wxid and content are required";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            // The sendappmsg CGI is replayed through the network manager
            // captured passively at the F120 submit hook.  If it hasn't been
            // captured yet this login, the caller must first send/forward one
            // real card (in any chat) so the manager becomes known.
            if (g_AppMsgSubmitManager == 0) {
                resp["ret"] = -5;
                resp["retmsg"] = "sendappmsg manager not captured yet: send or forward "
                                 "one link/card manually (any chat) after login, then retry.";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            bool success = false;
            try {
                success = WeixinSend::SendAppMsg(wxid, xml, typeVal);
            } catch (...) {
                success = false;
            }

            if (success) {
                resp["ret"] = 0;
                resp["retmsg"] = "success";
            }
            else {
                resp["ret"] = 1;
                resp["retmsg"] = "fail";
            }
            resp["type"] = typeVal;

            res.set_content(resp.dump(), "application/json; charset=utf-8");
        });
}
