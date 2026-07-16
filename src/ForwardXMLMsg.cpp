#include "json.hpp"
#include "httplib.h"

#include <windows.h>
#include "global.h"
#include "wx_send_xml.h"

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

            // The XML forwarding vtables in wx_send_xml.cpp are from an old
            // WeChat build and have not been validated against 4.1.10.27.
            // Reject valid-looking payloads rather than risking a process
            // crash through a stale object layout.
            resp["ret"] = -3;
            resp["retmsg"] = "XML send offsets are not runtime-verified for WeChat 4.1.10.27";
            res.set_content(resp.dump(), "application/json; charset=utf-8");
            return;

            bool success = false;
            try {
                WeixinSendXML::Initialize();
                success = WeixinSendXML::ForwardXmlMessage(wxid, xml);
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

            res.set_content(resp.dump(), "application/json; charset=utf-8");
        });
}
