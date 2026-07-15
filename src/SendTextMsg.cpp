#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include "global.h"
#include "wx_send.h"
#include "SendTextMsg.h"

using json = nlohmann::json;

void Route_SendTextMsg(httplib::Server& svr)
{
    svr.Post("/SendTextMsg", [](const httplib::Request& req, httplib::Response& res)
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

            std::string wxidorgid = reqJson.value("wxidorgid", "");
            std::string msg = reqJson.value("msg", "");

            res.set_header("Content-Type", "application/json; charset=utf-8");
            if (!g_IsLogin) {
                resp["ret"] = -2;
                resp["msg"] = "not logged in";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }
            if (wxidorgid.empty() || msg.empty()) {
                resp["ret"] = -1;
                resp["msg"] = "wxidorgid and msg are required";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            const bool queued = WeixinSend::SendText(wxidorgid, msg);

            resp["ret"] = queued ? 0 : -3;
            resp["retmsg"] = queued ? "queued" : "send failed";
            resp["queued"] = queued;

            res.set_content(resp.dump(), "application/json");
        });

    svr.Post("/Decode_Pic", [](const httplib::Request& req, httplib::Response& res)
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
			

            std::string src_path = reqJson.value("src_path", "");
            std::string dst_path = reqJson.value("dst_path", "");

            OutputDebugStringA(("Decode_Pic src_path: " + src_path + "\n").c_str());
            OutputDebugStringA(("Decode_Pic dst_path: " + dst_path + "\n").c_str());


            WeixinSend::DecodePic(src_path, dst_path);


            resp["ret"] = 0;
            resp["retmsg"] = "success";

            res.set_content(resp.dump(), "application/json");
        });

}
