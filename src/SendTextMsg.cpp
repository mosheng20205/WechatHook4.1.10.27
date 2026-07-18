#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include <filesystem>
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

            res.set_header("Content-Type", "application/json; charset=utf-8");
            if (src_path.empty() || dst_path.empty() || src_path.size() > 32768 ||
                dst_path.size() > 32768 || src_path.find('\0') != std::string::npos ||
                dst_path.find('\0') != std::string::npos) {
                resp["ret"] = -1;
                resp["msg"] = "src_path and dst_path are required";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }
            std::error_code fileError;
            if (!std::filesystem::is_regular_file(src_path, fileError) || fileError ||
                std::filesystem::file_size(src_path, fileError) == 0 || fileError) {
                resp["ret"] = -1;
                resp["msg"] = "src_path is not a readable regular file";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            // dec_pic_call (RVA 0x493E70) verified in IDA for 4.1.10.27:
            // sub_180493E70(a1, a2, mode) reads a1[2]/a1[3] as length/capacity
            // with the WeixinString ABI, decrypts a1 into a2 under `mode`.
            OutputDebugStringA(("Decode_Pic src_path: " + src_path + "\n").c_str());
            OutputDebugStringA(("Decode_Pic dst_path: " + dst_path + "\n").c_str());


            const bool ok = WeixinSend::DecodePic(src_path, dst_path,
                reqJson.value("mode", 1u), reqJson.value("wide", true));


            resp["ret"] = ok ? 0 : -3;
            resp["retmsg"] = ok ? "success" : "decode failed";

            res.set_content(resp.dump(), "application/json; charset=utf-8");
        });

}
