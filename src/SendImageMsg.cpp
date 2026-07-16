#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include <filesystem>
#include "global.h"
#include "wx_send.h"
#include "SendImageMsg.h"

using json = nlohmann::json;

void Route_SendImageMsg(httplib::Server& svr)
{
    svr.Post("/SendImgMsg", [](const httplib::Request& req, httplib::Response& res)
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
            std::string path = reqJson.value("path", "");

            res.set_header("Content-Type", "application/json; charset=utf-8");
            if (!g_IsLogin) {
                resp["ret"] = -2;
                resp["msg"] = "not logged in";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }
            if (wxidorgid.empty() || path.empty() || path.size() > 32768) {
                resp["ret"] = -1;
                resp["msg"] = "wxidorgid and path are required";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            std::error_code fileError;
            const std::filesystem::path imagePath(path);
            if (!std::filesystem::is_regular_file(imagePath, fileError) ||
                fileError || std::filesystem::file_size(imagePath, fileError) == 0 ||
                fileError) {
                resp["ret"] = -1;
                resp["msg"] = "image path is not a readable regular file";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            // The image message object layout has not been revalidated for
            // WeChat 4.1.10.27.  Do not enter the old offset-based builder:
            // a plausible executable address is not proof that its object
            // layout is compatible, and an invalid layout can terminate
            // Weixin.exe.  Keep the endpoint explicit until IDA/runtime
            // verification supplies the new vtables and call boundary.
            resp["ret"] = -3;
            resp["retmsg"] = "image send offsets are not runtime-verified for WeChat 4.1.10.27";
            resp["queued"] = false;
            res.set_content(resp.dump(), "application/json; charset=utf-8");
            return;

            const bool queued = WeixinSend::SendImage(wxidorgid, path);

            resp["ret"] = queued ? 0 : -3;
            resp["retmsg"] = queued ? "queued" : "send failed";
            resp["queued"] = queued;

            res.set_content(resp.dump(), "application/json; charset=utf-8");
        });
}
