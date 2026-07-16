#include "httplib.h"
#include "http_routes.h"
#include "SendTextMsg.h"
#include "GetSelfProfile.h"
#include "ForwardXMLMsg.h"
#include "SendImageMsg.h"
#include "QueryDB.h"
#include "global.h"
#include "json.hpp"

void RegisterRoutes(httplib::Server& svr)
{
    svr.Get("/", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_content("{\"status\":\"ok\",\"service\":\"WeChat-Hook\"}", "application/json; charset=utf-8");
    });

    Route_SendTextMsg(svr);
    RegisterGetSelfProfile(svr);
    RegisterGetContact(svr);
    Route_ForwardXMLMsg(svr);
    Route_SendImageMsg(svr);
    Route_QueryDB(svr);

    // Group auto-reply is opt-in.  Keep it disabled by default to prevent a
    // test message from replying to every member of a room accidentally.
    svr.Post("/AutoReply/config", [](const httplib::Request& req, httplib::Response& res)
    {
        using json = nlohmann::json;
        json response;
        try {
            const json body = json::parse(req.body.empty() ? "{}" : req.body);
            if (!body.contains("group_enabled") ||
                !(body["group_enabled"].is_boolean() ||
                  body["group_enabled"].is_number_integer())) {
                response["ret"] = -1;
                response["msg"] = "group_enabled boolean is required";
            } else {
                const bool enabled = body["group_enabled"].is_boolean()
                    ? body["group_enabled"].get<bool>()
                    : body["group_enabled"].get<int>() != 0;
                InterlockedExchange64(
                    reinterpret_cast<volatile LONG64*>(&g_AutoReplyGroupEnabled),
                    enabled ? 1 : 0);
                response["ret"] = 0;
                response["group_enabled"] = enabled;
            }
        } catch (...) {
            response["ret"] = -1;
            response["msg"] = "invalid json";
        }
        res.set_content(response.dump(), "application/json; charset=utf-8");
    });
}
