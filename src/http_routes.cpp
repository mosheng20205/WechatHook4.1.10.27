#include "httplib.h"
#include "http_routes.h"
#include "SendTextMsg.h"
#include "GetSelfProfile.h"
#include "ForwardXMLMsg.h"
#include "SendImageMsg.h"
#include "QueryDB.h"

void RegisterRoutes(httplib::Server& svr)
{
    svr.Get("/", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_content("{\"status\":\"ok\",\"service\":\"WeChat-Hook\"}", "application/json; charset=utf-8");
    });

    Route_SendTextMsg(svr);
    RegisterGetSelfProfile(svr);
    Route_ForwardXMLMsg(svr);
    Route_SendImageMsg(svr);
    Route_QueryDB(svr);
}
