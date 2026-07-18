#include "httplib.h"
#include "http_routes.h"
#include "SendTextMsg.h"
#include "GetSelfProfile.h"
#include "ForwardXMLMsg.h"
#include "SendImageMsg.h"
#include "QueryDB.h"
#include "global.h"
#include "auto_reply.h"
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
    RegisterGetContacts(svr);
    Route_ForwardXMLMsg(svr);
    Route_SendImageMsg(svr);
    Route_QueryDB(svr);

    // Full auto-reply rules engine, persisted to autoreply.json.
    //   GET  /AutoReply/config -> returns the full config
    //   POST /AutoReply/config -> merges posted fields onto the config and
    //        persists it.  Posting only {"group_enabled":true} still works
    //        (backward compatible); the global master switch defaults off.
    svr.Get("/AutoReply/config", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.set_content(AutoReply::ToJsonString(), "application/json; charset=utf-8");
    });

    svr.Post("/AutoReply/config", [](const httplib::Request& req, httplib::Response& res)
    {
        using json = nlohmann::json;
        res.set_header("Content-Type", "application/json; charset=utf-8");
        std::string err;
        if (!AutoReply::MergeFromJsonString(req.body, err)) {
            json response;
            response["ret"] = -1;
            response["msg"] = err.empty() ? "invalid json" : err;
            res.set_content(response.dump(), "application/json; charset=utf-8");
            return;
        }
        const bool saved = AutoReply::SaveToDisk();
        json response = json::parse(AutoReply::ToJsonString());
        response["ret"] = 0;
        response["saved"] = saved;
        res.set_content(response.dump(), "application/json; charset=utf-8");
    });

    // Rules-only management for finer-grained edits.
    //   GET  /AutoReply/rules -> array of rules
    //   POST /AutoReply/rules with {"action":"add","rule":{...}}
    //                             {"action":"delete","index":N}
    //                             {"action":"clear"}
    //                             {"action":"set","rules":[...]}
    svr.Get("/AutoReply/rules", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.set_content(AutoReply::RulesToJsonString(), "application/json; charset=utf-8");
    });

    svr.Post("/AutoReply/rules", [](const httplib::Request& req, httplib::Response& res)
    {
        using json = nlohmann::json;
        res.set_header("Content-Type", "application/json; charset=utf-8");
        json response;
        std::string err;
        std::string action;
        try {
            const json body = json::parse(req.body.empty() ? "{}" : req.body);
            action = body.value("action", std::string("add"));
            bool ok = false;
            if (action == "add") {
                ok = AutoReply::AddRuleFromJson(req.body, err);
            } else if (action == "delete") {
                if (!body.contains("index") || !body["index"].is_number_integer()) {
                    err = "index integer is required";
                } else {
                    ok = AutoReply::DeleteRuleAt(body["index"].get<size_t>());
                    if (!ok) err = "index out of range";
                }
            } else if (action == "clear") {
                AutoReply::ClearRules();
                ok = true;
            } else if (action == "set") {
                ok = AutoReply::ReplaceRulesFromJson(req.body, err);
            } else {
                err = "unknown action";
            }
            if (!ok) {
                response["ret"] = -1;
                response["msg"] = err.empty() ? "failed" : err;
                res.set_content(response.dump(), "application/json; charset=utf-8");
                return;
            }
        } catch (...) {
            response["ret"] = -1;
            response["msg"] = "invalid json";
            res.set_content(response.dump(), "application/json; charset=utf-8");
            return;
        }
        const bool saved = AutoReply::SaveToDisk();
        response["ret"] = 0;
        response["saved"] = saved;
        response["rules"] = json::parse(AutoReply::RulesToJsonString());
        res.set_content(response.dump(), "application/json; charset=utf-8");
    });

    // XML-forward offset self-discovery probe (read-only, default disarmed).
    //   POST /XmlProbe/arm  -> clears the last capture and arms the observer so
    //        the next real appmsg/XML forward is frozen into the probe globals.
    //   GET  /XmlProbe/result -> {armed, sendCalls, captured, vtable_rva,
    //        xml_offset, wxid_offset, field_map}.  Offsets are hex strings
    //        ("unset" until captured); field_map is the raw scan report.
    svr.Post("/XmlProbe/arm", [](const httplib::Request&, httplib::Response& res)
    {
        using json = nlohmann::json;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_XmlProbeCaptured), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_XmlProbeSendCalls), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_XmlProbeVtableRva), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_XmlProbeXmlOffset),
                              static_cast<LONG64>(UINT64_MAX));
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_XmlProbeWxidOffset),
                              static_cast<LONG64>(UINT64_MAX));
        g_XmlProbeFieldMap[0] = 0;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_XmlProbeArmed), 1);
        json response;
        response["ret"] = 0;
        response["armed"] = true;
        res.set_content(response.dump(), "application/json; charset=utf-8");
    });

    svr.Get("/XmlProbe/result", [](const httplib::Request&, httplib::Response& res)
    {
        using json = nlohmann::json;
        auto hexOrUnset = [](uint64_t v) -> std::string {
            if (v == UINT64_MAX) return std::string("unset");
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llX",
                     static_cast<unsigned long long>(v));
            return std::string(buf);
        };
        char vt[32];
        snprintf(vt, sizeof(vt), "0x%llX",
                 static_cast<unsigned long long>(g_XmlProbeVtableRva));
        json response;
        response["ret"] = 0;
        response["armed"] = g_XmlProbeArmed != 0;
        response["captured"] = g_XmlProbeCaptured != 0;
        response["sendCalls"] = g_XmlProbeSendCalls;
        response["vtable_rva"] = std::string(vt);
        response["xml_offset"] = hexOrUnset(g_XmlProbeXmlOffset);
        response["wxid_offset"] = hexOrUnset(g_XmlProbeWxidOffset);
        response["field_map"] = std::string(g_XmlProbeFieldMap);
        response["forward_calls"] = g_ForwardObserveCalls;
        response["forward_hook_installed"] = g_ForwardObserveHookInstalled;
        response["send_calls"] = g_SendContentObserveCalls;
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.set_content(response.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace), "application/json; charset=utf-8");
    });

    // sendappmsg CGI submit self-discovery probe (read-only, default disarmed).
    //   POST /AppMsgProbe/arm    -> clears the last capture and arms the submit
    //        observer so the next real sendappmsg is frozen into the globals.
    //   GET  /AppMsgProbe/result -> {armed, captured, calls, manager, request,
    //        request_vtable_rva, a3, a4, a5, report}.  The report holds the
    //        request object's qword map + any embedded to_wxid/appmsg XML.
    svr.Post("/AppMsgProbe/arm", [](const httplib::Request&, httplib::Response& res)
    {
        using json = nlohmann::json;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitCaptured), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitCalls), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitManager), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitRequestObj), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitRequestVtable), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitA3), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitA4), 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitA5), 0);
        g_AppMsgSubmitReport[0] = 0;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgSubmitArmed), 1);
        json response;
        response["ret"] = 0;
        response["armed"] = true;
        res.set_content(response.dump(), "application/json; charset=utf-8");
    });

    svr.Get("/AppMsgProbe/result", [](const httplib::Request&, httplib::Response& res)
    {
        using json = nlohmann::json;
        auto hx = [](uint64_t v) -> std::string {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
            return std::string(buf);
        };
        const uintptr_t base = reinterpret_cast<uintptr_t>(g_hWeixinDll);
        const uint64_t vt = g_AppMsgSubmitRequestVtable;
        json response;
        response["ret"] = 0;
        response["armed"] = g_AppMsgSubmitArmed != 0;
        response["captured"] = g_AppMsgSubmitCaptured != 0;
        response["calls"] = g_AppMsgSubmitCalls;
        response["hook_installed"] = g_AppMsgSubmitHookInstalled != 0;
        response["manager"] = hx(g_AppMsgSubmitManager);
        response["request"] = hx(g_AppMsgSubmitRequestObj);
        response["request_vtable"] = hx(vt);
        response["request_vtable_rva"] = hx((vt && vt > base) ? (vt - base) : 0);
        response["a3"] = hx(g_AppMsgSubmitA3);
        response["a4"] = hx(g_AppMsgSubmitA4);
        response["a5"] = hx(g_AppMsgSubmitA5);
        response["report"] = std::string(g_AppMsgSubmitReport);
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.set_content(response.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace), "application/json; charset=utf-8");
    });
}
