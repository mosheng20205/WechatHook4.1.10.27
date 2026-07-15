#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include "tools.h"
#include "global.h"
#include "db_mgr.h"

#include "QueryDB.h"


using json = nlohmann::json;
//static xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();

static std::string BytesToHex(const uint8_t* data, size_t len)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 2);

    for (size_t i = 0; i < len; ++i)
    {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}


void Route_QueryDB(httplib::Server& svr)
{
    svr.Post("/QueryDB/execute", [](const httplib::Request& req, httplib::Response& res)
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


            //初始化数据库管理器
            //OutputDebugStringA("[QueryDB] 初始化数据库管理器\n");
            xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();
            //OutputDebugStringA("[QueryDB] 初始化完成\n");


            std::string optDbName = reqJson.value("optDbName", "");         // MicroMsg.db
            std::string sql = reqJson.value("SQL", "");                     // 查询语句   SELECT * FROM ChatRoom LIMIT 10

            auto result = g_dbMgr.execute(optDbName, sql);


            // 使用临界区保护数据库访问
            /*
            EnterCriticalSection(&g_dbMgrCriticalSection);
            try {
                auto start = std::chrono::high_resolution_clock::now();
                auto result = g_dbMgr.execute(optDbName, sql);
                auto end = std::chrono::high_resolution_clock::now();

                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                resp["ret"] = result.value("status", 0);
                resp["msg"] = result.value("desc", "");
                resp["data"] = result.value("data", json::array());
                resp["duration_ms"] = duration.count();

                // 慢查询日志
                if (duration.count() > 1000) {
                    OutputDebugStringA(format_string("Slow query: %lldms - %s", duration.count(), sql.substr(0, 100)).c_str());
                }

            }
            catch (const std::exception& e) {
                resp["ret"] = -500;
                resp["msg"] = std::string("Database error: ") + e.what();
            }
            LeaveCriticalSection(&g_dbMgrCriticalSection);
            */


            res.set_content(result.dump(4, ' ', false), "application/json");


            //res.set_content(resp.dump(), "application/json");
        });
    svr.Post("/QueryDB/GetAllDBName", [](const httplib::Request& req, httplib::Response& res)
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


            //初始化数据库管理器
            //OutputDebugStringA("[QueryDB] 初始化数据库管理器\n");
            xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();
            //OutputDebugStringA("[QueryDB] 初始化完成\n");

            // 方式2：获取所有数据库信息
            auto dbInfo = g_dbMgr.getDatabaseInfo();
            // 返回：{"dbName":"MicroMsg.db","dbHandle":140736870540544}

            res.set_content(dbInfo.dump(4, ' ', false), "application/json");


            //res.set_content(resp.dump(), "application/json");
        });

    // 添加状态查询接口
    svr.Get("/QueryDB/status", [](const httplib::Request&, httplib::Response& res) {
        json resp;
        resp["IsLogin"] = g_IsLogin;
        resp["LoginProbeCalls"] = g_LoginProbeCalls;
        resp["LoginProbeLast"] = g_LoginProbeLast;
        resp["LoginFinishCalls"] = g_LoginFinishCalls;
        resp["LoginFinishContext"] = g_LoginFinishContext;
        resp["LoginFinishPayload"] = g_LoginFinishPayload;
        resp["ProfileGetterCalls"] = g_ProfileGetterCalls;
        resp["ProfileObject"] = g_ProfileObject;
        resp["ProfileFieldCalls"] = g_ProfileFieldCalls;
        resp["ProfileFieldObject"] = g_ProfileFieldObject;
        resp["ProfileFieldDescriptor"] = g_ProfileFieldDescriptor;
        resp["ProfileContainer830Calls"] = g_ProfileContainer830Calls;
        resp["ProfileContainer830Object"] = g_ProfileContainer830Object;
        resp["ProfileContainer830Root"] = g_ProfileContainer830Root;
        resp["ProfileContainer830Second"] = g_ProfileContainer830Second;
        resp["ProfileContainerFC00Calls"] = g_ProfileContainerFC00Calls;
        resp["ProfileContainerFC00Object"] = g_ProfileContainerFC00Object;
        resp["ProfileContainerFC00Root"] = g_ProfileContainerFC00Root;
        resp["ProfileContainerFC00Second"] = g_ProfileContainerFC00Second;
        resp["ManagerContainerGetterCalls"] = g_ManagerContainerGetterCalls;
        resp["ManagerContainerObject"] = g_ManagerContainerObject;
        resp["ProfileFieldTrace"] = json::array();
        const uint64_t end = g_ProfileTraceIndex;
        const uint64_t begin = end > kProfileTraceCapacity
            ? end - kProfileTraceCapacity : 0;
        for (uint64_t seq = begin; seq < end; ++seq) {
            const auto& item = g_ProfileTraces[seq % kProfileTraceCapacity];
            if (item.sequence != seq)
                continue;
            resp["ProfileFieldTrace"].push_back({
                {"sequence", item.sequence},
                {"object", item.object},
                {"output", item.output},
                {"descriptor", item.descriptor},
                {"result", item.result},
                {"caller", item.caller},
                {"outputBytes", nlohmann::json::binary(std::vector<uint8_t>(
                    item.outputBytes, item.outputBytes + sizeof(item.outputBytes)))}
            });
        }
        resp["hWeixin"] = (uint64_t)g_hWeixinDll;
        res.set_content(resp.dump(4, ' ', false), "application/json");
        });


}
