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
            nlohmann::ordered_json result;
            try
            {
                xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();
            //OutputDebugStringA("[QueryDB] 初始化完成\n");


            std::string optDbName = reqJson.value("optDbName", "");         // MicroMsg.db
            std::string sql = reqJson.value("SQL", "");                     // 查询语句   SELECT * FROM ChatRoom LIMIT 10

                result = g_dbMgr.execute(optDbName, sql);
            }
            catch (const std::exception& e)
            {
                result = { {"status",-500},{"desc",std::string("exception: ") + e.what()},{"debug",std::string(g_DbDebugText)} };
            }
            catch (...)
            {
                result = { {"status",-501},{"desc","unknown exception"},{"debug",std::string(g_DbDebugText)} };
            }


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


            res.set_content(result.dump(4, ' ', false), "application/json; charset=utf-8");


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
            nlohmann::ordered_json dbInfo;
            try
            {
                xmgr::DatabaseMgr& g_dbMgr = xmgr::DatabaseMgr::getInstance();
            //OutputDebugStringA("[QueryDB] 初始化完成\n");

            // 方式2：获取所有数据库信息
                dbInfo = g_dbMgr.getDatabaseInfo();
            }
            catch (const std::exception& e)
            {
                dbInfo = { {"status",-500},{"desc",std::string("exception: ") + e.what()},{"debug",std::string(g_DbDebugText)} };
            }
            catch (...)
            {
                dbInfo = { {"status",-501},{"desc","unknown exception"},{"debug",std::string(g_DbDebugText)} };
            }
            // 返回：{"dbName":"MicroMsg.db","dbHandle":140736870540544}

            res.set_content(dbInfo.dump(4, ' ', false), "application/json; charset=utf-8");


            //res.set_content(resp.dump(), "application/json");
        });

    // 添加状态查询接口
    svr.Get("/QueryDB/status", [](const httplib::Request&, httplib::Response& res) {
        json resp;
        resp["IsLogin"] = g_IsLogin;
        resp["LoginProbeCalls"] = g_LoginProbeCalls;
        resp["LoginProbeLast"] = g_LoginProbeLast;
        resp["LoginStateChanges"] = g_LoginStateChanges;
        resp["LoginStateLastChange"] = g_LoginStateLastChange;
        resp["LoginStateSource"] = g_LoginStateSource;
        resp["LoginProbeHookInstalled"] = g_LoginProbeHookInstalled;
        resp["LoginFinishCalls"] = g_LoginFinishCalls;
        resp["LoginFinishContext"] = g_LoginFinishContext;
        resp["LoginFinishPayload"] = g_LoginFinishPayload;
        resp["MessageReceiveCalls"] = g_MessageReceiveCalls;
        resp["MessageCallbackPosts"] = g_MessageCallbackPosts;
        resp["MessageHookInstalled"] = g_MessageHookInstalled;
        resp["MsgReplaceHandlerCalls"] = g_MsgReplaceHandlerCalls;
        resp["MsgReplaceHandlerContext"] = g_MsgReplaceHandlerContext;
        resp["MsgReplaceHandlerSync"] = g_MsgReplaceHandlerSync;
        resp["PlainTextMsgHandlerCalls"] = g_PlainTextMsgHandlerCalls;
        resp["PlainTextMsgHandlerContext"] = g_PlainTextMsgHandlerContext;
        resp["PlainTextMsgHandlerObject"] = g_PlainTextMsgHandlerObject;
        resp["MsgSourceParserCalls"] = g_MsgSourceParserCalls;
        resp["MsgWordingParserCalls"] = g_MsgWordingParserCalls;
        resp["MsgWordingObject"] = g_MsgWordingObject;
        resp["MessageStructCopyCalls"] = g_MessageStructCopyCalls;
        resp["MessageStructSource"] = g_MessageStructSource;
        resp["MessageStructTarget"] = g_MessageStructTarget;
        resp["MessageStructTalker"] = std::string(g_MessageStructTalker);
        resp["MessageStructContent"] = std::string(g_MessageStructContent);
        resp["MessageStructExtra1"] = std::string(g_MessageStructExtra1);
        resp["MessageStructExtra2"] = std::string(g_MessageStructExtra2);
        resp["RawSyncMsgProcessorCalls"] = g_RawSyncMsgProcessorCalls;
        resp["RawSyncMsgItemCount"] = g_RawSyncMsgItemCount;
        resp["RawSyncMsgLastItem"] = g_RawSyncMsgLastItem;
        resp["RawSyncMsgLastType"] = g_RawSyncMsgLastType;
        resp["SyncBatchProcessorCalls"] = g_SyncBatchProcessorCalls;
        resp["SyncBatchItemCount"] = g_SyncBatchItemCount;
        resp["SyncBatchLastContext"] = g_SyncBatchLastContext;
        resp["SyncBatchLastVector"] = g_SyncBatchLastVector;
        resp["SyncBatchLastCandidate"] = g_SyncBatchLastCandidate;
        resp["SyncBatchText1"] = std::string(g_SyncBatchText1);
        resp["SyncBatchText2"] = std::string(g_SyncBatchText2);
        resp["SyncBatchText3"] = std::string(g_SyncBatchText3);
        resp["SyncBatchText4"] = std::string(g_SyncBatchText4);
        resp["AutoReplyQueued"] = g_AutoReplyQueued;
        resp["AutoReplySent"] = g_AutoReplySent;
        resp["AutoReplyFailed"] = g_AutoReplyFailed;
        resp["AutoReplyCandidates"] = g_AutoReplyCandidates;
        resp["SysMsgParserCalls"] = g_SysMsgParserCalls;
        resp["HistoryAddMsgCalls"] = g_HistoryAddMsgCalls;
        resp["HistoryAddMsgCommitCalls"] = g_HistoryAddMsgCommitCalls;
        resp["SqlitePrepareCalls"] = g_SqlitePrepareCalls;
        resp["SqlitePrepareV2Calls"] = g_SqlitePrepareV2Calls;
        resp["SqliteBindTextCalls"] = g_SqliteBindTextCalls;
        resp["SqliteBindText16Calls"] = g_SqliteBindText16Calls;
        resp["SqliteStepCalls"] = g_SqliteStepCalls;
        resp["SqliteHookInstalled"] = g_SqliteHookInstalled;
        resp["SqliteApiTable"] = g_SqliteApiTable;
        resp["SqlitePrepareTarget"] = g_SqlitePrepareTarget;
        resp["SqlitePrepareV2Target"] = g_SqlitePrepareV2Target;
        resp["SqliteBindTextTarget"] = g_SqliteBindTextTarget;
        resp["SqliteBindText16Target"] = g_SqliteBindText16Target;
        resp["SqliteStepTarget"] = g_SqliteStepTarget;
        resp["SqliteLastSql"] = std::string(g_SqliteLastSql);
        resp["SqliteInterestingSql"] = std::string(g_SqliteInterestingSql);
        resp["SqliteLastBindText"] = std::string(g_SqliteLastBindText);
        resp["SqliteInterestingBindText"] = std::string(g_SqliteInterestingBindText);
        resp["SqliteBindTrace"] = json::array();
        const uint64_t sqliteEnd = g_SqliteBindTraceIndex;
        const uint64_t sqliteBegin = sqliteEnd > kSqliteBindTraceCapacity
            ? sqliteEnd - kSqliteBindTraceCapacity : 0;
        for (uint64_t seq = sqliteBegin; seq < sqliteEnd; ++seq) {
            const auto& item = g_SqliteBindTraces[seq % kSqliteBindTraceCapacity];
            if (item.sequence != seq)
                continue;
            resp["SqliteBindTrace"].push_back({
                {"sequence", item.sequence},
                {"stmt", item.stmt},
                {"index", item.index},
                {"caller", item.caller},
                {"api", std::string(item.api)},
                {"text", std::string(item.text)}
            });
        }
        resp["MessageParserCalls"] = g_MessageParserCalls;
        resp["MessageParserLastObject"] = g_MessageParserLastObject;
        resp["SyncContextObject"] = g_SyncContextObject;
        resp["FieldLookupCalls"] = g_FieldLookupCalls;
        resp["FieldLookupLastKey"] = g_FieldLookupLastKey;
        resp["FieldLookupLastKeyText"] = std::string(g_FieldLookupLastKeyText);
        resp["FieldFromCalls"] = g_FieldFromCalls;
        resp["FieldContentCalls"] = g_FieldContentCalls;
        resp["FieldMsgCalls"] = g_FieldMsgCalls;
        resp["FieldWordingCalls"] = g_FieldWordingCalls;
        resp["FieldFromText"] = std::string(g_FieldFromText);
        resp["FieldContentText"] = std::string(g_FieldContentText);
        resp["FieldMsgText"] = std::string(g_FieldMsgText);
        resp["FieldWordingText"] = std::string(g_FieldWordingText);
        resp["FieldMsgOutputHex"] = std::string(g_FieldMsgOutputHex);
        resp["FieldMsgNodeHex"] = std::string(g_FieldMsgNodeHex);
        resp["FieldMsgValueHex"] = std::string(g_FieldMsgValueHex);
        resp["FieldWordingOutputHex"] = std::string(g_FieldWordingOutputHex);
        resp["FieldWordingNodeHex"] = std::string(g_FieldWordingNodeHex);
        resp["FieldWordingValueHex"] = std::string(g_FieldWordingValueHex);
        resp["DbDebugText"] = std::string(g_DbDebugText);
        resp["FieldLookupTrace"] = json::array();
        const uint64_t fieldEnd = g_FieldLookupTraceIndex;
        const uint64_t fieldBegin = fieldEnd > kFieldLookupTraceCapacity
            ? fieldEnd - kFieldLookupTraceCapacity : 0;
        for (uint64_t seq = fieldBegin; seq < fieldEnd; ++seq) {
            const auto& item = g_FieldLookupTraces[seq % kFieldLookupTraceCapacity];
            if (item.sequence != seq)
                continue;
            resp["FieldLookupTrace"].push_back({
                {"sequence", item.sequence},
                {"container", item.container},
                {"output", item.output},
                {"keyPtr", item.keyPtr},
                {"result", item.result},
                {"key", std::string(item.key)},
                {"text", std::string(item.text)}
            });
        }
        resp["MessageBranchTrace"] = json::array();
        const uint64_t branchEnd = g_MessageBranchTraceIndex;
        const uint64_t branchBegin = branchEnd > kMessageBranchTraceCapacity
            ? branchEnd - kMessageBranchTraceCapacity : 0;
        for (uint64_t seq = branchBegin; seq < branchEnd; ++seq) {
            const auto& item = g_MessageBranchTraces[seq % kMessageBranchTraceCapacity];
            if (item.sequence != seq)
                continue;
            resp["MessageBranchTrace"].push_back({
                {"sequence", item.sequence},
                {"handler", item.handler},
                {"name", std::string(item.name)},
                {"a1", item.a1},
                {"a2", item.a2},
                {"a3", item.a3},
                {"caller", item.caller}
            });
        }
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
        res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
        });


}
