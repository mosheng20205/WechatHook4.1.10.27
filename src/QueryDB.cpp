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


            const std::string optDbName = reqJson.value("optDbName", "");
            const std::string sql = reqJson.value("SQL", "");
            nlohmann::ordered_json result;
            std::string resultJson;
            if (!g_IsLogin) {
                result = {{"status", -401}, {"desc", "微信未登录"}};
            } else if (!RunSqlQueryOnSqliteThread(optDbName, sql, resultJson, 15000)) {
                result = {{"status", -504},
                          {"desc", "read-only query timed out or was rejected"},
                          {"debug", std::string(g_DbDebugText)}};
            } else {
                try {
                    result = nlohmann::ordered_json::parse(resultJson);
                } catch (...) {
                    result = {{"status", -505},
                              {"desc", "invalid query response"},
                              {"debug", std::string(g_DbDebugText)}};
                }
            }


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


            // Only report handles captured from WeChat's own SQLite thread.
            // Do not scan memory or dereference the handle on the HTTP thread.
            nlohmann::ordered_json dbInfo = nlohmann::ordered_json::array();
            if (g_IsLogin && g_SqliteContactDbHandle != 0) {
                const std::string dbPath = g_SqliteContactDbPath;
                const bool modernContact = dbPath.find("contact.db") != std::string::npos &&
                    dbPath.find("contact_fts.db") == std::string::npos;
                dbInfo.push_back({
                    {"dbName", modernContact ? "contact.db" : "MicroMsg.db"},
                    {"dbHandle", g_SqliteContactDbHandle},
                    {"dbPath", dbPath},
                    {"source", "sqlite-hook"}
                });
            }

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
        resp["ProfileGetterNullStreak"] = g_ProfileGetterNullStreak;
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
        resp["SyncBatchVtableMatches"] = g_SyncBatchVtableMatches;
        resp["SyncBatchFieldReadCalls"] = g_SyncBatchFieldReadCalls;
        resp["SyncBatchLastMsgType"] = g_SyncBatchLastMsgType;
        resp["SyncBatchText1"] = std::string(g_SyncBatchText1);
        resp["SyncBatchText2"] = std::string(g_SyncBatchText2);
        resp["SyncBatchText3"] = std::string(g_SyncBatchText3);
        resp["SyncBatchText4"] = std::string(g_SyncBatchText4);
        resp["SyncBatchFromUsername"] = std::string(g_SyncBatchFromUsername);
        resp["SyncBatchToUsername"] = std::string(g_SyncBatchToUsername);
        resp["SyncBatchContent"] = std::string(g_SyncBatchContent);
        resp["AutoReplyQueued"] = g_AutoReplyQueued;
        resp["AutoReplySent"] = g_AutoReplySent;
        resp["AutoReplyFailed"] = g_AutoReplyFailed;
        resp["AutoReplyCandidates"] = g_AutoReplyCandidates;
        resp["AutoReplyFriendCandidates"] = g_AutoReplyFriendCandidates;
        resp["AutoReplyGroupCandidates"] = g_AutoReplyGroupCandidates;
        resp["AutoReplyGroupSkipped"] = g_AutoReplyGroupSkipped;
        resp["AutoReplySelfSkipped"] = g_AutoReplySelfSkipped;
        resp["AutoReplyGroupEnabled"] = g_AutoReplyGroupEnabled;
        resp["AutoReplyLastChatType"] = std::string(g_AutoReplyLastChatType);
        resp["AutoReplyLastSender"] = std::string(g_AutoReplyLastSender);
        resp["AutoReplyLastRoom"] = std::string(g_AutoReplyLastRoom);
        resp["SendRequestObserveCalls"] = g_SendRequestObserveCalls;
        resp["SendRequestObserveVtableValid"] = g_SendRequestObserveVtableValid;
        resp["SendRequestObserveFieldReadCalls"] = g_SendRequestObserveFieldReadCalls;
        resp["SendRequestObserveLastSource"] = g_SendRequestObserveLastSource;
        resp["SendRequestObserveLastDestination"] = g_SendRequestObserveLastDestination;
        resp["SendRequestObserveLastVtable"] = g_SendRequestObserveLastVtable;
        resp["SendRequestObserveLastField10Object"] = g_SendRequestObserveLastField10Object;
        resp["SendRequestObserveLastField20Object"] = g_SendRequestObserveLastField20Object;
        resp["SendRequestObserveHookInstalled"] = g_SendRequestObserveHookInstalled;
        resp["SendRequestObserveField10"] = std::string(g_SendRequestObserveField10);
        resp["SendRequestObserveField20"] = std::string(g_SendRequestObserveField20);
        resp["SendElementObserveCalls"] = g_SendElementObserveCalls;
        resp["SendElementObserveFlagMatches"] = g_SendElementObserveFlagMatches;
        resp["SendElementObserveFieldReadCalls"] = g_SendElementObserveFieldReadCalls;
        resp["SendElementObserveLastSource"] = g_SendElementObserveLastSource;
        resp["SendElementObserveLastDestination"] = g_SendElementObserveLastDestination;
        resp["SendElementObserveLastFlags"] = g_SendElementObserveLastFlags;
        resp["SendElementObserveHookInstalled"] = g_SendElementObserveHookInstalled;
        resp["SendElementObserveLastField1Object"] = g_SendElementObserveLastField1Object;
        resp["SendElementObserveLastField1Wrapper"] = g_SendElementObserveLastField1Wrapper;
        resp["SendElementObserveField1"] = std::string(g_SendElementObserveField1);
        resp["SendElementObserveField10"] = std::string(g_SendElementObserveField10);
        resp["SendElementObserveField20"] = std::string(g_SendElementObserveField20);
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
        resp["SqliteLastDbHandle"] = g_SqliteLastDbHandle;
        resp["SqliteLastDbThreadId"] = g_SqliteLastDbThreadId;
        resp["SqliteContactDbHandle"] = g_SqliteContactDbHandle;
        resp["SqliteContactDbThreadId"] = g_SqliteContactDbThreadId;
        resp["SqliteLastDbPath"] = std::string(g_SqliteLastDbPath);
        resp["SqliteContactDbPath"] = std::string(g_SqliteContactDbPath);
        resp["ContactQueryRequests"] = g_ContactQueryRequests;
        resp["ContactQueryTryCalls"] = g_ContactQueryTryCalls;
        resp["ContactQueryClaims"] = g_ContactQueryClaims;
        resp["ContactQueryExecuteCalls"] = g_ContactQueryExecuteCalls;
        resp["ContactQueryCompleteCalls"] = g_ContactQueryCompleteCalls;
        resp["ContactQueryLastDb"] = g_ContactQueryLastDb;
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
