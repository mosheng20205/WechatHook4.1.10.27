#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

// 前向声明，不需要完整类型
class HttpServer;



extern int g_receive_type;
extern int g_StartPort;
extern int g_MsgSendPort;
extern HMODULE g_hWeixinDll;
extern HMODULE g_hWeixinExe;


extern HANDLE g_hLoginMonitor;
extern HANDLE g_hAfterLoginInit;

extern DWORD g_MainThreadId;
extern DWORD 进程PID;
extern DWORD 父进程PID;
extern HWND  g_WeixinMainHwnd;
extern volatile uint64_t g_IsLogin;   // 0=未登录 1=已登录
extern volatile uint64_t g_LoginProbeCalls;
extern volatile uint64_t g_LoginProbeLast;
extern volatile uint64_t g_LoginStateChanges;
extern volatile uint64_t g_LoginStateLastChange;
extern volatile uint64_t g_LoginStateSource; // 0=unknown, 1=login-finish, 2=probe
extern volatile uint64_t g_LoginProbeHookInstalled;
extern volatile uint64_t g_LoginFinishCalls;
extern volatile uint64_t g_LoginFinishContext;
extern volatile uint64_t g_LoginFinishPayload;
extern volatile uint64_t g_ProfileGetterCalls;
extern volatile uint64_t g_ProfileGetterNullStreak;
extern volatile uint64_t g_MessageReceiveCalls;
extern volatile uint64_t g_MessageCallbackPosts;
extern volatile uint64_t g_MessageHookInstalled;
extern volatile uint64_t g_MsgReplaceHandlerCalls;
extern volatile uint64_t g_MsgReplaceHandlerContext;
extern volatile uint64_t g_MsgReplaceHandlerSync;
extern volatile uint64_t g_PlainTextMsgHandlerCalls;
extern volatile uint64_t g_PlainTextMsgHandlerContext;
extern volatile uint64_t g_PlainTextMsgHandlerObject;
extern volatile uint64_t g_MsgSourceParserCalls;
extern volatile uint64_t g_MsgWordingParserCalls;
extern volatile uint64_t g_MsgWordingObject;
extern volatile uint64_t g_MessageStructCopyCalls;
extern volatile uint64_t g_MessageStructSource;
extern volatile uint64_t g_MessageStructTarget;
extern char g_MessageStructTalker[256];
extern char g_MessageStructContent[4096];
extern char g_MessageStructExtra1[4096];
extern char g_MessageStructExtra2[4096];
extern volatile uint64_t g_RawSyncMsgProcessorCalls;
extern volatile uint64_t g_RawSyncMsgItemCount;
extern volatile uint64_t g_RawSyncMsgLastItem;
extern volatile uint64_t g_RawSyncMsgLastType;
extern volatile uint64_t g_SyncBatchProcessorCalls;
extern volatile uint64_t g_SyncBatchItemCount;
extern volatile uint64_t g_SyncBatchLastContext;
extern volatile uint64_t g_SyncBatchLastVector;
extern volatile uint64_t g_SyncBatchLastCandidate;
extern volatile uint64_t g_SyncBatchVtableMatches;
extern volatile uint64_t g_SyncBatchFieldReadCalls;
extern volatile uint64_t g_SyncBatchLastMsgType;
extern char g_SyncBatchText1[4096];
extern char g_SyncBatchText2[4096];
extern char g_SyncBatchText3[4096];
extern char g_SyncBatchText4[4096];
extern char g_SyncBatchFromUsername[4096];
extern char g_SyncBatchToUsername[4096];
extern char g_SyncBatchContent[4096];
extern volatile uint64_t g_RevokeDetectedCount;
extern volatile uint64_t g_RevokePostedCount;
extern volatile uint64_t g_RevokeLastNewMsgId;
extern char g_RevokeLastFrom[4096];
extern char g_RevokeLastSender[4096];
extern char g_RevokeLastTip[4096];
extern char g_RevokeLastTalker[4096];
extern volatile uint64_t g_RevokeLastRevokeTime;
extern volatile uint64_t g_RevokeDistinctCount;
extern volatile uint64_t g_RevokeSuppressedCount;

// True anti-revoke: keep the recalled bubble (text AND image) visible by
// skipping sub_1822D07C0's revoke-apply branch (jz@0x22D09E7 -> nop;jmp).
// Default OFF, byte-verified and reversible; toggled via /AntiRevoke/config.
extern volatile LONG g_AntiRevokeEnabled;
bool AntiRevoke_Enable();
bool AntiRevoke_Disable();

// Experimental recall-tip injection: when anti-revoke keeps the recalled
// bubble visible, optionally insert a local "<name> 撤回了一条消息" gray tip
// into the SAME conversation via the native local-sysmsg inserter
// (offset::revoke_tip_insert / sub_184C280B0), so the chat shows both the
// preserved original AND the recall notice.  Default OFF; the injection runs
// on a detached worker thread (never re-enters the receive hook) and is
// SEH-guarded.  The native inserter hard-codes sysmsg type="paymsg", so the
// on-screen rendering of arbitrary text is UNVERIFIED and must be confirmed on
// a real client before this is ever default-enabled.  Toggled via
// /RevokeTip/config.
extern volatile LONG g_RevokeTipInjectEnabled;
extern volatile uint64_t g_RevokeTipInjectCalls;
extern volatile uint64_t g_RevokeTipInjectOk;
extern volatile uint64_t g_RevokeTipInjectFail;

// Anti-revoke side-effect fix: the jz@0x22D09E7 patch makes sub_1822D07C0
// return 0 (unhandled) for revokemsg, so its caller sub_1822D0540 falls back to
// sub_1822D1640 and DISPLAYS the raw <sysmsg type="revokemsg"> XML as a message
// (leaking into a stray "微信用户" P2P chat).  When anti-revoke is on we force
// the hook to report handled (return 1 + zero the caller's out-byte) so the raw
// XML is consumed like vanilla WeChat, without touching the preserved bubble.
extern volatile uint64_t g_RevokeConsumeOverrides;
extern volatile uint64_t g_AutoReplyQueued;
extern volatile uint64_t g_AutoReplySent;
extern volatile uint64_t g_AutoReplyFailed;
extern volatile uint64_t g_AutoReplyCandidates;
extern volatile uint64_t g_AutoReplyFriendCandidates;
extern volatile uint64_t g_AutoReplyGroupCandidates;
extern volatile uint64_t g_AutoReplyGroupSkipped;
extern volatile uint64_t g_AutoReplySelfSkipped;
extern volatile uint64_t g_AutoReplyGroupEnabled;
extern char g_AutoReplyLastChatType[16];
extern char g_AutoReplyLastSender[256];
extern char g_AutoReplyLastRoom[256];
// Read-only observation of the nested SendMsgRequestNew copy boundary
// (Weixin.dll RVA 0x2C6D230). These fields never invoke or alter sending.
extern volatile uint64_t g_SendRequestObserveCalls;
extern volatile uint64_t g_SendRequestObserveVtableValid;
extern volatile uint64_t g_SendRequestObserveFieldReadCalls;
extern volatile uint64_t g_SendRequestObserveLastSource;
extern volatile uint64_t g_SendRequestObserveLastDestination;
extern volatile uint64_t g_SendRequestObserveLastVtable;
extern volatile uint64_t g_SendRequestObserveLastField10Object;
extern volatile uint64_t g_SendRequestObserveLastField20Object;
extern volatile uint64_t g_SendRequestObserveHookInstalled;
extern char g_SendRequestObserveField10[4096];
extern char g_SendRequestObserveField20[4096];
extern volatile uint64_t g_SendElementObserveCalls;
extern volatile uint64_t g_SendElementObserveFlagMatches;
extern volatile uint64_t g_SendElementObserveFieldReadCalls;
extern volatile uint64_t g_SendElementObserveLastSource;
extern volatile uint64_t g_SendElementObserveLastDestination;
extern volatile uint64_t g_SendElementObserveLastFlags;
extern volatile uint64_t g_SendElementObserveHookInstalled;
extern volatile uint64_t g_SendElementObserveLastField1Object;
extern volatile uint64_t g_SendElementObserveLastField1Wrapper;
extern char g_SendElementObserveField1[4096];
extern char g_SendElementObserveField10[4096];
extern char g_SendElementObserveField20[4096];
// Read-only observation of the verified unified send_message path.  These
// fields are populated by scanning the live content object used by a real
// send (including appmsg/XML forwarding); no send arguments are modified.
extern volatile uint64_t g_SendContentObserveCalls;
extern volatile uint64_t g_SendContentObserveLastArg1;
extern volatile uint64_t g_SendContentObserveLastArg2;
extern volatile uint64_t g_SendContentObserveLastObject;
extern volatile uint64_t g_SendContentObserveLastVtable;
extern volatile uint64_t g_SendContentObserveReceiverOffset;
extern volatile uint64_t g_SendContentObserveContentOffset;
extern volatile uint64_t g_SendContentObserveHookInstalled;
extern char g_SendContentObserveReport[16384];
// Armable XML-forward capture snapshot layered on the unified send observer
// above.  Default DISARMED => zero behavioral change (the observer already runs
// read-only).  While armed, the first appmsg/XML content object seen is frozen
// into these fields (vtable RVA, XML-body offset, receiver-wxid offset, field
// map) and the probe self-disarms so a subsequent text/image send cannot
// overwrite the capture.  Consumed via /XmlProbe/result and /QueryDB/status.
extern volatile uint64_t g_XmlProbeArmed;
extern volatile uint64_t g_XmlProbeCaptured;
extern volatile uint64_t g_XmlProbeSendCalls;
extern volatile uint64_t g_XmlProbeVtableRva;
extern volatile uint64_t g_XmlProbeXmlOffset;   // UINT64_MAX = unset
extern volatile uint64_t g_XmlProbeWxidOffset;  // UINT64_MAX = unset
extern char g_XmlProbeFieldMap[16384];
// Forward/resend appmsg source observer.  Hooks the copy-from-source content
// factory (Weixin.dll+0x1741640) whose 2nd arg carries the ORIGINAL message
// send-source object; the forward path (unlike text/image compose) never goes
// through the unified send_message boundary.  Arm-gated with g_XmlProbeArmed:
// while armed, the first forwarded appmsg whose source exposes an XML body is
// frozen into the g_XmlProbe* fields above.  Default disarmed => passthrough.
extern volatile uint64_t g_ForwardObserveCalls;
extern volatile uint64_t g_ForwardObserveHookInstalled;
// Read-only, arm-gated observation of the sendappmsg CGI submit primitive
// (Weixin.dll RVA 0x36AF120).  a1 = network manager, a2 = structured
// SendAppMsgReq protobuf object, a4 = endpoint config struct.  While armed
// (via /AppMsgProbe/arm) the first submit is frozen (manager + request layout
// hex/string map) so the real appmsg send can be replayed.  Default disarmed
// => only a call counter increments and the original submit is passed through.
extern volatile uint64_t g_AppMsgSubmitArmed;
extern volatile uint64_t g_AppMsgSubmitCaptured;
extern volatile uint64_t g_AppMsgSubmitCalls;
extern volatile uint64_t g_AppMsgSubmitHookInstalled;
extern volatile uint64_t g_AppMsgSubmitManager;
// Generic CGI task-dispatch observer (manager->vtable[5], Weixin.dll+0x304F80):
// fires on EVERY CGI dispatch (login/sync/contacts/sendappmsg), so the live
// network manager is captured without a manual card send.
extern volatile uint64_t g_TaskDispatchCalls;
extern volatile uint64_t g_TaskDispatchHookInstalled;
// Persistent clone of the first real complete SendAppMsgRequest, produced via
// WeChat's own ctor + deep-copy at the F120 observer hook.  SendAppMsg swaps
// only the appmsg recipient/content/clientmsgid on this template and replays
// it (F120 deep-copies the template into its task, so it is reusable).
extern volatile uint64_t g_AppMsgTemplate;
extern volatile uint64_t g_AppMsgSubmitRequestObj;
extern volatile uint64_t g_AppMsgSubmitRequestVtable;
extern volatile uint64_t g_AppMsgSubmitA3;
extern volatile uint64_t g_AppMsgSubmitA4;
extern volatile uint64_t g_AppMsgSubmitA5;
extern char g_AppMsgSubmitReport[65536];
// SendAppMsg (custom-vtable CGI task) diagnostics.
extern volatile uint64_t g_AppMsgSendCalls;      // SubmitAppMsgTask entered
extern volatile uint64_t g_AppMsgDispatchOk;     // dispatch returned without SEH
extern volatile uint64_t g_AppMsgDispatchFail;   // dispatch threw (SEH caught)
extern volatile uint64_t g_AppMsgSerializeCalls; // our serialize slot fired
extern volatile uint64_t g_AppMsgResponseCalls;  // our response slot fired
extern volatile uint64_t g_AppMsgLastRespSize;   // last response holder size
extern volatile int64_t  g_AppMsgLastRet;        // last parsed BaseResponse.ret
extern volatile uint64_t g_SysMsgParserCalls;
extern volatile uint64_t g_HistoryAddMsgCalls;
extern volatile uint64_t g_HistoryAddMsgCommitCalls;
extern volatile uint64_t g_SqlitePrepareCalls;
extern volatile uint64_t g_SqlitePrepareV2Calls;
extern volatile uint64_t g_SqliteBindTextCalls;
extern volatile uint64_t g_SqliteBindText16Calls;
extern volatile uint64_t g_SqliteStepCalls;
extern volatile uint64_t g_SqliteHookInstalled;
extern volatile uint64_t g_SqliteApiTable;
extern volatile uint64_t g_SqlitePrepareTarget;
extern volatile uint64_t g_SqlitePrepareV2Target;
extern volatile uint64_t g_SqliteBindTextTarget;
extern volatile uint64_t g_SqliteBindText16Target;
extern volatile uint64_t g_SqliteStepTarget;
extern volatile uint64_t g_SqliteLastDbHandle;
extern volatile uint64_t g_SqliteLastDbThreadId;
extern volatile uint64_t g_SqliteContactDbHandle;
extern volatile uint64_t g_SqliteContactDbThreadId;
extern char g_SqliteLastDbPath[512];
extern char g_SqliteContactDbPath[512];
extern volatile uint64_t g_ContactQueryRequests;
extern volatile uint64_t g_ContactQueryTryCalls;
extern volatile uint64_t g_ContactQueryClaims;
extern volatile uint64_t g_ContactQueryExecuteCalls;
extern volatile uint64_t g_ContactQueryCompleteCalls;
extern volatile uint64_t g_ContactQueryLastDb;
// Read-only observation of WeChat's contact response record parser
// (Weixin.dll RVA 0x2704F70).  The hook only copies validated fields into
// the bounded contact cache; it never calls back into WeChat.
extern volatile uint64_t g_ContactParserCalls;
extern volatile uint64_t g_ContactParserRows;
extern volatile uint64_t g_ContactParserHookInstalled;
extern volatile uint64_t g_ContactParserLastRecord;
extern char g_ContactParserLastUsername[256];
extern char g_ContactParserLastAlias[256];
extern char g_ContactParserLastNickname[512];
extern char g_ContactParserLastBigHeadUrl[1024];
extern char g_ContactParserLastSmallHeadUrl[1024];
// Read-only observation of the contact detail response branch
// (Weixin.dll RVA 0x26B03B0).
extern volatile uint64_t g_ContactDetailCalls;
extern volatile uint64_t g_ContactDetailHookInstalled;
extern volatile uint64_t g_ContactDetailLastManager;
extern volatile uint64_t g_ContactDetailLastOutput;
extern volatile uint64_t g_ContactDetailLastRequest;
extern volatile uint64_t g_ContactDetailLastStatus;
extern volatile uint64_t g_ContactDetailLastResult;
extern volatile uint64_t g_ContactDetailRecordCalls;
extern volatile uint64_t g_ContactDetailLastRecord;
extern char g_ContactDetailLastUsername[256];
extern char g_ContactDetailLastAlias[256];
extern char g_ContactDetailLastNickname[512];
// Read-only observation of the startup/login contact vector (RVA 0x26AC150).
// The vector contains 1080-byte contact records before WeChat folds them into
// its in-memory cache/tree.
extern volatile uint64_t g_ContactStartupCalls;
extern volatile uint64_t g_ContactStartupRecords;
extern volatile uint64_t g_ContactStartupHookInstalled;
extern volatile uint64_t g_ContactStartupLastVector;
extern volatile uint64_t g_ContactStartupLastCount;
extern char g_ContactStartupLastUsername[256];
extern char g_ContactStartupLastAlias[256];
extern char g_ContactStartupLastNickname[512];
// Read-only observation of the full contact-list response source
// (Weixin.dll RVA 0x2CEC8B0).  The callback receives a vector of the same
// 1080-byte Contact records that are later consumed by sub_182CF25E0.
extern volatile uint64_t g_ContactListSourceCalls;
extern volatile uint64_t g_ContactListSourceRecords;
extern volatile uint64_t g_ContactListSourceHookInstalled;
extern volatile uint64_t g_ContactListSourceLastVector;
extern volatile uint64_t g_ContactListSourceLastCount;
extern char g_ContactListSourceLastUsername[256];
extern char g_ContactListSourceLastAlias[256];
extern char g_ContactListSourceLastNickname[512];
// Read-only observation of sub_182CF25E0, the contact response task that
// splits the server response into 1080-byte contact vectors.
extern volatile uint64_t g_ContactResponseBatchCalls;
extern volatile uint64_t g_ContactResponseBatchRecords;
extern volatile uint64_t g_ContactResponseBatchHookInstalled;
extern volatile uint64_t g_ContactResponseBatchLastVector;
extern volatile uint64_t g_ContactResponseBatchLastCount;
extern volatile uint64_t g_ContactResponseSplitCalls;
extern volatile uint64_t g_ContactResponseSplitRecords;
extern volatile uint64_t g_ContactResponseSplitHookInstalled;
extern volatile uint64_t g_ContactResponseSplitLastInputCount;
extern volatile uint64_t g_ContactResponseSplitLastOutputCount;
extern volatile uint64_t g_ContactPipelineCalls;
extern volatile uint64_t g_ContactPipelineRecords;
extern volatile uint64_t g_ContactPipelineHookInstalled;
extern volatile uint64_t g_ContactPipelineLastCount;
extern volatile uint64_t g_ContactRecordParserCalls;
extern volatile uint64_t g_ContactRecordParserRows;
extern volatile uint64_t g_ContactRecordParserHookInstalled;
extern volatile uint64_t g_ContactManagerListCalls;
extern volatile uint64_t g_ContactManagerListRecords;
extern volatile uint64_t g_ContactManagerListHookInstalled;
extern volatile uint64_t g_ContactManagerListLastCount;
extern volatile uint64_t g_ContactManagerListLastVector;
extern volatile uint64_t g_ContactManagerListLastBegin;
extern volatile uint64_t g_ContactManagerListLastEnd;
extern volatile uint64_t g_ContactManagerListLastSpan;
extern volatile uint64_t g_ContactManagerListLastMode;
extern volatile uint64_t g_ContactManagerListLastCaller;
extern volatile uint64_t g_ContactManagerListMaxCount;
extern char g_ContactManagerListLastUsername[256];
// Read-only observation of sub_180F73660, the startup contact-sync source
// that prepares the username vector before CoGetContactListByCgi.
extern volatile uint64_t g_ContactSyncSourceCalls;
extern volatile uint64_t g_ContactSyncSourceItems;
extern volatile uint64_t g_ContactSyncSourceHookInstalled;
extern volatile uint64_t g_ContactSyncSourceLastVector;
extern volatile uint64_t g_ContactSyncSourceLastCount;
extern char g_ContactSyncSourceFirstUsername[256];
extern char g_ContactSyncSourceLastUsername[256];
extern volatile uint64_t g_ContactSyncCallbackCalls;
extern volatile uint64_t g_ContactSyncCallbackRecords;
extern volatile uint64_t g_ContactSyncCallbackHookInstalled;
extern volatile uint64_t g_ContactSyncCallbackLastCount;
extern volatile uint64_t g_ContactSyncCallbackLastVector;
extern char g_ContactSyncCallbackFirstUsername[256];
extern char g_ContactSyncCallbackLastUsername[256];
extern volatile uint64_t g_ContactListBuildCalls;
extern volatile uint64_t g_ContactListBuildRecords;
extern volatile uint64_t g_ContactListBuildHookInstalled;
extern volatile uint64_t g_ContactListBuildLastCount;
extern volatile uint64_t g_ContactListBuildLastVector;
extern char g_ContactListBuildFirstUsername[256];
extern char g_ContactListBuildLastUsername[256];
extern volatile uint64_t g_ContactSessionInfoCalls;
extern volatile uint64_t g_ContactSessionInfoItems;
extern volatile uint64_t g_ContactSessionInfoHookInstalled;
extern volatile uint64_t g_ContactSessionInfoLastCount;
extern volatile uint64_t g_ContactSessionInfoLastVector;
extern char g_ContactSessionInfoFirstUsername[256];
extern char g_ContactSessionInfoLastUsername[256];
// Read-only observation of the general contact DB response engine
// (Weixin.dll RVA 0x26E3330).  The row callback is wrapped only to count
// 344-byte response rows and copy bounded diagnostic strings.
extern volatile uint64_t g_ContactGeneralQueryCalls;
extern volatile uint64_t g_ContactGeneralQueryRows;
extern volatile uint64_t g_ContactGeneralQueryHookInstalled;
extern volatile uint64_t g_ContactGeneralQueryLastRow;
extern char g_ContactGeneralQueryLastField0[256];
extern char g_ContactGeneralQueryLastField1[256];
extern char g_ContactGeneralQueryLastField2[256];
extern char g_ContactGeneralQueryLastField3[256];
extern char g_ContactGeneralQueryLastField4[256];
extern char g_ContactGeneralQueryLastField5[256];
extern char g_ContactGeneralQueryLastField6[256];
extern char g_ContactGeneralQueryLastField7[256];
extern char g_SqliteLastSql[4096];
extern char g_SqliteInterestingSql[4096];
extern char g_SqliteLastBindText[4096];
extern char g_SqliteInterestingBindText[4096];
struct SqliteBindTrace {
    uint64_t sequence;
    uint64_t stmt;
    uint64_t index;
    uint64_t caller;
    char api[16];
    char text[512];
    char sql[1024];
};
inline constexpr size_t kSqliteBindTraceCapacity = 128;
extern SqliteBindTrace g_SqliteBindTraces[kSqliteBindTraceCapacity];
extern volatile uint64_t g_SqliteBindTraceIndex;
bool RunContactQueryOnSqliteThread(const std::string& wxid, std::string& resultJson,
                                   uint32_t timeoutMs);
bool RunSqlQueryOnSqliteThread(const std::string& dbname, const std::string& sql,
                               std::string& resultJson, uint32_t timeoutMs);
// Called only from the SQLite hook thread after a Contact row has been read.
// The HTTP thread consumes this bounded cache; it never dereferences SQLite
// objects directly.
void RecordCapturedContactRow(const std::string& wxid, const std::string& rowJson);
extern volatile uint64_t g_MessageParserCalls;
extern volatile uint64_t g_MessageParserLastObject;
extern volatile uint64_t g_SyncContextObject;
extern volatile uint64_t g_FieldLookupCalls;
extern volatile uint64_t g_FieldLookupLastKey;
extern char g_FieldLookupLastKeyText[128];
extern volatile uint64_t g_FieldFromCalls, g_FieldContentCalls, g_FieldMsgCalls, g_FieldWordingCalls;
extern char g_FieldFromText[256], g_FieldContentText[4096], g_FieldMsgText[4096], g_FieldWordingText[4096];
extern char g_FieldMsgOutputHex[256];
extern char g_FieldMsgNodeHex[512];
extern char g_FieldMsgValueHex[512];
extern char g_FieldWordingOutputHex[256];
extern char g_FieldWordingNodeHex[512];
extern char g_FieldWordingValueHex[512];
extern char g_DbDebugText[512];
struct FieldLookupTrace {
    uint64_t sequence;
    uint64_t container;
    uint64_t output;
    uint64_t keyPtr;
    uint64_t result;
    char key[64];
    char text[256];
};
inline constexpr size_t kFieldLookupTraceCapacity = 96;
extern FieldLookupTrace g_FieldLookupTraces[kFieldLookupTraceCapacity];
extern volatile uint64_t g_FieldLookupTraceIndex;

struct MessageBranchTrace {
    uint64_t sequence;
    uint64_t handler;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t caller;
    char name[32];
};
inline constexpr size_t kMessageBranchTraceCapacity = 96;
extern MessageBranchTrace g_MessageBranchTraces[kMessageBranchTraceCapacity];
extern volatile uint64_t g_MessageBranchTraceIndex;
extern volatile uint64_t g_ProfileObject;
extern volatile uint64_t g_ProfileFieldCalls;
extern volatile uint64_t g_ProfileFieldObject;
extern volatile uint64_t g_ProfileFieldDescriptor;
extern volatile uint64_t g_ProfileLookupCalls;
extern char g_ProfileLookupLastKey[128];
extern char g_ProfileLookupLastValue[1024];
extern volatile uint64_t g_ProfileContainer830Calls;
extern volatile uint64_t g_ProfileContainer830Object;
extern volatile uint64_t g_ProfileContainer830Root;
extern volatile uint64_t g_ProfileContainer830Second;
extern volatile uint64_t g_ProfileContainerFC00Calls;
extern volatile uint64_t g_ProfileContainerFC00Object;
extern volatile uint64_t g_ProfileContainerFC00Root;
extern volatile uint64_t g_ProfileContainerFC00Second;
extern volatile uint64_t g_ManagerContainerGetterCalls;
extern volatile uint64_t g_ManagerContainerObject;
struct ProfileFieldTrace {
    uint64_t object;
    uint64_t output;
    uint64_t descriptor;
    uint64_t result;
    uint64_t sequence;
    uint64_t caller;
    uint8_t outputBytes[32];
};
inline constexpr size_t kProfileTraceCapacity = 64;
extern ProfileFieldTrace g_ProfileTraces[kProfileTraceCapacity];
extern volatile uint64_t g_ProfileTraceIndex;
extern volatile uint64_t g_getprofile;

extern volatile bool g_LoginMonitorRunning;
extern std::string g_CallBack_Url;
extern CRITICAL_SECTION g_dbMgrCriticalSection;

extern std::wstring g_AppDataDir;
extern std::wstring g_DocumentDir;
extern std::wstring g_UsersDir;
extern HMODULE g_hModule;

extern uint64_t g_MyModuleBase;
extern uint64_t g_MyModuleSize;
extern uint64_t g_MyModuleEnd;


struct SelfInfo_t
{
    std::string wxid;
    std::string alias;
    std::string nickname;
    std::string phone;
    std::string email;

    uint64_t qq;
    std::string proiv;
    std::string area;
    std::string signinfo;
    std::string avatar;
    std::string small_avatar;
    int sex = 0;


};
// 全局唯一实例
extern SelfInfo_t SelfInfo;

#define WX_ADDR(offset) ((void*)((uintptr_t)g_hWeixinDll + (offset)))
#define XWECHAT_MAIN_CLAZZ_OFFSET            ((void*)((uintptr_t)g_hWeixinDll + 0xA83AB20))

inline std::wstring g_MyDir;

inline HttpServer* g_httpServer = nullptr;

inline constexpr uint64_t g_Patch_Revoke = 0x22D09E7;


// Weixin 4.1.10.27 (IDA imagebase 0x180000000).
// The previous 0x824F840/0x824F8F8 values pointed into unrelated data and
// caused the contact query path to call arbitrary addresses after login.
constexpr size_t XWECHAT_SQLITE3_VFS_OFFSET = 0xA6C04A8;
constexpr size_t XWECHAT_SQLITE3_API_ROUTINES_OFFSET = 0x8BB0D38;
constexpr size_t XWECHAT_SQLCIPHER_API_ROUTINES_OFFSET = 0x824FB48;
constexpr size_t XWECHAT_SQLITE3_CODEC_GET_KEY_FUNC = 0x4EE64D0;	//可以废弃不用

namespace offset
{
    inline constexpr uint64_t dec_pic_call = 0x493E70;
    // Public image-decode wrapper: normalizes wide paths (UTF-16 -> UTF-8),
    // probes the encryption type via sub_180494860, then dispatches to the
    // matching decoder (sub_180493E70 for the V2 "\x07\x08" format).
    inline constexpr uint64_t dec_pic_wrapper = 0x496E30;
    // Per-user image AES key derivation: sub_1809B1FD0(std::string* out, 2).
    // Returns the derived key string (first 16 bytes = AES-128-ECB key).
    inline constexpr uint64_t img_key_derive = 0x9B1FD0;
    // Per-user image XOR key derivation: sub_1809B1F20() (no args).
    // Returns the single XOR byte (low 8 bits) for the trailing XOR region.
    inline constexpr uint64_t img_xor_key = 0x9B1F20;
    inline constexpr uint64_t create_param2 = 0xDF40;
    inline constexpr uint64_t send_message = 0x1677A30;
    inline constexpr uint64_t param1_vtable = 0x84EC9C8; 

    inline constexpr uint64_t param2 = 0xA0CE0B0;
    inline constexpr uint64_t param2_1 = 0x8595F58;
    inline constexpr uint64_t param2_2 = 0x8595E98; 
    inline constexpr uint64_t param2_3 = 0x8595DD8; 
    inline constexpr uintptr_t txt_message_ctr = 0x6B2C30; 
    inline constexpr uintptr_t txt_message_vtbl = 0x8279358;
    inline constexpr uint64_t img_msg_vtbl = 0x84F96B8; 
    inline constexpr uint64_t img_msg_vtb2 = 0x84F9748;
    // Verified via content-object factory sub_182A1AC80 (see notes below):
    inline constexpr uint64_t video_msg_vtbl = 0x84F9888;   // "VideoMessageSendSource"
    // Candidate appmsg/XML (msgtype 49) content vtable = generic
    // "MessageSendSource" base; 0x718-byte (1816) object.
    inline constexpr uint64_t appmsg_base_vtbl = 0x84F9A78;
    // Verified default factory for the generic MessageSendSource base
    // (sub_7FFE90C092B0, one of the 4 xrefs that write vtable 0x84F9A78):
    // allocates 1816 bytes, sets vtable@+0 and refcount 0x100000001@+8,
    // constructs the base sub-object at wrapper+0x10 via sub_7FFE8F012D30,
    // and returns a shared_ptr pair {obj* (=wrapper+0x10), ctrl* (=wrapper)}
    // in the caller-supplied 2-qword out buffer.  Base sub-object layout
    // (IDA-derived from the base ctor + verified against the TextMessage
    // struct in wx_send.cpp): WeixinString slots at 0x18/0x38/0x58/0x78/
    // 0xB0/0x108/0x148/0x168/0x190/0x6A8/0x6C8/0x6E8; receiver@0xB0,
    // msgtype@0xD8, uuid@0x6A8.  copy-from-source (forward) preserves
    // 0x38/0x58/0x78 and resets receiver@0xB0, so the appmsg XML body is
    // one of 0x38/0x58/0x78 -- swept at runtime via /ForwardXMLMsg.
    inline constexpr uint64_t appmsg_default_ctor = 0x46A92B0;

    // ==== Verified sendappmsg CGI submit path (WeChat 4.1.10.27) ====
    // Reverse-engineered + runtime-captured via the F120 observer hook.
    // sendappmsg submit primitive (sub_7FFE9200F120): hardcodes
    // "/cgi-bin/micromsg-bin/sendappmsg" (cgi type 222), deep-copies the
    // caller's structured SendAppMsgRequest via sub_7FFE92DCC3D0 (CopyFrom,
    // const source => read-only), and dispatches through the network manager.
    inline constexpr uint64_t appmsg_submit = 0x36AF120;
    // SendAppMsgRequest default ctor (sub_7FFE92DB1B00): vtable 0x8A57138.
    // Sub-message pointers base@+0x08 / appmsg@+0x10 (has-bits dword @ +0x5C,
    // bit0x01=base, bit0x02=appmsg).
    inline constexpr uint64_t sendappmsg_req_ctor = 0x4451B00;
    // AppMsg sub-message default ctor (sub_7FFE92DB1AA0): vtable 0x8A570C8,
    // 120-byte object, has-bits dword @ +0x70.  ArenaStringPtr string fields:
    // fromusername@+0x08(0x01), tousername@+0x18(0x08), type int@+0x24(0x10),
    // content@+0x28(0x20), clientmsgid@+0x30(0x80).
    inline constexpr uint64_t appmsg_msg_ctor = 0x4451AA0;
    // BaseRequest sub-message default ctor (sub_7FFE8EF3A8A0): vtable
    // 0x82651E8, 56-byte object, has-bits dword @ +0x30; default-constructs
    // empty (no session data required).
    inline constexpr uint64_t sendappmsg_base_ctor = 0x5DA8A0;
    // SendAppMsgRequest deep-copy primitive (sub_7FFE92DCC3D0): calls
    // dest->Clear() then copy-assign (sub_7FFE92DCAC60), which deep-copies
    // every set field per the has-bits.  Used to clone the first real,
    // complete request into a persistent template so SendAppMsg replays a
    // fully-valid SendAppMsgRequest (valid BaseRequest session + all required
    // scalar fields) and only swaps the appmsg recipient/content/clientmsgid.
    inline constexpr uint64_t sendappmsg_req_copy = 0x446C3D0;

    // ==== Custom-vtable sendappmsg CGI task (WeChat 4.1.10.27) ====
    // Real-send path that NEVER hands WeChat a native protobuf object to
    // serialize (the async serialize of a native SendAppMsgRequest crashed the
    // worker at Weixin.dll+0x46a92e3).  Instead WeixinSend::SendAppMsg builds
    // the CGI task exactly like the native submit primitive, then overrides
    // the task vtable so the serialize slot emits hand-serialized protobuf
    // bytes and the response slot captures the reply; the task is dispatched
    // through the live manager (g_AppMsgSubmitManager) via manager->vtable[5]
    // and intentionally leaked (custom no-op dtor) to avoid any
    // cross-allocator free / uninitialised-field destruct.
    //
    // Task ctor sub_7FFE9200F460: cgi type<-task_info+16, endpoint<-task_info
    // +24, empty inner request built @task+240, response holder @task+208,
    // state=3.  Task vtable off_7FFE97216F98 = 6 slots
    // [dtor, serialize, response, getinner(->task+240), dummy, literal 1].
    inline constexpr uint64_t appmsg_task_ctor   = 0x36AF460;
    // Holder helpers used by the serialize/response slots (sub_7FFE8EF3A760 /
    // sub_7FFE8EF3A7D0 / sub_7FFE8EF3A7A0): append bytes to the output holder,
    // read the response holder size, and read the response holder data ptr.
    inline constexpr uint64_t appmsg_holder_write = 0x5DA760;
    inline constexpr uint64_t appmsg_holder_size  = 0x5DA7D0;
    inline constexpr uint64_t appmsg_holder_data  = 0x5DA7A0;

    // Native "insert local system message into a conversation" primitive
    // (sub_184C280B0): builds
    //   <?xml version="1.0"?>\n<sysmsg type="paymsg"><content>
    //     <![CDATA[<arg3>]]></content></sysmsg>
    // constructs a 728-byte local message object (type 10000 via
    // sub_180A1B1B0), stamps the talker via sub_180A1AB20, and inserts it into
    // the conversation through sub_18173DA00.  Signature (verified by
    // decompile; a1 is unused in the body):
    //   sub_184C280B0(void* /*unused*/, WeixinString* talker, WeixinString* content)
    // Both talker and content are WeixinString (16-byte SSO buffer, then
    // length @+0x10 / capacity @+0x18; heap when length >= 0x10).  Used by the
    // experimental recall-tip injection (WeixinSend::InsertLocalSysTip).
    inline constexpr uint64_t revoke_tip_insert = 0x4C280B0;
}


// XML-forwarding offsets below were reverse-engineered against WeChat
// 4.1.5.30 and are CONFIRMED STALE for 4.1.10.27 via IDA (imagebase
// 0x180000000, so RVA R decompiles at 0x180000000+R):
//   * FORWARD_XML_CALL (RVA 0x1CF3D20 -> 0x181CF3D20) is NOT a function
//     entry on 4.1.10.27: it lands 0xD80 bytes inside sub_181CF2FA0, a Qt
//     UI-layout routine (refs "splitter_left_min_width",
//     "main_window_mask_margin", QArrayData) -- not a message-forward call.
//   * The hardcoded rdx+0x20 reference g_weixinBase+0x367849 (0x180367849)
//     lands in the middle of sub_1803677F0, not a data target.
// Calling/using them on 4.1.10.27 would jump into unrelated UI code and
// crash Weixin.exe.  The forward-XML object graph (12 vtables + forward
// call + field offsets) has no symbol/string anchor to relocate reliably by
// static analysis alone, and per the project guardrail an enabled send Hook
// requires runtime verification on a live client.  ForwardXmlMessage stays
// behind a safe early-return in ForwardXMLMsg.cpp until these are re-derived
// and runtime-verified.
//
// Relocation anchors gathered via IDA for a future runtime-verification pass:
//   * Message send/forward is VIRTUAL DISPATCH per message class.  The
//     verified text-send sub_181677A30 is slot +0x10 of the text param-class
//     vtable at 0x1884EC9C8 (offset::param1_vtable 0x84EC9C8); slots are
//     {+0x00 sub_1816778E0, +0x08 sub_18000A820, +0x10 send sub_181677A30,
//      +0x18 sub_181677F00, +0x20 sub_181677F10, +0x28 sub_180009760}.
//   * The verified send path (SendText/SendImage) is: build a *content
//     object* whose vtable selects the message class, wrap it with
//     offset::param1_vtable (0x84EC9C8) + BuildSendParam2, then call the
//     single verified send_message (offset::send_message 0x1677A30).  XML
//     forwarding must be re-implemented on this same path, NOT the dead
//     4.1.5.30 FORWARD_XML_CALL object graph below.
//   * Content-object factory sub_182A1AC80 (RVA 0x2A1AC80) dispatches by the
//     serialized "<Type>MessageSendSource" type-name string (switch on
//     std::string length via pcmpeqb; jumptable jpt_182A1B119 @ 0x18876DE1C).
//     Verified case -> content vtable (RVA):
//       len 17 "MessageSendSource"      -> 0x84F9A78  (generic base, 0x718 obj,
//                                                       ctor sub_1806B4470)
//       len 21 "TextMessageSendSource"  -> 0x8279358  (== offset::txt_message_vtbl)
//       len 22 "ImageMessageSendSource" -> 0x84F96B8  (== offset::img_msg_vtbl)
//       len 22 "VideoMessageSendSource" -> 0x84F9888  (NEW: video content vtable)
//       len 32 "ChatInputTempApp..."    -> loc_182A1B464
//     There is NO dedicated "AppMessageSendSource" case (len 20 falls to the
//     default/error branch def_182A1B119).  The appmsg/XML (msgtype 49)
//     content is therefore most likely built on the generic
//     "MessageSendSource" base (vtable 0x84F9A78), but the 0x718-byte object
//     field layout (XML-content string, receiver wxid, appmsg type field) is
//     NOT derivable by static analysis and, per the project guardrail, must
//     be confirmed by runtime tracing on a live 4.1.10.27 client before an
//     enabled send Hook can be shipped.
//   * RTTI class-name strings are ENCRYPTED (typeDescriptor at 0x18A252F30
//     for the text class is non-ASCII), so the appmsg class cannot be found
//     by name statically -- confirming the layout needs runtime tracing of
//     an actual forward on a live 4.1.10.27 client.
//4.1.5.30  xml (UNVERIFIED / STALE for 4.1.10.27)
namespace Offsets
{
    inline constexpr uintptr_t IMAGE_FIELD_VTABLE = 0x80D1098;          //ok  41930 ? 41923
    inline constexpr uintptr_t IMAGE_FIELD_VTABLE2 = 0x80D1128;         //ok
    inline constexpr uintptr_t IMAGE_DATA_VTABLE = 0x7415D28;
    inline constexpr uintptr_t IMAGE_DATA_VTABLE2 = 0x7415DB8;
    inline constexpr uintptr_t VIDEO_FIELD_VTABLE = 0x750C7F8;
    inline constexpr uintptr_t VIDEO_FIELD_VTABLE2 = 0x750C888;
    inline constexpr uintptr_t ANIMATION_FIELD_VTABLE = 0x750CC18;
    inline constexpr uintptr_t ANIMATION_FIELD_VTABLE2 = 0x750CCA8;
    inline constexpr uintptr_t MESSAGE_STRUCT_VTABLE = 0x76BD388;
    inline constexpr uintptr_t MESSAGE_STRUCT_VTABLE2 = 0x76BD338;
    inline constexpr uintptr_t MESSAGE_PARAM_VTABLE = 0x76BCF38;
    inline constexpr uintptr_t FORWARD_XML_CALL = 0x1CF3D20;
}



