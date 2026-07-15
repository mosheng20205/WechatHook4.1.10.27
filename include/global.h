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
extern char g_SyncBatchText1[4096];
extern char g_SyncBatchText2[4096];
extern char g_SyncBatchText3[4096];
extern char g_SyncBatchText4[4096];
extern volatile uint64_t g_AutoReplyQueued;
extern volatile uint64_t g_AutoReplySent;
extern volatile uint64_t g_AutoReplyFailed;
extern volatile uint64_t g_AutoReplyCandidates;
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
};
inline constexpr size_t kSqliteBindTraceCapacity = 128;
extern SqliteBindTrace g_SqliteBindTraces[kSqliteBindTraceCapacity];
extern volatile uint64_t g_SqliteBindTraceIndex;
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


constexpr size_t XWECHAT_SQLITE3_VFS_OFFSET = 0x824F840;
constexpr size_t XWECHAT_SQLITE3_API_ROUTINES_OFFSET = 0x824F8F8;
constexpr size_t XWECHAT_SQLCIPHER_API_ROUTINES_OFFSET = 0x824FB48;
constexpr size_t XWECHAT_SQLITE3_CODEC_GET_KEY_FUNC = 0x4EE64D0;	//可以废弃不用

namespace offset
{
    inline constexpr uint64_t dec_pic_call = 0x493E70;
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
}


//4.1.5.30  xml
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



