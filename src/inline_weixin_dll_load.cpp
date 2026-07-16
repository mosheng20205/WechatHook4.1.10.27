#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <string>
#include <Windows.h>
#include <winternl.h>
#include <cstring>
#include <cctype>
#include <sstream>
#include <condition_variable>
#include <chrono>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "http_server.h"
#include "Hook_Method.h"

#include "global.h"
#include <MinHook.h>
#include "tools.h"
#include "HookManager.h"
#include "json.hpp"
#include "wx_ini_reader.h"
#include "inline_weixin_dll_load.h"
#include "hook_xlog.h"
#include "http_post.h"
#include "wx_send.h"
#include "../xdb/sqlite3.h"
#include "../xdb/db_mgr.h"



using json = nlohmann::json;

typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );



DWORD GetParentProcessId()
{
    PFN_NtQueryInformationProcess NtQueryInformationProcess =
        (PFN_NtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtQueryInformationProcess"
        );

    if (!NtQueryInformationProcess)
        return 0;

    PROCESS_BASIC_INFORMATION pbi = { 0 };

    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );

    if (status != 0)
        return 0;

    return (DWORD)(ULONG_PTR)pbi.Reserved3;
}


DWORD WINAPI AfterLoginInitThread(LPVOID)
{
    // 等待登录成功
    while (g_IsLogin != 1)
    {
        Sleep(300);
    }

    return 0;
}

// 过低版本
void Patch_Low_Version()
{
    // XWECHAT_MAIN_CLAZZ_OFFSET 4.1.8.67
    DWORD_PTR baseAddress = (DWORD_PTR)g_hWeixinDll + reinterpret_cast<uintptr_t>(XWECHAT_MAIN_CLAZZ_OFFSET);

    DWORD_PTR* pPointer = (DWORD_PTR*)baseAddress;
    if (*pPointer == NULL) {
        // 处理空指针情况
        return;
    }

    DWORD_PTR targetAddress = (*pPointer) + 0xB8 + 0x90;        //80  = 00000000F2541843



    // 直接通过指针修改
    BYTE* pTarget = (BYTE*)targetAddress;

    // 修改内存保护属性
    DWORD oldProtect;
    VirtualProtect(pTarget, 4, PAGE_EXECUTE_READWRITE, &oldProtect);

    *(pTarget) = 0x43;      // 低位字节 = 67
    *(pTarget + 1) = 0x18;
    *(pTarget + 2) = 0x54;  // 高位字节
    *(pTarget + 3) = 0xF2;  

    // 恢复保护属性
    VirtualProtect(pTarget, 4, oldProtect, &oldProtect);
}


void Patch_Low_Version_m2()
{
    // 4.1.8.67 addresses
    struct PatchInfo {
        DWORD_PTR addr;
        BYTE bytes[4];
    };

    // F2510201
    // F2541843
    PatchInfo patches[] = {
        { (DWORD_PTR)g_hWeixinExe + 0x36E2, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0x18EB, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0x1B0E, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0x204B, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0xDE4C33, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0x2AC9481, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0x3248CE9, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0x379D66E, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinExe + 0x204FA0, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0xDE540C, { 0x43, 0x19, 0x6C, 0xF2 } }, 
        { (DWORD_PTR)g_hWeixinDll + 0xA3518D0, { 0x43, 0x19, 0x6C, 0xF2 } },
        { (DWORD_PTR)g_hWeixinDll + 0xA3518D4, { 0x43, 0x19, 0x6C, 0xF2 } }
    };

    DWORD oldProtect;
    for (int i = 0; i < 3; i++) {
        VirtualProtect((LPVOID)patches[i].addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)patches[i].addr, patches[i].bytes, 4);
        VirtualProtect((LPVOID)patches[i].addr, 4, oldProtect, &oldProtect);
    }

}


//启用防撤回
void Patch_Revoke()
{
    // 计算目标地址
    DWORD_PTR targetAddress = (DWORD_PTR)g_hWeixinDll + g_Patch_Revoke;

    // 直接通过指针修改
    BYTE* pTarget = (BYTE*)targetAddress;

    // 修改内存保护属性
    DWORD oldProtect;
    VirtualProtect(pTarget, 2, PAGE_EXECUTE_READWRITE, &oldProtect);

    *pTarget = 0x90;           // 第一个字节改为 nop
    *(pTarget + 1) = 0xE9;     // 第二个字节改为 jmp 操作码

    // 恢复保护属性
    VirtualProtect(pTarget, 2, oldProtect, &oldProtect);
}


using FnWcProbe = void(__fastcall*)(void* out_buffer, void* out_len, void* input_param);
FnWcProbe g_Original = nullptr;

// Weixin 4.1.10.27: account_username-backed login-state probe.
// This is deliberately an observation hook: call the original on the
// Weixin-owned thread and only mirror its boolean return into our API state.
using FnLoginStateProbe = unsigned char(__fastcall*)(int64_t context);
static FnLoginStateProbe g_OriginalLoginStateProbe = nullptr;
static LONG g_LoginStateHookInstalled = 0;
using FnLoginFinish = int64_t(__fastcall*)(int64_t context, void* payload);
static FnLoginFinish g_OriginalLoginFinish = nullptr;
static LONG g_LoginFinishHookInstalled = 0;
using FnManagerGetter = void*(__fastcall*)();
using FnProfileGetter = void(__fastcall*)(void* manager, void** out_object);
static FnManagerGetter g_OriginalManagerGetter = nullptr;
static FnProfileGetter g_OriginalProfileGetter = nullptr;
static LONG g_ManagerHookInstalled = 0;
static LONG g_ProfileHookInstalled = 0;
using FnProfileFieldRead = void*(__fastcall*)(void* object, void* output, void* descriptor);
static FnProfileFieldRead g_OriginalProfileFieldRead = nullptr;
static LONG g_ProfileFieldHookInstalled = 0;
using FnProfileContainer = __int64*(__fastcall*)(__int64*);
static FnProfileContainer g_OriginalContainer830 = nullptr;
static FnProfileContainer g_OriginalContainerFC00 = nullptr;
static LONG g_ProfileContainerHooksInstalled = 0;

// Message dispatch path identified in Weixin.dll 4.1.10.27 by IDA:
// sub_181749DC0(a1, message_object, message_type).
using FnMessageDispatch = char(__fastcall*)(void* manager, void* message, unsigned int type);
static FnMessageDispatch g_OriginalMessageDispatch = nullptr;
static LONG g_MessageHookState = 0;
using FnMessageParser = int64_t(__fastcall*)(void* context, void* message, unsigned char type);
static FnMessageParser g_OriginalMessageParser = nullptr;
static LONG g_MessageParserHookState = 0;
using FnPbMessageParser = int64_t(__fastcall*)(int64_t, int64_t);
static FnPbMessageParser g_OriginalPbTextParser = nullptr;
static FnPbMessageParser g_OriginalPbVideoParser = nullptr;
using FnMsgUserParser = __m128i* (__fastcall*)(__m128i*, int64_t*);
static FnMsgUserParser g_OriginalMsgUserParser = nullptr;
static LONG g_PbParserHookState = 0;
using FnDbAddMessage = int64_t(__fastcall*)(int64_t, int64_t, int64_t, char);
static FnDbAddMessage g_OriginalDbAddMessage = nullptr;
static LONG g_DbAddMessageHookState = 0;
using FnRawSyncMsgProcessor = int64_t(__fastcall*)(int64_t* items, uint64_t* context, char a3, char a4);
static FnRawSyncMsgProcessor g_OriginalRawSyncMsgProcessor = nullptr;
static LONG g_RawSyncMsgProcessorHookState = 0;
// sub_182C2C810 passes the 0x78-byte sync vector to sub_1816D5180.  This is
// the first ordinary-text processing stage after the raw sync dispatcher.
using FnSyncBatchProcessor = char(__fastcall*)(int64_t context, int64_t* items,
                                                unsigned char a3, char a4);
static FnSyncBatchProcessor g_OriginalSyncBatchProcessor = nullptr;
static LONG g_SyncBatchProcessorHookState = 0;
using FnMessageObjectCopy = int64_t(__fastcall*)(int64_t object, int64_t source);
static FnMessageObjectCopy g_OriginalMessageObjectCopy = nullptr;
static LONG g_MessageObjectCopyHookState = 0;
// sub_182C6D230 copies the nested MicroMsgRequestNew portion of
// SendMsgRequestNew before it is serialized into /cgi-bin/micromsg-bin/newsendmsg.
// This hook is observation-only: it captures fields and then calls the original.
using FnSendMsgRequestCopy = void(__fastcall*)(void* destination, void* source);
static FnSendMsgRequestCopy g_OriginalSendMsgRequestCopy = nullptr;
static LONG g_SendMsgRequestObserveHookState = 0;
// sub_182C6C060 copies one 56-byte message element.  Its source object owns
// the field-2 and field-6 native strings at +0x10 and +0x20 respectively.
using FnSendMsgElementCopy = int64_t(__fastcall*)(void* destination,
                                                   void* source,
                                                   void* arena);
static FnSendMsgElementCopy g_OriginalSendMsgElementCopy = nullptr;
static LONG g_SendMsgElementObserveHookState = 0;
using FnSyncDispatcher = int64_t(__fastcall*)(int64_t);
static FnSyncDispatcher g_OriginalSyncDispatcher = nullptr;
static LONG g_SyncDispatcherHookState = 0;
using FnFieldLookup = int64_t(__fastcall*)(int64_t, int64_t, int64_t);
static FnFieldLookup g_OriginalFieldLookup = nullptr;
static FnFieldLookup g_OriginalFieldLookupByNode = nullptr;
static LONG g_FieldLookupHookState = 0;
using FnMsgReplaceHandler = int64_t(__fastcall*)(int64_t, int64_t);
static FnMsgReplaceHandler g_OriginalMsgReplaceHandler = nullptr;
static LONG g_MsgReplaceHandlerHookState = 0;
using FnPlainTextMsgHandler = int64_t(__fastcall*)(int64_t, int64_t);
static FnPlainTextMsgHandler g_OriginalPlainTextMsgHandler = nullptr;
static LONG g_PlainTextMsgHandlerHookState = 0;
using FnMsgSourceParser = int64_t(__fastcall*)(int64_t, int64_t);
static FnMsgSourceParser g_OriginalMsgSourceParser = nullptr;
static LONG g_MsgSourceParserHookState = 0;
using FnMsgWordingParser = unsigned char(__fastcall*)(int64_t, int64_t);
static FnMsgWordingParser g_OriginalMsgWordingParser = nullptr;
static LONG g_MsgWordingParserHookState = 0;
using FnMessageStructCopy = int64_t(__fastcall*)(int64_t, int64_t);
static FnMessageStructCopy g_OriginalMessageStructCopy = nullptr;
static LONG g_MessageStructCopyHookState = 0;
using FnMsgDbStruct1 = int64_t(__fastcall*)(int64_t);
using FnMsgDbStruct2 = int64_t(__fastcall*)(int64_t, int64_t);
static LONG g_MessageDbStructHookState = 0;
using FnSysMsgParser = int64_t(__fastcall*)(int64_t, int64_t, int64_t);
static FnSysMsgParser g_OriginalSysMsgParser = nullptr;
static LONG g_SysMsgParserHookState = 0;
using FnHistoryAddMsgQuery = int64_t(__fastcall*)(int64_t, int64_t, int64_t, int64_t);
static FnHistoryAddMsgQuery g_OriginalHistoryAddMsgQuery = nullptr;
static LONG g_HistoryAddMsgQueryHookState = 0;
using FnHistoryAddMsgCommit = int64_t(__fastcall*)(int64_t);
static FnHistoryAddMsgCommit g_OriginalHistoryAddMsgCommit = nullptr;
static LONG g_HistoryAddMsgCommitHookState = 0;
using FnSqlitePrepare = int(*)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
using FnSqlitePrepare16 = int(*)(sqlite3*, const void*, int, sqlite3_stmt**, const void**);
using FnSqliteBindText = int(*)(sqlite3_stmt*, int, const char*, int, void(*)(void*));
using FnSqliteBindText16 = int(*)(sqlite3_stmt*, int, const void*, int, void(*)(void*));
using FnSqliteStep = int(*)(sqlite3_stmt*);
static FnSqlitePrepare g_OriginalSqlitePrepare = nullptr;
static FnSqlitePrepare g_OriginalSqlitePrepareV2 = nullptr;
static FnSqliteBindText g_OriginalSqliteBindText = nullptr;
static FnSqliteBindText16 g_OriginalSqliteBindText16 = nullptr;
static FnSqliteStep g_OriginalSqliteStep = nullptr;
static LONG g_SqliteApiHookState = 0;
using FnMessageBranch2 = int64_t(__fastcall*)(int64_t, int64_t);
using FnMessageBranch3 = int64_t(__fastcall*)(int64_t, int64_t, int64_t);
static LONG g_MessageBranchHookState = 0;
struct HookNativeString { union { char inline_buf[16]; char* heap_buf; }; uint64_t length; uint64_t capacity; };
static int64_t FindHookValueNode(int64_t node)
{
    for (int depth = 0; node && depth < 32; ++depth) {
        uint64_t tag = 0;
        __try { tag = *reinterpret_cast<const uint64_t*>(node); } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        const uint64_t type = tag & 0xF;
        if (type == 3 || type == 4 || (type == 2 && *reinterpret_cast<const int64_t*>(node + 0x10))) return node;
        int64_t child = 0;
        __try { child = *reinterpret_cast<const int64_t*>(node + 0x20); } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        if (!child) return 0;
        node = child;
    }
    return 0;
}
static void CopyHookOutput(int64_t output, char* dst, size_t cap)
{
    if (!dst || cap == 0) return;
    dst[0] = 0;
    __try {
        int64_t node = 0;
        __try { node = *reinterpret_cast<const int64_t*>(output); } __except (EXCEPTION_EXECUTE_HANDLER) { node = 0; }
        if (!node) return;
        node = FindHookValueNode(node);
        if (!node) return;
        const int64_t value = *reinterpret_cast<const int64_t*>(node + 0x10);
        if (!value) return;
        const char* p = reinterpret_cast<const char*>(value);
        size_t n = 0;
        while (n + 1 < cap && n < 8192 && p[n]) ++n;
        if (n > 0 && n + 1 < cap) {
            memcpy(dst, p, n);
            dst[n] = 0;
            return;
        }
        auto* s = reinterpret_cast<HookNativeString*>(value);
        if (s->length == 0 || s->length >= cap) return;
        p = s->capacity >= 0x10 ? s->heap_buf : s->inline_buf;
        if (p) { memcpy(dst, p, static_cast<size_t>(s->length)); dst[s->length] = 0; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void CopySafeText(const char* src, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return;
    dst[0] = 0;
    if (!src)
        return;
    __try {
        size_t n = 0;
        while (n + 1 < cap && src[n])
            ++n;
        memcpy(dst, src, n);
        dst[n] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
    }
}

static void RecordMessageBranchTrace(const char* name, uint64_t handler,
                                     uint64_t a1, uint64_t a2, uint64_t a3);

static bool IsReadablePointer(const void* ptr)
{
    if (!ptr)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
        return false;
    return true;
}

static bool IsExecutablePointer(const void* ptr)
{
    if (!ptr)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return false;
    const DWORD protection = mbi.Protect & 0xFF;
    return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
           protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
}

static size_t CopyNativeStringAt(int64_t object, size_t offset,
                                 char* dst, size_t cap);
static bool TryCopyNativeStringObject(int64_t object, char* dst, size_t cap);

// Contact response records are produced by WeChat's own response parser at
// RVA 0x2704F70.  Keep this observer deliberately read-only: call the
// original first, then copy only bounded native-string fields from the
// caller-owned 1080-byte record.  No WeChat routine is called from here.
using FnContactResponseParser = int64_t(__fastcall*)(int64_t, int64_t, int64_t);
static FnContactResponseParser g_OriginalContactResponseParser = nullptr;
static LONG g_ContactResponseParserHookState = 0;

static bool IsLikelyContactUsername(const char* text)
{
    if (!text)
        return false;
    size_t n = 0;
    while (n < 255 && text[n])
        ++n;
    if (n < 3 || n >= 255)
        return false;
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c <= 0x20 || c == '\\' || c == '"')
            return false;
    }
    return true;
}

static int64_t __fastcall Hook_ContactResponseParser(int64_t context,
                                                     int64_t response,
                                                     int64_t record)
{
    const int64_t result = g_OriginalContactResponseParser
        ? g_OriginalContactResponseParser(context, response, record) : 0;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactParserCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactParserLastRecord),
                          static_cast<LONG64>(record));

    if (!result || !g_IsLogin || !record ||
        !IsReadablePointer(reinterpret_cast<const void*>(record)))
        return result;

    char username[256]{};
    char alias[256]{};
    char nickname[512]{};
    char quanPin[512]{};
    char bigHeadUrl[1024]{};
    char smallHeadUrl[1024]{};
    char description[1024]{};
    if (!CopyNativeStringAt(record, 8, username, sizeof(username)) ||
        !IsLikelyContactUsername(username))
        return result;

    // Offsets are the fields written by sub_182704F70 for 4.1.10.27:
    // username 0x08, alias 0x28, nickname 0xD8, quan_pin 0x118,
    // big_head_url 0x138, small_head_url 0x158, description 0x1A0.
    CopyNativeStringAt(record, 40, alias, sizeof(alias));
    CopyNativeStringAt(record, 216, nickname, sizeof(nickname));
    CopyNativeStringAt(record, 280, quanPin, sizeof(quanPin));
    CopyNativeStringAt(record, 312, bigHeadUrl, sizeof(bigHeadUrl));
    CopyNativeStringAt(record, 344, smallHeadUrl, sizeof(smallHeadUrl));
    CopyNativeStringAt(record, 416, description, sizeof(description));

    CopySafeText(username, g_ContactParserLastUsername,
                 sizeof(g_ContactParserLastUsername));
    CopySafeText(alias, g_ContactParserLastAlias,
                 sizeof(g_ContactParserLastAlias));
    CopySafeText(nickname, g_ContactParserLastNickname,
                 sizeof(g_ContactParserLastNickname));
    CopySafeText(bigHeadUrl, g_ContactParserLastBigHeadUrl,
                 sizeof(g_ContactParserLastBigHeadUrl));
    CopySafeText(smallHeadUrl, g_ContactParserLastSmallHeadUrl,
                 sizeof(g_ContactParserLastSmallHeadUrl));

    try {
        json row = {
            {"UserName", username},
            {"Alias", alias},
            {"NickName", nickname},
            {"Nick_Name", nickname},
            {"QuanPin", quanPin},
            {"BigHeadImgUrl", bigHeadUrl},
            {"SmallHeadImgUrl", smallHeadUrl},
            {"Description", description}
        };
        RecordCapturedContactRow(username, row.dump());
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactParserRows));
    } catch (...) {
        // A cache allocation failure must never affect WeChat's parser.
    }
    return result;
}

static void InstallContactResponseParserHook()
{
    if (InterlockedCompareExchange(&g_ContactResponseParserHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2704F70);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactResponseParser),
                      reinterpret_cast<void**>(&g_OriginalContactResponseParser)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactResponseParser = nullptr;
        InterlockedExchange(&g_ContactResponseParserHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactParserHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactParserHookInstalled), 1);
}

// The detail-from-db branch inserts one 1080-byte Contact record at a time
// through sub_1826D0DB0.  The source record is the value object at a3+8;
// keep this observer read-only and reuse the already verified Contact layout.
static bool CaptureContactDetailRecord(int64_t record)
{
    if (!g_IsLogin || !record || !IsReadablePointer(reinterpret_cast<const void*>(record)))
        return false;

    char username[256]{};
    char alias[256]{};
    char nickname[512]{};
    char quanPin[512]{};
    char bigHeadUrl[1024]{};
    char smallHeadUrl[1024]{};
    char description[1024]{};
    if (!CopyNativeStringAt(record, 8, username, sizeof(username)) ||
        !IsLikelyContactUsername(username))
        return false;

    CopyNativeStringAt(record, 40, alias, sizeof(alias));
    CopyNativeStringAt(record, 216, nickname, sizeof(nickname));
    CopyNativeStringAt(record, 280, quanPin, sizeof(quanPin));
    CopyNativeStringAt(record, 312, bigHeadUrl, sizeof(bigHeadUrl));
    CopyNativeStringAt(record, 344, smallHeadUrl, sizeof(smallHeadUrl));
    CopyNativeStringAt(record, 416, description, sizeof(description));

    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailLastRecord),
                          static_cast<LONG64>(record));
    CopySafeText(username, g_ContactDetailLastUsername,
                 sizeof(g_ContactDetailLastUsername));
    CopySafeText(alias, g_ContactDetailLastAlias,
                 sizeof(g_ContactDetailLastAlias));
    CopySafeText(nickname, g_ContactDetailLastNickname,
                 sizeof(g_ContactDetailLastNickname));
    try {
        json row = {
            {"UserName", username},
            {"Alias", alias},
            {"NickName", nickname},
            {"Nick_Name", nickname},
            {"QuanPin", quanPin},
            {"BigHeadImgUrl", bigHeadUrl},
            {"SmallHeadImgUrl", smallHeadUrl},
            {"Description", description}
        };
        RecordCapturedContactRow(username, row.dump());
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactDetailRecordCalls));
        return true;
    } catch (...) {
        return false;
    }
}

// At login/startup WeChat receives a contiguous vector of 1080-byte Contact
// records and then folds it into the in-memory cache/tree.  Observe that
// vector before the original routine destroys the temporary records.  This
// hook is deliberately read-only and does not call any WeChat routine.
static bool CaptureStartupContactRecord(int64_t record)
{
    if (!record || !IsReadablePointer(reinterpret_cast<const void*>(record)))
        return false;

    char username[256]{};
    char alias[256]{};
    char nickname[512]{};
    char quanPin[512]{};
    char bigHeadUrl[1024]{};
    char smallHeadUrl[1024]{};
    char description[1024]{};
    if (!CopyNativeStringAt(record, 8, username, sizeof(username)) ||
        !IsLikelyContactUsername(username))
        return false;

    CopyNativeStringAt(record, 40, alias, sizeof(alias));
    CopyNativeStringAt(record, 216, nickname, sizeof(nickname));
    CopyNativeStringAt(record, 280, quanPin, sizeof(quanPin));
    CopyNativeStringAt(record, 312, bigHeadUrl, sizeof(bigHeadUrl));
    CopyNativeStringAt(record, 344, smallHeadUrl, sizeof(smallHeadUrl));
    CopyNativeStringAt(record, 416, description, sizeof(description));

    CopySafeText(username, g_ContactStartupLastUsername,
                 sizeof(g_ContactStartupLastUsername));
    CopySafeText(alias, g_ContactStartupLastAlias,
                 sizeof(g_ContactStartupLastAlias));
    CopySafeText(nickname, g_ContactStartupLastNickname,
                 sizeof(g_ContactStartupLastNickname));
    try {
        json row = {
            {"UserName", username},
            {"Alias", alias},
            {"NickName", nickname},
            {"Nick_Name", nickname},
            {"QuanPin", quanPin},
            {"BigHeadImgUrl", bigHeadUrl},
            {"SmallHeadImgUrl", smallHeadUrl},
            {"Description", description}
        };
        RecordCapturedContactRow(username, row.dump());
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactStartupRecords));
        return true;
    } catch (...) {
        return false;
    }
}

using FnContactStartupVector = int64_t(__fastcall*)(int64_t, int64_t*, char);
static FnContactStartupVector g_OriginalContactStartupVector = nullptr;
static LONG g_ContactStartupHookState = 0;

static int64_t __fastcall Hook_ContactStartupVector(int64_t manager,
                                                    int64_t* records,
                                                    char mode)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactStartupCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactStartupLastVector),
                          reinterpret_cast<LONG64>(records));

    uint64_t count = 0;
    __try {
        if (records && IsReadablePointer(records) &&
            IsReadablePointer(records + 1)) {
            const int64_t begin = records[0];
            const int64_t end = records[1];
            if (begin && end >= begin &&
                static_cast<uint64_t>(end - begin) % 1080u == 0) {
                count = static_cast<uint64_t>(end - begin) / 1080u;
                // A normal contact sync is bounded; reject corrupt ranges
                // before walking caller-owned memory.
                if (count <= 4096 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        const int64_t record = begin + static_cast<int64_t>(i * 1080u);
                        if (!CaptureStartupContactRecord(record))
                            continue;
                    }
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactStartupLastCount),
                          static_cast<LONG64>(count));

    return g_OriginalContactStartupVector
        ? g_OriginalContactStartupVector(manager, records, mode) : 0;
}

static void InstallContactStartupVectorHook()
{
    if (InterlockedCompareExchange(&g_ContactStartupHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26AC150);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactStartupVector),
                      reinterpret_cast<void**>(&g_OriginalContactStartupVector)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactStartupVector = nullptr;
        InterlockedExchange(&g_ContactStartupHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactStartupHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactStartupHookInstalled), 1);
}

// sub_1826AC5A0 receives the list vector that sub_1826D2C60 walks with a
// 1080-byte stride before constructing the contact UI/cache nodes. Observe
// this vector without changing ownership or the callback arguments.
using FnContactListBuild = int64_t(__fastcall*)(
    int64_t, int64_t*, int64_t, int64_t, int64_t, int32_t, char);
static FnContactListBuild g_OriginalContactListBuild = nullptr;
static LONG g_ContactListBuildHookState = 0;

static int64_t __fastcall Hook_ContactListBuild(int64_t owner,
                                                 int64_t* records,
                                                 int64_t context,
                                                 int64_t callback,
                                                 int64_t arg5,
                                                 int32_t arg6,
                                                 char arg7)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactListBuildCalls));
    uint64_t count = 0;
    __try {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListBuildLastVector),
                              reinterpret_cast<LONG64>(records));
        char first[256]{};
        char last[256]{};
        if (records && IsReadablePointer(records) && IsReadablePointer(records + 1)) {
            const int64_t begin = records[0];
            const int64_t end = records[1];
            if (begin && end >= begin &&
                static_cast<uint64_t>(end - begin) % 1080u == 0) {
                count = static_cast<uint64_t>(end - begin) / 1080u;
                if (count <= 4096 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        const int64_t record = begin + static_cast<int64_t>(i * 1080u);
                        char username[256]{};
                        if (!CopyNativeStringAt(record, 8, username, sizeof(username)) ||
                            !IsLikelyContactUsername(username))
                            continue;
                        if (first[0] == 0)
                            CopySafeText(username, first, sizeof(first));
                        CopySafeText(username, last, sizeof(last));
                        CaptureStartupContactRecord(record);
                        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactListBuildRecords));
                    }
                    CopySafeText(first, g_ContactListBuildFirstUsername,
                                 sizeof(g_ContactListBuildFirstUsername));
                    CopySafeText(last, g_ContactListBuildLastUsername,
                                 sizeof(g_ContactListBuildLastUsername));
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListBuildLastCount),
                          static_cast<LONG64>(count));
    return g_OriginalContactListBuild
        ? g_OriginalContactListBuild(owner, records, context, callback, arg5, arg6, arg7) : 0;
}

static void InstallContactListBuildHook()
{
    if (InterlockedCompareExchange(&g_ContactListBuildHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26AC5A0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactListBuild),
                      reinterpret_cast<void**>(&g_OriginalContactListBuild)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactListBuild = nullptr;
        InterlockedExchange(&g_ContactListBuildHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListBuildHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListBuildHookInstalled), 1);
}

// sub_182CF90A0 is the LoginFlow GetSessionInfoByUsernameList path. The
// input object owns a 32-byte native-string vector at +0x38/+0x40. Observe
// only its bounded username list and preserve the original call unchanged.
using FnContactSessionInfo = int64_t(__fastcall*)(int64_t);
static FnContactSessionInfo g_OriginalContactSessionInfo = nullptr;
static LONG g_ContactSessionInfoHookState = 0;

// Keep C++ exception handling outside the SEH-protected hook body.  The
// snapshot is best-effort and must never affect the original login flow.
static void CacheContactSessionUsername(const char* username)
{
    if (!username || !username[0])
        return;
    try {
        json row = {
            {"UserName", username},
            {"username", username},
            {"wxid", username},
            {"source", "login-session-info"}
        };
        RecordCapturedContactRow(username, row.dump());
    } catch (...) {
        // Snapshot caching must never affect WeChat's call.
    }
}

static int64_t __fastcall Hook_ContactSessionInfo(int64_t context)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactSessionInfoCalls));
    uint64_t count = 0;
    __try {
        const auto* base = reinterpret_cast<const int64_t*>(context);
        const int64_t begin = base ? *reinterpret_cast<const int64_t*>(context + 56) : 0;
        const int64_t end = base ? *reinterpret_cast<const int64_t*>(context + 64) : 0;
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSessionInfoLastVector),
                              static_cast<LONG64>(begin));
        if (begin && end >= begin &&
            static_cast<uint64_t>(end - begin) % 32u == 0) {
            count = static_cast<uint64_t>(end - begin) / 32u;
            if (count <= 16384 &&
                IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                char first[256]{};
                char last[256]{};
                for (uint64_t i = 0; i < count; ++i) {
                    char username[256]{};
                    const int64_t item = begin + static_cast<int64_t>(i * 32u);
                    if (!TryCopyNativeStringObject(item, username, sizeof(username)) ||
                        !IsLikelyContactUsername(username))
                        continue;
                    if (first[0] == 0)
                        CopySafeText(username, first, sizeof(first));
                    CopySafeText(username, last, sizeof(last));
                    CacheContactSessionUsername(username);
                    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactSessionInfoItems));
                }
                CopySafeText(first, g_ContactSessionInfoFirstUsername,
                             sizeof(g_ContactSessionInfoFirstUsername));
                CopySafeText(last, g_ContactSessionInfoLastUsername,
                             sizeof(g_ContactSessionInfoLastUsername));
            } else {
                count = 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSessionInfoLastCount),
                          static_cast<LONG64>(count));
    return g_OriginalContactSessionInfo
        ? g_OriginalContactSessionInfo(context) : 0;
}

static void InstallContactSessionInfoHook()
{
    if (InterlockedCompareExchange(&g_ContactSessionInfoHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2CF90A0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactSessionInfo),
                      reinterpret_cast<void**>(&g_OriginalContactSessionInfo)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactSessionInfo = nullptr;
        InterlockedExchange(&g_ContactSessionInfoHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSessionInfoHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSessionInfoHookInstalled), 1);
}

// sub_180CCD320 receives the complete 1080-byte Contact vector before it is
// split/classified and passed to sub_1826C6A00/sub_1826AC150.  Observe this
// pre-split vector so the cache can be populated from the full list.  The
// hook is read-only and forwards every argument and the original return value.
using FnContactPipeline = int64_t(__fastcall*)(int64_t, int64_t*, int32_t*, int64_t);
static FnContactPipeline g_OriginalContactPipeline = nullptr;
static LONG g_ContactPipelineHookState = 0;

static int64_t __fastcall Hook_ContactPipeline(int64_t owner,
                                                int64_t* records,
                                                int32_t* stats,
                                                int64_t context)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactPipelineCalls));
    uint64_t count = 0;
    __try {
        if (records && IsReadablePointer(records) &&
            IsReadablePointer(records + 1)) {
            const int64_t begin = records[0];
            const int64_t end = records[1];
            if (begin && end >= begin &&
                static_cast<uint64_t>(end - begin) % 1080u == 0) {
                count = static_cast<uint64_t>(end - begin) / 1080u;
                if (count <= 4096 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        const int64_t record = begin + static_cast<int64_t>(i * 1080u);
                        if (CaptureStartupContactRecord(record)) {
                            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactPipelineRecords));
                        }
                    }
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactPipelineLastCount),
                          static_cast<LONG64>(count));
    return g_OriginalContactPipeline
        ? g_OriginalContactPipeline(owner, records, stats, context) : 0;
}

static void InstallContactPipelineHook()
{
    if (InterlockedCompareExchange(&g_ContactPipelineHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x0CCD320);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactPipeline),
                      reinterpret_cast<void**>(&g_OriginalContactPipeline)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactPipeline = nullptr;
        InterlockedExchange(&g_ContactPipelineHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactPipelineHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactPipelineHookInstalled), 1);
}

// sub_1826B0E00 parses a successful contact response and creates one local
// 1080-byte record per item.  It delivers each record through its third
// argument callback.  Wrap only that callback, capture the already validated
// Contact fields, then call WeChat's callback unchanged.
using FnContactRecordCallback = int64_t(__fastcall*)(int64_t);
using FnContactRecordParser = int64_t(__fastcall*)(
    int64_t, int64_t, FnContactRecordCallback, int64_t,
    int64_t, int64_t, int64_t, int64_t);
static FnContactRecordParser g_OriginalContactRecordParser = nullptr;
static LONG g_ContactRecordParserHookState = 0;
static thread_local FnContactRecordCallback g_ActiveContactRecordCallback = nullptr;

static int64_t __fastcall Hook_ContactRecordCallback(int64_t record)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactRecordParserRows));
    __try {
        CaptureStartupContactRecord(record);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A malformed response row must never affect WeChat's callback.
    }
    return g_ActiveContactRecordCallback
        ? g_ActiveContactRecordCallback(record) : 0;
}

static int64_t __fastcall Hook_ContactRecordParser(
    int64_t owner, int64_t request, FnContactRecordCallback callback,
    int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactRecordParserCalls));
    const FnContactRecordCallback previous = g_ActiveContactRecordCallback;
    g_ActiveContactRecordCallback = callback;
    const int64_t result = g_OriginalContactRecordParser
        ? g_OriginalContactRecordParser(owner, request,
                                        callback ? &Hook_ContactRecordCallback : nullptr,
                                        arg4, arg5, arg6, arg7, arg8)
        : 0;
    g_ActiveContactRecordCallback = previous;
    return result;
}

static void InstallContactRecordParserHook()
{
    if (InterlockedCompareExchange(&g_ContactRecordParserHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26B0E00);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactRecordParser),
                      reinterpret_cast<void**>(&g_OriginalContactRecordParser)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactRecordParser = nullptr;
        InterlockedExchange(&g_ContactRecordParserHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactRecordParserHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactRecordParserHookInstalled), 1);
}

// sub_1826C6A00 selects manager+0x78 or manager+0x80 and passes the resulting
// vector to sub_1826C6C10.  IDA's callee type confirms that the second
// argument is a pointer to that vector; its elements are 1080-byte contact
// records (the decompiler's `_QWORD* += 135` is 135 QWORDs, i.e. 1080 bytes).
// The previous experiment incorrectly declared this argument as an int and
// derived a vector from manager, which could corrupt the call ABI.
// Keep this corrected observer read-only and forward the exact vector pointer.
using FnContactManagerList = char(__fastcall*)(int64_t, int64_t*, char);
static FnContactManagerList g_OriginalContactManagerList = nullptr;
static LONG g_ContactManagerListHookState = 0;

static char __fastcall Hook_ContactManagerList(int64_t manager,
                                               int64_t* records,
                                               char listMode)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactManagerListCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastMode),
                          static_cast<LONG64>(static_cast<unsigned char>(listMode)));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastCaller),
                          static_cast<LONG64>(reinterpret_cast<uintptr_t>(_ReturnAddress())));
    uint64_t count = 0;
    __try {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastVector),
                              reinterpret_cast<LONG64>(records));
        if (records && IsReadablePointer(records) && IsReadablePointer(records + 1)) {
            const int64_t vectorAddress = reinterpret_cast<int64_t>(records);
            auto* vector = reinterpret_cast<const int64_t*>(vectorAddress);
            const int64_t begin = vector[0];
            const int64_t end = vector[1];
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastBegin),
                                  static_cast<LONG64>(begin));
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastEnd),
                                  static_cast<LONG64>(end));
            const uint64_t span = begin && end >= begin
                ? static_cast<uint64_t>(end - begin) : 0;
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastSpan),
                                  static_cast<LONG64>(span));
            if (begin && end >= begin &&
                span % 1080u == 0) {
                count = span / 1080u;
                uint64_t oldMax = g_ContactManagerListMaxCount;
                while (count > oldMax) {
                    const uint64_t observed = static_cast<uint64_t>(InterlockedCompareExchange64(
                        reinterpret_cast<volatile LONG64*>(&g_ContactManagerListMaxCount),
                        static_cast<LONG64>(count), static_cast<LONG64>(oldMax)));
                    if (observed == oldMax)
                        break;
                    oldMax = observed;
                }
                if (count <= 4096 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        const int64_t element = begin + static_cast<int64_t>(i * 1080u);
                        char username[256]{};
                        if (TryCopyNativeStringObject(element, username, sizeof(username)) &&
                            IsLikelyContactUsername(username)) {
                            CopySafeText(username, g_ContactManagerListLastUsername,
                                         sizeof(g_ContactManagerListLastUsername));
                            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactManagerListRecords));
                        }
                    }
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListLastCount),
                           static_cast<LONG64>(count));
    return g_OriginalContactManagerList
        ? g_OriginalContactManagerList(manager, records, listMode) : 0;
}

static void InstallContactManagerListHook()
{
    if (InterlockedCompareExchange(&g_ContactManagerListHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26C6A00);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactManagerList),
                      reinterpret_cast<void**>(&g_OriginalContactManagerList)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactManagerList = nullptr;
        InterlockedExchange(&g_ContactManagerListHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactManagerListHookInstalled), 1);
}

// sub_180F73660 is the startup contact-sync source identified in IDA by its
// CoGetContactListByCgi request path.  The second argument is a vector of
// 32-byte native strings; WeChat walks it before requesting contact records.
// Observe only bounded usernames and always forward the original call.
using FnContactSyncSource = int64_t(__fastcall*)(int64_t, int64_t*);
static FnContactSyncSource g_OriginalContactSyncSource = nullptr;
static LONG g_ContactSyncSourceHookState = 0;

static int64_t __fastcall Hook_ContactSyncSource(int64_t owner, int64_t* items)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactSyncSourceCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncSourceLastVector),
                          reinterpret_cast<LONG64>(items));

    uint64_t count = 0;
    __try {
        if (items && IsReadablePointer(items) && IsReadablePointer(items + 1)) {
            const int64_t begin = items[0];
            const int64_t end = items[1];
            if (begin && end >= begin &&
                static_cast<uint64_t>(end - begin) % 32u == 0) {
                count = static_cast<uint64_t>(end - begin) / 32u;
                if (count <= 16384 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    char first[256]{};
                    char last[256]{};
                    for (uint64_t i = 0; i < count; ++i) {
                        char username[256]{};
                        const int64_t element = begin + static_cast<int64_t>(i * 32u);
                        if (!TryCopyNativeStringObject(element, username, sizeof(username)) ||
                            !IsLikelyContactUsername(username)) {
                            continue;
                        }
                        if (first[0] == 0)
                            CopySafeText(username, first, sizeof(first));
                        CopySafeText(username, last, sizeof(last));
                        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactSyncSourceItems));
                    }
                    CopySafeText(first, g_ContactSyncSourceFirstUsername,
                                 sizeof(g_ContactSyncSourceFirstUsername));
                    CopySafeText(last, g_ContactSyncSourceLastUsername,
                                 sizeof(g_ContactSyncSourceLastUsername));
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncSourceLastCount),
                          static_cast<LONG64>(count));
    return g_OriginalContactSyncSource
        ? g_OriginalContactSyncSource(owner, items) : 0;
}

static void InstallContactSyncSourceHook()
{
    if (InterlockedCompareExchange(&g_ContactSyncSourceHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x0F73660);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactSyncSource),
                      reinterpret_cast<void**>(&g_OriginalContactSyncSource)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactSyncSource = nullptr;
        InterlockedExchange(&g_ContactSyncSourceHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncSourceHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncSourceHookInstalled), 1);
}

// sub_182CEC8B0 is the async contact-list response entry.  Its third
// argument is a vector of the same 1080-byte Contact records later split by
// sub_182CF20C0 and consumed by sub_1826C6A00/sub_1826AC150.  Keep this hook
// read-only: validate the vector bounds, copy bounded fields, then forward
// the call unchanged.
using FnContactListSource = int64_t(__fastcall*)(int64_t, int64_t, int64_t);
static FnContactListSource g_OriginalContactListSource = nullptr;
static LONG g_ContactListSourceHookState = 0;

static bool CaptureContactListSourceRecord(int64_t record)
{
    if (!g_IsLogin || !record || !IsReadablePointer(reinterpret_cast<const void*>(record)))
        return false;

    char username[256]{};
    char alias[256]{};
    char nickname[512]{};
    char quanPin[512]{};
    char bigHeadUrl[1024]{};
    char smallHeadUrl[1024]{};
    char description[1024]{};
    if (!CopyNativeStringAt(record, 8, username, sizeof(username)) ||
        !IsLikelyContactUsername(username))
        return false;

    CopyNativeStringAt(record, 40, alias, sizeof(alias));
    CopyNativeStringAt(record, 216, nickname, sizeof(nickname));
    CopyNativeStringAt(record, 280, quanPin, sizeof(quanPin));
    CopyNativeStringAt(record, 312, bigHeadUrl, sizeof(bigHeadUrl));
    CopyNativeStringAt(record, 344, smallHeadUrl, sizeof(smallHeadUrl));
    CopyNativeStringAt(record, 416, description, sizeof(description));

    CopySafeText(username, g_ContactListSourceLastUsername,
                 sizeof(g_ContactListSourceLastUsername));
    CopySafeText(alias, g_ContactListSourceLastAlias,
                 sizeof(g_ContactListSourceLastAlias));
    CopySafeText(nickname, g_ContactListSourceLastNickname,
                 sizeof(g_ContactListSourceLastNickname));
    try {
        json row = {
            {"UserName", username},
            {"Alias", alias},
            {"NickName", nickname},
            {"Nick_Name", nickname},
            {"QuanPin", quanPin},
            {"BigHeadImgUrl", bigHeadUrl},
            {"SmallHeadImgUrl", smallHeadUrl},
            {"Description", description}
        };
        RecordCapturedContactRow(username, row.dump());
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactListSourceRecords));
        return true;
    } catch (...) {
        return false;
    }
}

static int64_t __fastcall Hook_ContactListSource(int64_t owner,
                                                  int64_t output,
                                                  int64_t records)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactListSourceCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListSourceLastVector),
                           static_cast<LONG64>(records));

    uint64_t count = 0;
    __try {
        auto* vector = reinterpret_cast<const int64_t*>(records);
        if (records && IsReadablePointer(vector) && IsReadablePointer(vector + 1)) {
            const int64_t begin = vector[0];
            const int64_t end = vector[1];
            if (begin && end >= begin &&
                static_cast<uint64_t>(end - begin) % 1080u == 0) {
                count = static_cast<uint64_t>(end - begin) / 1080u;
                if (count <= 4096 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        CaptureContactListSourceRecord(
                            begin + static_cast<int64_t>(i * 1080u));
                    }
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListSourceLastCount),
                           static_cast<LONG64>(count));

    return g_OriginalContactListSource
        ? g_OriginalContactListSource(owner, output, records) : 0;
}

static void InstallContactListSourceHook()
{
    if (InterlockedCompareExchange(&g_ContactListSourceHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2CEC8B0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactListSource),
                      reinterpret_cast<void**>(&g_OriginalContactListSource)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactListSource = nullptr;
        InterlockedExchange(&g_ContactListSourceHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListSourceHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactListSourceHookInstalled), 1);
}

// sub_180F6E470 is the direct startup/contact-response callback. Its second
// argument is forwarded as the 1080-byte record vector to sub_182CEC8B0.
// Observe only bounded records and always forward the exact ABI/return value.
using FnContactSyncCallback = int64_t(__fastcall*)(int64_t, int64_t*, char, char);
static FnContactSyncCallback g_OriginalContactSyncCallback = nullptr;
static LONG g_ContactSyncCallbackHookState = 0;

static int64_t __fastcall Hook_ContactSyncCallback(int64_t owner,
                                                    int64_t* records,
                                                    char flag1,
                                                    char flag2)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactSyncCallbackCalls));
    uint64_t count = 0;
    __try {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncCallbackLastVector),
                              reinterpret_cast<LONG64>(records));
        char first[256]{};
        char last[256]{};
        if (records && IsReadablePointer(records) && IsReadablePointer(records + 1)) {
            const int64_t begin = records[0];
            const int64_t end = records[1];
            if (begin && end >= begin &&
                static_cast<uint64_t>(end - begin) % 1080u == 0) {
                count = static_cast<uint64_t>(end - begin) / 1080u;
                if (count <= 4096 &&
                    IsReadablePointer(reinterpret_cast<const void*>(begin)) &&
                    IsReadablePointer(reinterpret_cast<const void*>(end - 1))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        const int64_t record = begin + static_cast<int64_t>(i * 1080u);
                        char username[256]{};
                        if (!CopyNativeStringAt(record, 8, username, sizeof(username)) ||
                            !IsLikelyContactUsername(username))
                            continue;
                        if (first[0] == 0)
                            CopySafeText(username, first, sizeof(first));
                        CopySafeText(username, last, sizeof(last));
                        CaptureContactListSourceRecord(record);
                        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactSyncCallbackRecords));
                    }
                    CopySafeText(first, g_ContactSyncCallbackFirstUsername,
                                 sizeof(g_ContactSyncCallbackFirstUsername));
                    CopySafeText(last, g_ContactSyncCallbackLastUsername,
                                 sizeof(g_ContactSyncCallbackLastUsername));
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncCallbackLastCount),
                          static_cast<LONG64>(count));
    return g_OriginalContactSyncCallback
        ? g_OriginalContactSyncCallback(owner, records, flag1, flag2) : 0;
}

static void InstallContactSyncCallbackHook()
{
    if (InterlockedCompareExchange(&g_ContactSyncCallbackHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x0F6E470);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactSyncCallback),
                      reinterpret_cast<void**>(&g_OriginalContactSyncCallback)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactSyncCallback = nullptr;
        InterlockedExchange(&g_ContactSyncCallbackHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncCallbackHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactSyncCallbackHookInstalled), 1);
}

// sub_182CF25E0 consumes the asynchronous contact response task.  IDA shows
// its input vector at context+0x38/+0x40; it then splits that vector and calls
// sub_1826C6A00/sub_1826AC150.  Observe the records before the original task
// takes ownership.  This hook is intentionally read-only and forwards the
// original return value unchanged.
using FnContactResponseBatch = int64_t(__fastcall*)(int64_t);
static FnContactResponseBatch g_OriginalContactResponseBatch = nullptr;
static LONG g_ContactResponseBatchHookState = 0;

static int64_t __fastcall Hook_ContactResponseBatch(int64_t context)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactResponseBatchCalls));
    uint64_t count = 0;
    int64_t lastVector = 0;
    __try {
        if (context && IsReadablePointer(reinterpret_cast<const void*>(context + 56)) &&
            IsReadablePointer(reinterpret_cast<const void*>(context + 64))) {
            const int64_t begin = *reinterpret_cast<const int64_t*>(context + 56);
            const int64_t end = *reinterpret_cast<const int64_t*>(context + 64);
            lastVector = begin;
            if (begin && end > begin &&
                static_cast<uint64_t>(end - begin) % 1080u == 0) {
                count = static_cast<uint64_t>(end - begin) / 1080u;
                if (count <= 4096 && IsReadablePointer(reinterpret_cast<const void*>(begin))) {
                    for (uint64_t i = 0; i < count; ++i) {
                        const int64_t record = begin + static_cast<int64_t>(i * 1080u);
                        __try {
                            if (CaptureStartupContactRecord(record))
                                InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactResponseBatchRecords));
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            // A malformed record is skipped without affecting
                            // the response task or the remaining records.
                        }
                    }
                } else {
                    count = 0;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        count = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseBatchLastVector),
                          static_cast<LONG64>(lastVector));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseBatchLastCount),
                          static_cast<LONG64>(count));
    return g_OriginalContactResponseBatch
        ? g_OriginalContactResponseBatch(context) : 0;
}

static void InstallContactResponseBatchHook()
{
    if (InterlockedCompareExchange(&g_ContactResponseBatchHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2CF25E0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactResponseBatch),
                      reinterpret_cast<void**>(&g_OriginalContactResponseBatch)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactResponseBatch = nullptr;
        InterlockedExchange(&g_ContactResponseBatchHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseBatchHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseBatchHookInstalled), 1);
}

// sub_182CF20C0 converts the raw response vector into the two 1080-byte
// vectors consumed by sub_1826C6A00/sub_1826AC150.  Capture the output only
// after the original returns, while the caller still owns those vectors.
using FnContactResponseSplit = uint64_t(__fastcall*)(int64_t*, int64_t*, int64_t*);
static FnContactResponseSplit g_OriginalContactResponseSplit = nullptr;
static LONG g_ContactResponseSplitHookState = 0;

static uint64_t CountContactRecordVector(const int64_t* vector)
{
    if (!vector)
        return 0;
    __try {
        if (!IsReadablePointer(vector) || !IsReadablePointer(vector + 1))
            return 0;
        const int64_t begin = vector[0];
        const int64_t end = vector[1];
        if (!begin || end <= begin ||
            static_cast<uint64_t>(end - begin) % 1080u != 0)
            return 0;
        const uint64_t count = static_cast<uint64_t>(end - begin) / 1080u;
        return count <= 4096 ? count : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static uint64_t CaptureContactRecordVector(const int64_t* vector)
{
    const uint64_t count = CountContactRecordVector(vector);
    if (!count)
        return 0;
    uint64_t captured = 0;
    __try {
        const int64_t begin = vector[0];
        for (uint64_t i = 0; i < count; ++i) {
            __try {
                if (CaptureStartupContactRecord(begin + static_cast<int64_t>(i * 1080u)))
                    ++captured;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return captured;
}

static uint64_t __fastcall Hook_ContactResponseSplit(int64_t* input,
                                                      int64_t* output1,
                                                      int64_t* output2)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactResponseSplitCalls));
    const uint64_t inputCount = CountContactRecordVector(input);
    const uint64_t output1Count = CountContactRecordVector(output1);
    const uint64_t output2Count = CountContactRecordVector(output2);
    const uint64_t outputCount = output1Count + output2Count;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseSplitLastInputCount),
                          static_cast<LONG64>(inputCount));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseSplitLastOutputCount),
                          static_cast<LONG64>(outputCount));

    const uint64_t result = g_OriginalContactResponseSplit
        ? g_OriginalContactResponseSplit(input, output1, output2) : 0;
    const uint64_t captured = CaptureContactRecordVector(output1) +
                              CaptureContactRecordVector(output2);
    InterlockedExchangeAdd64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseSplitRecords),
                              static_cast<LONG64>(captured));
    return result;
}

static void InstallContactResponseSplitHook()
{
    if (InterlockedCompareExchange(&g_ContactResponseSplitHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2CF20C0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactResponseSplit),
                      reinterpret_cast<void**>(&g_OriginalContactResponseSplit)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactResponseSplit = nullptr;
        InterlockedExchange(&g_ContactResponseSplitHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseSplitHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactResponseSplitHookInstalled), 1);
}

// The generic "get contact from db" branch calls sub_1826E3330, which
// materializes each result as a temporary 344-byte row and invokes a callback
// (sub_180082060 is the identity callback for this path).  Observe the row
// before forwarding it to the original callback.  The field meanings are not
// assumed here; only bounded strings are copied for later runtime mapping.
using FnContactGeneralRowCallback = int64_t(__fastcall*)(int64_t);
using FnContactGeneralQueryEngine = int64_t(__fastcall*)(
    int64_t, int64_t, FnContactGeneralRowCallback,
    int64_t, int64_t, int64_t, int64_t, int64_t);
static FnContactGeneralQueryEngine g_OriginalContactGeneralQueryEngine = nullptr;
static LONG g_ContactGeneralQueryHookState = 0;
static thread_local FnContactGeneralRowCallback g_ContactGeneralCurrentCallback = nullptr;

static int64_t __fastcall Hook_ContactGeneralRow(int64_t row)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactGeneralQueryRows));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactGeneralQueryLastRow),
                          static_cast<LONG64>(row));
    if (row && IsReadablePointer(reinterpret_cast<const void*>(row))) {
        char field0[256]{};
        char field1[256]{};
        char field2[256]{};
        char field3[256]{};
        char field4[256]{};
        char field5[256]{};
        char field6[256]{};
        char field7[256]{};
        // sub_1826E4360 moves the row's native-string members at these
        // offsets into its 368-byte contact-cache node.  They are kept as
        // diagnostics until runtime values establish their semantic names.
        CopyNativeStringAt(row, 0x08, field0, sizeof(field0));
        CopyNativeStringAt(row, 0x38, field1, sizeof(field1));
        CopyNativeStringAt(row, 0x60, field2, sizeof(field2));
        CopyNativeStringAt(row, 0x80, field3, sizeof(field3));
        CopyNativeStringAt(row, 0xA8, field4, sizeof(field4));
        CopyNativeStringAt(row, 0xC8, field5, sizeof(field5));
        CopyNativeStringAt(row, 0xE8, field6, sizeof(field6));
        CopyNativeStringAt(row, 0x108, field7, sizeof(field7));
        CopySafeText(field0, g_ContactGeneralQueryLastField0,
                     sizeof(g_ContactGeneralQueryLastField0));
        CopySafeText(field1, g_ContactGeneralQueryLastField1,
                     sizeof(g_ContactGeneralQueryLastField1));
        CopySafeText(field2, g_ContactGeneralQueryLastField2,
                     sizeof(g_ContactGeneralQueryLastField2));
        CopySafeText(field3, g_ContactGeneralQueryLastField3,
                     sizeof(g_ContactGeneralQueryLastField3));
        CopySafeText(field4, g_ContactGeneralQueryLastField4,
                     sizeof(g_ContactGeneralQueryLastField4));
        CopySafeText(field5, g_ContactGeneralQueryLastField5,
                     sizeof(g_ContactGeneralQueryLastField5));
        CopySafeText(field6, g_ContactGeneralQueryLastField6,
                     sizeof(g_ContactGeneralQueryLastField6));
        CopySafeText(field7, g_ContactGeneralQueryLastField7,
                     sizeof(g_ContactGeneralQueryLastField7));

        // Runtime observation on 4.1.10.27 shows field0 is the username for
        // this response branch (for example gh_b8ebf357de37), while field6
        // carries an avatar URL when present.  Cache only those validated
        // meanings and retain the remaining fields under diagnostic names;
        // do not guess alias/nickname offsets from this temporary row.
        if (IsLikelyContactUsername(field0)) {
            try {
                json cached = {
                    {"UserName", field0},
                    {"username", field0},
                    {"wxid", field0},
                    {"Field1", field1},
                    {"Field2", field2},
                    {"Field3", field3},
                    {"Field4", field4},
                    {"Field5", field5},
                    {"Field6", field6},
                    {"Field7", field7}
                };
                if (strncmp(field6, "http", 4) == 0) {
                    cached["BigHeadImgUrl"] = field6;
                    cached["SmallHeadImgUrl"] = field6;
                }
                RecordCapturedContactRow(field0, cached.dump());
            } catch (...) {
                // A diagnostic cache failure must never affect the original
                // contact callback or its owning WeChat thread.
            }
        }
    }
    return g_ContactGeneralCurrentCallback
        ? g_ContactGeneralCurrentCallback(row) : row;
}

static int64_t __fastcall Hook_ContactGeneralQueryEngine(
    int64_t a1, int64_t a2, FnContactGeneralRowCallback callback,
    int64_t a4, int64_t a5, int64_t a6, int64_t a7, int64_t a8)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactGeneralQueryCalls));
    const FnContactGeneralRowCallback previous = g_ContactGeneralCurrentCallback;
    g_ContactGeneralCurrentCallback = callback;
    const int64_t result = g_OriginalContactGeneralQueryEngine
        ? g_OriginalContactGeneralQueryEngine(a1, a2, &Hook_ContactGeneralRow,
                                               a4, a5, a6, a7, a8)
        : 0;
    g_ContactGeneralCurrentCallback = previous;
    return result;
}

static void InstallContactGeneralQueryHook()
{
    if (InterlockedCompareExchange(&g_ContactGeneralQueryHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26E3330);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactGeneralQueryEngine),
                      reinterpret_cast<void**>(&g_OriginalContactGeneralQueryEngine)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactGeneralQueryEngine = nullptr;
        InterlockedExchange(&g_ContactGeneralQueryHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactGeneralQueryHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactGeneralQueryHookInstalled), 1);
}

using FnContactDetailRecordInsert = int64_t(__fastcall*)(int64_t, int64_t,
                                                          unsigned char*);
static FnContactDetailRecordInsert g_OriginalContactDetailRecordInsert = nullptr;
static LONG g_ContactDetailRecordHookState = 0;

static int64_t __fastcall Hook_ContactDetailRecordInsert(int64_t object,
                                                         int64_t result,
                                                         unsigned char* node)
{
    const int64_t originalResult = g_OriginalContactDetailRecordInsert
        ? g_OriginalContactDetailRecordInsert(object, result, node) : 0;
    if (node) {
        __try {
            // sub_1826D0DB0 calls sub_18064ECB0(dst, node + 8), so node+8
            // is the complete source Contact record.
            CaptureContactDetailRecord(reinterpret_cast<int64_t>(node) + 8);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return originalResult;
}

static void InstallContactDetailRecordHook()
{
    if (InterlockedCompareExchange(&g_ContactDetailRecordHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26D0DB0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactDetailRecordInsert),
                      reinterpret_cast<void**>(&g_OriginalContactDetailRecordInsert)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactDetailRecordInsert = nullptr;
        InterlockedExchange(&g_ContactDetailRecordHookState, 0);
        return;
    }
}

using FnContactDetail = int64_t(__fastcall*)(int64_t, int64_t, int64_t,
                                              int64_t, char, unsigned char);
static FnContactDetail g_OriginalContactDetail = nullptr;
static LONG g_ContactDetailHookState = 0;

static int64_t __fastcall Hook_ContactDetail(int64_t manager, int64_t output,
                                              int64_t request, int64_t extra,
                                              char flag, unsigned char mask)
{
    const int64_t result = g_OriginalContactDetail
        ? g_OriginalContactDetail(manager, output, request, extra, flag, mask) : 0;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactDetailCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailLastManager),
                          static_cast<LONG64>(manager));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailLastOutput),
                          static_cast<LONG64>(output));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailLastRequest),
                          static_cast<LONG64>(request));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailLastResult),
                          static_cast<LONG64>(result));
    uint64_t status = 0;
    if (output) {
        __try { status = *reinterpret_cast<const unsigned char*>(output + 64); }
        __except (EXCEPTION_EXECUTE_HANDLER) { status = 0; }
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailLastStatus),
                          static_cast<LONG64>(status));
    return result;
}

static void InstallContactDetailHook()
{
    if (InterlockedCompareExchange(&g_ContactDetailHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x26B03B0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ContactDetail),
                      reinterpret_cast<void**>(&g_OriginalContactDetail)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalContactDetail = nullptr;
        InterlockedExchange(&g_ContactDetailHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailHookInstalled), 0);
        return;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactDetailHookInstalled), 1);
}

static void CopySafeTextN(const char* src, int len, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return;
    dst[0] = 0;
    if (!src)
        return;
    __try {
        size_t n = 0;
        const size_t maxLen = len >= 0 ? static_cast<size_t>(len) : 8192;
        while (n + 1 < cap && n < maxLen && src[n])
            ++n;
        memcpy(dst, src, n);
        dst[n] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
    }
}

static bool LooksInterestingSqlOrText(const char* text)
{
    if (!text || !*text)
        return false;
    return strstr(text, "123") ||
           strstr(text, "Msg") || strstr(text, "MSG") || strstr(text, "msg") ||
           strstr(text, "Chat") || strstr(text, "chat") ||
           strstr(text, "Session") || strstr(text, "session") ||
           strstr(text, "INSERT") || strstr(text, "insert") ||
           strstr(text, "UPDATE") || strstr(text, "update") ||
           strstr(text, "Content") || strstr(text, "content") ||
           strstr(text, "Talker") || strstr(text, "talker");
}

static void CopyEscapedBytesForJson(const char* src, int len, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return;
    dst[0] = 0;
    if (!src)
        return;
    __try {
        size_t out = 0;
        const size_t maxLen = len >= 0 ? static_cast<size_t>(len) : 8192;
        for (size_t i = 0; i < maxLen && src[i] && out + 1 < cap; ++i) {
            const unsigned char c = static_cast<unsigned char>(src[i]);
            if (c >= 0x20 && c < 0x7F && c != '\\' && c != '"') {
                dst[out++] = static_cast<char>(c);
            } else if (out + 4 < cap) {
                out += static_cast<size_t>(sprintf_s(dst + out, cap - out, "\\x%02X", c));
            } else {
                break;
            }
        }
        dst[out] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
    }
}

static void CaptureSqlText(const char* sql, int len, char* last, char* interesting)
{
    char raw[4096]{};
    CopySafeTextN(sql, len, raw, sizeof(raw));
    CopyEscapedBytesForJson(sql, len, last, 4096);
    if (LooksInterestingSqlOrText(raw))
        CopySafeText(last, interesting, 4096);
}

static void CaptureSqlText16(const void* text16, int len, char* last, char* interesting)
{
    if (!last)
        return;
    last[0] = 0;
    if (!text16)
        return;
    __try {
        int chars = len >= 0 ? (len / static_cast<int>(sizeof(wchar_t))) : -1;
        if (chars < 0) {
            const wchar_t* p = reinterpret_cast<const wchar_t*>(text16);
            chars = 0;
            while (chars < 2048 && p[chars])
                ++chars;
        }
        if (chars <= 0)
            return;
        if (chars > 2048)
            chars = 2048;
        const int written = WideCharToMultiByte(CP_UTF8, 0,
            reinterpret_cast<const wchar_t*>(text16), chars,
            last, 4095, nullptr, nullptr);
        if (written > 0) {
            last[written] = 0;
            if (LooksInterestingSqlOrText(last))
                CopySafeText(last, interesting, 4096);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        last[0] = 0;
    }
}

static void RecordSqliteBindTrace(const char* apiName, sqlite3_stmt* stmt, int index,
                                  const char* text, int len)
{
    const uint64_t sequence = InterlockedIncrement64(
        reinterpret_cast<volatile LONG64*>(&g_SqliteBindTraceIndex));
    auto& item = g_SqliteBindTraces[sequence % kSqliteBindTraceCapacity];
    item.sequence = sequence;
    item.stmt = reinterpret_cast<uint64_t>(stmt);
    item.index = static_cast<uint64_t>(index);
    item.caller = reinterpret_cast<uint64_t>(_ReturnAddress());
    CopySafeText(apiName, item.api, sizeof(item.api));
    CopyEscapedBytesForJson(text, len, item.text, sizeof(item.text));
}

static void RecordSqliteBindTrace16(const char* apiName, sqlite3_stmt* stmt, int index,
                                    const void* text16, int len)
{
    const uint64_t sequence = InterlockedIncrement64(
        reinterpret_cast<volatile LONG64*>(&g_SqliteBindTraceIndex));
    auto& item = g_SqliteBindTraces[sequence % kSqliteBindTraceCapacity];
    item.sequence = sequence;
    item.stmt = reinterpret_cast<uint64_t>(stmt);
    item.index = static_cast<uint64_t>(index);
    item.caller = reinterpret_cast<uint64_t>(_ReturnAddress());
    CopySafeText(apiName, item.api, sizeof(item.api));
    CaptureSqlText16(text16, len, item.text, g_SqliteInterestingBindText);
}

static void CaptureSqliteDbPath(sqlite3* db, char* dst, size_t cap);
static int IdentifyMicroMsgDatabase(sqlite3* db);

static void CaptureSqliteDbHandle(sqlite3* db)
{
    if (!db)
        return;
    __try {
        if (IsReadablePointer(db))
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteLastDbHandle),
                                  reinterpret_cast<LONG64>(db));
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteLastDbThreadId),
                              static_cast<LONG64>(GetCurrentThreadId()));
        CaptureSqliteDbPath(db, g_SqliteLastDbPath, sizeof(g_SqliteLastDbPath));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static void CaptureSqliteDbPath(sqlite3* db, char* dst, size_t cap)
{
    if (!db || !dst || cap == 0 || !g_hWeixinDll)
        return;
    __try {
        auto* api = reinterpret_cast<sqlite3_api_routines*>(
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
        if (!IsReadablePointer(api) ||
            !IsExecutablePointer(reinterpret_cast<void*>(api->db_filename)))
            return;
        const char* filename = api->db_filename(db, "main");
        if (filename && IsReadablePointer(filename))
            CopySafeText(filename, dst, cap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static void CaptureContactDbHandle(sqlite3* db, const char* sql, int nByte)
{
    if (!db || !sql)
        return;
    char text[2048]{};
    CopySafeTextN(sql, nByte, text, sizeof(text));
    auto hasTableReference = [](const char* value, const char* table) {
        if (!value || !table)
            return false;
        std::string lower(value);
        for (char& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        const std::string name(table);
        for (const char* verb : {"from ", "join ", "update ", "into "}) {
            const std::string needle = std::string(verb) + name;
            size_t pos = lower.find(needle);
            while (pos != std::string::npos) {
                const size_t end = pos + needle.size();
                if (end == lower.size() ||
                    !(std::isalnum(static_cast<unsigned char>(lower[end])) ||
                      lower[end] == '_'))
                    return true;
                pos = lower.find(needle, pos + 1);
            }
        }
        return false;
    };
    // Match the actual Contact/ChatRoom tables, not ContactFTS or other
    // auxiliary databases whose SQL merely contains the word "Contact".
    if (!hasTableReference(text, "contact") && !hasTableReference(text, "chatroom"))
        return;
    if (!IsReadablePointer(db))
        return;
    // Queries against contact_fts.db also contain the word "Contact", but
    // that database does not contain the Contact table used by this route.
    // An exact Contact/ChatRoom table reference is a stronger signal than the
    // filename API, which is empty for this encrypted build.  Reject only a
    // connection that SQLite positively identifies as another named database.
    if (IdentifyMicroMsgDatabase(db) == 0)
        return;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteContactDbHandle),
                          reinterpret_cast<LONG64>(db));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteContactDbThreadId),
                          static_cast<LONG64>(GetCurrentThreadId()));
    CaptureSqliteDbPath(db, g_SqliteContactDbPath, sizeof(g_SqliteContactDbPath));
}

// Identify the connection by SQLite's own filename API instead of assuming
// that the most recently observed connection is MicroMsg.db.  WeChat 4.1.10.27
// uses db_storage\contact\contact.db for contacts, while older builds used
// MicroMsg.db.  Return 1 for either supported contact database, 0 for another
// named database, and -1 when the API/filename is unavailable.
static int IdentifyMicroMsgDatabase(sqlite3* db)
{
    if (!db || !g_hWeixinDll)
        return -1;
    char filenameCopy[1024]{};
    __try {
        auto* api = reinterpret_cast<sqlite3_api_routines*>(
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
        if (!IsReadablePointer(api) || !IsExecutablePointer(reinterpret_cast<void*>(api->db_filename)))
            return -1;
        const char* filename = api->db_filename(db, "main");
        if (!filename || !IsReadablePointer(filename))
            return -1;
        strncpy_s(filenameCopy, sizeof(filenameCopy), filename, _TRUNCATE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
    if (!filenameCopy[0])
        return -1;
    for (char* p = filenameCopy; *p; ++p)
        *p = static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));
    const bool oldContactDb = strstr(filenameCopy, "micromsg.db") != nullptr;
    const bool modernContactDb = strstr(filenameCopy, "\\contact\\contact.db") != nullptr ||
        strstr(filenameCopy, "/contact/contact.db") != nullptr ||
        (strlen(filenameCopy) >= 10 &&
         _stricmp(filenameCopy + strlen(filenameCopy) - 10, "contact.db") == 0);
    return oldContactDb || modernContactDb ? 1 : 0;
}

namespace {

std::mutex g_ContactQueryMutex;
std::condition_variable g_ContactQueryCv;
bool g_ContactQueryActive = false;
bool g_ContactQueryDone = false;
bool g_ContactQueryClaimed = false;
std::string g_ContactQueryWxid;
std::string g_ContactQueryDbName;
std::string g_ContactQuerySql;
bool g_ContactQueryGeneric = false;
std::string g_ContactQueryResult;
thread_local bool g_ContactQueryInProgress = false;
std::mutex g_SqliteStmtSqlMutex;
std::unordered_map<sqlite3_stmt*, std::string> g_SqliteStmtSql;

static std::string QuoteSqlText(const std::string& value)
{
    std::string quoted("'");
    quoted.reserve(value.size() + 2);
    for (const char c : value) {
        if (c == '\'')
            quoted.push_back('\'');
        quoted.push_back(c);
    }
    quoted.push_back('\'');
    return quoted;
}

static void TryProcessPendingContactQuery(sqlite3* db)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactQueryTryCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ContactQueryLastDb),
                          reinterpret_cast<LONG64>(db));
    if (!db || g_ContactQueryInProgress)
        return;
    std::string wxid;
    std::string sql;
    {
        std::lock_guard<std::mutex> lock(g_ContactQueryMutex);
        if (!g_ContactQueryActive || g_ContactQueryClaimed)
            return;
        if (g_SqliteContactDbHandle != 0 &&
            reinterpret_cast<uint64_t>(db) != g_SqliteContactDbHandle) {
            // WeChat may rotate connections while keeping the same contact
            // worker thread.  Accept a new handle from that already observed
            // thread; the schema check below still rejects auxiliary DBs.
            const bool sameContactThread =
                g_SqliteContactDbThreadId != 0 &&
                static_cast<uint64_t>(GetCurrentThreadId()) ==
                    g_SqliteContactDbThreadId;
            if (!sameContactThread && IdentifyMicroMsgDatabase(db) == 0)
                return;
        }
        if (g_ContactQueryGeneric) {
            const int databaseKind = IdentifyMicroMsgDatabase(db);
            if (databaseKind == 0)
                return;
            if (databaseKind < 0 && g_SqliteContactDbHandle != 0 &&
                reinterpret_cast<uint64_t>(db) != g_SqliteContactDbHandle)
                return;
        }
        g_ContactQueryClaimed = true;
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactQueryClaims));
        wxid = g_ContactQueryWxid;
        sql = g_ContactQueryGeneric
            ? g_ContactQuerySql
            : "SELECT * FROM Contact WHERE UserName=" + QuoteSqlText(wxid) + " LIMIT 1";
    }

    g_ContactQueryInProgress = true;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactQueryExecuteCalls));
    nlohmann::ordered_json result;
    try {
        // The contact database in 4.1.10.27 is encrypted and some builds do
        // not expose a reliable sqlite_master result through the wrapper.
        // The handle was already captured from a Contact/ChatRoom statement
        // on this SQLite worker thread, so a second schema probe is both
        // redundant and capable of swallowing a valid query. Execute the
        // requested read directly and propagate its concrete SQLite status.
        result = xmgr::DatabaseMgr::getInstance().execute(db, sql);
    } catch (const std::exception& e) {
        result = { {"status", -500}, {"desc", e.what()} };
    } catch (...) {
        result = { {"status", -501}, {"desc", "contact query exception"} };
    }
    g_ContactQueryInProgress = false;

    {
        std::lock_guard<std::mutex> lock(g_ContactQueryMutex);
        const int resultStatus = result.is_object() ? result.value("status", -1) : -1;
        if (g_ContactQueryActive && resultStatus == 0) {
            g_ContactQueryResult = result.dump();
            g_ContactQueryDone = true;
            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactQueryCompleteCalls));
        } else if (g_ContactQueryActive) {
            // Keep the concrete SQLite error visible to /QueryDB/status.  A
            // non-zero result is deliberately retried on a later SQLite hook
            // call, but a timeout without this detail is indistinguishable
            // from a connection/handle mismatch.
            const std::string diagnostic = result.dump();
            sprintf_s(g_DbDebugText, sizeof(g_DbDebugText),
                      "contact query result: %s", diagnostic.c_str());
        }
        g_ContactQueryClaimed = false;
    }
    g_ContactQueryCv.notify_all();
}

static bool IsReadOnlySql(const std::string& sql)
{
    if (sql.empty() || sql.size() > 8192 || sql.find(';') != std::string::npos)
        return false;

    std::string normalized;
    normalized.reserve(sql.size());
    for (const unsigned char c : sql) {
        normalized.push_back(static_cast<char>(std::tolower(c)));
    }
    size_t first = normalized.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return false;
    const bool startsRead = normalized.compare(first, 6, "select") == 0 ||
        normalized.compare(first, 4, "with") == 0 ||
        normalized.compare(first, 6, "pragma") == 0;
    if (!startsRead)
        return false;

    static constexpr const char* kBlocked[] = {
        "insert", "update", "delete", "replace", "attach", "detach",
        "create", "drop", "alter", "vacuum", "reindex", "begin",
        "commit", "rollback"
    };
    for (const char* word : kBlocked) {
        if (normalized.find(word) != std::string::npos)
            return false;
    }
    return true;
}

static void RememberSqliteStatement(sqlite3_stmt* stmt, const char* sql, int nByte)
{
    if (!stmt || !sql)
        return;
    char text[8192]{};
    CopySafeTextN(sql, nByte, text, sizeof(text));
    std::lock_guard<std::mutex> lock(g_SqliteStmtSqlMutex);
    if (g_SqliteStmtSql.size() >= 256 && g_SqliteStmtSql.find(stmt) == g_SqliteStmtSql.end())
        g_SqliteStmtSql.erase(g_SqliteStmtSql.begin());
    g_SqliteStmtSql[stmt] = text;
}

static std::string LookupSqliteStatement(sqlite3_stmt* stmt)
{
    std::lock_guard<std::mutex> lock(g_SqliteStmtSqlMutex);
    const auto it = g_SqliteStmtSql.find(stmt);
    return it == g_SqliteStmtSql.end() ? std::string{} : it->second;
}

static void ForgetSqliteStatement(sqlite3_stmt* stmt)
{
    if (!stmt)
        return;
    std::lock_guard<std::mutex> lock(g_SqliteStmtSqlMutex);
    g_SqliteStmtSql.erase(stmt);
}

static void CaptureContactRowFromStatement(sqlite3_stmt* stmt, const std::string& sql)
{
    if (!stmt || sql.empty() ||
        (sql.find("Contact") == std::string::npos &&
         sql.find("contact") == std::string::npos))
        return;
    auto* api = reinterpret_cast<sqlite3_api_routines*>(
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
    if (!api || !IsReadablePointer(api) ||
        !IsExecutablePointer(reinterpret_cast<void*>(api->column_count)) ||
        !IsExecutablePointer(reinterpret_cast<void*>(api->column_name)) ||
        !IsExecutablePointer(reinterpret_cast<void*>(api->column_type)) ||
        !IsExecutablePointer(reinterpret_cast<void*>(api->column_blob)) ||
        !IsExecutablePointer(reinterpret_cast<void*>(api->column_bytes)))
        return;
    const int count = api->column_count(stmt);
    if (count <= 0 || count > 256)
        return;
    nlohmann::ordered_json row = nlohmann::ordered_json::object();
    std::string wxid;
    for (int i = 0; i < count; ++i) {
        const char* name = api->column_name(stmt, i);
        if (!name || !*name)
            continue;
        const void* value = api->column_blob(stmt, i);
        const int length = api->column_bytes(stmt, i);
        if (length < 0 || length > 1024 * 1024)
            continue;
        std::string text;
        if (value && length > 0)
            text.assign(static_cast<const char*>(value), static_cast<size_t>(length));
        row[name] = text;
        std::string lower(name);
        for (char& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if ((lower == "username" || lower == "user_name" || lower == "wxid") &&
            !text.empty())
            wxid = text;
    }
    if (!wxid.empty())
        RecordCapturedContactRow(wxid, row.dump());
}

} // namespace

bool RunContactQueryOnSqliteThread(const std::string& wxid, std::string& resultJson,
                                   uint32_t timeoutMs)
{
    resultJson.clear();
    if (wxid.empty() || wxid.size() > 512 || timeoutMs == 0)
        return false;
    std::unique_lock<std::mutex> lock(g_ContactQueryMutex);
    if (g_ContactQueryActive)
        return false;
    g_ContactQueryActive = true;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ContactQueryRequests));
    g_ContactQueryDone = false;
    g_ContactQueryClaimed = false;
    g_ContactQueryGeneric = false;
    g_ContactQueryWxid = wxid;
    g_ContactQueryDbName = "MicroMsg.db";
    g_ContactQuerySql.clear();
    g_ContactQueryResult.clear();
    if (!g_ContactQueryCv.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                   [] { return g_ContactQueryDone; })) {
        g_ContactQueryActive = false;
        g_ContactQueryWxid.clear();
        return false;
    }
    resultJson = g_ContactQueryResult;
    g_ContactQueryActive = false;
    g_ContactQueryWxid.clear();
    g_ContactQueryDbName.clear();
    return !resultJson.empty();
}

bool RunSqlQueryOnSqliteThread(const std::string& dbname, const std::string& sql,
                               std::string& resultJson, uint32_t timeoutMs)
{
    resultJson.clear();
    if (dbname != "MicroMsg.db" && dbname != "contact.db") {
        resultJson = R"({"status":-400,"desc":"only MicroMsg.db or contact.db is supported"})";
        return true;
    }
    if (!IsReadOnlySql(sql)) {
        resultJson = R"({"status":-400,"desc":"only single read-only SELECT/WITH/PRAGMA statements are allowed"})";
        return true;
    }
    if (timeoutMs == 0)
        return false;

    std::unique_lock<std::mutex> lock(g_ContactQueryMutex);
    if (g_ContactQueryActive)
        return false;
    g_ContactQueryActive = true;
    g_ContactQueryDone = false;
    g_ContactQueryClaimed = false;
    g_ContactQueryGeneric = true;
    g_ContactQueryWxid.clear();
    g_ContactQueryDbName = dbname;
    g_ContactQuerySql = sql;
    g_ContactQueryResult.clear();
    if (!g_ContactQueryCv.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                   [] { return g_ContactQueryDone; })) {
        g_ContactQueryActive = false;
        g_ContactQueryGeneric = false;
        g_ContactQueryDbName.clear();
        g_ContactQuerySql.clear();
        return false;
    }
    resultJson = g_ContactQueryResult;
    g_ContactQueryActive = false;
    g_ContactQueryGeneric = false;
    g_ContactQueryDbName.clear();
    g_ContactQuerySql.clear();
    return !resultJson.empty();
}

static void CaptureSqliteDbHandleFromStmt(sqlite3_stmt* stmt)
{
    if (!stmt || !g_hWeixinDll)
        return;
    __try {
        auto* api = reinterpret_cast<sqlite3_api_routines*>(
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
        if (!IsReadablePointer(api) || !IsExecutablePointer(reinterpret_cast<void*>(api->db_handle)))
            return;
        CaptureSqliteDbHandle(api->db_handle(stmt));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static size_t CopyNativeStringAt(int64_t object, size_t offset, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return 0;
    dst[0] = 0;
    if (!object)
        return 0;
    __try {
        const auto* s = reinterpret_cast<const HookNativeString*>(object + offset);
        if (s->length == 0 || s->length >= cap || s->length > 8192)
            return 0;
        const char* p = s->capacity >= 0x10 ? s->heap_buf : s->inline_buf;
        if (!p)
            return 0;
        memcpy(dst, p, static_cast<size_t>(s->length));
        dst[s->length] = 0;
        return static_cast<size_t>(s->length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
        return 0;
    }
}

static bool TryCopyNativeStringObject(int64_t object, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return false;
    dst[0] = 0;
    if (!object)
        return false;
    __try {
        const auto* s = reinterpret_cast<const HookNativeString*>(object);
        if (s->length == 0 || s->length >= cap || s->length > 8192)
            return false;
        if (s->capacity < s->length)
            return false;
        const char* p = s->capacity >= 0x10 ? s->heap_buf : s->inline_buf;
        if (!p)
            return false;
        memcpy(dst, p, static_cast<size_t>(s->length));
        dst[s->length] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
        return false;
    }
}

// Read one of the pointer-backed native strings used by the nested
// SendMsgRequestNew object.  This routine is deliberately conservative:
// it validates the object and string metadata, bounds the copy, and never
// calls a Weixin routine from the observer.
static bool CopySendRequestString(uintptr_t stringObject, char* dst, size_t cap)
{
    if (!dst || cap == 0 || !stringObject ||
        !IsReadablePointer(reinterpret_cast<const void*>(stringObject)))
        return false;
    dst[0] = 0;
    __try {
        const auto* value = reinterpret_cast<const HookNativeString*>(stringObject);
        const uint64_t length = value->length;
        const uint64_t capacity = value->capacity;
        if (length == 0 || length >= cap || length > 4095 ||
            capacity < length || capacity > 0x100000)
            return false;
        const char* text = capacity >= 0x10 ? value->heap_buf : value->inline_buf;
        if (!text || !IsReadablePointer(text))
            return false;
        memcpy(dst, text, static_cast<size_t>(length));
        dst[length] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
        return false;
    }
}

static bool CaptureSendRequestField(void* request, size_t offset,
                                    char* dst, size_t cap,
                                    uint64_t* fieldObject)
{
    if (!request || !dst || cap == 0)
        return false;
    uintptr_t object = 0;
    __try {
        object = *reinterpret_cast<const uintptr_t*>(
            reinterpret_cast<uintptr_t>(request) + offset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        object = 0;
    }
    if (fieldObject)
        *fieldObject = object;
    if (object && CopySendRequestString(object, dst, cap))
        return true;

    // Keep a guarded fallback for builds where the field is embedded rather
    // than pointer-backed.  The pointer form remains the preferred path.
    return CopySendRequestString(reinterpret_cast<uintptr_t>(request) + offset,
                                 dst, cap);
}

static void ObserveSendMsgRequest(void* destination, void* source)
{
    if (!source)
        return;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendRequestObserveCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastSource),
                          static_cast<LONG64>(reinterpret_cast<uintptr_t>(source)));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastDestination),
                          static_cast<LONG64>(reinterpret_cast<uintptr_t>(destination)));

    uintptr_t vtable = 0;
    __try { vtable = *reinterpret_cast<const uintptr_t*>(source); }
    __except (EXCEPTION_EXECUTE_HANDLER) { vtable = 0; }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastVtable),
                          static_cast<LONG64>(vtable));
    if (vtable && IsExecutablePointer(reinterpret_cast<const void*>(vtable)))
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendRequestObserveVtableValid));

    char field10[4096]{};
    char field20[4096]{};
    uint64_t field10Object = 0;
    uint64_t field20Object = 0;
    const bool got10 = CaptureSendRequestField(source, 0x10, field10,
                                               sizeof(field10), &field10Object);
    const bool got20 = CaptureSendRequestField(source, 0x20, field20,
                                               sizeof(field20), &field20Object);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastField10Object),
                          static_cast<LONG64>(field10Object));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastField20Object),
                          static_cast<LONG64>(field20Object));
    g_SendRequestObserveField10[0] = 0;
    g_SendRequestObserveField20[0] = 0;
    if (got10) {
        CopySafeText(field10, g_SendRequestObserveField10,
                     sizeof(g_SendRequestObserveField10));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendRequestObserveFieldReadCalls));
    }
    if (got20) {
        CopySafeText(field20, g_SendRequestObserveField20,
                     sizeof(g_SendRequestObserveField20));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendRequestObserveFieldReadCalls));
    }
}

static void ObserveSendMsgRequestDestination(void* destination)
{
    if (!destination)
        return;
    char field10[4096]{};
    char field20[4096]{};
    uint64_t field10Object = 0;
    uint64_t field20Object = 0;
    const bool got10 = CaptureSendRequestField(destination, 0x10, field10,
                                               sizeof(field10), &field10Object);
    const bool got20 = CaptureSendRequestField(destination, 0x20, field20,
                                               sizeof(field20), &field20Object);
    if (got10) {
        CopySafeText(field10, g_SendRequestObserveField10,
                     sizeof(g_SendRequestObserveField10));
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastField10Object),
                              static_cast<LONG64>(field10Object));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendRequestObserveFieldReadCalls));
    }
    if (got20) {
        CopySafeText(field20, g_SendRequestObserveField20,
                     sizeof(g_SendRequestObserveField20));
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveLastField20Object),
                              static_cast<LONG64>(field20Object));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendRequestObserveFieldReadCalls));
    }
}

static void __fastcall Hook_SendMsgRequestCopy(void* destination, void* source)
{
    // Capture the source before the original copy and the destination after
    // it.  Neither observation changes arguments, return state, or network
    // behavior.
    ObserveSendMsgRequest(destination, source);
    if (g_OriginalSendMsgRequestCopy)
        g_OriginalSendMsgRequestCopy(destination, source);
    // The source observed above is a wrapper in the current runtime.  The
    // copied destination is the second safe boundary to inspect; it is still
    // read-only and is checked only after the original copy has completed.
    ObserveSendMsgRequestDestination(destination);
}

static void InstallSendMsgRequestObserverHook()
{
    if (InterlockedCompareExchange(&g_SendMsgRequestObserveHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2C6D230);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_SendMsgRequestCopy),
                      reinterpret_cast<void**>(&g_OriginalSendMsgRequestCopy)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalSendMsgRequestCopy = nullptr;
        InterlockedExchange(&g_SendMsgRequestObserveHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveHookInstalled), 0);
    }
    else
    {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendRequestObserveHookInstalled), 1);
    }
}

static void ObserveSendMsgElement(void* destination, void* source)
{
    if (!source)
        return;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendElementObserveCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveLastSource),
                          static_cast<LONG64>(reinterpret_cast<uintptr_t>(source)));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveLastDestination),
                          static_cast<LONG64>(reinterpret_cast<uintptr_t>(destination)));

    uint32_t flags = 0;
    __try {
        flags = *reinterpret_cast<const uint32_t*>(
            reinterpret_cast<uintptr_t>(source) + 0x34);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        flags = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveLastFlags),
                          static_cast<LONG64>(flags));
    if ((flags & (0x02u | 0x20u)) == 0)
        ;
    else
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendElementObserveFlagMatches));

    // Field 1 is a nested base-type string.  sub_1805D3710 reads its
    // wrapper's presence bit at +0x14 and the native string object at +0x08.
    g_SendElementObserveField1[0] = 0;
    uintptr_t field1Wrapper = 0;
    uintptr_t field1Object = 0;
    uint8_t field1Present = 0;
    __try {
        field1Wrapper = *reinterpret_cast<const uintptr_t*>(
            reinterpret_cast<uintptr_t>(source) + 0x08);
        if (field1Wrapper)
            field1Present = *reinterpret_cast<const uint8_t*>(field1Wrapper + 0x14);
        if (field1Wrapper && (field1Present & 1u))
            field1Object = *reinterpret_cast<const uintptr_t*>(field1Wrapper + 0x08);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        field1Wrapper = 0;
        field1Object = 0;
    }
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveLastField1Wrapper),
                          static_cast<LONG64>(field1Wrapper));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveLastField1Object),
                          static_cast<LONG64>(field1Object));
    if (field1Present & 1u) {
        char field1[4096]{};
        if (CopySendRequestString(field1Object, field1, sizeof(field1))) {
            CopySafeText(field1, g_SendElementObserveField1,
                         sizeof(g_SendElementObserveField1));
            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendElementObserveFieldReadCalls));
        }
    }

    char field10[4096]{};
    char field20[4096]{};
    const bool got10 = (flags & 0x02u) != 0 &&
        CaptureSendRequestField(source, 0x10, field10, sizeof(field10), nullptr);
    const bool got20 = (flags & 0x20u) != 0 &&
        CaptureSendRequestField(source, 0x20, field20, sizeof(field20), nullptr);
    g_SendElementObserveField10[0] = 0;
    g_SendElementObserveField20[0] = 0;
    if (got10) {
        CopySafeText(field10, g_SendElementObserveField10,
                     sizeof(g_SendElementObserveField10));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendElementObserveFieldReadCalls));
    }
    if (got20) {
        CopySafeText(field20, g_SendElementObserveField20,
                     sizeof(g_SendElementObserveField20));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SendElementObserveFieldReadCalls));
    }
}

static int64_t __fastcall Hook_SendMsgElementCopy(void* destination,
                                                   void* source,
                                                   void* arena)
{
    ObserveSendMsgElement(destination, source);
    return g_OriginalSendMsgElementCopy
        ? g_OriginalSendMsgElementCopy(destination, source, arena) : 0;
}

static void InstallSendMsgElementObserverHook()
{
    if (InterlockedCompareExchange(&g_SendMsgElementObserveHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2C6C060);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_SendMsgElementCopy),
                      reinterpret_cast<void**>(&g_OriginalSendMsgElementCopy)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalSendMsgElementCopy = nullptr;
        InterlockedExchange(&g_SendMsgElementObserveHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveHookInstalled), 0);
    }
    else
    {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SendElementObserveHookInstalled), 1);
    }
}

static bool IsUsefulMessageText(const char* s)
{
    if (!s || !*s)
        return false;
    const size_t n = strlen(s);
    if (n < 2 || n > 2048)
        return false;
    if (strstr(s, "你好") || strstr(s, "123"))
        return true;
    if (strstr(s, "wxid_") || strstr(s, "@chatroom") || strstr(s, "gh_"))
        return true;
    return false;
}

struct NativeWxString;
static bool ReadMessageFields(void* message, std::string& field1, std::string& field2);

struct AutoReplyTask {
    std::string wxid;
    std::string content;
    bool is_group = false;
    std::string sender_wxid;
};

static std::mutex g_AutoReplyMutex;
static std::condition_variable g_AutoReplyCv;
static std::deque<AutoReplyTask> g_AutoReplyQueue;
static std::once_flag g_AutoReplyWorkerOnce;
static std::string g_AutoReplyLastKey;

static bool IsLikelyWxid(const std::string& value)
{
    return value.rfind("wxid_", 0) == 0 ||
           value.find("@chatroom") != std::string::npos ||
           value == "filehelper" || value.rfind("gh_", 0) == 0;
}

static bool IsGroupWxid(const std::string& value)
{
    return value.find("@chatroom") != std::string::npos;
}

static bool IsSelfWxid(const std::string& value)
{
    if (value.empty())
        return false;
    if (!SelfInfo.wxid.empty() && value == SelfInfo.wxid)
        return true;
    return g_SyncBatchToUsername[0] && value == g_SyncBatchToUsername;
}

static void RecordAutoReplyClassification(const char* type,
                                          const std::string& sender,
                                          const std::string& room)
{
    CopySafeText(type ? type : "unknown", g_AutoReplyLastChatType,
                 sizeof(g_AutoReplyLastChatType));
    CopySafeText(sender.c_str(), g_AutoReplyLastSender,
                 sizeof(g_AutoReplyLastSender));
    CopySafeText(room.c_str(), g_AutoReplyLastRoom,
                 sizeof(g_AutoReplyLastRoom));
}

static void StartAutoReplyWorker()
{
    std::call_once(g_AutoReplyWorkerOnce, [] {
        std::thread([] {
            for (;;) {
                AutoReplyTask task;
                {
                    std::unique_lock<std::mutex> lock(g_AutoReplyMutex);
                    g_AutoReplyCv.wait(lock, [] { return !g_AutoReplyQueue.empty(); });
                    task = std::move(g_AutoReplyQueue.front());
                    g_AutoReplyQueue.pop_front();
                }
                // Let WeChat finish its receive/commit path before entering
                // the send routine on a separate thread.
                Sleep(300);
                if (g_IsLogin && !task.wxid.empty() && !task.content.empty()) {
                    // Keep the generated prefix ASCII-only so the injected
                    // DLL does not depend on the source-file code page.
                    const std::string reply = "[auto-reply] " + task.content;
                    if (WeixinSend::SendText(task.wxid, reply))
                        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplySent));
                    else
                        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyFailed));
                }
            }
        }).detach();
    });
}

static void QueueAutoReplyDirect(const std::string& wxid, const std::string& content,
                                 bool isGroup = false,
                                 const std::string& senderWxid = {})
{
    if (!g_IsLogin || !IsLikelyWxid(wxid) || content.empty() || wxid == SelfInfo.wxid)
        return;
    const std::string key = wxid + "\n" + content;
    {
        std::lock_guard<std::mutex> lock(g_AutoReplyMutex);
        if (key == g_AutoReplyLastKey)
            return;
        g_AutoReplyLastKey = key;
        if (g_AutoReplyQueue.size() >= 32)
            g_AutoReplyQueue.pop_front();
        g_AutoReplyQueue.push_back({wxid, content, isGroup, senderWxid});
    }
    StartAutoReplyWorker();
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyQueued));
    g_AutoReplyCv.notify_one();
}

// Classify incoming messages before they can reach the send worker.  In this
// build friend replies are enabled; group replies are recognized but disabled
// by default to prevent accidental group-wide spam.  The group switch is
// exposed in status so it can be explicitly enabled later.
static void ClassifyAndQueueAutoReply(const std::string& fromWxid,
                                      const std::string& toWxid,
                                      const std::string& content)
{
    if (!g_IsLogin || content.empty() || fromWxid.empty())
        return;
    if (IsSelfWxid(fromWxid)) {
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplySelfSkipped));
        RecordAutoReplyClassification("self", fromWxid, {});
        return;
    }
    if (IsGroupWxid(fromWxid)) {
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyGroupCandidates));
        RecordAutoReplyClassification("group", fromWxid, fromWxid);
        if (!g_AutoReplyGroupEnabled) {
            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyGroupSkipped));
            return;
        }
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyCandidates));
        QueueAutoReplyDirect(fromWxid, content, true, {});
        return;
    }
    if (!IsLikelyWxid(fromWxid))
        return;
    // A normal friend message uses the sender as the reply target.  The
    // destination is retained for diagnostics; it must not replace sender.
    (void)toWxid;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyFriendCandidates));
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AutoReplyCandidates));
    RecordAutoReplyClassification("friend", fromWxid, {});
    QueueAutoReplyDirect(fromWxid, content, false, fromWxid);
}

static void QueueAutoReply(const std::string& wxid, const std::string& content)
{
    ClassifyAndQueueAutoReply(wxid, {}, content);
}

static bool IsPlainTextCandidate(const char* text)
{
    if (!text || !*text)
        return false;
    const size_t n = strlen(text);
    if (n == 0 || n > 2048 || text[0] == '<')
        return false;
    bool hasNonAscii = false;
    bool hasAlphaNumeric = false;
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x20 && c != '\t' && c != '\r' && c != '\n')
            return false;
        if (c >= 0x80)
            hasNonAscii = true;
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z'))
            hasAlphaNumeric = true;
    }
    return hasNonAscii || hasAlphaNumeric;
}

static uintptr_t ReadPointerSafe(int64_t address);

static void ConsiderSyncBatchText(const char* text, char* sender, size_t senderCap,
                                  char* body, size_t bodyCap)
{
    if (!text || !*text || !sender || !body)
        return;
    if (!sender[0] && IsLikelyWxid(text)) {
        CopySafeText(text, sender, senderCap);
        return;
    }
    if (!body[0] && !IsLikelyWxid(text) && IsPlainTextCandidate(text))
        CopySafeText(text, body, bodyCap);
}

static void CaptureStructuredMessageObject(int64_t object, int64_t source)
{
    if (!object)
        return;

    // sub_180A19E90 copies the two username-like members to +0x18/+0x38
    // and the content-like members to +0x180/+0x1C0. Keep these exact fields
    // visible through QueryDB while also probing the remaining native strings.
    g_SyncBatchText1[0] = g_SyncBatchText2[0] = 0;
    g_SyncBatchText3[0] = g_SyncBatchText4[0] = 0;
    CopyNativeStringAt(object, 0x18, g_SyncBatchText1, sizeof(g_SyncBatchText1));
    CopyNativeStringAt(object, 0x38, g_SyncBatchText2, sizeof(g_SyncBatchText2));
    CopyNativeStringAt(object, 0x180, g_SyncBatchText3, sizeof(g_SyncBatchText3));
    CopyNativeStringAt(object, 0x1C0, g_SyncBatchText4, sizeof(g_SyncBatchText4));

    char sender[256]{};
    char body[4096]{};
    ConsiderSyncBatchText(g_SyncBatchText1, sender, sizeof(sender), body, sizeof(body));
    ConsiderSyncBatchText(g_SyncBatchText2, sender, sizeof(sender), body, sizeof(body));
    // Prefer the content slots before falling back to other object fields.
    if (!body[0]) {
        ConsiderSyncBatchText(g_SyncBatchText3, sender, sizeof(sender), body, sizeof(body));
        ConsiderSyncBatchText(g_SyncBatchText4, sender, sizeof(sender), body, sizeof(body));
    }

    static constexpr size_t kObjectTextOffsets[] = {
        0x58, 0x78, 0x98, 0x100, 0x120, 0x144, 0x180, 0x1A0,
        0x1C0, 0x1E0, 0x248, 0x260, 0x278, 0x288, 0x2B8
    };
    for (const size_t off : kObjectTextOffsets) {
        char text[4096]{};
        if (CopyNativeStringAt(object, off, text, sizeof(text)))
            ConsiderSyncBatchText(text, sender, sizeof(sender), body, sizeof(body));
    }

    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchLastCandidate),
                          static_cast<LONG64>(object));
    if (sender[0]) {
        CopySafeText(sender, g_FieldFromText, sizeof(g_FieldFromText));
        CopySafeText(sender, g_MessageStructTalker, sizeof(g_MessageStructTalker));
    }
    if (body[0]) {
        CopySafeText(body, g_FieldContentText, sizeof(g_FieldContentText));
        CopySafeText(body, g_MessageStructContent, sizeof(g_MessageStructContent));
    }
    if (sender[0] && body[0] && IsLikelyWxid(sender)) {
        QueueAutoReply(sender, body);
    }
    (void)source;
}

static int64_t __fastcall Hook_MessageObjectCopy(int64_t object, int64_t source)
{
    const int64_t result = g_OriginalMessageObjectCopy
        ? g_OriginalMessageObjectCopy(object, source) : object;
    CaptureStructuredMessageObject(object, source);
    return result;
}

static void InstallMessageObjectCopyHook()
{
    if (InterlockedCompareExchange(&g_MessageObjectCopyHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0xA1B9C0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MessageObjectCopy),
                      reinterpret_cast<void**>(&g_OriginalMessageObjectCopy)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalMessageObjectCopy = nullptr;
        InterlockedExchange(&g_MessageObjectCopyHookState, 0);
    }
}

static void CaptureSyncBatchItem(int64_t item)
{
    if (!item)
        return;
    char sender[256]{};
    char body[4096]{};

    // sub_182C2C810 destroys each item after processing it. Read only while
    // the item is live, and probe both inline/native-string fields and pointer
    // fields. This is diagnostic first; it does not alter the vector.
    for (size_t off = 0; off <= 0x78; off += 8) {
        char text[4096]{};
        if (TryCopyNativeStringObject(item + static_cast<int64_t>(off),
                                      text, sizeof(text)))
            ConsiderSyncBatchText(text, sender, sizeof(sender), body, sizeof(body));
        const uintptr_t ptr = ReadPointerSafe(item + static_cast<int64_t>(off));
        if (ptr && TryCopyNativeStringObject(static_cast<int64_t>(ptr),
                                             text, sizeof(text)))
            ConsiderSyncBatchText(text, sender, sizeof(sender), body, sizeof(body));
    }

    if (!sender[0] && !body[0])
        return;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchLastCandidate),
                          static_cast<LONG64>(item));
    if (sender[0]) {
        CopySafeText(sender, g_FieldFromText, sizeof(g_FieldFromText));
        CopySafeText(sender, g_MessageStructTalker, sizeof(g_MessageStructTalker));
    }
    if (body[0]) {
        CopySafeText(body, g_FieldContentText, sizeof(g_FieldContentText));
        CopySafeText(body, g_MessageStructContent, sizeof(g_MessageStructContent));
    }
    RecordMessageBranchTrace("sub_1816D5180_item", 0,
                             static_cast<uint64_t>(item),
                             reinterpret_cast<uint64_t>(sender),
                             reinterpret_cast<uint64_t>(body));
    if (sender[0] && body[0] && IsLikelyWxid(sender)) {
        QueueAutoReply(sender, body);
    }
}

static bool CopyValidatedAddMsgString(int64_t item, size_t fieldOffset,
                                      uint32_t hasBit, char* dst, size_t cap)
{
    if (!item || !dst || cap == 0 || !g_hWeixinDll)
        return false;
    dst[0] = 0;
    __try {
        const uint32_t hasBits = *reinterpret_cast<const uint32_t*>(item + 0x6C);
        if ((hasBits & hasBit) == 0)
            return false;

        const uintptr_t arenaString =
            *reinterpret_cast<const uintptr_t*>(item + fieldOffset);
        if (!arenaString || !IsReadablePointer(reinterpret_cast<const void*>(arenaString)))
            return false;

        // micromsg.AddMsg string fields use the generated ArenaStringPtr
        // wrapper (vtable off_1882643A8), not a raw std::string at item+off.
        const uintptr_t stringVtable =
            *reinterpret_cast<const uintptr_t*>(arenaString);
        const uintptr_t expectedStringVtable =
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x82643A8;
        if (stringVtable != expectedStringVtable)
            return false;

        const uintptr_t stringRep =
            *reinterpret_cast<const uintptr_t*>(arenaString + 8);
        if (!stringRep || !IsReadablePointer(reinterpret_cast<const void*>(stringRep)))
            return false;

        const auto* value = reinterpret_cast<const HookNativeString*>(stringRep);
        const uint64_t length = value->length;
        const uint64_t capacity = value->capacity;
        if (length == 0 || length >= cap || length > 4096 || capacity < length ||
            capacity > 0x100000)
            return false;

        const char* text = capacity >= 0x10 ? value->heap_buf : value->inline_buf;
        if (!text || !IsReadablePointer(text))
            return false;
        memcpy(dst, text, static_cast<size_t>(length));
        dst[length] = 0;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
        return false;
    }
}

struct AddMsgCapture {
    bool captured = false;
    bool gotFrom = false;
    bool gotTo = false;
    bool gotContent = false;
    char from[4096]{};
    char to[4096]{};
    char content[4096]{};
};

static bool CaptureValidatedAddMsgItemRaw(int64_t item, AddMsgCapture& capture)
{
    if (!item || !g_hWeixinDll)
        return false;

    __try {
        const uintptr_t vtable = *reinterpret_cast<const uintptr_t*>(item);
        const uintptr_t expectedVtable =
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x83DF408;
        if (vtable != expectedVtable)
            return false;

        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SyncBatchVtableMatches));
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchLastCandidate),
                              static_cast<LONG64>(item));

        const uint32_t msgType = *reinterpret_cast<const uint32_t*>(item + 0x10);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchLastMsgType),
                              static_cast<LONG64>(msgType));

        capture.gotFrom = CopyValidatedAddMsgString(item, 0x08, 0x02,
                                                     capture.from, sizeof(capture.from));
        capture.gotTo = CopyValidatedAddMsgString(item, 0x18, 0x04,
                                                  capture.to, sizeof(capture.to));
        capture.gotContent = CopyValidatedAddMsgString(item, 0x20, 0x10,
                                                        capture.content, sizeof(capture.content));
        if (!capture.gotFrom && !capture.gotTo && !capture.gotContent)
            return false;

        if (capture.gotFrom)
            CopySafeText(capture.from, g_SyncBatchFromUsername, sizeof(g_SyncBatchFromUsername));
        if (capture.gotTo)
            CopySafeText(capture.to, g_SyncBatchToUsername, sizeof(g_SyncBatchToUsername));
        if (capture.gotContent)
            CopySafeText(capture.content, g_SyncBatchContent, sizeof(g_SyncBatchContent));
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SyncBatchFieldReadCalls));
        capture.captured = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        capture.captured = false;
    }
    return capture.captured;
}

static bool CaptureValidatedAddMsgItem(int64_t item)
{
    AddMsgCapture capture{};
    if (!CaptureValidatedAddMsgItemRaw(item, capture))
        return false;
    if (capture.gotFrom && capture.gotContent) {
        const std::string fromValue(capture.from);
        const std::string toValue(capture.gotTo ? capture.to : "");
        const std::string contentValue(capture.content);
        ClassifyAndQueueAutoReply(fromValue, toValue, contentValue);
    }
    return true;
}

static uint64_t ProbeSyncBatchVector(int64_t* vector)
{
    if (!vector)
        return 0;
    uint64_t count = 0;
    __try {
        const int64_t begin = vector[0];
        const int64_t end = vector[1];
        constexpr int64_t kSyncBatchItemStride = 0x78;
        if (begin && end >= begin && (end - begin) <= kSyncBatchItemStride * 1024 &&
            ((end - begin) % kSyncBatchItemStride) == 0) {
            count = static_cast<uint64_t>((end - begin) / kSyncBatchItemStride);
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchLastVector),
                                  static_cast<LONG64>(reinterpret_cast<uintptr_t>(vector)));
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchItemCount),
                                  static_cast<LONG64>(count));
            g_SyncBatchFromUsername[0] = 0;
            g_SyncBatchToUsername[0] = 0;
            g_SyncBatchContent[0] = 0;
            // Read only validated micromsg.AddMsg items.  The vector is
            // destroyed by sub_182C2C810 after the downstream call, so all
            // reads must finish before the original function is entered.
            const uint64_t limit = count > 64 ? 64 : count;
            for (uint64_t i = 0; i < limit; ++i)
                CaptureValidatedAddMsgItem(begin + static_cast<int64_t>(i * kSyncBatchItemStride));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return count;
}

static char __fastcall Hook_SyncBatchProcessor(int64_t context, int64_t* items,
                                                unsigned char a3, char a4)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SyncBatchProcessorCalls));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SyncBatchLastContext),
                          static_cast<LONG64>(context));
    RecordMessageBranchTrace("sub_1816D5180_args",
                             reinterpret_cast<uint64_t>(g_hWeixinDll) + 0x16D5180,
                             static_cast<uint64_t>(context),
                             reinterpret_cast<uint64_t>(items),
                             (static_cast<uint64_t>(a3) << 8) |
                                 static_cast<uint64_t>(static_cast<unsigned char>(a4)));
    ProbeSyncBatchVector(items);
    return g_OriginalSyncBatchProcessor
        ? g_OriginalSyncBatchProcessor(context, items, a3, a4) : 0;
}

static void InstallSyncBatchProcessorHook()
{
    if (InterlockedCompareExchange(&g_SyncBatchProcessorHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x16D5180);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_SyncBatchProcessor),
                      reinterpret_cast<void**>(&g_OriginalSyncBatchProcessor)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalSyncBatchProcessor = nullptr;
        InterlockedExchange(&g_SyncBatchProcessorHookState, 0);
    }
}

static uintptr_t ReadPointerSafe(int64_t address)
{
    uintptr_t value = 0;
    __try {
        value = *reinterpret_cast<uintptr_t*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return value;
}

static void TryQueueAutoReplyFromItem(int64_t item)
{
    // The vector element is a 0x70-byte wrapper. Depending on message type,
    // the getter object is either the element itself or one of its pointer
    // fields, so probe both forms using the guarded native getters.
    for (int off = -1; off < 0x70; off += 8) {
        uintptr_t candidate = static_cast<uintptr_t>(item);
        if (off >= 0) {
            candidate = ReadPointerSafe(item + off);
        }
        if (!candidate)
            continue;
        std::string senderId;
        std::string messageBody;
        if (ReadMessageFields(reinterpret_cast<void*>(candidate), senderId, messageBody) &&
            IsLikelyWxid(senderId) && !messageBody.empty()) {
            QueueAutoReply(senderId, messageBody);
            return;
        }
    }
}

static void TryQueueAutoReplyFromDispatchObject(int64_t object)
{
    if (!object)
        return;
    char sender[256]{};
    char body[4096]{};
    for (size_t off = 0; off <= 0x380; off += 8) {
        char text[4096]{};
        if (!CopyNativeStringAt(object, off, text, sizeof(text)))
            continue;
        if (sender[0] == 0 && IsLikelyWxid(text)) {
            CopySafeText(text, sender, sizeof(sender));
            continue;
        }
        if (body[0] == 0 && IsUsefulMessageText(text) && !IsLikelyWxid(text))
            CopySafeText(text, body, sizeof(body));
    }
    if (sender[0] && body[0]) {
        CopySafeText(sender, g_MessageStructTalker, sizeof(g_MessageStructTalker));
        CopySafeText(body, g_MessageStructContent, sizeof(g_MessageStructContent));
        QueueAutoReply(sender, body);
    }
}

using FnPlainTextMessageProcessor = int64_t(__fastcall*)(int64_t message);
static FnPlainTextMessageProcessor g_OriginalPlainTextMessageProcessor = nullptr;
static LONG g_PlainTextMessageProcessorHookState = 0;

static int64_t __fastcall Hook_PlainTextMessageProcessor(int64_t message)
{
    std::string senderId;
    std::string messageBody;
    if (message && ReadMessageFields(reinterpret_cast<void*>(message), senderId, messageBody)) {
        if (IsLikelyWxid(senderId) && !messageBody.empty()) {
            CopySafeText(senderId.c_str(), g_MessageStructTalker, sizeof(g_MessageStructTalker));
            CopySafeText(messageBody.c_str(), g_MessageStructContent, sizeof(g_MessageStructContent));
            QueueAutoReply(senderId, messageBody);
        }
    }
    return g_OriginalPlainTextMessageProcessor
        ? g_OriginalPlainTextMessageProcessor(message) : 0;
}

static void InstallPlainTextMessageProcessorHook()
{
    if (InterlockedCompareExchange(&g_PlainTextMessageProcessorHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x29EFD30);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_PlainTextMessageProcessor),
                      reinterpret_cast<void**>(&g_OriginalPlainTextMessageProcessor)) != MH_OK ||
        MH_EnableHook(target) != MH_OK) {
        g_OriginalPlainTextMessageProcessor = nullptr;
        InterlockedExchange(&g_PlainTextMessageProcessorHookState, 0);
    }
}

static void CaptureRawSyncMessageItem(int64_t item)
{
    if (!item)
        return;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_RawSyncMsgLastItem),
                          static_cast<LONG64>(item));
    __try {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_RawSyncMsgLastType),
                              static_cast<LONG64>(*reinterpret_cast<int*>(item + 0x48)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    char found[4][4096]{};
    int foundCount = 0;
    for (int off = 0; off <= 112 && foundCount < 4; off += 8) {
        char text[4096]{};
        if (TryCopyNativeStringObject(item + off, text, sizeof(text)) && IsUsefulMessageText(text)) {
            CopySafeText(text, found[foundCount++], sizeof(found[0]));
            continue;
        }
        __try {
            const int64_t ptr = *reinterpret_cast<int64_t*>(item + off);
            if (TryCopyNativeStringObject(ptr, text, sizeof(text)) && IsUsefulMessageText(text)) {
                CopySafeText(text, found[foundCount++], sizeof(found[0]));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (foundCount > 0) {
        CopySafeText(found[0], g_MessageStructTalker, sizeof(g_MessageStructTalker));
    }
    if (foundCount > 1) {
        CopySafeText(found[1], g_MessageStructContent, sizeof(g_MessageStructContent));
    }
    if (foundCount > 2) {
        CopySafeText(found[2], g_MessageStructExtra1, sizeof(g_MessageStructExtra1));
    }
    if (foundCount > 3) {
        CopySafeText(found[3], g_MessageStructExtra2, sizeof(g_MessageStructExtra2));
    }

    // The ordinary text item currently exposes one formatted field such as
    // "NickName : message text". Split it so the HTTP status can expose the
    // sender and body separately even before the underlying object fields are
    // fully mapped.
    if (foundCount == 1) {
        char* separator = strstr(g_MessageStructTalker, " : ");
        if (separator) {
            char body[sizeof(g_MessageStructContent)]{};
            CopySafeText(separator + 3, body, sizeof(body));
            *separator = 0;
            CopySafeText(body, g_MessageStructContent, sizeof(g_MessageStructContent));
        }
    }
    TryQueueAutoReplyFromItem(item);
    if (foundCount > 0) {
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageStructCopyCalls));
        RecordMessageBranchTrace("sub_182C28700_item", 0,
                                 static_cast<uint64_t>(item),
                                 static_cast<uint64_t>(foundCount),
                                 static_cast<uint64_t>(g_RawSyncMsgLastType));
    }
}

static uint64_t ProbeRawSyncVectorCandidate(const char* name, int64_t candidate)
{
    if (!candidate)
        return 0;
    uint64_t count = 0;
    __try {
        const int64_t begin = *reinterpret_cast<int64_t*>(candidate);
        const int64_t end = *reinterpret_cast<int64_t*>(candidate + 8);
        // sub_183544650 iterates the same message vector with add r14, 70h.
        // The element size for Weixin 4.1.10.27 is therefore 0x70 bytes.
        constexpr int64_t kRawSyncItemStride = 0x70;
        if (begin && end >= begin && (end - begin) <= kRawSyncItemStride * 1024 &&
            ((end - begin) % kRawSyncItemStride) == 0) {
            count = static_cast<uint64_t>((end - begin) / kRawSyncItemStride);
            RecordMessageBranchTrace(name, 0, static_cast<uint64_t>(candidate),
                                     static_cast<uint64_t>(begin), static_cast<uint64_t>(end));
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_RawSyncMsgItemCount),
                                  static_cast<LONG64>(count));
            const uint64_t limit = count > 64 ? 64 : count;
            for (uint64_t i = 0; i < limit; ++i)
                CaptureRawSyncMessageItem(begin + static_cast<int64_t>(i * kRawSyncItemStride));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return count;
}

static int64_t __fastcall Hook_RawSyncMsgProcessor(int64_t* items, uint64_t* context, char a3, char a4)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_RawSyncMsgProcessorCalls));
    RecordMessageBranchTrace("sub_182C28700_args", 0,
                             reinterpret_cast<uint64_t>(items),
                             reinterpret_cast<uint64_t>(context),
                             (static_cast<uint64_t>(static_cast<unsigned char>(a3)) << 8) |
                                 static_cast<uint64_t>(static_cast<unsigned char>(a4)));
    // Do not dereference or call message getters on the raw sync arguments.
    // During login this function also receives non-message bootstrap vectors;
    // treating those as 0x70-byte message items caused unbounded allocations.
    return g_OriginalRawSyncMsgProcessor
        ? g_OriginalRawSyncMsgProcessor(items, context, a3, a4)
        : 0;
}

static void InstallRawSyncMsgProcessorHook()
{
    if (InterlockedCompareExchange(&g_RawSyncMsgProcessorHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2C28700);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_RawSyncMsgProcessor),
                      reinterpret_cast<void**>(&g_OriginalRawSyncMsgProcessor)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalRawSyncMsgProcessor = nullptr;
        InterlockedExchange(&g_RawSyncMsgProcessorHookState, 0);
    }
}

static void RecordFieldLookupTrace(int64_t container, int64_t output, int64_t key,
                                   int64_t result, const char* keyText)
{
    const uint64_t sequence = InterlockedIncrement64(
        reinterpret_cast<volatile LONG64*>(&g_FieldLookupTraceIndex));
    auto& item = g_FieldLookupTraces[sequence % kFieldLookupTraceCapacity];
    item.sequence = sequence;
    item.container = static_cast<uint64_t>(container);
    item.output = static_cast<uint64_t>(output);
    item.keyPtr = static_cast<uint64_t>(key);
    item.result = static_cast<uint64_t>(result);
    CopySafeText(keyText, item.key, sizeof(item.key));
    CopyHookOutput(output, item.text, sizeof(item.text));
}

static void RecordMessageBranchTrace(const char* name, uint64_t handler,
                                     uint64_t a1, uint64_t a2, uint64_t a3)
{
    const uint64_t sequence = InterlockedIncrement64(
        reinterpret_cast<volatile LONG64*>(&g_MessageBranchTraceIndex));
    auto& item = g_MessageBranchTraces[sequence % kMessageBranchTraceCapacity];
    item.sequence = sequence;
    item.handler = handler;
    item.a1 = a1;
    item.a2 = a2;
    item.a3 = a3;
    item.caller = reinterpret_cast<uint64_t>(_ReturnAddress());
    CopySafeText(name, item.name, sizeof(item.name));
}

#define DEFINE_MESSAGE_BRANCH2(symbol, rva) \
    static FnMessageBranch2 g_OriginalBranch_##symbol = nullptr; \
    static int64_t __fastcall HookBranch_##symbol(int64_t a1, int64_t a2) { \
        RecordMessageBranchTrace(#symbol, reinterpret_cast<uint64_t>(g_hWeixinDll) + (rva), \
                                 static_cast<uint64_t>(a1), static_cast<uint64_t>(a2), 0); \
        return g_OriginalBranch_##symbol ? g_OriginalBranch_##symbol(a1, a2) : 0; \
    }

#define DEFINE_MESSAGE_BRANCH3(symbol, rva) \
    static FnMessageBranch3 g_OriginalBranch_##symbol = nullptr; \
    static int64_t __fastcall HookBranch_##symbol(int64_t a1, int64_t a2, int64_t a3) { \
        RecordMessageBranchTrace(#symbol, reinterpret_cast<uint64_t>(g_hWeixinDll) + (rva), \
                                 static_cast<uint64_t>(a1), static_cast<uint64_t>(a2), \
                                 static_cast<uint64_t>(a3)); \
        return g_OriginalBranch_##symbol ? g_OriginalBranch_##symbol(a1, a2, a3) : 0; \
    }

DEFINE_MESSAGE_BRANCH2(sub_1816E5F30, 0x16E5F30)
DEFINE_MESSAGE_BRANCH2(sub_18172CF60, 0x172CF60)
DEFINE_MESSAGE_BRANCH2(sub_181738FD0, 0x1738FD0)
DEFINE_MESSAGE_BRANCH2(sub_18173B310, 0x173B310)
DEFINE_MESSAGE_BRANCH2(sub_18173BEF0, 0x173BEF0)
DEFINE_MESSAGE_BRANCH2(sub_182427440, 0x2427440)
DEFINE_MESSAGE_BRANCH2(sub_182429AE0, 0x2429AE0)
DEFINE_MESSAGE_BRANCH2(sub_181D37A50, 0x1D37A50)
DEFINE_MESSAGE_BRANCH2(sub_18039F080, 0x039F080)
DEFINE_MESSAGE_BRANCH2(sub_18242D1F0, 0x242D1F0)
DEFINE_MESSAGE_BRANCH2(sub_1816E2960, 0x16E2960)
DEFINE_MESSAGE_BRANCH2(sub_1816E4340, 0x16E4340)
DEFINE_MESSAGE_BRANCH2(sub_1816E4AD0, 0x16E4AD0)
DEFINE_MESSAGE_BRANCH2(sub_185EA44F0, 0x5EA44F0)
DEFINE_MESSAGE_BRANCH2(sub_182B77C80, 0x2B77C80)
DEFINE_MESSAGE_BRANCH2(sub_1820E1BF0, 0x20E1BF0)
DEFINE_MESSAGE_BRANCH2(sub_18173D590, 0x173D590)
DEFINE_MESSAGE_BRANCH2(sub_182B96940, 0x2B96940)
DEFINE_MESSAGE_BRANCH2(sub_18173C490, 0x173C490)
DEFINE_MESSAGE_BRANCH2(sub_18246FA90, 0x246FA90)
DEFINE_MESSAGE_BRANCH2(sub_18172B830, 0x172B830)
DEFINE_MESSAGE_BRANCH2(sub_18172BDA0, 0x172BDA0)
DEFINE_MESSAGE_BRANCH2(sub_1820E1FD0, 0x20E1FD0)
DEFINE_MESSAGE_BRANCH2(sub_18354DE40, 0x354DE40)
DEFINE_MESSAGE_BRANCH3(sub_183503570, 0x3503570)
DEFINE_MESSAGE_BRANCH3(sub_182B06660, 0x2B06660)
DEFINE_MESSAGE_BRANCH3(sub_1818BEEC0, 0x18BEEC0)

static void TryInstallMessageBranch2(void* hook, void** original, uintptr_t rva)
{
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + rva);
    if (MH_CreateHook(target, hook, original) == MH_OK)
        MH_EnableHook(target);
}

static void TryInstallMessageBranch3(void* hook, void** original, uintptr_t rva)
{
    TryInstallMessageBranch2(hook, original, rva);
}

static void InstallMessageBranchTraceHooks()
{
    if (InterlockedCompareExchange(&g_MessageBranchHookState, 1, 0) != 0)
        return;
#define INSTALL_BRANCH2(symbol, rva) \
    TryInstallMessageBranch2(reinterpret_cast<void*>(&HookBranch_##symbol), \
                             reinterpret_cast<void**>(&g_OriginalBranch_##symbol), (rva))
#define INSTALL_BRANCH3(symbol, rva) \
    TryInstallMessageBranch3(reinterpret_cast<void*>(&HookBranch_##symbol), \
                             reinterpret_cast<void**>(&g_OriginalBranch_##symbol), (rva))

    INSTALL_BRANCH2(sub_1816E5F30, 0x16E5F30);
    INSTALL_BRANCH2(sub_18172CF60, 0x172CF60);
    INSTALL_BRANCH2(sub_181738FD0, 0x1738FD0);
    INSTALL_BRANCH2(sub_18173B310, 0x173B310);
    INSTALL_BRANCH2(sub_18173BEF0, 0x173BEF0);
    INSTALL_BRANCH2(sub_182427440, 0x2427440);
    INSTALL_BRANCH2(sub_182429AE0, 0x2429AE0);
    INSTALL_BRANCH2(sub_181D37A50, 0x1D37A50);
    INSTALL_BRANCH2(sub_18039F080, 0x039F080);
    INSTALL_BRANCH2(sub_18242D1F0, 0x242D1F0);
    INSTALL_BRANCH2(sub_1816E2960, 0x16E2960);
    INSTALL_BRANCH2(sub_1816E4340, 0x16E4340);
    INSTALL_BRANCH2(sub_1816E4AD0, 0x16E4AD0);
    INSTALL_BRANCH2(sub_185EA44F0, 0x5EA44F0);
    INSTALL_BRANCH2(sub_182B77C80, 0x2B77C80);
    INSTALL_BRANCH2(sub_1820E1BF0, 0x20E1BF0);
    INSTALL_BRANCH2(sub_18173D590, 0x173D590);
    INSTALL_BRANCH2(sub_182B96940, 0x2B96940);
    INSTALL_BRANCH2(sub_18173C490, 0x173C490);
    INSTALL_BRANCH2(sub_18246FA90, 0x246FA90);
    INSTALL_BRANCH2(sub_18172B830, 0x172B830);
    INSTALL_BRANCH2(sub_18172BDA0, 0x172BDA0);
    INSTALL_BRANCH2(sub_1820E1FD0, 0x20E1FD0);
    INSTALL_BRANCH2(sub_18354DE40, 0x354DE40);
    INSTALL_BRANCH3(sub_183503570, 0x3503570);
    INSTALL_BRANCH3(sub_182B06660, 0x2B06660);
    INSTALL_BRANCH3(sub_1818BEEC0, 0x18BEEC0);

#undef INSTALL_BRANCH2
#undef INSTALL_BRANCH3
}

static void DumpHookOutput(int64_t output, char* outHex, size_t outCap,
                           char* nodeHex, size_t nodeCap,
                           char* valueHex, size_t valueCap)
{
    if (!outHex || !nodeHex || !valueHex) return;
    outHex[0] = nodeHex[0] = valueHex[0] = 0;
    __try {
        const auto* p = reinterpret_cast<const unsigned char*>(output);
        size_t pos = 0;
        for (size_t i = 0; i < 64 && pos + 3 < outCap; ++i)
            pos += static_cast<size_t>(sprintf_s(outHex + pos, outCap - pos, "%02X ", p[i]));
        const int64_t node = *reinterpret_cast<const int64_t*>(output);
        if (!node) return;
        const auto* np = reinterpret_cast<const unsigned char*>(node);
        pos = 0;
        for (size_t i = 0; i < 128 && pos + 3 < nodeCap; ++i)
            pos += static_cast<size_t>(sprintf_s(nodeHex + pos, nodeCap - pos, "%02X ", np[i]));
        const int64_t valueNode = FindHookValueNode(node);
        const int64_t value = valueNode ? *reinterpret_cast<const int64_t*>(valueNode + 0x10) : 0;
        if (!value) return;
        const auto* vp = reinterpret_cast<const unsigned char*>(value);
        pos = 0;
        for (size_t i = 0; i < 128 && pos + 3 < valueCap; ++i)
            pos += static_cast<size_t>(sprintf_s(valueHex + pos, valueCap - pos, "%02X ", vp[i]));
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static int64_t __fastcall Hook_MessageParser(void* context, void* message, unsigned char type)
{
    g_MessageParserLastObject = reinterpret_cast<uint64_t>(message);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageParserCalls));
    return g_OriginalMessageParser ? g_OriginalMessageParser(context, message, type) : 0;
}

static void InstallMessageParserHook()
{
    if (InterlockedCompareExchange(&g_MessageParserHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x357E790);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MessageParser),
                      reinterpret_cast<void**>(&g_OriginalMessageParser)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalMessageParser = nullptr;
        InterlockedExchange(&g_MessageParserHookState, 0);
    }
}

static int64_t __fastcall Hook_PbTextParser(int64_t a1, int64_t a2)
{
    g_MessageParserLastObject = static_cast<uint64_t>(a2);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageParserCalls));
    return g_OriginalPbTextParser ? g_OriginalPbTextParser(a1, a2) : 0;
}

static int64_t __fastcall Hook_PbVideoParser(int64_t a1, int64_t a2)
{
    g_MessageParserLastObject = static_cast<uint64_t>(a2);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageParserCalls));
    return g_OriginalPbVideoParser ? g_OriginalPbVideoParser(a1, a2) : 0;
}

static __m128i* __fastcall Hook_MsgUserParser(__m128i* a1, int64_t* a2)
{
    g_MessageParserLastObject = reinterpret_cast<uint64_t>(a2);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageParserCalls));
    return g_OriginalMsgUserParser ? g_OriginalMsgUserParser(a1, a2) : a1;
}

static void InstallPbMessageParserHooks()
{
    if (InterlockedCompareExchange(&g_PbParserHookState, 1, 0) != 0)
        return;
    auto text = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x231AB40);
    auto video = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x231B6C0);
    auto msgUser = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x3C0CB50);
    bool ok = MH_CreateHook(text, reinterpret_cast<void*>(&Hook_PbTextParser),
                            reinterpret_cast<void**>(&g_OriginalPbTextParser)) == MH_OK &&
              MH_EnableHook(text) == MH_OK;
    ok = (MH_CreateHook(video, reinterpret_cast<void*>(&Hook_PbVideoParser),
                        reinterpret_cast<void**>(&g_OriginalPbVideoParser)) == MH_OK &&
          MH_EnableHook(video) == MH_OK) && ok;
    ok = (MH_CreateHook(msgUser, reinterpret_cast<void*>(&Hook_MsgUserParser),
                        reinterpret_cast<void**>(&g_OriginalMsgUserParser)) == MH_OK &&
          MH_EnableHook(msgUser) == MH_OK) && ok;
    if (!ok)
        InterlockedExchange(&g_PbParserHookState, 0);
}

static int64_t __fastcall Hook_DbAddMessage(int64_t a1, int64_t a2, int64_t a3, char a4)
{
    g_MessageParserLastObject = static_cast<uint64_t>(a2);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageReceiveCalls));
    return g_OriginalDbAddMessage ? g_OriginalDbAddMessage(a1, a2, a3, a4) : 0;
}

static void InstallDbAddMessageHook()
{
    if (InterlockedCompareExchange(&g_DbAddMessageHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x1452050);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_DbAddMessage),
                      reinterpret_cast<void**>(&g_OriginalDbAddMessage)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalDbAddMessage = nullptr;
        InterlockedExchange(&g_DbAddMessageHookState, 0);
    }
}

static int64_t __fastcall Hook_SyncDispatcher(int64_t a1)
{
    g_MessageParserLastObject = static_cast<uint64_t>(a1);
    __try {
        g_SyncContextObject = *reinterpret_cast<uint64_t*>(a1 + 0x20);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_SyncContextObject = 0;
    }
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageReceiveCalls));
    return g_OriginalSyncDispatcher ? g_OriginalSyncDispatcher(a1) : 0;
}

static void InstallSyncDispatcherHook()
{
    if (InterlockedCompareExchange(&g_SyncDispatcherHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x4D93DB0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_SyncDispatcher),
                      reinterpret_cast<void**>(&g_OriginalSyncDispatcher)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalSyncDispatcher = nullptr;
        InterlockedExchange(&g_SyncDispatcherHookState, 0);
    }
}

static int64_t ObserveFieldLookup(FnFieldLookup original, int64_t container, int64_t output, int64_t key)
{
    g_FieldLookupLastKey = static_cast<uint64_t>(key);
    g_FieldLookupLastKeyText[0] = 0;
    __try {
        const char* p = reinterpret_cast<const char*>(key);
        if (p) {
            size_t n = 0;
            while (n + 1 < sizeof(g_FieldLookupLastKeyText) && p[n]) ++n;
            memcpy(g_FieldLookupLastKeyText, p, n);
            g_FieldLookupLastKeyText[n] = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (strcmp(g_FieldLookupLastKeyText, "fromusername") == 0) InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_FieldFromCalls));
    else if (strcmp(g_FieldLookupLastKeyText, "content") == 0) InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_FieldContentCalls));
    else if (strcmp(g_FieldLookupLastKeyText, "msg") == 0) InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_FieldMsgCalls));
    else if (strcmp(g_FieldLookupLastKeyText, "msg_wording") == 0) InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_FieldWordingCalls));
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_FieldLookupCalls));
    const int64_t result = original ? original(container, output, key) : 0;
    RecordFieldLookupTrace(container, output, key, result, g_FieldLookupLastKeyText);
    if (strcmp(g_FieldLookupLastKeyText, "msg") == 0)
        DumpHookOutput(output, g_FieldMsgOutputHex, sizeof(g_FieldMsgOutputHex),
                       g_FieldMsgNodeHex, sizeof(g_FieldMsgNodeHex),
                       g_FieldMsgValueHex, sizeof(g_FieldMsgValueHex));
    else if (strcmp(g_FieldLookupLastKeyText, "msg_wording") == 0)
        DumpHookOutput(output, g_FieldWordingOutputHex, sizeof(g_FieldWordingOutputHex),
                       g_FieldWordingNodeHex, sizeof(g_FieldWordingNodeHex),
                       g_FieldWordingValueHex, sizeof(g_FieldWordingValueHex));
    if (strcmp(g_FieldLookupLastKeyText, "fromusername") == 0) CopyHookOutput(output, g_FieldFromText, sizeof(g_FieldFromText));
    else if (strcmp(g_FieldLookupLastKeyText, "content") == 0) CopyHookOutput(output, g_FieldContentText, sizeof(g_FieldContentText));
    else if (strcmp(g_FieldLookupLastKeyText, "msg") == 0) CopyHookOutput(output, g_FieldMsgText, sizeof(g_FieldMsgText));
    else if (strcmp(g_FieldLookupLastKeyText, "msg_wording") == 0) CopyHookOutput(output, g_FieldWordingText, sizeof(g_FieldWordingText));
    return result;
}

static int64_t __fastcall Hook_FieldLookup(int64_t container, int64_t output, int64_t key)
{
    return ObserveFieldLookup(g_OriginalFieldLookup, container, output, key);
}

static int64_t __fastcall Hook_FieldLookupByNode(int64_t container, int64_t output, int64_t key)
{
    return ObserveFieldLookup(g_OriginalFieldLookupByNode, container, output, key);
}

static void InstallFieldLookupHook()
{
    if (InterlockedCompareExchange(&g_FieldLookupHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x5AB2D0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_FieldLookup),
                      reinterpret_cast<void**>(&g_OriginalFieldLookup)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalFieldLookup = nullptr;
        InterlockedExchange(&g_FieldLookupHookState, 0);
    }
    void* targetByNode = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x5AB340);
    if (MH_CreateHook(targetByNode, reinterpret_cast<void*>(&Hook_FieldLookupByNode),
                      reinterpret_cast<void**>(&g_OriginalFieldLookupByNode)) == MH_OK)
    {
        MH_EnableHook(targetByNode);
    }
}

static int64_t __fastcall Hook_MsgReplaceHandler(int64_t context, int64_t sync)
{
    g_MsgReplaceHandlerContext = static_cast<uint64_t>(context);
    g_MsgReplaceHandlerSync = static_cast<uint64_t>(sync);
    RecordMessageBranchTrace("sub_18174E550", reinterpret_cast<uint64_t>(g_hWeixinDll) + 0x174E550,
                             static_cast<uint64_t>(context), static_cast<uint64_t>(sync), 0);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MsgReplaceHandlerCalls));
    return g_OriginalMsgReplaceHandler ? g_OriginalMsgReplaceHandler(context, sync) : 0;
}

static void InstallMsgReplaceHandlerHook()
{
    if (InterlockedCompareExchange(&g_MsgReplaceHandlerHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x174E550);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MsgReplaceHandler),
                      reinterpret_cast<void**>(&g_OriginalMsgReplaceHandler)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalMsgReplaceHandler = nullptr;
        InterlockedExchange(&g_MsgReplaceHandlerHookState, 0);
    }
}

static int64_t __fastcall Hook_PlainTextMsgHandler(int64_t context, int64_t object)
{
    g_PlainTextMsgHandlerContext = static_cast<uint64_t>(context);
    g_PlainTextMsgHandlerObject = static_cast<uint64_t>(object);
    RecordMessageBranchTrace("sub_183588820", reinterpret_cast<uint64_t>(g_hWeixinDll) + 0x3588820,
                             static_cast<uint64_t>(context), static_cast<uint64_t>(object), 0);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_PlainTextMsgHandlerCalls));
    return g_OriginalPlainTextMsgHandler ? g_OriginalPlainTextMsgHandler(context, object) : 0;
}

static void InstallPlainTextMsgHandlerHook()
{
    if (InterlockedCompareExchange(&g_PlainTextMsgHandlerHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x3588820);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_PlainTextMsgHandler),
                      reinterpret_cast<void**>(&g_OriginalPlainTextMsgHandler)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalPlainTextMsgHandler = nullptr;
        InterlockedExchange(&g_PlainTextMsgHandlerHookState, 0);
    }
}

static int64_t __fastcall Hook_MessageStructCopy(int64_t target, int64_t source)
{
    const int64_t result = g_OriginalMessageStructCopy
        ? g_OriginalMessageStructCopy(target, source) : target;
    g_MessageStructSource = static_cast<uint64_t>(source);
    g_MessageStructTarget = static_cast<uint64_t>(target);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageStructCopyCalls));

    // Message row model candidates observed in IDA:
    // compact model: strTalker +0x08, strContent +0x40.
    // extended model copied by sub_185BB0920: strings at +0x188 and +0x1A8.
    if (!CopyNativeStringAt(target, 0x08, g_MessageStructTalker, sizeof(g_MessageStructTalker)))
        CopyNativeStringAt(source, 0x08, g_MessageStructTalker, sizeof(g_MessageStructTalker));
    if (!CopyNativeStringAt(target, 0x40, g_MessageStructContent, sizeof(g_MessageStructContent)))
        CopyNativeStringAt(source, 0x40, g_MessageStructContent, sizeof(g_MessageStructContent));
    if (!CopyNativeStringAt(target, 0x188, g_MessageStructExtra1, sizeof(g_MessageStructExtra1)))
        CopyNativeStringAt(source, 0x188, g_MessageStructExtra1, sizeof(g_MessageStructExtra1));
    if (!CopyNativeStringAt(target, 0x1A8, g_MessageStructExtra2, sizeof(g_MessageStructExtra2)))
        CopyNativeStringAt(source, 0x1A8, g_MessageStructExtra2, sizeof(g_MessageStructExtra2));
    return result;
}

static void InstallMessageStructCopyHook()
{
    if (InterlockedCompareExchange(&g_MessageStructCopyHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x5BB0920);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MessageStructCopy),
                      reinterpret_cast<void**>(&g_OriginalMessageStructCopy)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalMessageStructCopy = nullptr;
        InterlockedExchange(&g_MessageStructCopyHookState, 0);
    }
}

static void CopyNativeStringPointer(int64_t ptr, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return;
    dst[0] = 0;
    if (!ptr)
        return;
    __try {
        const auto* s = reinterpret_cast<const HookNativeString*>(ptr);
        if (s->length == 0 || s->length >= cap || s->length > 8192)
            return;
        const char* p = s->capacity >= 0x10 ? s->heap_buf : s->inline_buf;
        if (!p)
            return;
        memcpy(dst, p, static_cast<size_t>(s->length));
        dst[s->length] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
    }
}

static void ObserveMessageDbStruct(const char* name, int64_t a1, int64_t a2)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageStructCopyCalls));
    g_MessageStructSource = static_cast<uint64_t>(a1);
    g_MessageStructTarget = static_cast<uint64_t>(a2);
    RecordMessageBranchTrace(name, 0, static_cast<uint64_t>(a1), static_cast<uint64_t>(a2), 0);
    __try {
        CopyNativeStringPointer(*reinterpret_cast<int64_t*>(a1 + 8), g_MessageStructTalker, sizeof(g_MessageStructTalker));
        CopyNativeStringPointer(*reinterpret_cast<int64_t*>(a1 + 16), g_MessageStructContent, sizeof(g_MessageStructContent));
        CopyNativeStringPointer(*reinterpret_cast<int64_t*>(a1 + 24), g_MessageStructExtra1, sizeof(g_MessageStructExtra1));
        CopyNativeStringPointer(*reinterpret_cast<int64_t*>(a1 + 32), g_MessageStructExtra2, sizeof(g_MessageStructExtra2));
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

#define DEFINE_MSG_DB_STRUCT1(symbol, rva) \
    static FnMsgDbStruct1 g_OriginalMsgDb_##symbol = nullptr; \
    static int64_t __fastcall HookMsgDb_##symbol(int64_t a1) { \
        ObserveMessageDbStruct(#symbol, a1, 0); \
        return g_OriginalMsgDb_##symbol ? g_OriginalMsgDb_##symbol(a1) : 0; \
    }

#define DEFINE_MSG_DB_STRUCT2(symbol, rva) \
    static FnMsgDbStruct2 g_OriginalMsgDb_##symbol = nullptr; \
    static int64_t __fastcall HookMsgDb_##symbol(int64_t a1, int64_t a2) { \
        ObserveMessageDbStruct(#symbol, a1, a2); \
        return g_OriginalMsgDb_##symbol ? g_OriginalMsgDb_##symbol(a1, a2) : 0; \
    }

DEFINE_MSG_DB_STRUCT2(sub_185BB12C0, 0x5BB12C0)
DEFINE_MSG_DB_STRUCT1(sub_185BB4670, 0x5BB4670)
DEFINE_MSG_DB_STRUCT1(sub_185BB54F0, 0x5BB54F0)
DEFINE_MSG_DB_STRUCT2(sub_185BB74D0, 0x5BB74D0)
DEFINE_MSG_DB_STRUCT1(sub_185BD2600, 0x5BD2600)
DEFINE_MSG_DB_STRUCT1(sub_185BD5610, 0x5BD5610)
DEFINE_MSG_DB_STRUCT2(sub_185BD6560, 0x5BD6560)
DEFINE_MSG_DB_STRUCT2(sub_185BD7170, 0x5BD7170)
DEFINE_MSG_DB_STRUCT2(sub_185BD7EC0, 0x5BD7EC0)
DEFINE_MSG_DB_STRUCT2(sub_185BD9120, 0x5BD9120)

static void TryInstallMsgDbStructHook(void* target, void* hook, void** original)
{
    if (target && MH_CreateHook(target, hook, original) == MH_OK)
        MH_EnableHook(target);
}

static void InstallMessageDbStructHooks()
{
    if (InterlockedCompareExchange(&g_MessageDbStructHookState, 1, 0) != 0)
        return;
#define INSTALL_MSG_DB(symbol, rva) \
    TryInstallMsgDbStructHook(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + (rva)), \
                              reinterpret_cast<void*>(&HookMsgDb_##symbol), \
                              reinterpret_cast<void**>(&g_OriginalMsgDb_##symbol))
    INSTALL_MSG_DB(sub_185BB12C0, 0x5BB12C0);
    INSTALL_MSG_DB(sub_185BB4670, 0x5BB4670);
    INSTALL_MSG_DB(sub_185BB54F0, 0x5BB54F0);
    INSTALL_MSG_DB(sub_185BB74D0, 0x5BB74D0);
    INSTALL_MSG_DB(sub_185BD2600, 0x5BD2600);
    INSTALL_MSG_DB(sub_185BD5610, 0x5BD5610);
    INSTALL_MSG_DB(sub_185BD6560, 0x5BD6560);
    INSTALL_MSG_DB(sub_185BD7170, 0x5BD7170);
    INSTALL_MSG_DB(sub_185BD7EC0, 0x5BD7EC0);
    INSTALL_MSG_DB(sub_185BD9120, 0x5BD9120);
#undef INSTALL_MSG_DB
}

static int64_t __fastcall Hook_SysMsgParser(int64_t object, int64_t node, int64_t flag)
{
    const int64_t result = g_OriginalSysMsgParser
        ? g_OriginalSysMsgParser(object, node, flag) : 0;
    g_MessageStructSource = static_cast<uint64_t>(node);
    g_MessageStructTarget = static_cast<uint64_t>(object);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SysMsgParserCalls));
    RecordMessageBranchTrace("sub_1822D07C0", reinterpret_cast<uint64_t>(g_hWeixinDll) + 0x22D07C0,
                             static_cast<uint64_t>(object), static_cast<uint64_t>(node),
                             static_cast<uint64_t>(flag));

    CopyNativeStringAt(object, 0x1A0, g_MessageStructTalker, sizeof(g_MessageStructTalker));   // sysmsg type
    CopyNativeStringAt(object, 0x1D0, g_MessageStructContent, sizeof(g_MessageStructContent)); // content/replacemsg
    CopyNativeStringAt(object, 0x1F0, g_MessageStructExtra1, sizeof(g_MessageStructExtra1));    // session
    CopyNativeStringAt(object, 0x350, g_MessageStructExtra2, sizeof(g_MessageStructExtra2));    // replacemsg variant
    return result;
}

static void InstallSysMsgParserHook()
{
    if (InterlockedCompareExchange(&g_SysMsgParserHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x22D07C0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_SysMsgParser),
                      reinterpret_cast<void**>(&g_OriginalSysMsgParser)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalSysMsgParser = nullptr;
        InterlockedExchange(&g_SysMsgParserHookState, 0);
    }
}

static int64_t __fastcall Hook_HistoryAddMsgQuery(int64_t a1, int64_t a2, int64_t a3, int64_t a4)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_HistoryAddMsgCalls));
    RecordMessageBranchTrace("sub_182D9DE00", reinterpret_cast<uint64_t>(g_hWeixinDll) + 0x2D9DE00,
                             static_cast<uint64_t>(a1), static_cast<uint64_t>(a2),
                             static_cast<uint64_t>(a3));
    return g_OriginalHistoryAddMsgQuery ? g_OriginalHistoryAddMsgQuery(a1, a2, a3, a4) : 0;
}

static void InstallHistoryAddMsgQueryHook()
{
    if (InterlockedCompareExchange(&g_HistoryAddMsgQueryHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2D9DE00);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_HistoryAddMsgQuery),
                      reinterpret_cast<void**>(&g_OriginalHistoryAddMsgQuery)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalHistoryAddMsgQuery = nullptr;
        InterlockedExchange(&g_HistoryAddMsgQueryHookState, 0);
    }
}

static int64_t __fastcall Hook_HistoryAddMsgCommit(int64_t a1)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_HistoryAddMsgCommitCalls));
    RecordMessageBranchTrace("sub_182DA0E70", reinterpret_cast<uint64_t>(g_hWeixinDll) + 0x2DA0E70,
                             static_cast<uint64_t>(a1), 0, 0);
    return g_OriginalHistoryAddMsgCommit ? g_OriginalHistoryAddMsgCommit(a1) : 0;
}

static void InstallHistoryAddMsgCommitHook()
{
    if (InterlockedCompareExchange(&g_HistoryAddMsgCommitHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2DA0E70);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_HistoryAddMsgCommit),
                      reinterpret_cast<void**>(&g_OriginalHistoryAddMsgCommit)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalHistoryAddMsgCommit = nullptr;
        InterlockedExchange(&g_HistoryAddMsgCommitHookState, 0);
    }
}

static int Hook_SqlitePrepare(sqlite3* db, const char* sql, int nByte,
                              sqlite3_stmt** stmt, const char** tail)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqlitePrepareCalls));
    CaptureSqliteDbHandle(db);
    CaptureSqlText(sql, nByte, g_SqliteLastSql, g_SqliteInterestingSql);
    if (!g_ContactQueryInProgress)
        CaptureContactDbHandle(db, sql, nByte);
    const int rc = g_OriginalSqlitePrepare
        ? g_OriginalSqlitePrepare(db, sql, nByte, stmt, tail)
        : SQLITE_ERROR;
    if (rc == SQLITE_OK && stmt)
        RememberSqliteStatement(stmt, sql, nByte);
    TryProcessPendingContactQuery(db);
    return rc;
}

static int Hook_SqlitePrepareV2(sqlite3* db, const char* sql, int nByte,
                                sqlite3_stmt** stmt, const char** tail)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqlitePrepareV2Calls));
    CaptureSqliteDbHandle(db);
    CaptureSqlText(sql, nByte, g_SqliteLastSql, g_SqliteInterestingSql);
    if (!g_ContactQueryInProgress)
        CaptureContactDbHandle(db, sql, nByte);
    const int rc = g_OriginalSqlitePrepareV2
        ? g_OriginalSqlitePrepareV2(db, sql, nByte, stmt, tail)
        : SQLITE_ERROR;
    if (rc == SQLITE_OK && stmt)
        RememberSqliteStatement(stmt, sql, nByte);
    TryProcessPendingContactQuery(db);
    return rc;
}

static int Hook_SqliteBindText(sqlite3_stmt* stmt, int index, const char* text,
                               int nByte, void(*destructor)(void*))
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqliteBindTextCalls));
    CaptureSqliteDbHandleFromStmt(stmt);
    CaptureSqlText(text, nByte, g_SqliteLastBindText, g_SqliteInterestingBindText);
    RecordSqliteBindTrace("bind_text", stmt, index, text, nByte);
    const int rc = g_OriginalSqliteBindText
        ? g_OriginalSqliteBindText(stmt, index, text, nByte, destructor)
        : SQLITE_ERROR;
    // Contact/profile pages often bind their lookup key and payload before
    // stepping the statement.  Give a queued read a chance on this same
    // SQLite worker thread instead of waiting for a later prepare/step call.
    if (g_SqliteLastDbHandle)
        TryProcessPendingContactQuery(reinterpret_cast<sqlite3*>(
            static_cast<uintptr_t>(g_SqliteLastDbHandle)));
    return rc;
}

static int Hook_SqliteBindText16(sqlite3_stmt* stmt, int index, const void* text,
                                 int nByte, void(*destructor)(void*))
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqliteBindText16Calls));
    CaptureSqliteDbHandleFromStmt(stmt);
    CaptureSqlText16(text, nByte, g_SqliteLastBindText, g_SqliteInterestingBindText);
    RecordSqliteBindTrace16("bind_text16", stmt, index, text, nByte);
    const int rc = g_OriginalSqliteBindText16
        ? g_OriginalSqliteBindText16(stmt, index, text, nByte, destructor)
        : SQLITE_ERROR;
    if (g_SqliteLastDbHandle)
        TryProcessPendingContactQuery(reinterpret_cast<sqlite3*>(
            static_cast<uintptr_t>(g_SqliteLastDbHandle)));
    return rc;
}

static int Hook_SqliteStep(sqlite3_stmt* stmt)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqliteStepCalls));
    CaptureSqliteDbHandleFromStmt(stmt);
    const int rc = g_OriginalSqliteStep ? g_OriginalSqliteStep(stmt) : SQLITE_ERROR;
    const std::string sql = LookupSqliteStatement(stmt);
    if (rc == SQLITE_ROW)
        CaptureContactRowFromStatement(stmt, sql);
    else if (rc == SQLITE_DONE || rc == SQLITE_ERROR || rc == SQLITE_MISUSE)
        ForgetSqliteStatement(stmt);
    if (g_SqliteLastDbHandle)
        TryProcessPendingContactQuery(reinterpret_cast<sqlite3*>(
            static_cast<uintptr_t>(g_SqliteLastDbHandle)));
    return rc;
}

template <typename Fn>
static bool TryInstallSqliteApiHook(Fn target, void* hook, Fn* original, volatile uint64_t* targetStore)
{
    if (targetStore)
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(targetStore),
                              reinterpret_cast<LONG64>(target));
    // Never patch a data pointer.  The old offset table contained readable
    // data that happened to look like a function pointer, which corrupted
    // unrelated Weixin code and resulted in an immediate crash.
    if (!target || !IsExecutablePointer(reinterpret_cast<void*>(target)))
        return false;
    if (MH_CreateHook(reinterpret_cast<void*>(target), hook,
                      reinterpret_cast<void**>(original)) != MH_OK)
        return false;
    return MH_EnableHook(reinterpret_cast<void*>(target)) == MH_OK;
}

static void InstallSqliteApiHooks()
{
    if (InterlockedCompareExchange(&g_SqliteApiHookState, 1, 0) != 0)
        return;
    if (!g_hWeixinDll) {
        InterlockedExchange(&g_SqliteApiHookState, 0);
        return;
    }

    bool ok = false;
    __try {
        auto* api = reinterpret_cast<sqlite3_api_routines*>(
            reinterpret_cast<uintptr_t>(g_hWeixinDll) + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteApiTable),
                              reinterpret_cast<LONG64>(api));
        if (!IsReadablePointer(api)) {
            InterlockedExchange(&g_SqliteApiHookState, 0);
            return;
        }

        ok = TryInstallSqliteApiHook(api->prepare, reinterpret_cast<void*>(&Hook_SqlitePrepare),
                                     &g_OriginalSqlitePrepare, &g_SqlitePrepareTarget) || ok;
        ok = TryInstallSqliteApiHook(api->prepare_v2, reinterpret_cast<void*>(&Hook_SqlitePrepareV2),
                                     &g_OriginalSqlitePrepareV2, &g_SqlitePrepareV2Target) || ok;
        ok = TryInstallSqliteApiHook(api->bind_text, reinterpret_cast<void*>(&Hook_SqliteBindText),
                                     &g_OriginalSqliteBindText, &g_SqliteBindTextTarget) || ok;
        ok = TryInstallSqliteApiHook(api->bind_text16, reinterpret_cast<void*>(&Hook_SqliteBindText16),
                                     &g_OriginalSqliteBindText16, &g_SqliteBindText16Target) || ok;
        ok = TryInstallSqliteApiHook(api->step, reinterpret_cast<void*>(&Hook_SqliteStep),
                                     &g_OriginalSqliteStep, &g_SqliteStepTarget) || ok;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }

    if (ok) {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteHookInstalled), 1);
    } else {
        g_OriginalSqlitePrepare = nullptr;
        g_OriginalSqlitePrepareV2 = nullptr;
        g_OriginalSqliteBindText = nullptr;
        g_OriginalSqliteBindText16 = nullptr;
        g_OriginalSqliteStep = nullptr;
        InterlockedExchange(&g_SqliteApiHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_SqliteHookInstalled), 0);
    }
}

static int64_t __fastcall Hook_MsgSourceParser(int64_t out_object, int64_t node)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MsgSourceParserCalls));
    return g_OriginalMsgSourceParser ? g_OriginalMsgSourceParser(out_object, node) : 0;
}

static unsigned char __fastcall Hook_MsgWordingParser(int64_t object, int64_t node)
{
    const unsigned char result = g_OriginalMsgWordingParser
        ? g_OriginalMsgWordingParser(object, node) : 0;
    g_MsgWordingObject = static_cast<uint64_t>(object);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MsgWordingParserCalls));
    __try {
        auto* s = reinterpret_cast<HookNativeString*>(object + 8);
        if (s->length > 0 && s->length < sizeof(g_FieldWordingText)) {
            const char* p = s->capacity >= 0x10 ? s->heap_buf : s->inline_buf;
            if (p) {
                memcpy(g_FieldWordingText, p, static_cast<size_t>(s->length));
                g_FieldWordingText[s->length] = 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return result;
}

static void InstallMsgSourceParserHooks()
{
    if (InterlockedCompareExchange(&g_MsgSourceParserHookState, 1, 0) == 0) {
        void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x2314C00);
        if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MsgSourceParser),
                          reinterpret_cast<void**>(&g_OriginalMsgSourceParser)) != MH_OK ||
            MH_EnableHook(target) != MH_OK)
        {
            g_OriginalMsgSourceParser = nullptr;
            InterlockedExchange(&g_MsgSourceParserHookState, 0);
        }
    }
    if (InterlockedCompareExchange(&g_MsgWordingParserHookState, 1, 0) == 0) {
        void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x23160E0);
        if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MsgWordingParser),
                          reinterpret_cast<void**>(&g_OriginalMsgWordingParser)) != MH_OK ||
            MH_EnableHook(target) != MH_OK)
        {
            g_OriginalMsgWordingParser = nullptr;
            InterlockedExchange(&g_MsgWordingParserHookState, 0);
        }
    }
}

struct NativeWxString {
    union { char inline_buf[16]; char* heap_buf; };
    uint64_t length;
    uint64_t capacity;
};

static size_t CopyNativeString(const NativeWxString* value, char* out, size_t out_size)
{
    if (!value || !out || out_size == 0 || value->length == 0 || value->length >= out_size)
        return 0;
    const char* p = value->capacity >= 0x10 ? value->heap_buf : value->inline_buf;
    if (!p) return 0;
    __try {
        memcpy(out, p, static_cast<size_t>(value->length));
        out[value->length] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return static_cast<size_t>(value->length);
}

static bool InvokeMessageGetters(void* message, NativeWxString* s1, NativeWxString* s2)
{
    if (!message || !s1 || !s2) return false;
    using Getter = void(__fastcall*)(void*, NativeWxString*);
    auto get1 = reinterpret_cast<Getter>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0xA1ECC0);
    auto get2 = reinterpret_cast<Getter>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0xA1EBB0);
    __try {
        get1(message, s1);
        get2(message, s2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static bool ReadMessageFields(void* message, std::string& field1, std::string& field2)
{
    NativeWxString s1{};
    NativeWxString s2{};
    if (!InvokeMessageGetters(message, &s1, &s2)) return false;
    char b1[4096]{};
    char b2[4096]{};
    const size_t n1 = CopyNativeString(&s1, b1, sizeof(b1));
    const size_t n2 = CopyNativeString(&s2, b2, sizeof(b2));
    if (n1) field1.assign(b1, n1);
    if (n2) field2.assign(b2, n2);
    return !field1.empty() || !field2.empty();
}

static void PostReceivedMessage(void* message, unsigned int type,
                                const std::string& field1, const std::string& field2)
{
    if (g_CallBack_Url.empty()) return;
    json item;
    item["cmdId"] = 5;
    item["msgtype"] = type;
    item["fromid"] = field1;
    item["toid"] = "";
    item["msg"] = field2;
    item["field1"] = field1;
    item["field2"] = field2;
    item["message_object"] = reinterpret_cast<uint64_t>(message);
    item["msgsvrid"] = 0;
    item["time"] = static_cast<uint64_t>(GetTickCount64());

    json payload;
    payload["ServerPort"] = g_StartPort;
    payload["msgnumber"] = 1;
    payload["sendorrecv"] = 2;
    payload["selfwxid"] = SelfInfo.wxid;
    payload["msglist"] = json::array({item});
    HttpPostJsonAsync(g_CallBack_Url, payload.dump());
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageCallbackPosts));
}

static char __fastcall Hook_MessageDispatch(void* manager, void* message, unsigned int type)
{
    TryQueueAutoReplyFromDispatchObject(reinterpret_cast<int64_t>(message));
    std::string field1;
    std::string field2;
    const bool captured = ReadMessageFields(message, field1, field2);
    const char result = g_OriginalMessageDispatch
        ? g_OriginalMessageDispatch(manager, message, type) : 0;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_MessageReceiveCalls));
    if (captured)
        PostReceivedMessage(message, type, field1, field2);
    return result;
}

static void InstallMessageReceiveHook()
{
    if (InterlockedCompareExchange(&g_MessageHookState, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x1749DC0);
    if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook_MessageDispatch),
                      reinterpret_cast<void**>(&g_OriginalMessageDispatch)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalMessageDispatch = nullptr;
        InterlockedExchange(&g_MessageHookState, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_MessageHookInstalled), 0);
    }
    else
    {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_MessageHookInstalled), 1);
    }
}

static void SetMirroredLoginState(uint64_t state)
{
    const uint64_t next = state ? 1 : 0;
    const uint64_t previous = static_cast<uint64_t>(InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&g_IsLogin),
        static_cast<LONG64>(next)));
    if (previous == next)
        return;

    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&g_LoginStateChanges));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_LoginStateLastChange),
                          static_cast<LONG64>(GetTickCount64()));
    if (!next) {
        // The profile object belongs to the logged-in session. Never retain
        // its address after logout, since it may be freed by Weixin.
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ProfileObject), 0);
    }
}

static __int64* __fastcall Hook_ProfileContainer830(__int64* object)
{
    __int64* result = g_OriginalContainer830 ? g_OriginalContainer830(object) : object;
    g_ProfileContainer830Object = reinterpret_cast<uint64_t>(result);
    if (result) {
        g_ProfileContainer830Root = static_cast<uint64_t>(result[0]);
        g_ProfileContainer830Second = static_cast<uint64_t>(result[1]);
    }
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ProfileContainer830Calls));
    return result;
}

static __int64* __fastcall Hook_ProfileContainerFC00(__int64* object)
{
    __int64* result = g_OriginalContainerFC00 ? g_OriginalContainerFC00(object) : object;
    g_ProfileContainerFC00Object = reinterpret_cast<uint64_t>(result);
    if (result) {
        g_ProfileContainerFC00Root = static_cast<uint64_t>(result[0]);
        g_ProfileContainerFC00Second = static_cast<uint64_t>(result[1]);
    }
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ProfileContainerFC00Calls));
    return result;
}

static void InstallProfileContainerHooks()
{
    if (InterlockedCompareExchange(&g_ProfileContainerHooksInstalled, 1, 0) != 0)
        return;
    void* target830 = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x212F830);
    void* targetFC00 = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x212FC00);
    if (MH_CreateHook(target830, reinterpret_cast<void*>(&Hook_ProfileContainer830),
                      reinterpret_cast<void**>(&g_OriginalContainer830)) != MH_OK ||
        MH_EnableHook(target830) != MH_OK ||
        MH_CreateHook(targetFC00, reinterpret_cast<void*>(&Hook_ProfileContainerFC00),
                      reinterpret_cast<void**>(&g_OriginalContainerFC00)) != MH_OK ||
        MH_EnableHook(targetFC00) != MH_OK)
    {
        InterlockedExchange(&g_ProfileContainerHooksInstalled, 0);
    }
}

static void CopyProfileDescriptorKey(void* descriptor, char* dst, size_t cap)
{
    if (!dst || cap == 0)
        return;
    dst[0] = 0;
    if (!descriptor)
        return;
    __try {
        auto** vtable = *reinterpret_cast<uintptr_t***>(descriptor);
        if (!vtable || !IsExecutablePointer(reinterpret_cast<const void*>(vtable[1])))
            return;
        using DescriptorKeyGetter = int64_t(__fastcall*)(void*);
        const int64_t keyPtr = reinterpret_cast<DescriptorKeyGetter>(vtable[1])(descriptor);
        if (!keyPtr || !IsReadablePointer(reinterpret_cast<const void*>(keyPtr)))
            return;
        const auto* text = reinterpret_cast<const unsigned char*>(keyPtr);
        size_t n = 0;
        while (n + 1 < cap) {
            const unsigned char c = text[n];
            if (c == 0)
                break;
            if (c < 0x20 || c > 0x7E) {
                dst[0] = 0;
                return;
            }
            dst[n++] = static_cast<char>(c);
        }
        dst[n] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        dst[0] = 0;
    }
}

static void* __fastcall Hook_ProfileFieldRead(void* object, void* output, void* descriptor)
{
    // Capture the descriptor while its temporary key string is alive.  The
    // original lookup may release that temporary before it returns.
    char descriptorKey[sizeof(g_ProfileLookupLastKey)]{};
    CopyProfileDescriptorKey(descriptor, descriptorKey, sizeof(descriptorKey));
    void* result = g_OriginalProfileFieldRead
        ? g_OriginalProfileFieldRead(object, output, descriptor)
        : nullptr;
    g_ProfileFieldObject = reinterpret_cast<uint64_t>(object);
    g_ProfileFieldDescriptor = reinterpret_cast<uint64_t>(descriptor);
    CopySafeText(descriptorKey, g_ProfileLookupLastKey,
                 sizeof(g_ProfileLookupLastKey));
    g_ProfileLookupLastValue[0] = 0;
    if (output) {
        __try {
            // Preserve a bounded, printable view of the first output bytes.
            // The profile getter owns this object; no internal method is called.
            const auto* bytes = reinterpret_cast<const unsigned char*>(output);
            size_t n = 0;
            for (size_t i = 0; i < 32 && n + 1 < sizeof(g_ProfileLookupLastValue); ++i) {
                const unsigned char c = bytes[i];
                if (c < 0x20 || c > 0x7E)
                    break;
                g_ProfileLookupLastValue[n++] = static_cast<char>(c);
            }
            g_ProfileLookupLastValue[n] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_ProfileLookupLastValue[0] = 0;
        }
    }
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ProfileLookupCalls));
    const uint64_t sequence = InterlockedIncrement64(
        reinterpret_cast<volatile LONG64*>(&g_ProfileTraceIndex));
    const size_t slot = static_cast<size_t>(sequence % kProfileTraceCapacity);
    ProfileFieldTrace trace{
        reinterpret_cast<uint64_t>(object),
        reinterpret_cast<uint64_t>(output),
        reinterpret_cast<uint64_t>(descriptor),
        reinterpret_cast<uint64_t>(result),
        sequence,
        reinterpret_cast<uint64_t>(_ReturnAddress()),
        {}
    };
    if (output) {
        __try {
            memcpy(trace.outputBytes, output, sizeof(trace.outputBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            memset(trace.outputBytes, 0, sizeof(trace.outputBytes));
        }
    }
    g_ProfileTraces[slot] = trace;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ProfileFieldCalls));
    return result;
}

static void InstallProfileFieldHook()
{
    if (InterlockedCompareExchange(&g_ProfileFieldHookInstalled, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x1B0270);
    if (MH_CreateHook(
            target,
            reinterpret_cast<void*>(&Hook_ProfileFieldRead),
            reinterpret_cast<void**>(&g_OriginalProfileFieldRead)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalProfileFieldRead = nullptr;
        InterlockedExchange(&g_ProfileFieldHookInstalled, 0);
    }
}

static void __fastcall Hook_ProfileGetter(void* manager, void** out_object)
{
    if (g_OriginalProfileGetter)
        g_OriginalProfileGetter(manager, out_object);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ProfileGetterCalls));
    if (out_object && *out_object) {
        g_ProfileObject = reinterpret_cast<uint64_t>(*out_object);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_ProfileGetterNullStreak), 0);
        if (!g_IsLogin)
            SetMirroredLoginState(1);
    } else {
        const uint64_t nullStreak = InterlockedIncrement64(
            reinterpret_cast<volatile LONG64*>(&g_ProfileGetterNullStreak));
        // A single null result can be a transient manager refresh. Require a
        // consecutive run before mirroring logout and clearing the session
        // object.
        if (g_IsLogin && nullStreak >= 8)
            SetMirroredLoginState(0);
    }
}

using FnManagerContainerGetter = void(__fastcall*)(void* manager, void** out_object);
static FnManagerContainerGetter g_OriginalManagerContainerGetter = nullptr;
static LONG g_ManagerContainerHookInstalled = 0;

static void __fastcall Hook_ManagerContainerGetter(void* manager, void** out_object)
{
    if (g_OriginalManagerContainerGetter)
        g_OriginalManagerContainerGetter(manager, out_object);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_ManagerContainerGetterCalls));
    g_ManagerContainerObject = (out_object && *out_object)
        ? reinterpret_cast<uint64_t>(*out_object) : 0;
}

static void InstallManagerContainerHook(void* manager)
{
    if (!manager || InterlockedCompareExchange(&g_ManagerContainerHookInstalled, 1, 0) != 0)
        return;
    void** vtable = *reinterpret_cast<void***>(manager);
    void* target = vtable ? vtable[16] : nullptr; // vtable + 0x80
    if (!target || MH_CreateHook(target, reinterpret_cast<void*>(&Hook_ManagerContainerGetter),
                                 reinterpret_cast<void**>(&g_OriginalManagerContainerGetter)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalManagerContainerGetter = nullptr;
        InterlockedExchange(&g_ManagerContainerHookInstalled, 0);
    }
}

static void* __fastcall Hook_ManagerGetter()
{
    void* manager = g_OriginalManagerGetter ? g_OriginalManagerGetter() : nullptr;
    if (manager && InterlockedCompareExchange(&g_ProfileHookInstalled, 1, 0) == 0)
    {
        void** vtable = *reinterpret_cast<void***>(manager);
        InstallManagerContainerHook(manager);
        void* target = vtable ? vtable[12] : nullptr; // vtable + 0x60
        if (!target || MH_CreateHook(
                target,
                reinterpret_cast<void*>(&Hook_ProfileGetter),
                reinterpret_cast<void**>(&g_OriginalProfileGetter)) != MH_OK ||
            MH_EnableHook(target) != MH_OK)
        {
            g_OriginalProfileGetter = nullptr;
            InterlockedExchange(&g_ProfileHookInstalled, 0);
        }
    }
    return manager;
}

static void InstallManagerGetterHook()
{
    if (InterlockedCompareExchange(&g_ManagerHookInstalled, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x410C0);
    if (MH_CreateHook(
            target,
            reinterpret_cast<void*>(&Hook_ManagerGetter),
            reinterpret_cast<void**>(&g_OriginalManagerGetter)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalManagerGetter = nullptr;
        InterlockedExchange(&g_ManagerHookInstalled, 0);
    }
}

static int64_t __fastcall Hook_LoginFinish(int64_t context, void* payload)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_LoginFinishCalls));
    g_LoginFinishContext = static_cast<uint64_t>(context);
    g_LoginFinishPayload = reinterpret_cast<uint64_t>(payload);
    int64_t result = g_OriginalLoginFinish ? g_OriginalLoginFinish(context, payload) : 0;
    // This callback was observed exactly once on the successful login path.
    // This callback returns zero on the observed successful-login path;
    // the non-null payload is the reliable success indicator for this build.
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_LoginStateSource), 1);
    SetMirroredLoginState(result != 0 || payload != nullptr);
    return result;
}

static unsigned char __fastcall Hook_LoginStateProbe(int64_t context)
{
    if (!g_OriginalLoginStateProbe)
        return 0;

    unsigned char result = g_OriginalLoginStateProbe(context);
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_LoginProbeCalls));
    InterlockedExchange(
        reinterpret_cast<volatile LONG*>(&g_LoginProbeLast),
        result ? 1L : 0L);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_LoginStateSource), 2);
    SetMirroredLoginState(result != 0);
    return result;
}

static void InstallLoginStateProbeHook()
{
    if (InterlockedCompareExchange(&g_LoginStateHookInstalled, 1, 0) != 0)
        return;

    // IDA imagebase 0x180000000, function RVA 0x36AB30.
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x36AB30);
    if (MH_CreateHook(
            target,
            reinterpret_cast<void*>(&Hook_LoginStateProbe),
            reinterpret_cast<void**>(&g_OriginalLoginStateProbe)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalLoginStateProbe = nullptr;
        InterlockedExchange(&g_LoginStateHookInstalled, 0);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_LoginProbeHookInstalled), 0);
    } else {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_LoginProbeHookInstalled), 1);
    }
}

static void InstallLoginFinishHook()
{
    if (InterlockedCompareExchange(&g_LoginFinishHookInstalled, 1, 0) != 0)
        return;
    void* target = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(g_hWeixinDll) + 0x70FB30);
    if (MH_CreateHook(
            target,
            reinterpret_cast<void*>(&Hook_LoginFinish),
            reinterpret_cast<void**>(&g_OriginalLoginFinish)) != MH_OK ||
        MH_EnableHook(target) != MH_OK)
    {
        g_OriginalLoginFinish = nullptr;
        InterlockedExchange(&g_LoginFinishHookInstalled, 0);
    }
}





void Evt_WeixinLoad()
{
    g_hWeixinDll = GetModuleHandleW(L"Weixin.dll");
    if (!g_hWeixinDll)
    {
        return;
    }

#ifdef _DEBUG
    char debugMsg[256];
    snprintf(debugMsg, sizeof(debugMsg),"[Evt_WeixinLoad] Weixin.dll: 0x%p\n",g_hWeixinDll);
    OutputDebugStringA(debugMsg);
#endif


    进程PID = GetCurrentProcessId();
    父进程PID = GetParentProcessId();

    //过低版本 4.1.8.67
    //Patch_Low_Version_m2();

    //get base DirPath
    //InitStandardPaths();
    
    //Patch_Revoke(); // disabled for 4.1.11.24


    // 创建并启动HTTP服务器
    if (!g_httpServer)
    {
        g_httpServer = new HttpServer();
        g_httpServer->Start("0.0.0.0", g_StartPort);
    }

    InstallLoginStateProbeHook();
    InstallLoginFinishHook();
    // Re-enable only profile observation for the current isolation pass.
    InstallManagerGetterHook();
    InstallProfileFieldHook();
    InstallProfileContainerHooks();
    // The older dispatch hook uses unverified getter offsets on a different
    // message object. Keep it disabled while the safe 0x78-byte observation
    // boundary is being validated in Hook_SyncBatchProcessor.
    InstallMessageParserHook();
    InstallPbMessageParserHooks();
    InstallDbAddMessageHook();
    InstallRawSyncMsgProcessorHook();
    InstallSyncBatchProcessorHook();
    // Read-only observation boundary for SendMsgRequestNew.  This does not
    // call the sender or enqueue a request; it only records native strings
    // when another code path invokes the copy/serialization helper.
    InstallSendMsgRequestObserverHook();
    InstallSendMsgElementObserverHook();
    // Read-only contact response parser observation.  This populates the
    // bounded contact cache from WeChat's own response objects, so /GetContact
    // does not need to wake or access an idle SQLite connection.
    InstallContactResponseParserHook();
    InstallContactStartupVectorHook();
    InstallContactListBuildHook();
    InstallContactSessionInfoHook();
    InstallContactPipelineHook();
    InstallContactRecordParserHook();
    InstallContactSyncSourceHook();
    InstallContactSyncCallbackHook();
    // ABI was rechecked against sub_1826C6C10: the second argument is the
    // caller-owned vector pointer, not an integer mode.  The corrected hook
    // observes the 1080-byte contact-record list without calling WeChat code.
    InstallContactManagerListHook();
    InstallContactListSourceHook();
    InstallContactResponseBatchHook();
    InstallContactResponseSplitHook();
    InstallContactGeneralQueryHook();
    InstallContactDetailHook();
    InstallContactDetailRecordHook();
    InstallSqliteApiHooks();
    // Message/database hooks remain disabled until the login-time memory
    // regression is isolated.
    // SQLite API patching is disabled for now.  Calling the 4.1.10.27
    // internal routines from our injected callbacks caused unbounded memory
    // growth during login; contact access must be implemented through a
    // queued operation on WeChat's own database thread instead.

#ifdef _DEBUG
    //xLog 日志
    Hook_Call(WeixinDll_Offset(0x108678), 5, hook::MyCallHandler_xLog);
#endif
    

    
    //取回调URL
    GetWxRecvUrl();         
}
