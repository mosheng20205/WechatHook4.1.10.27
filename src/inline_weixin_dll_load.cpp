#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <cstdio>
#include <string>
#include <Windows.h>
#include <winternl.h>
#include <cstring>
#include <sstream>

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
#include "../xdb/sqlite3.h"



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
    __try {
        if (ProbeRawSyncVectorCandidate("sub_182C28700_vec_rcx", reinterpret_cast<int64_t>(items)) == 0) {
            ProbeRawSyncVectorCandidate("sub_182C28700_vec_rdx", reinterpret_cast<int64_t>(context));
        }
        if (items) {
            ProbeRawSyncVectorCandidate("sub_182C28700_vec_rcx_deref0", items[0]);
            ProbeRawSyncVectorCandidate("sub_182C28700_vec_rcx_deref1", items[1]);
        }
        if (context) {
            ProbeRawSyncVectorCandidate("sub_182C28700_vec_rdx_deref0", static_cast<int64_t>(context[0]));
            ProbeRawSyncVectorCandidate("sub_182C28700_vec_rdx_deref1", static_cast<int64_t>(context[1]));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
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
    CaptureSqlText(sql, nByte, g_SqliteLastSql, g_SqliteInterestingSql);
    return g_OriginalSqlitePrepare
        ? g_OriginalSqlitePrepare(db, sql, nByte, stmt, tail)
        : SQLITE_ERROR;
}

static int Hook_SqlitePrepareV2(sqlite3* db, const char* sql, int nByte,
                                sqlite3_stmt** stmt, const char** tail)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqlitePrepareV2Calls));
    CaptureSqlText(sql, nByte, g_SqliteLastSql, g_SqliteInterestingSql);
    return g_OriginalSqlitePrepareV2
        ? g_OriginalSqlitePrepareV2(db, sql, nByte, stmt, tail)
        : SQLITE_ERROR;
}

static int Hook_SqliteBindText(sqlite3_stmt* stmt, int index, const char* text,
                               int nByte, void(*destructor)(void*))
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqliteBindTextCalls));
    CaptureSqlText(text, nByte, g_SqliteLastBindText, g_SqliteInterestingBindText);
    RecordSqliteBindTrace("bind_text", stmt, index, text, nByte);
    return g_OriginalSqliteBindText
        ? g_OriginalSqliteBindText(stmt, index, text, nByte, destructor)
        : SQLITE_ERROR;
}

static int Hook_SqliteBindText16(sqlite3_stmt* stmt, int index, const void* text,
                                 int nByte, void(*destructor)(void*))
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqliteBindText16Calls));
    CaptureSqlText16(text, nByte, g_SqliteLastBindText, g_SqliteInterestingBindText);
    RecordSqliteBindTrace16("bind_text16", stmt, index, text, nByte);
    return g_OriginalSqliteBindText16
        ? g_OriginalSqliteBindText16(stmt, index, text, nByte, destructor)
        : SQLITE_ERROR;
}

static int Hook_SqliteStep(sqlite3_stmt* stmt)
{
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_SqliteStepCalls));
    return g_OriginalSqliteStep ? g_OriginalSqliteStep(stmt) : SQLITE_ERROR;
}

template <typename Fn>
static bool TryInstallSqliteApiHook(Fn target, void* hook, Fn* original, volatile uint64_t* targetStore)
{
    if (targetStore)
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(targetStore),
                              reinterpret_cast<LONG64>(target));
    if (!target || !IsReadablePointer(reinterpret_cast<void*>(target)))
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

static void* __fastcall Hook_ProfileFieldRead(void* object, void* output, void* descriptor)
{
    void* result = g_OriginalProfileFieldRead
        ? g_OriginalProfileFieldRead(object, output, descriptor)
        : nullptr;
    g_ProfileFieldObject = reinterpret_cast<uint64_t>(object);
    g_ProfileFieldDescriptor = reinterpret_cast<uint64_t>(descriptor);
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
    if (out_object && *out_object)
        g_ProfileObject = reinterpret_cast<uint64_t>(*out_object);
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
    InstallManagerGetterHook();
    InstallProfileFieldHook();
    InstallProfileContainerHooks();
    InstallMessageReceiveHook();
    InstallMessageParserHook();
    InstallPbMessageParserHooks();
    InstallDbAddMessageHook();
    InstallRawSyncMsgProcessorHook();
    InstallSyncDispatcherHook();
    InstallFieldLookupHook();
    InstallMsgReplaceHandlerHook();
    InstallPlainTextMsgHandlerHook();
    InstallMsgSourceParserHooks();
    InstallMessageBranchTraceHooks();
    InstallMessageStructCopyHook();
    InstallMessageDbStructHooks();
    InstallSysMsgParserHook();
    InstallHistoryAddMsgQueryHook();
    InstallHistoryAddMsgCommitHook();
    InstallSqliteApiHooks();

#ifdef _DEBUG
    //xLog 日志
    Hook_Call(WeixinDll_Offset(0x108678), 5, hook::MyCallHandler_xLog);
#endif
    

    
    //取回调URL
    GetWxRecvUrl();         
}
