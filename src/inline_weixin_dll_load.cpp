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
    InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_IsLogin), 1L);
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
    InterlockedExchange(
        reinterpret_cast<volatile LONG*>(&g_IsLogin),
        result ? 1L : 0L);
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

#ifdef _DEBUG
    //xLog 日志
    Hook_Call(WeixinDll_Offset(0x108678), 5, hook::MyCallHandler_xLog);
#endif
    

    
    //取回调URL
    GetWxRecvUrl();         
}
