#include "global.h"

HMODULE g_hModule = NULL;
uint64_t g_MyModuleBase = 0;
uint64_t g_MyModuleSize = 0;
uint64_t g_MyModuleEnd = 0;
DWORD   进程PID = 0;
DWORD   父进程PID = 0;
DWORD   g_MainThreadId = 0;
HANDLE g_hLoginMonitor = nullptr;
HANDLE g_hAfterLoginInit = nullptr;

HMODULE g_hWeixinDll = nullptr;
HMODULE g_hWeixinExe = nullptr;
HWND    g_WeixinMainHwnd = nullptr;
volatile uint64_t g_IsLogin = 0;
volatile uint64_t g_LoginProbeCalls = 0;
volatile uint64_t g_LoginProbeLast = 0;
volatile uint64_t g_LoginFinishCalls = 0;
volatile uint64_t g_LoginFinishContext = 0;
volatile uint64_t g_LoginFinishPayload = 0;
volatile uint64_t g_ProfileGetterCalls = 0;
volatile uint64_t g_ProfileObject = 0;
volatile uint64_t g_ProfileFieldCalls = 0;
volatile uint64_t g_ProfileFieldObject = 0;
volatile uint64_t g_ProfileFieldDescriptor = 0;
volatile uint64_t g_ProfileContainer830Calls = 0;
volatile uint64_t g_ProfileContainer830Object = 0;
volatile uint64_t g_ProfileContainer830Root = 0;
volatile uint64_t g_ProfileContainer830Second = 0;
volatile uint64_t g_ProfileContainerFC00Calls = 0;
volatile uint64_t g_ProfileContainerFC00Object = 0;
volatile uint64_t g_ProfileContainerFC00Root = 0;
volatile uint64_t g_ProfileContainerFC00Second = 0;
volatile uint64_t g_ManagerContainerGetterCalls = 0;
volatile uint64_t g_ManagerContainerObject = 0;
ProfileFieldTrace g_ProfileTraces[kProfileTraceCapacity]{};
volatile uint64_t g_ProfileTraceIndex = 0;
volatile uint64_t g_getprofile = 0;
CRITICAL_SECTION g_dbMgrCriticalSection;

volatile bool g_LoginMonitorRunning = true;
std::string g_CallBack_Url;

std::wstring g_AppDataDir;
std::wstring g_DocumentDir;
std::wstring g_UsersDir;

SelfInfo_t SelfInfo;

