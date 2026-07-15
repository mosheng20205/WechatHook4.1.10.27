#include <windows.h>
#include <tlhelp32.h>
#include <string>

static const wchar_t* EXE = L"C:\\Program Files\\Tencent\\Weixin\\Weixin.exe";
static const wchar_t* DLL = L"C:\\Program Files\\Tencent\\Weixin\\version.dll";
static HWND g_status;

static bool Inject(DWORD pid, std::wstring& err) {
  HANDLE p=OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,FALSE,pid);
  if(!p){err=L"OpenProcess failed "+std::to_wstring(GetLastError());return false;}
  SIZE_T n=(wcslen(DLL)+1)*sizeof(wchar_t); void* mem=VirtualAllocEx(p,nullptr,n,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  if(!mem||!WriteProcessMemory(p,mem,DLL,n,nullptr)){err=L"WriteProcessMemory failed";CloseHandle(p);return false;}
  auto load=(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW");
  HANDLE t=CreateRemoteThread(p,nullptr,0,load,mem,0,nullptr); if(!t){err=L"CreateRemoteThread failed "+std::to_wstring(GetLastError());CloseHandle(p);return false;}
  WaitForSingleObject(t,10000); DWORD code=0; GetExitCodeThread(t,&code); CloseHandle(t); VirtualFreeEx(p,mem,0,MEM_RELEASE); CloseHandle(p);
  if(!code){err=L"LoadLibraryW failed";return false;} return true;
}

static DWORD Existing() {
  HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(s==INVALID_HANDLE_VALUE)return 0; PROCESSENTRY32W e{sizeof(e)}; DWORD id=0;
  if(Process32FirstW(s,&e)) do { if(!_wcsicmp(e.szExeFile,L"Weixin.exe")){HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,e.th32ProcessID); if(p){wchar_t path[MAX_PATH];DWORD n=MAX_PATH;if(QueryFullProcessImageNameW(p,0,path,&n)&&!_wcsicmp(path,EXE))id=e.th32ProcessID;CloseHandle(p);} } } while(!id&&Process32NextW(s,&e)); CloseHandle(s); return id;
}

static bool Start(std::wstring& err,DWORD& pid) {
  if(GetFileAttributesW(EXE)==INVALID_FILE_ATTRIBUTES){err=L"Weixin.exe not found";return false;}
  if(GetFileAttributesW(DLL)==INVALID_FILE_ATTRIBUTES){err=L"version.dll not found";return false;}
  pid=Existing(); if(pid)return Inject(pid,err);
  STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{}; std::wstring cmd=std::wstring(L"\"")+EXE+L"\" StartPort=30001 RecvType=2 CallBackURL=\"http://127.0.0.1:8080/callback\"";
  if(!CreateProcessW(EXE,cmd.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED,nullptr,L"C:\\Program Files\\Tencent\\Weixin",&si,&pi)){err=L"CreateProcess failed "+std::to_wstring(GetLastError());return false;}
  pid=pi.dwProcessId; bool ok=Inject(pid,err); if(ok)ResumeThread(pi.hThread);else TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return ok;
}

static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
  if(m==WM_CREATE){CreateWindowW(L"STATIC",L"WeChat Hook Launcher",WS_CHILD|WS_VISIBLE,24,20,350,28,w,0,0,0);CreateWindowW(L"BUTTON",L"Start WeChat + Inject",WS_CHILD|WS_VISIBLE,24,62,190,36,w,(HMENU)1,0,0);g_status=CreateWindowW(L"STATIC",L"Ready",WS_CHILD|WS_VISIBLE,24,116,440,32,w,0,0,0);return 0;}
  if(m==WM_COMMAND&&LOWORD(wp)==1){EnableWindow((HWND)lp,FALSE);SetWindowTextW(g_status,L"Starting...");std::wstring e;DWORD pid=0;bool ok=Start(e,pid);std::wstring text=ok?(L"Success, PID="+std::to_wstring(pid)):(L"Failed: "+e);SetWindowTextW(g_status,text.c_str());EnableWindow((HWND)lp,TRUE);return 0;}
  if(m==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(w,m,wp,lp);
}

int WINAPI wWinMain(HINSTANCE h,HINSTANCE,LPWSTR cmdLine,int show){
  // Headless mode for scripts/shortcuts: start WeChat and inject immediately.
  // The existing GUI remains the default when no switch is supplied.
  if (cmdLine && (wcsstr(cmdLine, L"--start") || wcsstr(cmdLine, L"/start"))) {
    std::wstring err; DWORD pid = 0;
    if (Start(err, pid)) return 0;
    MessageBoxW(nullptr, (L"WeChat Hook Launcher failed: " + err).c_str(),
                L"WeChat Hook Launcher", MB_OK | MB_ICONERROR);
    return 1;
  }
  WNDCLASSW c{};c.hInstance=h;c.lpfnWndProc=WndProc;c.lpszClassName=L"WeChatHookLauncher";c.hCursor=LoadCursorW(0,IDC_ARROW);RegisterClassW(&c);HWND w=CreateWindowW(c.lpszClassName,L"WeChat Hook Launcher",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,CW_USEDEFAULT,CW_USEDEFAULT,500,210,0,0,h,0);ShowWindow(w,show);MSG m;while(GetMessageW(&m,0,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}return 0;}
