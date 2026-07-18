#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "resource.h"

namespace {

constexpr wchar_t kWindowClass[] = L"WeChatMultiLauncherWindow";
constexpr wchar_t kWindowTitle[] = L"微信多开器";
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kObjectNameInformation = 1;
constexpr ULONG kObjectTypeInformation = 2;

struct SystemHandleEntryEx {
    PVOID object;
    ULONG_PTR process_id;
    ULONG_PTR handle_value;
    ULONG granted_access;
    USHORT creator_back_trace_index;
    USHORT object_type_index;
    ULONG handle_attributes;
    ULONG reserved;
};

struct SystemHandleInformationEx {
    ULONG_PTR handle_count;
    ULONG_PTR reserved;
    SystemHandleEntryEx handles[1];
};

using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObjectFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

HINSTANCE g_instance = nullptr;
HFONT g_font = nullptr;
HWND g_path_edit = nullptr;
HWND g_count_edit = nullptr;
HWND g_browse_button = nullptr;
HWND g_normal_button = nullptr;
HWND g_force_button = nullptr;

int ScaleForDpi(int value, UINT dpi) {
    return MulDiv(value, static_cast<int>(dpi), 96);
}

std::wstring Trim(std::wstring value) {
    const auto is_space = [](wchar_t ch) { return iswspace(ch) != 0; };
    value.erase(value.begin(), std::find_if_not(value.begin(), value.end(), is_space));
    value.erase(std::find_if_not(value.rbegin(), value.rend(), is_space).base(), value.end());
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"') {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}

std::wstring GetWindowTextString(HWND window) {
    const int length = GetWindowTextLengthW(window);
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    if (length > 0) {
        GetWindowTextW(window, text.data(), static_cast<int>(text.size()));
    }
    text.resize(static_cast<size_t>(length));
    return text;
}

bool IsWeChatExecutableName(const std::wstring& name) {
    return _wcsicmp(name.c_str(), L"WeChat.exe") == 0 ||
           _wcsicmp(name.c_str(), L"Weixin.exe") == 0;
}

std::wstring SelectExistingExecutable(const std::filesystem::path& value) {
    std::error_code error;
    if (std::filesystem::is_regular_file(value, error)) {
        return value.wstring();
    }
    if (!std::filesystem::is_directory(value, error)) {
        return {};
    }

    const auto weixin = value / L"Weixin.exe";
    if (std::filesystem::is_regular_file(weixin, error)) {
        return weixin.wstring();
    }
    const auto wechat = value / L"WeChat.exe";
    if (std::filesystem::is_regular_file(wechat, error)) {
        return wechat.wstring();
    }
    return {};
}

std::wstring ReadRegistryInstallPath() {
    constexpr const wchar_t* keys[] = {
        L"Software\\Tencent\\WeiXin",
        L"Software\\Tencent\\Weixin",
        L"Software\\Tencent\\WeChat",
    };
    constexpr const wchar_t* values[] = {
        L"InstallPath",
        L"InstallDir",
    };

    for (const auto* key : keys) {
        for (const auto* value_name : values) {
            DWORD byte_count = 0;
            const LSTATUS size_status = RegGetValueW(
                HKEY_CURRENT_USER, key, value_name, RRF_RT_REG_SZ, nullptr, nullptr, &byte_count);
            if (size_status != ERROR_SUCCESS || byte_count < sizeof(wchar_t)) {
                continue;
            }

            std::vector<wchar_t> buffer(byte_count / sizeof(wchar_t) + 1, L'\0');
            if (RegGetValueW(HKEY_CURRENT_USER, key, value_name, RRF_RT_REG_SZ, nullptr,
                             buffer.data(), &byte_count) != ERROR_SUCCESS) {
                continue;
            }

            const auto executable = SelectExistingExecutable(Trim(buffer.data()));
            if (!executable.empty()) {
                return executable;
            }
        }
    }
    return {};
}

bool ValidateInputs(HWND owner, std::wstring& executable, int& count) {
    executable = Trim(GetWindowTextString(g_path_edit));
    if (executable.empty()) {
        MessageBoxW(owner, L"请先选定微信安装目录。", kWindowTitle, MB_OK | MB_ICONWARNING);
        return false;
    }

    const std::filesystem::path path(executable);
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) ||
        !IsWeChatExecutableName(path.filename().wstring())) {
        MessageBoxW(owner, L"请选择 WeChat.exe 或 Weixin.exe。", kWindowTitle,
                    MB_OK | MB_ICONWARNING);
        return false;
    }

    const std::wstring count_text = Trim(GetWindowTextString(g_count_edit));
    wchar_t* end = nullptr;
    const long parsed = wcstol(count_text.c_str(), &end, 10);
    if (count_text.empty() || end == nullptr || *end != L'\0' || parsed <= 0 || parsed > 100) {
        MessageBoxW(owner, L"启动数量必须是 1 到 100 之间的整数。", kWindowTitle,
                    MB_OK | MB_ICONWARNING);
        return false;
    }
    count = static_cast<int>(parsed);
    return true;
}

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    const BOOL adjusted = AdjustTokenPrivileges(
        token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    const DWORD last_error = GetLastError();
    CloseHandle(token);
    return adjusted && last_error != ERROR_NOT_ALL_ASSIGNED;
}

std::vector<DWORD> FindWeChatProcesses() {
    std::vector<DWORD> process_ids;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return process_ids;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (IsWeChatExecutableName(entry.szExeFile)) {
                process_ids.push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return process_ids;
}

bool TerminateWeChatProcesses(int& terminated, int& failed) {
    terminated = 0;
    failed = 0;
    for (const DWORD process_id : FindWeChatProcesses()) {
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, process_id);
        if (process == nullptr) {
            ++failed;
            continue;
        }
        if (TerminateProcess(process, 0)) {
            WaitForSingleObject(process, 3000);
            ++terminated;
        } else {
            ++failed;
        }
        CloseHandle(process);
    }
    return failed == 0;
}

bool LaunchWeChat(const std::wstring& executable, DWORD& error_code) {
    std::wstring command_line = L"\"" + executable + L"\"";
    const std::filesystem::path working_directory =
        std::filesystem::path(executable).parent_path();

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        executable.c_str(), command_line.data(), nullptr, nullptr, FALSE,
        CREATE_NEW_PROCESS_GROUP, nullptr, working_directory.c_str(), &startup, &process);
    if (!created) {
        error_code = GetLastError();
        return false;
    }

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    error_code = ERROR_SUCCESS;
    return true;
}

std::wstring FormatWindowsError(DWORD error_code) {
    wchar_t* message = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error_code, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring result = length > 0 && message != nullptr ? message : L"未知错误";
    if (message != nullptr) {
        LocalFree(message);
    }
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) {
        result.pop_back();
    }
    return result;
}

bool QueryObjectText(NtQueryObjectFn query_object,
                     HANDLE handle,
                     ULONG information_class,
                     std::wstring& text) {
    std::vector<std::uint8_t> buffer(4096);
    for (int attempt = 0; attempt < 4; ++attempt) {
        ULONG required = 0;
        const LONG status = query_object(handle, information_class, buffer.data(),
                                         static_cast<ULONG>(buffer.size()), &required);
        if (status >= 0) {
            const auto* value = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
            if (value->Buffer == nullptr || value->Length == 0) {
                text.clear();
            } else {
                text.assign(value->Buffer, value->Length / sizeof(wchar_t));
            }
            return true;
        }
        if (status != kStatusInfoLengthMismatch && status != kStatusBufferTooSmall) {
            return false;
        }
        buffer.resize(std::max<size_t>(required + 512, buffer.size() * 2));
    }
    return false;
}

bool IsWeChatMutexName(const std::wstring& name) {
    return name.find(L"_WeChat_App_Instance_Identity_Mutex_Name") != std::wstring::npos ||
           name.find(L"XWeChat_App_Instance_Identity_Mutex_Name") != std::wstring::npos;
}

struct PatchResult {
    int processes = 0;
    int closed_mutexes = 0;
    int errors = 0;
    std::wstring fatal_error;
};

PatchResult PatchWeChatMutexes() {
    PatchResult result;
    EnableDebugPrivilege();

    const auto process_ids = FindWeChatProcesses();
    result.processes = static_cast<int>(process_ids.size());
    if (process_ids.empty()) {
        return result;
    }

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_system_information = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    const auto query_object =
        reinterpret_cast<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject"));
    if (query_system_information == nullptr || query_object == nullptr) {
        result.fatal_error = L"无法加载系统句柄查询函数。";
        return result;
    }

    std::unordered_map<ULONG_PTR, HANDLE> process_handles;
    for (const DWORD process_id : process_ids) {
        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, process_id);
        if (process != nullptr) {
            process_handles.emplace(process_id, process);
        } else {
            ++result.errors;
        }
    }

    std::vector<std::uint8_t> buffer(1024 * 1024);
    LONG status = 0;
    ULONG required = 0;
    for (;;) {
        status = query_system_information(
            kSystemExtendedHandleInformation, buffer.data(),
            static_cast<ULONG>(buffer.size()), &required);
        if (status != kStatusInfoLengthMismatch) {
            break;
        }
        if (required > 256U * 1024U * 1024U) {
            result.fatal_error = L"系统句柄数据过大，已停止操作。";
            break;
        }
        buffer.resize(std::max<size_t>(required + 1024 * 1024, buffer.size() * 2));
    }

    if (result.fatal_error.empty() && status < 0) {
        result.fatal_error = L"读取系统句柄失败。";
    }

    if (result.fatal_error.empty()) {
        const auto* information =
            reinterpret_cast<const SystemHandleInformationEx*>(buffer.data());
        const size_t available_entries =
            (buffer.size() - offsetof(SystemHandleInformationEx, handles)) /
            sizeof(SystemHandleEntryEx);
        const size_t count =
            std::min<size_t>(information->handle_count, available_entries);

        for (size_t index = 0; index < count; ++index) {
            const auto& entry = information->handles[index];
            const auto process_it = process_handles.find(entry.process_id);
            if (process_it == process_handles.end()) {
                continue;
            }

            const HANDLE remote_handle =
                reinterpret_cast<HANDLE>(entry.handle_value);
            HANDLE local_handle = nullptr;
            if (!DuplicateHandle(process_it->second, remote_handle, GetCurrentProcess(),
                                 &local_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                continue;
            }

            std::wstring type_name;
            const bool is_mutant =
                QueryObjectText(query_object, local_handle, kObjectTypeInformation, type_name) &&
                _wcsicmp(type_name.c_str(), L"Mutant") == 0;

            std::wstring object_name;
            const bool is_target =
                is_mutant &&
                QueryObjectText(query_object, local_handle, kObjectNameInformation, object_name) &&
                IsWeChatMutexName(object_name);
            CloseHandle(local_handle);

            if (!is_target) {
                continue;
            }

            HANDLE closing_copy = nullptr;
            if (DuplicateHandle(process_it->second, remote_handle, GetCurrentProcess(),
                                &closing_copy, 0, FALSE,
                                DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
                ++result.closed_mutexes;
                if (closing_copy != nullptr) {
                    CloseHandle(closing_copy);
                }
            } else {
                ++result.errors;
            }
        }
    }

    for (const auto& item : process_handles) {
        CloseHandle(item.second);
    }
    return result;
}

class UiBusyGuard {
public:
    explicit UiBusyGuard(HWND owner) : owner_(owner), old_cursor_(SetCursor(LoadCursor(nullptr, IDC_WAIT))) {
        EnableWindow(g_browse_button, FALSE);
        EnableWindow(g_normal_button, FALSE);
        EnableWindow(g_force_button, FALSE);
        EnableWindow(g_path_edit, FALSE);
        EnableWindow(g_count_edit, FALSE);
        UpdateWindow(owner_);
    }

    ~UiBusyGuard() {
        EnableWindow(g_browse_button, TRUE);
        EnableWindow(g_normal_button, TRUE);
        EnableWindow(g_force_button, TRUE);
        EnableWindow(g_path_edit, TRUE);
        EnableWindow(g_count_edit, TRUE);
        SetCursor(old_cursor_);
        SetFocus(g_path_edit);
    }

private:
    HWND owner_;
    HCURSOR old_cursor_;
};

void BrowseForWeChat(HWND owner) {
    wchar_t file_name[MAX_PATH] = {};
    const std::wstring current = GetWindowTextString(g_path_edit);
    wcsncpy_s(file_name, current.c_str(), _TRUNCATE);

    constexpr wchar_t filter[] =
        L"微信程序 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0\0";
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFilter = filter;
    dialog.lpstrFile = file_name;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrTitle = L"选择微信程序";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(g_path_edit, file_name);
    }
}

void RunNormalLaunch(HWND owner) {
    std::wstring executable;
    int count = 0;
    if (!ValidateInputs(owner, executable, count)) {
        return;
    }

    UiBusyGuard busy(owner);
    int terminated = 0;
    int failed_to_terminate = 0;
    if (!TerminateWeChatProcesses(terminated, failed_to_terminate)) {
        MessageBoxW(owner, L"无法关闭全部微信进程，请确认程序已用管理员身份运行。",
                    kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }

    int launched = 0;
    DWORD launch_error = ERROR_SUCCESS;
    for (int index = 0; index < count; ++index) {
        if (LaunchWeChat(executable, launch_error)) {
            ++launched;
        } else {
            break;
        }
    }

    if (launched != count) {
        const std::wstring message =
            L"已启动 " + std::to_wstring(launched) + L" 个微信，随后启动失败：\n" +
            FormatWindowsError(launch_error);
        MessageBoxW(owner, message.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
    }
}

void RunForceLaunch(HWND owner) {
    std::wstring executable;
    int ignored_count = 0;
    if (!ValidateInputs(owner, executable, ignored_count)) {
        return;
    }

    UiBusyGuard busy(owner);
    const PatchResult patch = PatchWeChatMutexes();
    if (!patch.fatal_error.empty()) {
        MessageBoxW(owner, patch.fatal_error.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }

    DWORD launch_error = ERROR_SUCCESS;
    if (!LaunchWeChat(executable, launch_error)) {
        const std::wstring message =
            L"微信启动失败：\n" + FormatWindowsError(launch_error);
        MessageBoxW(owner, message.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }

    if (patch.processes > 0 && patch.closed_mutexes == 0) {
        MessageBoxW(owner,
                    L"未找到微信多开互斥体，已尝试启动微信。当前微信版本可能使用了不同的互斥体名称。",
                    kWindowTitle, MB_OK | MB_ICONWARNING);
    }
}

HWND CreateControl(HWND parent,
                   DWORD extended_style,
                   const wchar_t* class_name,
                   const wchar_t* text,
                   DWORD style,
                   int x,
                   int y,
                   int width,
                   int height,
                   int id,
                   UINT dpi) {
    HWND control = CreateWindowExW(
        extended_style, class_name, text, WS_CHILD | WS_VISIBLE | style,
        ScaleForDpi(x, dpi), ScaleForDpi(y, dpi), ScaleForDpi(width, dpi),
        ScaleForDpi(height, dpi), parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        g_instance, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    return control;
}

void CreateMainControls(HWND window) {
    const UINT dpi = GetDpiForWindow(window);
    g_font = CreateFontW(
        -MulDiv(9, static_cast<int>(dpi), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        GB2312_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"宋体");

    CreateControl(window, 0, L"STATIC", L"微信安装目录:", SS_LEFT | SS_CENTERIMAGE,
                  21, 23, 88, 24, 0, dpi);
    g_path_edit = CreateControl(
        window, WS_EX_CLIENTEDGE, L"EDIT", L"", ES_LEFT | ES_AUTOHSCROLL,
        104, 23, 152, 24, IDC_EDIT_PATH, dpi);
    g_browse_button = CreateControl(
        window, 0, L"BUTTON", L"目录", BS_PUSHBUTTON,
        273, 23, 56, 24, IDC_BUTTON_BROWSE, dpi);

    CreateControl(window, 0, L"STATIC", L"启动微信数目:", SS_LEFT | SS_CENTERIMAGE,
                  24, 64, 80, 24, 0, dpi);
    g_count_edit = CreateControl(
        window, WS_EX_CLIENTEDGE, L"EDIT", L"2", ES_LEFT | ES_AUTOHSCROLL | ES_NUMBER,
        104, 65, 72, 24, IDC_EDIT_COUNT, dpi);
    g_normal_button = CreateControl(
        window, 0, L"BUTTON", L"常规多开", BS_PUSHBUTTON,
        196, 64, 60, 33, IDC_BUTTON_NORMAL, dpi);
    g_force_button = CreateControl(
        window, 0, L"BUTTON", L"暴力多开", BS_PUSHBUTTON,
        272, 64, 64, 32, IDC_BUTTON_FORCE, dpi);

    CreateControl(window, 0, L"STATIC", L"常规多开:使用之前请先关闭全部微信",
                  SS_LEFT | SS_CENTERIMAGE, 5, 99, 260, 16, 0, dpi);

    SendMessageW(g_path_edit, EM_SETLIMITTEXT, 32767, 0);
    SendMessageW(g_count_edit, EM_SETLIMITTEXT, 3, 0);
    const std::wstring install_path = ReadRegistryInstallPath();
    if (!install_path.empty()) {
        SetWindowTextW(g_path_edit, install_path.c_str());
    } else {
        SetWindowTextW(g_path_edit, L"D:\\software\\Tencent\\Weixin\\Weixin.exe");
    }
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    switch (message) {
    case WM_CREATE:
        CreateMainControls(window);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(w_param)) {
        case IDC_BUTTON_BROWSE:
            if (HIWORD(w_param) == BN_CLICKED) {
                BrowseForWeChat(window);
            }
            return 0;
        case IDC_BUTTON_NORMAL:
            if (HIWORD(w_param) == BN_CLICKED) {
                RunNormalLaunch(window);
            }
            return 0;
        case IDC_BUTTON_FORCE:
            if (HIWORD(w_param) == BN_CLICKED) {
                RunForceLaunch(window);
            }
            return 0;
        default:
            break;
        }
        break;

    case WM_CTLCOLORSTATIC: {
        const HDC device_context = reinterpret_cast<HDC>(w_param);
        SetBkMode(device_context, TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
    }

    case WM_DESTROY:
        if (g_font != nullptr) {
            DeleteObject(g_font);
            g_font = nullptr;
        }
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    g_instance = instance;
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    const HICON icon = static_cast<HICON>(
        LoadImageW(instance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 0, 0,
                   LR_DEFAULTSIZE));

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = WindowProcedure;
    window_class.hInstance = instance;
    window_class.hIcon = icon;
    window_class.hIconSm = icon;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);
    window_class.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&window_class)) {
        return 1;
    }

    constexpr DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    constexpr DWORD extended_style = WS_EX_APPWINDOW;
    const UINT dpi = GetDpiForSystem();
    RECT bounds{0, 0, ScaleForDpi(350, dpi), ScaleForDpi(149, dpi)};
    AdjustWindowRectExForDpi(&bounds, style, FALSE, extended_style, dpi);

    HWND window = CreateWindowExW(
        extended_style, kWindowClass, kWindowTitle, style,
        ScaleForDpi(50, dpi), ScaleForDpi(50, dpi),
        bounds.right - bounds.left, bounds.bottom - bounds.top,
        nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        return 1;
    }

    ShowWindow(window, show_command);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
