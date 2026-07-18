# 微信多开（C++）

这是 `神域VX多开.e` 的原生 Win32 C++ 版本，按原易语言窗体的尺寸、控件位置、标题、文字和图标还原。

## 功能

- 自动读取 `HKCU\Software\Tencent\WeiXin`、`Weixin` 或 `WeChat` 下的微信安装路径。
- “常规多开”会结束现有的 `WeChat.exe` / `Weixin.exe`，再按数量启动微信。
- “暴力多开”会枚举微信进程句柄，关闭名称包含以下标记的互斥体，然后再启动一个微信：
  - `_WeChat_App_Instance_Identity_Mutex_Name`
  - `XWeChat_App_Instance_Identity_Mutex_Name`
- 支持 64 位 Windows 和 Unicode 路径。

## 编译

使用 Visual Studio 2022 打开 `微信多开.sln`，选择 `Release | x64` 后生成。

也可以在 Developer PowerShell 中执行：

```powershell
msbuild .\微信多开.sln /m /p:Configuration=Release /p:Platform=x64
```

生成文件位于 `bin\Release\微信多开.exe`。程序需要管理员权限，因为关闭其他进程句柄和结束进程都属于高权限操作。

