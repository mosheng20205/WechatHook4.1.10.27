#include "wx_send.h"
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <objbase.h>
#include "global.h"
#include "tools.h"

#pragma comment(lib, "bcrypt.lib")

using WeixinCall = __int64(*)(...);


namespace Memory
{
    // 分配内存（在当前进程）
    inline void* Allocate(size_t size)
    {
        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    // 释放内存
    inline void Free(void* ptr)
    {
        if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
    }

    // 写入内存
    template<typename T>
    inline void Write(void* address, T value)
    {
        if (address) {
            *reinterpret_cast<T*>(address) = value;
        }
    }

    // 写入字节集
    inline void WriteBytes(void* address, const void* data, size_t size)
    {
        if (address && data) {
            memcpy(address, data, size);
        }
    }

    // 写入字符串
    inline void WriteString(void* address, const std::string& str)
    {
        if (address) {
            memcpy(address, str.c_str(), str.length() + 1);
        }
    }
}


namespace WeixinSend
{
    // ============================================================
    // util
    // ============================================================
    uintptr_t GetWeixinDllBase()
    {
        static uintptr_t base = 0;
        if (!base)
            base = (uintptr_t)GetModuleHandleA("Weixin.dll");
        return base;
    }

    static std::string GenGuidString()
    {
        GUID guid;
        CoCreateGuid(&guid);

        char buf[64] = { 0 };
        // 36 chars, no braces
        snprintf(buf, sizeof(buf),
            "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1,
            guid.Data2,
            guid.Data3,
            guid.Data4[0], guid.Data4[1],
            guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]
        );

        return std::string(buf);
    }

    static uint64_t CalcWxCapacity(uint64_t len)
    {
        uint64_t need = len + 1;                
        uint64_t cap = (need + 0xF) & ~0xFULL;  
        return cap - 1;                           // 微信风格
    }


    template<typename T>
    T* HeapAlloc_mb(size_t count)
    {
        return (T*)::HeapAlloc(
            ::GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(T) * count
        );
    }


#pragma pack(push, 1)

    struct WeixinStringUnicode
    {
        union
        {
            wchar_t inline_buf[8];  
            wchar_t* heap_buf;
        };
        uint64_t length;  
        uint64_t cap;    
    };

    struct WeixinString
    {
        union
        {
            char  inline_buf[16];
            char* heap_buf;
        };
        uint64_t length;
        uint64_t cap; 
    };
    struct TextMessage
    {
        uint64_t pad0[22] = { 0 };          // 0x000
        WeixinString receiver;              // 0x0B0
        uint64_t pad1[1] = { 0 };           // 0x0D0
        uint64_t type;                      // 0x0D8
        uint64_t pad2[21] = { 0 };          // 0x0E0
        uint64_t msg_len;                   // 0x188
        uint64_t pad3[163] = { 0 };         // 0x190
        WeixinString uuid;                  // 0x6A8
        uint64_t pad4[8] = { 0 };           // 0x6C8
        WeixinString content;               // 0x708
        WeixinString atlist;                // 0x728
    };

    static_assert(sizeof(WeixinString) == 0x20);
    static_assert(offsetof(TextMessage, receiver) == 0x0B0);
    static_assert(offsetof(TextMessage, uuid) == 0x6A8);
    static_assert(offsetof(TextMessage, content) == 0x708);

    struct UnknownBlock
    {
        uint64_t vtable;
        uint64_t temp[6];
        uint64_t self;
    };

    struct InnerStruct1
    {
        void* ptr1;      // +0x00
        void* ptr2;      // +0x08
        void* ptr3;      // +0x10
        uint64_t count;  // +0x18
    };
    struct InnerStruct2
    {
        void* vtable;    // +0x00
        void* ptr1;      // +0x08
        uint64_t data1;  // +0x10
        uint64_t data2;  // +0x18
        uint64_t field1; // +0x20
    };


#pragma pack(pop)

    // 新增: 设置 Unicode 字符串
    inline void SetWeixinStringU(WeixinStringUnicode* ws, const std::string& s)
    {
        memset(ws, 0, sizeof(WeixinStringUnicode));

        // 将 std::string (UTF-8) 转换为 std::wstring (Unicode)
        int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring wstr(size - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &wstr[0], size);

        ws->length = wstr.size();  // 设置长度
        if (wstr.size() < 8)
        {
            // 短字符串: 使用内联缓冲区
            memcpy(ws->inline_buf, wstr.data(), wstr.size() * sizeof(wchar_t));
            ws->inline_buf[wstr.size()] = L'\0';
            ws->cap = 0xF;
        }
        else
        {
            // 长字符串: 堆分配
            wchar_t* buf = (wchar_t*)::HeapAlloc(
                ::GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                (wstr.size() + 1) * sizeof(wchar_t)
            );
            memcpy(buf, wstr.data(), (wstr.size() + 1) * sizeof(wchar_t));
            ws->heap_buf = buf;
            ws->cap = CalcWxCapacity(wstr.size());
        }
    }

    inline void SetWeixinString(WeixinString* dst, const std::string& src)
    {
        // 必须先清零
        memset(dst, 0, sizeof(WeixinString));

        dst->length = src.size();

        if (src.size() < 16)
        {
            // inline 模式
            memcpy(dst->inline_buf, src.data(), src.size());
            dst->cap = 0xF;
        }
        else
        {
            // heap 模式
            char* buf = (char*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, src.size() + 1);
            //char* buf = (char*)Memory::Allocate(s.size() + 1);
            if (!buf) {
                Memory::Free(buf);
                return;
            }

            memcpy(buf, src.data(), src.size());
            buf[src.size()] = '\0';
            dst->heap_buf = buf;
            dst->cap = CalcWxCapacity(src.size());

        }
    }



    void BuildSendParam1_sub(uint64_t* msgBuf, const std::string& wxid, const std::string& imgPath)
    {
        uint64_t filesize = 文件_取大小(imgPath);
        std::string guid = GenGuidString();

        msgBuf[0] = (uintptr_t)g_hWeixinDll + offset::img_msg_vtbl;
        msgBuf[1] = 0x200000006;
        msgBuf[2] = (uintptr_t)g_hWeixinDll + offset::img_msg_vtb2;


        *(uint64_t*)(msgBuf + 0x40 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x60 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x80 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0xA0 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0xA8 / 8) = 0x0000000100000000;
        *(uint64_t*)(msgBuf + 0xB0 / 8) = 0x0000000700000000;

        // === wxid ===
        SetWeixinString((WeixinString*)(msgBuf + 0xC0 / 8), wxid);
        *(uint64_t*)(msgBuf + 0xD0 / 8) = wxid.size();
        *(uint64_t*)(msgBuf + 0xD8 / 8) = CalcWxCapacity(wxid.size());

        //文件类型 3= png图片   47 = gif
        *(uint64_t*)(msgBuf + 0xE8 / 8) = 3;        


        // === 图片路径 ===
        SetWeixinStringU((WeixinStringUnicode*)(msgBuf + 0xF0 / 8), imgPath);
        *(uint64_t*)(msgBuf + 0x100 / 8) = imgPath.size(); // 图片路径长度
        *(uint64_t*)(msgBuf + 0x108 / 8) = CalcWxCapacity(imgPath.size());


        *(uint64_t*)(msgBuf + 0x130 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x150 / 8) = 7;
        *(uint64_t*)(msgBuf + 0x170 / 8) = 0xF;

        //0x178 = filename
		//0x188 & 0x190= filename length & capacity

        *(uint64_t*)(msgBuf + 0x198 / 8) = filesize;         //图片大小
        *(uint64_t*)(msgBuf + 0x1B8 / 8) = 0xF;

        *(uint64_t*)(msgBuf + 0x668 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x688 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x6B0 / 8) = 0xF;
        SetWeixinString((WeixinString*)(msgBuf + 0x6B8 / 8), guid);
        *(uint64_t*)(msgBuf + 0x6C8 / 8) = guid.size();      // length = 36
        *(uint64_t*)(msgBuf + 0x6D0 / 8) = CalcWxCapacity(guid.size());


        *(uint64_t*)(msgBuf + 0x6F0 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x710 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x738 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x760 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x780 / 8) = 0xF;
        *(uint64_t*)(msgBuf + 0x7A0 / 8) = 0xF;
    }

    void BuildSendParam2_Image(uint64_t* out)
    {
        // 获取 Weixin.dll 模块句柄
        uintptr_t hModule = (uintptr_t)GetModuleHandleA("Weixin.dll");

        uint64_t globalValue = *(uint64_t*)(hModule + offset::param2);


        WeixinCall create = (WeixinCall)(hModule + offset::create_param2);

        // 第一个分配: 16字节 (不是 0x10 * 8 = 128字节!)
        uint64_t* buf = (uint64_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x10);

        // 分配三个 64 字节的结构
        auto p2 = (UnknownBlock*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
        auto p3 = (UnknownBlock*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
        auto p4 = (UnknownBlock*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);

        p2->vtable = hModule + offset::param2_1;
        p2->temp[0] = 0;
        p2->temp[1] = 0;
        p2->temp[2] = 0;
        p2->temp[3] = 0;
        p2->temp[4] = 0;
        p2->temp[5] = 0;
        p2->self = (uint64_t)p2;

        p3->vtable = hModule + offset::param2_2;
        p3->temp[0] = 0;
        p3->temp[1] = 0;
        p3->temp[2] = 0;
        p3->temp[3] = 0;
        p3->temp[4] = 0;
        p3->temp[5] = 0;
        p3->self = (uint64_t)p3;

        p4->vtable = hModule + offset::param2_3;
        p4->temp[0] = 0;
        p4->temp[1] = 0;
        p4->temp[2] = 0;
        p4->temp[3] = 0;
        p4->temp[4] = 0;
        p4->temp[5] = 0;
        p4->self = (uint64_t)p4;

        // 调用子函数，参数顺序根据汇编确定
        // rcx = out, rdx = p4, r8 = p3, r9 = p2, [rsp+0x30] = buf, [rsp+0x38] = globalValue
        create(
            (uint64_t)out,      // arg1
            (uint64_t)p2,       // arg2
            (uint64_t)p3,       // arg3
            (uint64_t)p4,       // arg4
            (uint64_t)buf,      // arg5
            globalValue         // arg6 - 从 Weixin.dll+0x8E4C758 读取的值
        );
    }

    InnerStruct2* BuildSendParam1(uint64_t msgStruct)
    {
        // 获取 Weixin.dll 模块句柄
        uintptr_t hModule = (uintptr_t)GetModuleHandleA("Weixin.dll");

        // 分配第一个结构: 0x20 (32字节)
        InnerStruct1* struct1 = (InnerStruct1*)HeapAlloc(GetProcessHeap(), 8, 0x20);
        if (!struct1)
            return nullptr;

        // 初始化第一个结构
        struct1->ptr1 = (void*)(msgStruct + 0x10);  // 指向消息结构的 +0x10 偏移
        struct1->ptr2 = (void*)(msgStruct); 
        struct1->ptr3 = nullptr;
        struct1->count = 0;

        // 分配第二个结构: 0x28 (40字节)
        InnerStruct2* struct2 = (InnerStruct2*)HeapAlloc(GetProcessHeap(), 8, 0x28);
        if (!struct2) {
            HeapFree(GetProcessHeap(), 0, struct1);
            return nullptr;
        }

        // 初始化第二个结构
        struct2->vtable = (void*)(hModule + offset::param1_vtable);  // vtable 指针
        struct2->ptr1 = struct1;                           // 指向第一个结构
        struct2->data1 = (uint64_t)struct1 + 0x10;               // 重复指针
        struct2->data2 = (uint64_t)struct1 + 0x10;               // 重复指针
        struct2->field1 = 1;                                 // 标志位 = 1

        // 返回第二个结构
        return struct2;
    }

    bool SendImage(const std::string& wxid, const std::string& imgPath)
    {
        if (wxid.empty() || imgPath.empty() || !GetModuleHandleA("Weixin.dll"))
            return false;
        const uint64_t filesize = 文件_取大小(imgPath);
        if (filesize == 0)
            return false;
        uintptr_t WeixinDLL_baseAddr = GetWeixinDllBase();

        uint64_t* msgStruct = (uint64_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x7C0);
        if (!msgStruct) {
            return false;
        }

        BuildSendParam1_sub(msgStruct, wxid, imgPath);

        uint64_t* struct2 = (uint64_t*)BuildSendParam1((uint64_t)msgStruct);
        if (!struct2)
            return false;


        uint64_t* paramStruct = (uint64_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xE8);
        if (!paramStruct)
            return false;

        WeixinCall send_message = (WeixinCall)(WeixinDLL_baseAddr + offset::send_message);
        if (!send_message)
            return false;
        // Guard the native construction/send: a layout mismatch faults inside
        // Weixin rather than corrupting the caller, so translate any access
        // violation into a false result instead of terminating the host.
        __try {
            BuildSendParam2_Image(paramStruct);
            send_message((uint64_t)struct2, (uint64_t)paramStruct);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        return true;
    }



    void BuildTextMessage(uint64_t* ptr, const std::string& text, const std::string& wxid)
    {
        uintptr_t base = GetWeixinDllBase();

        // 对齐原始布局
        ptr[0] = base + offset::txt_message_vtbl;
        ptr[1] = 0x200000005LL;


        WeixinCall init_text_st = (WeixinCall)(base + offset::txt_message_ctr);

        TextMessage* msg = reinterpret_cast<TextMessage*>(ptr + 2);
        init_text_st(reinterpret_cast<uint64_t>(msg));

        SetWeixinString(&msg->receiver, wxid);
        SetWeixinString(&msg->content, text);
        msg->msg_len = text.length();
        msg->type = 1;
    }

    void BuildSendParam2_Text(uint64_t* a1)
    {
        uintptr_t base = GetWeixinDllBase();
        WeixinCall Build_Send_TextImg_Pars2 = (WeixinCall)(base + offset::create_param2);

        uint64_t a2 = base + offset::param2_1;
        uint64_t a3 = base + offset::param2_2;
        uint64_t a4 = base + offset::param2_3;

        uint64_t param2_addr = base + offset::param2;  
         

        uint64_t* buf = HeapAlloc_mb<uint64_t>(16);


        auto p2 = (UnknownBlock*)HeapAlloc_mb<uint64_t>(64);
        auto p3 = (UnknownBlock*)HeapAlloc_mb<uint64_t>(64);
        auto p4 = (UnknownBlock*)HeapAlloc_mb<uint64_t>(64);

        // === 必须清零 ===
        memset(p2, 0, sizeof(UnknownBlock));
        memset(p3, 0, sizeof(UnknownBlock));
        memset(p4, 0, sizeof(UnknownBlock));

        p2->vtable = a2;
        p2->self = (uint64_t)p2;

        p3->vtable = a3;
        p3->self = (uint64_t)p3;

        p4->vtable = a4;
        p4->self = (uint64_t)p4;

        // === 核心：最后一个参数必须解引用 ===
        Build_Send_TextImg_Pars2(
            (uint64_t)a1,
            (uint64_t)p2,
            (uint64_t)p3,
            (uint64_t)p4,
            (uint64_t)buf,
            *(uint64_t*)param2_addr
        );
    }

    bool SendText(const std::string& wxidorgid, const std::string& msg)
    {
        if (wxidorgid.empty() || msg.empty() || !GetModuleHandleA("Weixin.dll"))
            return false;
        uintptr_t base = GetWeixinDllBase();

		//不同版本需要调整 msgBuf 大小，过小会导致发送失败，过大会浪费内存 
        uint64_t* msgBuf = HeapAlloc_mb<uint64_t>(0x768);
        if (!msgBuf) return false;
        BuildTextMessage(msgBuf, msg, wxidorgid);

        uint64_t* data = HeapAlloc_mb<uint64_t>(0x20);
        if (!data) return false;
        data[0] = (uint64_t)(msgBuf + 2);
        data[1] = (uint64_t)(msgBuf);
        data[2] = 0;

        uint64_t* arg1 = HeapAlloc_mb<uint64_t>(0x28);
        if (!arg1) return false;
        arg1[0] = base + offset::param1_vtable;
        arg1[1] = reinterpret_cast<uint64_t>(data);
        arg1[2] = (uint64_t)data + 0x10;
        arg1[3] = (uint64_t)data + 0x10;
        arg1[4] = 1;

        uint64_t* arg2 = HeapAlloc_mb<uint64_t>(0xE8);
        if (!arg2) return false;
        BuildSendParam2_Text(arg2);

        WeixinCall send_message = (WeixinCall)(base + offset::send_message);
        send_message((uint64_t)arg1, (uint64_t)arg2);
        return true;
    }



    // ---- Self-implemented WeChat 4.0 "\x07\x08V2" image decryption ----
    //
    // Encrypted .dat layout (little-endian 15-byte header):
    //   [0..3]  magic 07 08 56 3x  ('1' = V1, '2' = V2)
    //   [4..5]  07 08 (constant)
    //   [6..9]  u32 aesPlainLen  plaintext length of the AES-128-ECB region
    //   [10..13]u32 xorLen       length of the trailing single-byte XOR region
    //   [14]    flag (0x01)
    // Body: [AES-128-ECB ciphertext][unencrypted middle][XOR region]
    //   aesEncLen = fileLen - 15 - xorLen             (multiple of 16, PKCS7)
    //   middleLen = fileLen - 15 - aesEncLen - xorLen (0 unless orig > 1KB+1MB)
    // Both keys are per-user and derived live from WeChat's account context,
    // mirroring the native encoder sub_1809BA970:
    //   AES-128 key = first 16 ASCII bytes of sub_1809B1FD0(std::string*, 2)
    //   XOR   key   = low byte of sub_1809B1F20()

    // SEH-isolated: derive the 16-byte AES key. No C++ objects (C2712). The
    // derived std::string's small heap buffer is intentionally leaked (freeing
    // it with our allocator would fault); DecodePic is user-triggered so the
    // per-call leak is negligible.
    static bool DeriveImageAesKey(uintptr_t base, unsigned char* out16)
    {
        __try {
            unsigned char strbuf[0x20];
            memset(strbuf, 0, sizeof(strbuf));
            using DerivFn = void*(__fastcall*)(void*, unsigned int);
            reinterpret_cast<DerivFn>(base + offset::img_key_derive)(strbuf, 2);
            unsigned long long sz = *(unsigned long long*)(strbuf + 0x10);
            if (sz < 16)
                return false;
            const unsigned char* p = *(const unsigned char**)strbuf;
            memcpy(out16, p, 16);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // SEH-isolated: derive the single XOR byte via sub_1809B1F20() (no args).
    static bool DeriveImageXorKey(uintptr_t base, unsigned char* outByte)
    {
        __try {
            using XorFn = __int64(__fastcall*)();
            __int64 r = reinterpret_cast<XorFn>(base + offset::img_xor_key)();
            *outByte = (unsigned char)(r & 0xFF);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // AES-128-ECB block decrypt (no padding removal). inLen must be a multiple
    // of 16; writes inLen bytes into out.
    static bool AesEcbDecrypt(const unsigned char* key16,
                              const unsigned char* in, unsigned long inLen,
                              unsigned char* out, unsigned long outCap)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0)
            return false;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                sizeof(BCRYPT_CHAIN_MODE_ECB), 0) >= 0 &&
            BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                (PUCHAR)key16, 16, 0) >= 0) {
            ULONG cb = 0;
            if (BCryptDecrypt(hKey, (PUCHAR)in, inLen, nullptr, nullptr, 0,
                    out, outCap, &cb, 0) >= 0)
                ok = true;
        }
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    // Read an entire file (wide path) into buf. Caps at 200 MB.
    static bool ReadWholeFileW(const wchar_t* path, std::vector<unsigned char>& buf)
    {
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 ||
            sz.QuadPart > (LONGLONG)200 * 1024 * 1024) {
            CloseHandle(h);
            return false;
        }
        buf.resize((size_t)sz.QuadPart);
        DWORD total = 0;
        bool ok = true;
        while (total < buf.size()) {
            DWORD got = 0;
            if (!ReadFile(h, buf.data() + total, (DWORD)(buf.size() - total),
                    &got, nullptr) || got == 0) {
                ok = false;
                break;
            }
            total += got;
        }
        CloseHandle(h);
        return ok && total == buf.size();
    }

    // Write the whole buffer to a wide path, truncating any existing file.
    static bool WriteWholeFileW(const wchar_t* path, const unsigned char* data, size_t len)
    {
        HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        size_t total = 0;
        bool ok = true;
        while (total < len) {
            DWORD chunk = (DWORD)((len - total > 0x400000) ? 0x400000 : (len - total));
            DWORD wrote = 0;
            if (!WriteFile(h, data + total, chunk, &wrote, nullptr) || wrote == 0) {
                ok = false;
                break;
            }
            total += wrote;
        }
        CloseHandle(h);
        return ok && total == len;
    }

    static std::wstring Utf8ToWide(const std::string& s)
    {
        std::wstring w;
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        if (n > 0) {
            w.resize(n - 1);
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
        }
        return w;
    }

    bool DecodePic(const std::string& enc_pic_path, const std::string& dec_pic_path,
                   uint32_t mode, bool wide_path)
    {
        (void)wide_path;
        (void)mode;
        uintptr_t base = GetWeixinDllBase();
        if (!base || enc_pic_path.empty() || dec_pic_path.empty() ||
            enc_pic_path.size() > 32768 || dec_pic_path.size() > 32768)
            return false;

        std::wstring wsrc = Utf8ToWide(enc_pic_path);
        std::wstring wdst = Utf8ToWide(dec_pic_path);
        if (wsrc.empty() || wdst.empty())
            return false;

        std::vector<unsigned char> buf;
        if (!ReadWholeFileW(wsrc.c_str(), buf) || buf.size() < 15)
            return false;

        // Parse the 15-byte V1/V2 header.
        if (buf[0] != 0x07 || buf[1] != 0x08 || buf[2] != 0x56)
            return false;  // not a WeChat encrypted image container
        uint32_t aesPlainLen = *(const uint32_t*)(buf.data() + 6);
        uint32_t xorLen      = *(const uint32_t*)(buf.data() + 10);

        if ((size_t)15 + xorLen > buf.size())
            return false;
        size_t aesEncLen = buf.size() - 15 - xorLen;
        if ((aesEncLen & 0xF) != 0)
            return false;                        // AES region must be 16-aligned
        if (aesPlainLen > aesEncLen)
            aesPlainLen = (uint32_t)aesEncLen;    // clamp to available plaintext
        size_t middleLen = buf.size() - 15 - aesEncLen - xorLen;

        // Derive the per-user keys from WeChat's live account context.
        unsigned char aeskey[16];
        unsigned char xorkey = 0;
        if (!DeriveImageAesKey(base, aeskey))
            return false;
        if (!DeriveImageXorKey(base, &xorkey))
            return false;

        // Decrypt the AES-128-ECB region.
        std::vector<unsigned char> aesOut;
        if (aesEncLen > 0) {
            aesOut.resize(aesEncLen);
            if (!AesEcbDecrypt(aeskey, buf.data() + 15, (unsigned long)aesEncLen,
                               aesOut.data(), (unsigned long)aesEncLen))
                return false;
        }

        // Assemble: [AES plaintext][unencrypted middle][XOR-decrypted region].
        std::vector<unsigned char> out;
        out.reserve((size_t)aesPlainLen + middleLen + xorLen);
        out.insert(out.end(), aesOut.begin(), aesOut.begin() + aesPlainLen);
        const unsigned char* mid = buf.data() + 15 + aesEncLen;
        out.insert(out.end(), mid, mid + middleLen);
        const unsigned char* xr = mid + middleLen;
        for (size_t i = 0; i < xorLen; ++i)
            out.push_back((unsigned char)(xr[i] ^ xorkey));

        // Lightweight diagnostic: header fields, key prefixes, output magic.
        {
            char line[512];
            _snprintf_s(line, sizeof(line), _TRUNCATE,
                "DecodePic(v2) fileLen=%llu aesPlain=%u aesEnc=%llu mid=%llu "
                "xorLen=%u aeskey0=%02X%02X xorkey=%02X outLen=%llu "
                "magic=%02X%02X%02X%02X\n",
                (unsigned long long)buf.size(), aesPlainLen,
                (unsigned long long)aesEncLen, (unsigned long long)middleLen,
                xorLen, aeskey[0], aeskey[1], xorkey,
                (unsigned long long)out.size(),
                out.size() > 0 ? out[0] : 0, out.size() > 1 ? out[1] : 0,
                out.size() > 2 ? out[2] : 0, out.size() > 3 ? out[3] : 0);
            OutputDebugStringA(line);
        }

        return WriteWholeFileW(wdst.c_str(), out.data(), out.size());
    }

    // ==================================================================
    // appmsg / XML (msgtype 49) REAL send via a CUSTOM-VTABLE CGI task
    // (WeChat 4.1.10.27).
    //
    // Earlier attempts handed WeChat a NATIVE SendAppMsgRequest protobuf object
    // (from-scratch or template-cloned) and let the async network worker
    // serialize it; both crashed in the worker at Weixin.dll+0x46a92e3 while
    // serializing that native object (any ArenaStringPtr / has-bit / arena
    // mismatch is fatal there and outside SEH reach).  This path NEVER hands
    // WeChat a native object to serialize.
    //
    // We build the sendappmsg CGI task exactly like the native submit primitive
    // (offset::appmsg_task_ctor = sub_7FFE9200F460: cgi type 222, endpoint
    // "/cgi-bin/micromsg-bin/sendappmsg", empty inner request @task+240), then
    // OVERRIDE the task's 6-slot vtable so:
    //   [0] dtor      -> no-op (task intentionally leaked: avoids cross-
    //                   allocator free + destruct of the never-populated
    //                   response object @task+336)
    //   [1] serialize -> emit our OWN hand-serialized protobuf bytes into the
    //                   output holder (native inner-req serialize, the crash
    //                   path, is never called)
    //   [2] response  -> capture the reply bytes + parse BaseResponse.ret
    //   [3] getinner  -> return task+240 (native semantics)
    //   [4] dummy / [5] literal 1 (native semantics)
    // task+208 is pointed at a dummy-vtable callback holder so the framework's
    // response-notify path has a valid (harmless) object.  The task is
    // dispatched directly through the live network manager
    // (g_AppMsgSubmitManager, captured passively at the F120 observer) via
    // manager->vtable[5] -- identical to what F120 does.
    //
    // protobuf wire format (schema-version independent, mirrors the working
    // reference project):
    //   AppMsg:        1=from(str) 3=0(varint) 4=to(str) 5=type(varint)
    //                  6=xml(str) 7=timestamp(varint) 8=clientmsgid(str)
    //                  12=msgsource(str)
    //   BaseRequest:   1="" 2=0 3="Windows" 4=0 5="Windows" 6=0
    //   SendAppMsgReq: 1=BaseRequest(bytes) 2=AppMsg(bytes)
    // ==================================================================

    // ---- pending registry (POD only: safe to touch inside SEH-guarded,
    //      worker-thread vtable callbacks) --------------------------------
    struct AppMsgPending
    {
        volatile LONG64 taskPtr;   // key (0 = free slot)
        const uint8_t*  reqData;   // leaked pre-serialized request bytes
        uint32_t        reqSize;
        HANDLE          evt;       // manual-reset, signaled by response cb (leaked)
        volatile LONG   done;
        int             ret;       // parsed BaseResponse.ret
    };
    static AppMsgPending    g_appmsgPending[16] = {};
    static CRITICAL_SECTION g_appmsgCs;
    static volatile LONG    g_appmsgCsState = 0;

    static void AppMsgEnsureCs()
    {
        if (InterlockedCompareExchange(&g_appmsgCsState, 1, 0) == 0) {
            InitializeCriticalSection(&g_appmsgCs);
            InterlockedExchange(&g_appmsgCsState, 2);
        }
        while (g_appmsgCsState != 2)
            Sleep(0);
    }

    static void AppMsgRegister(uint64_t taskPtr, const uint8_t* data,
                               uint32_t size, HANDLE evt)
    {
        AppMsgEnsureCs();
        EnterCriticalSection(&g_appmsgCs);
        for (int i = 0; i < 16; ++i) {
            if (g_appmsgPending[i].taskPtr == 0) {
                g_appmsgPending[i].reqData = data;
                g_appmsgPending[i].reqSize = size;
                g_appmsgPending[i].evt     = evt;
                g_appmsgPending[i].done    = 0;
                g_appmsgPending[i].ret     = 0;
                InterlockedExchange64(&g_appmsgPending[i].taskPtr,
                                      static_cast<LONG64>(taskPtr));
                break;
            }
        }
        LeaveCriticalSection(&g_appmsgCs);
    }

    static void AppMsgUnregister(uint64_t taskPtr, LONG* outDone, int* outRet)
    {
        AppMsgEnsureCs();
        EnterCriticalSection(&g_appmsgCs);
        for (int i = 0; i < 16; ++i) {
            if (static_cast<uint64_t>(g_appmsgPending[i].taskPtr) == taskPtr) {
                if (outDone) *outDone = g_appmsgPending[i].done;
                if (outRet)  *outRet  = g_appmsgPending[i].ret;
                // Leak evt (do NOT close): the async worker may still touch it.
                InterlockedExchange64(&g_appmsgPending[i].taskPtr, 0);
                g_appmsgPending[i].reqData = nullptr;
                g_appmsgPending[i].reqSize = 0;
                g_appmsgPending[i].evt     = nullptr;
                break;
            }
        }
        LeaveCriticalSection(&g_appmsgCs);
    }

    // ---- protobuf serialize helpers (std::string; only ever called from
    //      SendAppMsg, never from the SEH-guarded worker callbacks) --------
    static void PbVarint(std::string& out, uint64_t v)
    {
        while (v >= 0x80) { out.push_back(static_cast<char>((v & 0x7F) | 0x80)); v >>= 7; }
        out.push_back(static_cast<char>(v));
    }
    static void PbTag(std::string& out, uint32_t field, uint32_t wire)
    {
        PbVarint(out, (static_cast<uint64_t>(field) << 3) | wire);
    }
    static void PbVarintField(std::string& out, uint32_t field, uint64_t v)
    {
        PbTag(out, field, 0); PbVarint(out, v);
    }
    static void PbBytesField(std::string& out, uint32_t field, const char* d, size_t n)
    {
        PbTag(out, field, 2); PbVarint(out, n); out.append(d, n);
    }
    static void PbStringField(std::string& out, uint32_t field, const std::string& s)
    {
        PbBytesField(out, field, s.data(), s.size());
    }

    static std::string BuildBaseRequest()
    {
        std::string m;
        static const char dev[] = "Windows";
        PbBytesField(m, 1, "", 0);
        PbVarintField(m, 2, 0);
        PbBytesField(m, 3, dev, sizeof(dev) - 1);
        PbVarintField(m, 4, 0);
        PbBytesField(m, 5, dev, sizeof(dev) - 1);
        PbVarintField(m, 6, 0);
        return m;
    }
    static std::string BuildAppMsg(const std::string& from, const std::string& to,
                                   const std::string& xml, uint32_t type,
                                   const std::string& cmid)
    {
        std::string m;
        PbStringField(m, 1, from);
        PbVarintField(m, 3, 0);
        PbStringField(m, 4, to);
        PbVarintField(m, 5, type);
        PbStringField(m, 6, xml);
        PbVarintField(m, 7, static_cast<uint32_t>(::time(nullptr)));
        PbStringField(m, 8, cmid);
        PbStringField(m, 12, "<msgsource><bizflag>0</bizflag></msgsource>");
        return m;
    }
    static std::string BuildSendAppMsgReq(const std::string& from, const std::string& to,
                                          const std::string& xml, uint32_t type,
                                          const std::string& cmid)
    {
        std::string base   = BuildBaseRequest();
        std::string appmsg = BuildAppMsg(from, to, xml, type, cmid);
        std::string out;
        PbBytesField(out, 1, base.data(), base.size());
        PbBytesField(out, 2, appmsg.data(), appmsg.size());
        return out;
    }

    // ---- POD protobuf response parsers (usable inside __try) -------------
    static bool PbReadVarint(const uint8_t* d, uint32_t n, uint32_t* pos, uint64_t* val)
    {
        uint64_t r = 0; int sh = 0;
        while (*pos < n && sh <= 63) {
            uint8_t b = d[(*pos)++];
            r |= static_cast<uint64_t>(b & 0x7F) << sh;
            if (!(b & 0x80)) { *val = r; return true; }
            sh += 7;
        }
        return false;
    }
    static int ParseBaseResponseRet(const uint8_t* d, uint32_t n)
    {
        uint32_t pos = 0;
        while (pos < n) {
            uint64_t tag = 0;
            if (!PbReadVarint(d, n, &pos, &tag)) return 0;
            uint32_t f = static_cast<uint32_t>(tag >> 3), w = static_cast<uint32_t>(tag & 7);
            if (w == 0) { uint64_t v = 0; if (!PbReadVarint(d, n, &pos, &v)) return 0; if (f == 1) return static_cast<int>(v); }
            else if (w == 2) { uint64_t l = 0; if (!PbReadVarint(d, n, &pos, &l) || pos + l > n) return 0; pos += static_cast<uint32_t>(l); }
            else if (w == 1) { if (pos + 8 > n) return 0; pos += 8; }
            else if (w == 5) { if (pos + 4 > n) return 0; pos += 4; }
            else return 0;
        }
        return 0;
    }
    static int ParseSendAppMsgRet(const uint8_t* d, uint32_t n)
    {
        uint32_t pos = 0;
        while (pos < n) {
            uint64_t tag = 0;
            if (!PbReadVarint(d, n, &pos, &tag)) break;
            uint32_t f = static_cast<uint32_t>(tag >> 3), w = static_cast<uint32_t>(tag & 7);
            if (w == 0) { uint64_t v = 0; if (!PbReadVarint(d, n, &pos, &v)) break; }
            else if (w == 2) { uint64_t l = 0; if (!PbReadVarint(d, n, &pos, &l) || pos + l > n) break; if (f == 1) return ParseBaseResponseRet(d + pos, static_cast<uint32_t>(l)); pos += static_cast<uint32_t>(l); }
            else if (w == 1) { if (pos + 8 > n) break; pos += 8; }
            else if (w == 5) { if (pos + 4 > n) break; pos += 4; }
            else break;
        }
        return 0;
    }

    // ---- custom task vtable slots (POD, __fastcall; run on WeChat's network
    //      worker thread => SEH-guarded, no C++ objects needing unwinding) --
    static __int64 __fastcall MyAppMsgDtor(uint64_t self, __int64, __int64)
    {
        return static_cast<__int64>(self);   // no-op: task intentionally leaked
    }
    static __int64 __fastcall MyAppMsgGetInner(uint64_t self)
    {
        return static_cast<__int64>(self + 240);
    }
    static __int64 __fastcall MyAppMsgDummy(uint64_t, __int64, __int64, __int64)
    {
        return 1;
    }
    static char __fastcall MyAppMsgSerialize(uint64_t self, uint64_t holder,
                                             uint64_t /*a3*/, uint8_t* a4, uint64_t /*a5*/)
    {
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AppMsgSerializeCalls));
        __try {
            if (a4) *a4 = 1;   // BaseRequest is embedded in our bytes => report OK
            const uint8_t* data = nullptr; uint32_t size = 0;
            AppMsgEnsureCs();
            EnterCriticalSection(&g_appmsgCs);
            for (int i = 0; i < 16; ++i) {
                if (static_cast<uint64_t>(g_appmsgPending[i].taskPtr) == self) {
                    data = g_appmsgPending[i].reqData;
                    size = g_appmsgPending[i].reqSize;
                    break;
                }
            }
            LeaveCriticalSection(&g_appmsgCs);
            if (data && size && holder) {
                using HolderWrite_t = __int64(__fastcall*)(uint64_t, uint64_t, uint32_t);
                HolderWrite_t hw = reinterpret_cast<HolderWrite_t>(
                    GetWeixinDllBase() + offset::appmsg_holder_write);
                hw(holder, reinterpret_cast<uint64_t>(data), size);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return 1;
    }
    static char __fastcall MyAppMsgResponse(uint64_t self, uint64_t holder)
    {
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AppMsgResponseCalls));
        __try {
            uintptr_t base = GetWeixinDllBase();
            using HolderSize_t = __int64(__fastcall*)(uint64_t);
            using HolderData_t = __int64(__fastcall*)(uint64_t, int);
            HolderSize_t hs = reinterpret_cast<HolderSize_t>(base + offset::appmsg_holder_size);
            HolderData_t hd = reinterpret_cast<HolderData_t>(base + offset::appmsg_holder_data);
            uint32_t size = static_cast<uint32_t>(hs(holder));
            const uint8_t* data = reinterpret_cast<const uint8_t*>(hd(holder, 0));
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgLastRespSize),
                                  static_cast<LONG64>(size));
            int ret = 0;
            if (data && size && size < 8u * 1024u * 1024u)
                ret = ParseSendAppMsgRet(data, size);
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AppMsgLastRet),
                                  static_cast<LONG64>(ret));
            AppMsgEnsureCs();
            EnterCriticalSection(&g_appmsgCs);
            for (int i = 0; i < 16; ++i) {
                if (static_cast<uint64_t>(g_appmsgPending[i].taskPtr) == self) {
                    g_appmsgPending[i].ret = ret;
                    InterlockedExchange(&g_appmsgPending[i].done, 1);
                    if (g_appmsgPending[i].evt) SetEvent(g_appmsgPending[i].evt);
                    break;
                }
            }
            LeaveCriticalSection(&g_appmsgCs);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return 1;
    }

    static void*        g_appmsgVtable[6]  = {};
    static void*        g_appmsgVtable2[4] = {};
    static volatile LONG g_appmsgVtableState = 0;
    static void AppMsgEnsureVtable()
    {
        if (InterlockedCompareExchange(&g_appmsgVtableState, 1, 0) == 0) {
            g_appmsgVtable[0] = reinterpret_cast<void*>(&MyAppMsgDtor);
            g_appmsgVtable[1] = reinterpret_cast<void*>(&MyAppMsgSerialize);
            g_appmsgVtable[2] = reinterpret_cast<void*>(&MyAppMsgResponse);
            g_appmsgVtable[3] = reinterpret_cast<void*>(&MyAppMsgGetInner);
            g_appmsgVtable[4] = reinterpret_cast<void*>(&MyAppMsgDummy);
            g_appmsgVtable[5] = reinterpret_cast<void*>(static_cast<uintptr_t>(1));
            g_appmsgVtable2[0] = reinterpret_cast<void*>(&MyAppMsgDummy);
            g_appmsgVtable2[1] = reinterpret_cast<void*>(&MyAppMsgDummy);
            g_appmsgVtable2[2] = reinterpret_cast<void*>(&MyAppMsgDummy);
            g_appmsgVtable2[3] = reinterpret_cast<void*>(&MyAppMsgDummy);
            InterlockedExchange(&g_appmsgVtableState, 2);
        }
        while (g_appmsgVtableState != 2)
            Sleep(0);
    }

    // SEH-guarded task build + dispatch.  POD only (raw pointers + Win32
    // handles), so __try/__except is legal.  The task, task_info, callback
    // holder and pre-serialized request bytes are all intentionally leaked so
    // the async worker can never hit a use-after-free.
    static bool SubmitAppMsgTask(uintptr_t base, uint64_t manager,
                                 const uint8_t* reqData, uint32_t reqSize,
                                 uint32_t timeoutMs, int* outRet)
    {
        if (!base || !manager || !reqData || !reqSize)
            return false;
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AppMsgSendCalls));
        AppMsgEnsureCs();
        AppMsgEnsureVtable();

        static const char kEndpoint[] = "/cgi-bin/micromsg-bin/sendappmsg"; // 32 chars

        HANDLE evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!evt)
            return false;

        void* task_info = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, 0x40);
        void* task      = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, 0x200);
        void* cbHolder  = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, 0x08);
        if (!task_info || !task || !cbHolder) {
            CloseHandle(evt);
            return false;
        }

        bool dispatched = false;
        __try {
            // task_info layout (verified against sub_7FFE9200F120):
            uint8_t* ti = static_cast<uint8_t*>(task_info);
            ti[0]  = 0xDE;                                    // header (echoes cgi id)
            ti[12] = 0x01;                                    // dword@+12 != 0 => task+57 flag
            *reinterpret_cast<uint32_t*>(ti + 16) = 222;      // cgi type => task+12
            *reinterpret_cast<uint32_t*>(ti + 20) = 0;        // => task+80
            *reinterpret_cast<uint64_t*>(ti + 24) =           // endpoint data ptr (cap>=16 branch)
                reinterpret_cast<uint64_t>(kEndpoint);
            *reinterpret_cast<uint64_t*>(ti + 40) = 32;       // endpoint len
            *reinterpret_cast<uint64_t*>(ti + 48) = 47;       // endpoint cap
            ti[56] = 0x01;                                    // byte@+56 => task+59

            using TaskCtor_t = void(__fastcall*)(void*, void*);
            TaskCtor_t ctor = reinterpret_cast<TaskCtor_t>(base + offset::appmsg_task_ctor);
            ctor(task, task_info);

            // Override the task vtable + response-callback holder so no native
            // serialize/destruct ever runs on our leaked task.
            *reinterpret_cast<uint64_t*>(task) = reinterpret_cast<uint64_t>(&g_appmsgVtable[0]);
            *reinterpret_cast<uint64_t*>(cbHolder) = reinterpret_cast<uint64_t>(&g_appmsgVtable2[0]);
            *reinterpret_cast<uint64_t*>(static_cast<uint8_t*>(task) + 208) =
                reinterpret_cast<uint64_t>(cbHolder);

            AppMsgRegister(reinterpret_cast<uint64_t>(task), reqData, reqSize, evt);

            // Dispatch through the live network manager: manager->vtable[5].
            using Dispatch_t = __int64(__fastcall*)(uint64_t, uint64_t);
            uint64_t mvt = *reinterpret_cast<uint64_t*>(manager);
            Dispatch_t dispatch = *reinterpret_cast<Dispatch_t*>(mvt + 40);
            dispatch(manager, reinterpret_cast<uint64_t>(task));
            dispatched = true;
            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AppMsgDispatchOk));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            dispatched = false;
            InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_AppMsgDispatchFail));
        }

        if (dispatched && timeoutMs)
            WaitForSingleObject(evt, timeoutMs);

        LONG done = 0; int ret = 0;
        AppMsgUnregister(reinterpret_cast<uint64_t>(task), &done, &ret);
        if (outRet) *outRet = ret;
        // Success = the task was dispatched through the live manager.  The
        // response-notify callback (vtable slot[2]) is best-effort: the card is
        // already handed to WeChat's network worker at dispatch time and sends
        // regardless of whether our reply parse lands inside the timeout.  When
        // no response arrives, `ret` stays 0 (initial), so the caller treats it
        // as success; only a response that actually parses a non-zero
        // BaseResponse.ret marks a real server-side rejection.
        (void)done;
        return dispatched;
    }

    // Resolve the current account's REAL internal wxid (wxid_xxx), which the
    // sendappmsg CGI requires as AppMsg.fromusername.  SelfInfo.wxid may hold
    // the human alias (e.g. "python100day") which the server rejects (ret=-2),
    // so prefer, in order:
    //   1) the self wxid captured live at the sync-message hook (object+0x38),
    //   2) the wxid parsed from the captured contact-DB path
    //      (...\xwechat_files\<wxid>_<suffix>\db_storage\contact\contact.db),
    //   3) SelfInfo.wxid only if it already looks like a wxid_ id.
    static std::string ResolveSelfWxid()
    {
        auto looksLikeWxid = [](const std::string& s) {
            return s.size() > 5 && s.rfind("wxid_", 0) == 0;
        };

        // 1) live self wxid from the message hook.
        std::string live(g_SyncBatchText2);
        if (looksLikeWxid(live))
            return live;

        // 2) parse the contact-DB path folder name.
        std::string path(g_SqliteContactDbPath);
        const char* marker = "xwechat_files\\";
        size_t p = path.find(marker);
        if (p != std::string::npos) {
            size_t start = p + strlen(marker);
            size_t end = path.find('\\', start);
            if (end != std::string::npos && end > start) {
                std::string folder = path.substr(start, end - start);
                // folder = "<wxid>_<suffix>": strip the trailing "_<suffix>"
                // only when there is more than one underscore (the first one
                // belongs to the "wxid_" prefix itself).
                if (folder.rfind("wxid_", 0) == 0) {
                    size_t last = folder.rfind('_');
                    if (last != std::string::npos &&
                        folder.find('_') != last) {
                        folder = folder.substr(0, last);
                    }
                    if (looksLikeWxid(folder))
                        return folder;
                }
            }
        }

        // 3) last resort: SelfInfo.wxid if it is already a wxid_ id.
        if (looksLikeWxid(SelfInfo.wxid))
            return SelfInfo.wxid;
        return std::string();
    }

    bool SendAppMsg(const std::string& to_wxid, const std::string& xml,
                    uint64_t type)
    {
        if (to_wxid.empty() || xml.empty() || !GetModuleHandleA("Weixin.dll"))
            return false;
        uintptr_t base = GetWeixinDllBase();
        if (!base)
            return false;
        // Live network manager captured passively at the F120 submit hook.  A
        // prior real card send/forward THIS login is required to populate it.
        uint64_t manager = static_cast<uint64_t>(g_AppMsgSubmitManager);
        if (!manager)
            return false;
        std::string fromWxid = ResolveSelfWxid();
        if (fromWxid.empty())
            return false;

        // clientmsgid: "{tick}{tid}" (mirrors the reference project).
        char cmidBuf[64];
        snprintf(cmidBuf, sizeof(cmidBuf), "%llu%lu",
                 static_cast<unsigned long long>(::GetTickCount64()),
                 static_cast<unsigned long>(::GetCurrentThreadId()));
        std::string cmid(cmidBuf);

        std::string req = BuildSendAppMsgReq(fromWxid, to_wxid, xml,
                                             static_cast<uint32_t>(type), cmid);
        if (req.empty() || req.size() > 4u * 1024u * 1024u)
            return false;

        // Leak the serialized bytes: the async worker's serialize callback
        // reads them on another thread, so freeing here would risk a UAF.
        uint8_t* leaked = static_cast<uint8_t*>(
            ::HeapAlloc(::GetProcessHeap(), 0, req.size()));
        if (!leaked)
            return false;
        memcpy(leaked, req.data(), req.size());

        int ret = 0;
        bool ok = SubmitAppMsgTask(base, manager, leaked,
                                   static_cast<uint32_t>(req.size()), 1500, &ret);
        return ok && ret == 0;
    }

}
