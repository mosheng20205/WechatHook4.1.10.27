#include "SundaySearch.h"
#include <algorithm>

static size_t SundaySearch(const BYTE* target, int tLen, const BYTE* pattern, int pLen, std::vector<size_t>& offsets)
{
    if (!target || !pattern || tLen < pLen || pLen <= 0)
        return offsets.size();
    const size_t SHIFT_SIZE = 0x100;
    BYTE shift[SHIFT_SIZE] = { 0 };
    memset(shift, pLen + 1, SHIFT_SIZE);
    for (int i = 0; i < pLen; i++)
        shift[pattern[i]] = pLen - i;
    for (int i = 0; i <= tLen - pLen; )
    {
        for (int j = 0; j < pLen; j++)
        {
            if (target[i + j] != pattern[j]) break;
            if (j == pLen - 1)
                offsets.push_back(i);
        }
        if (i == tLen - pLen)
            break;
        i += shift[target[i + pLen]];
    }
    return offsets.size();
}

size_t ScanPattern(HANDLE hProcess, BYTE* pattern, int pLen, std::vector<LPVOID>& results)
{
    if (!hProcess || !pattern || pLen <= 0)
        return results.size();

    // The old implementation issued one ReadProcessMemory call per 4 KB
    // page while walking the entire 128-TB user address range. That made the
    // first contact query block for tens of seconds. Scan readable regions in
    // 1 MB chunks instead, retaining pLen-1 bytes between chunks.
    constexpr size_t kChunkSize = 0x100000;
    const size_t overlap = pLen > 1 ? static_cast<size_t>(pLen - 1) : 0;
    std::vector<BYTE> mem(kChunkSize + overlap);
    MEMORY_BASIC_INFORMATION mbi{};

    auto isReadable = [](DWORD protect) {
        if (protect & (PAGE_NOACCESS | PAGE_GUARD))
            return false;
        switch (protect & 0xFF) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    };
#ifndef _WIN64
    uintptr_t curAddress = 0x10000;
    const uintptr_t maxAddress = 0xFFFEFFFF;
#else
    // WeChat 4.1.10.27 stores its live SQLite handles in private heap
    // allocations in this user-VA band. Restricting discovery to this band
    // avoids walking the full 128-TB address space and keeps HTTP reads fast.
    uintptr_t curAddress = 0x10000000000ULL;
    const uintptr_t maxAddress = 0x40000000000ULL;
#endif
    while (curAddress < maxAddress)
    {
        const SIZE_T queried = VirtualQueryEx(hProcess, reinterpret_cast<void*>(curAddress),
                                              &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (queried == 0 || mbi.RegionSize == 0) {
            curAddress += 0x1000;
            continue;
        }
        const uintptr_t regionEnd = mbi.BaseAddress &&
            reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize > curAddress
            ? reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize
            : curAddress + 0x1000;
#ifndef _WIN64
        if (regionEnd <= curAddress) break;
#else
        if (regionEnd <= curAddress) break;
#endif
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && isReadable(mbi.Protect)) {
            for (uintptr_t chunkBegin = curAddress; chunkBegin < regionEnd; chunkBegin += kChunkSize) {
                const uintptr_t readBegin = chunkBegin > curAddress + overlap
                    ? chunkBegin - overlap : curAddress;
                const size_t request = static_cast<size_t>(std::min<uintptr_t>(
                    kChunkSize + overlap, regionEnd - readBegin));
                SIZE_T numberOfRead = 0;
                if (!ReadProcessMemory(hProcess, reinterpret_cast<void*>(readBegin),
                                       mem.data(), request, &numberOfRead) ||
                    numberOfRead < static_cast<SIZE_T>(pLen))
                    continue;
                std::vector<size_t> offsets;
                SundaySearch(mem.data(), static_cast<int>(numberOfRead), pattern, pLen, offsets);
                for (const size_t offset : offsets) {
                    const uintptr_t match = readBegin + offset;
                    if (match >= chunkBegin && match + static_cast<size_t>(pLen) <= regionEnd)
                        results.push_back(reinterpret_cast<LPVOID>(match));
                }
            }
        }
        curAddress = regionEnd;
    }
    return results.size();
}
