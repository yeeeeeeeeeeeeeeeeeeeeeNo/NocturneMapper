#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "carrier_io.hpp"

namespace nocturne {

struct Ring0Telemetry {
    uint64_t magic = 0;       // 0x4E4F435455524E45ULL ("NOCTURNE")
    uint64_t hwCr3 = 0;       // __readcr3()
    uint64_t hwCr4 = 0;       // __readcr4()
    uint64_t msrLstar = 0;    // __readmsr(0xC0000082) -> KiSystemCall64
    uint64_t kthread = 0;     // __readgsqword(0x188)  -> _ETHREAD*
    uint64_t irql = 0;        // __readcr8()
    uint64_t tsc = 0;         // __rdtsc()
};

struct MappedImageInfo {
    uint64_t kernelBase = 0;
    uint32_t imageSize = 0;
    uint32_t entryPointRva = 0;
    NTSTATUS entryStatus = 0;
    bool usedIndependentPages = false;
    Ring0Telemetry ring0Proof{};
};

class PeLoader {
public:
    PeLoader(CarrierIo& io, const MapperConfig& cfg);

    bool LoadFileToMemory(const std::wstring& filePath, std::vector<uint8_t>& outBytes);
    bool ValidatePe64(const std::vector<uint8_t>& rawBytes, IMAGE_NT_HEADERS64*& outNtHeaders);

    // Kernel memory allocation (Independent Pages + PTE NX-bit clear, or Pool fallback)
    uint64_t AllocateKernelMemory(uint32_t size, bool& outUsedIndependentPages);
    bool FreeKernelMemory(uint64_t baseAddr, uint32_t size, bool usedIndependentPages);
    bool MakeRegionExecutable(uint64_t baseAddr, uint32_t size);

    // Full manual map pipeline
    bool MapDriver(const std::vector<uint8_t>& rawPeBytes, uint64_t param1, uint64_t param2, MappedImageInfo& outInfo);

private:
    bool ProcessRelocations(uint8_t* localImageBase, uint64_t remoteKernelBase, IMAGE_NT_HEADERS64* ntHeaders);
    bool ResolveImports(uint8_t* localImageBase, IMAGE_NT_HEADERS64* ntHeaders);
    void InitializeSecurityCookie(uint8_t* localImageBase, uint64_t remoteKernelBase, IMAGE_NT_HEADERS64* ntHeaders);
    void ScrubDiscardableAndHeaders(uint8_t* localImageBase, uint64_t remoteKernelBase, IMAGE_NT_HEADERS64* ntHeaders);

    CarrierIo& m_io;
    MapperConfig m_cfg;
};

} // namespace nocturne
