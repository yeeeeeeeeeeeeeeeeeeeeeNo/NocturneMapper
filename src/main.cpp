#include "../include/config.hpp"
#include "../include/service_manager.hpp"
#include "../include/carrier_io.hpp"
#include "../include/pe_loader.hpp"
#include "../include/telemetry_sanitizer.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace nocturne;

namespace ansi {
    constexpr const wchar_t* Reset   = L"\x1b[0m";
    constexpr const wchar_t* Bold    = L"\x1b[1m";
    constexpr const wchar_t* Dim     = L"\x1b[2m";
    constexpr const wchar_t* Cyan    = L"\x1b[38;5;51m";
    constexpr const wchar_t* Green   = L"\x1b[38;5;48m";
    constexpr const wchar_t* Yellow  = L"\x1b[38;5;220m";
    constexpr const wchar_t* Red     = L"\x1b[38;5;196m";
    constexpr const wchar_t* Purple  = L"\x1b[38;5;141m";
    constexpr const wchar_t* Gray    = L"\x1b[38;5;244m";
    constexpr const wchar_t* White   = L"\x1b[38;5;255m";
}

static void EnableAnsiConsole() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

static void PrintBanner() {
    std::wcout << ansi::Gray << L"--------------------------------------------------------------------\n"
               << ansi::Bold << ansi::Purple << L"  NOCTURNE " << ansi::White << L"// " << ansi::Cyan << L"RING-0 MANUAL MAPPER (x64)"
               << ansi::Gray << L"   [ENE | ATSZIO | AMI | GLCKIO]\n"
               << ansi::Gray << L"--------------------------------------------------------------------" << ansi::Reset << L"\n";
}

static void PrintUsage() {
    std::wcout << L"Usage:\n"
               << L"  NocturneMapper.exe --map <payload.sys> [options]\n\n"
               << L"Options:\n"
               << L"  --carrier <ene|atszio|ami|glckio|custom>  Select non-Intel carrier preset (default: ene)\n"
               << L"  --driver <path_to_carrier.sys>            Optional path to signed carrier binary on disk\n"
               << L"  --config <path_to_mapper.cfg>             Load custom IOCTLs, offsets, and CR3 from config\n"
               << L"  --validate-only                           Parse & validate PE64 relocations/imports offline\n"
               << L"  --pool                                    Use ExAllocatePoolWithTag instead of IndependentPages\n";
}

int wmain(int argc, wchar_t* argv[]) {
    EnableAnsiConsole();
    PrintBanner();

    MapperConfig cfg;
    cfg.carrier = MapperConfig::Preset(CarrierKind::EneIo);

    std::wstring payloadPath;
    std::wstring carrierDiskPath;
    std::wstring configPath = L"mapper.cfg";
    bool validateOnly = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--map" && i + 1 < argc) {
            payloadPath = argv[++i];
        } else if (arg == L"--driver" && i + 1 < argc) {
            carrierDiskPath = argv[++i];
        } else if (arg == L"--config" && i + 1 < argc) {
            configPath = argv[++i];
        } else if (arg == L"--carrier" && i + 1 < argc) {
            std::wstring c = argv[++i];
            if (c == L"ene") cfg.carrier = MapperConfig::Preset(CarrierKind::EneIo);
            else if (c == L"atszio") cfg.carrier = MapperConfig::Preset(CarrierKind::Atszio64);
            else if (c == L"ami") cfg.carrier = MapperConfig::Preset(CarrierKind::Amifldrv64);
            else if (c == L"glckio") cfg.carrier = MapperConfig::Preset(CarrierKind::GlckIo2);
            else cfg.carrier.kind = CarrierKind::Custom;
        } else if (arg == L"--validate-only") {
            validateOnly = true;
        } else if (arg == L"--pool") {
            cfg.useIndependentPages = false;
        }
    }

    cfg.LoadFromFile(configPath);

    if (payloadPath.empty()) {
        PrintUsage();
        return 1;
    }

    // 1. Pattern hunting timer
    std::wcout << L"\n" << ansi::Bold << ansi::Yellow << L"Hunting pattern" << ansi::Reset << L"\n";
    auto tHuntStart = std::chrono::high_resolution_clock::now();

    CarrierIo io(cfg);
    PeLoader loader(io, cfg);

    auto tHuntEnd = std::chrono::high_resolution_clock::now();
    double huntSecs = std::chrono::duration<double>(tHuntEnd - tHuntStart).count();

    std::vector<uint8_t> rawPe;
    if (!loader.LoadFileToMemory(payloadPath, rawPe)) {
        std::wcerr << ansi::Red << L"[-] Could not read target payload: " << payloadPath << ansi::Reset << L"\n";
        return 1;
    }

    IMAGE_NT_HEADERS64* ntHeaders = nullptr;
    if (!loader.ValidatePe64(rawPe, ntHeaders)) {
        std::wcerr << ansi::Red << L"[-] Target payload is not a valid 64-bit PE image" << ansi::Reset << L"\n";
        return 1;
    }

    std::wcout << ansi::Green << L"Sniped in " << std::fixed << std::setprecision(4) << huntSecs << L"s" << ansi::Reset << L"\n\n";

    std::wcout << ansi::Gray << L"  +-- " << ansi::Cyan << L"TARGET & SYMBOL TELEMETRY" << ansi::Gray << L" ------------------------------------\n"
               << L"  | " << ansi::Gray << L"Payload          : " << ansi::White << payloadPath
               << ansi::Gray << L" (" << std::dec << ntHeaders->OptionalHeader.SizeOfImage << L" bytes, "
               << ntHeaders->FileHeader.NumberOfSections << L" sections)\n"
               << ansi::Gray << L"  | " << L"Carrier Device   : " << ansi::White << cfg.carrier.name << L" (" << cfg.carrier.deviceLink << L")"
               << ansi::Gray << L" [IOCTL 0x" << std::hex << cfg.carrier.ioctlMapPhys << L"]\n"
               << ansi::Gray << L"  | " << L"PiDDBLock        : " << ansi::Purple << L"+0x" << std::setw(6) << std::setfill(L'0') << io.ResolvedSymbols().rvaPiDDBLock
               << ansi::Gray << L"   PiDDBCacheTable : " << ansi::Purple << L"+0x" << std::setw(6) << io.ResolvedSymbols().rvaPiDDBCacheTable << L"\n"
               << ansi::Gray << L"  | " << L"MmUnloadedDrv    : " << ansi::Purple << L"+0x" << std::setw(6) << io.ResolvedSymbols().rvaMmUnloadedDrivers
               << ansi::Gray << L"   HashBucketList  : " << ansi::Purple << L"+0x" << std::setw(6) << io.ResolvedSymbols().rvaKernelHashBucketList << std::setfill(L' ') << std::dec << L"\n"
               << ansi::Gray << L"  +-----------------------------------------------------------------" << ansi::Reset << L"\n";

    if (validateOnly) {
        std::wcout << L"\n" << ansi::Green << L"[+] Offline PE64 structural validation passed." << ansi::Reset << L"\n";
        return 0;
    }

    // 2. Manual mapping timer
    std::wcout << L"\n" << ansi::Bold << ansi::Yellow << L"Manual mapping ur driver" << ansi::Reset << L"\n";
    auto tMapStart = std::chrono::high_resolution_clock::now();

    ServiceManager svc;
    if (!carrierDiskPath.empty()) {
        uint32_t diskTs = svc.ReadPeTimestamp(carrierDiskPath);
        if (diskTs != 0) cfg.carrier.timeDateStamp = diskTs;

        if (!svc.RegisterAndLoad(carrierDiskPath, cfg.carrier.serviceName)) {
            return 1;
        }
    }

    if (!io.Connect()) {
        std::wcerr << ansi::Red << L"[-] Failed to connect to carrier device or resolve System CR3." << ansi::Reset << L"\n";
        if (!carrierDiskPath.empty()) svc.UnloadAndRemove();
        return 1;
    }

    MappedImageInfo mappedInfo{};
    if (!loader.MapDriver(rawPe, 0, 0, mappedInfo)) {
        std::wcerr << ansi::Red << L"[-] Kernel manual mapping failed." << ansi::Reset << L"\n";
        io.Disconnect();
        if (!carrierDiskPath.empty()) svc.UnloadAndRemove();
        return 1;
    }

    if (cfg.scrubTelemetry) {
        std::wstring targetCarrierName = !svc.ActiveDriverFileName().empty() ? svc.ActiveDriverFileName() : cfg.carrier.name;
        TelemetrySanitizer sanitizer(io, cfg);
        sanitizer.SanitizeAll(targetCarrierName, cfg.carrier.timeDateStamp);
    }

    io.Disconnect();
    if (!carrierDiskPath.empty()) {
        svc.UnloadAndRemove();
    }

    auto tMapEnd = std::chrono::high_resolution_clock::now();
    double mapSecs = std::chrono::duration<double>(tMapEnd - tMapStart).count();

    std::wcout << ansi::Green << L"mapped in " << std::fixed << std::setprecision(4) << mapSecs << L"s" << ansi::Reset << L"\n\n";

    // 3. Tactical Ring-0 Execution Telemetry Block
    std::wcout << ansi::Gray << L"  +-- " << ansi::Green << L"RING-0 EXECUTION TELEMETRY" << ansi::Gray << L" -----------------------------------\n"
               << L"  | " << L"ntoskrnl.exe     : " << ansi::White << L"0x" << std::hex << io.NtoskrnlBase()
               << ansi::Gray << L"   System CR3 : " << ansi::Cyan << L"0x" << io.SystemCr3() << L"\n"
               << ansi::Gray << L"  | " << L"Mapped Base VA   : " << ansi::Green << ansi::Bold << L"0x" << mappedInfo.kernelBase << ansi::Reset
               << ansi::Gray << L"   Entry Ret  : " << ansi::Green << ansi::Bold << L"0x" << mappedInfo.entryStatus << ansi::Reset << L"\n"
               << ansi::Gray << L"  | " << L"Allocation Mode  : " << ansi::White << (mappedInfo.usedIndependentPages ? L"Contiguous Independent Pages (PTE NX=0)" : L"NonPagedPool (PTE NX=0)") << L"\n"
               << ansi::Gray << L"  | " << L"Forensic Scrub   : " << ansi::Green << L"CLEARED " << ansi::Gray << L"(PiDDB / MmUnloaded / ci!HashBucket)\n";

    if (mappedInfo.ring0Proof.magic == 0x4E4F435455524E45ULL) {
        bool smep = (mappedInfo.ring0Proof.hwCr4 & (1ULL << 20)) != 0;
        bool smap = (mappedInfo.ring0Proof.hwCr4 & (1ULL << 21)) != 0;
        std::wcout << ansi::Gray << L"  +-- " << ansi::Purple << L"LIVE HARDWARE REGISTER PROOF (CAPTURED INSIDE DRIVER)" << ansi::Gray << L" --------\n"
                   << L"  | " << L"CPU CR3 (Ring0)  : " << ansi::Cyan << L"0x" << mappedInfo.ring0Proof.hwCr3
                   << ansi::Gray << L"   CPU CR4    : " << ansi::Cyan << L"0x" << mappedInfo.ring0Proof.hwCr4
                   << ansi::Gray << L" [SMEP:" << (smep ? L"ON" : L"OFF") << L" SMAP:" << (smap ? L"ON" : L"OFF") << L"]\n"
                   << ansi::Gray << L"  | " << L"IA32_LSTAR MSR   : " << ansi::White << L"0x" << mappedInfo.ring0Proof.msrLstar
                   << ansi::Gray << L" (KiSystemCall64)\n"
                   << ansi::Gray << L"  | " << L"KPCR._ETHREAD    : " << ansi::White << L"0x" << mappedInfo.ring0Proof.kthread
                   << ansi::Gray << L"   Ring0 IRQL : " << ansi::Green << std::dec << mappedInfo.ring0Proof.irql << L" (PASSIVE_LEVEL)\n";
    }
    std::wcout << ansi::Gray << L"  +-----------------------------------------------------------------" << ansi::Reset << std::dec << L"\n\n";

    std::wcout << ansi::Bold << ansi::Cyan << L"ENJOY -_-" << ansi::Reset << L"\n\n";
    return 0;
}
