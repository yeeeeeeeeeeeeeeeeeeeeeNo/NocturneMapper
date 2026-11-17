#include "../include/config.hpp"
#include "../include/service_manager.hpp"
#include "../include/carrier_io.hpp"
#include "../include/pe_loader.hpp"
#include "../include/telemetry_sanitizer.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace nocturne;

static void PrintUsage() {
    std::wcout << L"Usage:\n"
               << L"  NocturneMapper.exe --map <payload.sys> --driver <carrier.sys>\n\n"
               << L"Options:\n"
               << L"  --carrier <ene|atszio|ami|glckio|custom>  Select non-Intel carrier preset\n"
               << L"  --driver <path_to_carrier.sys>            Path to signed carrier binary on disk\n"
               << L"  --config <path_to_mapper.cfg>             Load custom IOCTLs, offsets, and CR3 from config\n"
               << L"  --validate-only                           Parse & validate PE64 relocations/imports offline\n"
               << L"  --pool                                    Use ExAllocatePoolWithTag instead of IndependentPages\n";
}

int wmain(int argc, wchar_t* argv[]) {
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

    std::wcout << L"Hunting pattern\n";
    auto tHuntStart = std::chrono::high_resolution_clock::now();

    CarrierIo io(cfg);
    PeLoader loader(io, cfg);

    auto tHuntEnd = std::chrono::high_resolution_clock::now();
    double huntSecs = std::chrono::duration<double>(tHuntEnd - tHuntStart).count();

    std::vector<uint8_t> rawPe;
    if (!loader.LoadFileToMemory(payloadPath, rawPe)) {
        std::wcerr << L"Could not read target payload: " << payloadPath << L"\n";
        return 1;
    }

    IMAGE_NT_HEADERS64* ntHeaders = nullptr;
    if (!loader.ValidatePe64(rawPe, ntHeaders)) {
        std::wcerr << L"Target payload is not a valid 64-bit PE image\n";
        return 1;
    }

    std::wcout << L"Sniped in " << std::fixed << std::setprecision(4) << huntSecs << L"s\n\n";

    if (validateOnly) {
        std::wcout << L"Offline PE64 validation passed.\n";
        return 0;
    }

    std::wcout << L"Manual mapping ur driver\n";
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
        std::wcerr << L"Failed to connect to carrier device or resolve System CR3.\n";
        if (!carrierDiskPath.empty()) svc.UnloadAndRemove();
        return 1;
    }

    MappedImageInfo mappedInfo{};
    if (!loader.MapDriver(rawPe, 0, 0, mappedInfo)) {
        std::wcerr << L"Kernel manual mapping failed.\n";
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

    std::wcout << L"mapped in " << std::fixed << std::setprecision(4) << mapSecs << L"s\n\n";
    std::wcout << L"ENJOY -_-\n";
    return 0;
}
