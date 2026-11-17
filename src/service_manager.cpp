#include "../include/service_manager.hpp"
#include <winternl.h>
#include <fstream>
#include <vector>
#include <iostream>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ntdll.lib")

extern "C" {
    NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);
    NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
    NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
}

namespace nocturne {

constexpr ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
constexpr NTSTATUS STATUS_IMAGE_ALREADY_LOADED = 0xC000010EL;
constexpr NTSTATUS STATUS_OBJECT_NAME_COLLISION = 0xC0000035L;

ServiceManager::~ServiceManager() {
    UnloadAndRemove();
}

bool ServiceManager::EnablePrivilege(ULONG privilegeId) {
    BOOLEAN wasEnabled = FALSE;
    NTSTATUS status = RtlAdjustPrivilege(privilegeId, TRUE, FALSE, &wasEnabled);
    return NT_SUCCESS(status);
}

uint32_t ServiceManager::ReadPeTimestamp(const std::wstring& driverDiskPath) const {
    std::ifstream file(driverDiskPath, std::ios::binary);
    if (!file.is_open()) return 0;
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    file.seekg(dos.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS64 nt{};
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt.FileHeader.TimeDateStamp;
}

bool ServiceManager::RegisterAndLoad(const std::wstring& driverDiskPath, const std::wstring& serviceName) {
    if (!EnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE)) {
        std::wcerr << L"Failed to enable SeLoadDriverPrivilege (Run as Administrator)\n";
        return false;
    }

    wchar_t fullPath[MAX_PATH * 2] = {};
    if (!GetFullPathNameW(driverDiskPath.c_str(), MAX_PATH * 2, fullPath, nullptr)) {
        return false;
    }

    std::wstring resolvedPath(fullPath);
    auto slashPos = resolvedPath.find_last_of(L"\\/");
    m_driverFileName = (slashPos != std::wstring::npos) ? resolvedPath.substr(slashPos + 1) : resolvedPath;
    m_serviceName = serviceName;
    m_registryKeyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + m_serviceName;

    HKEY hKey = nullptr;
    LSTATUS regStatus = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        m_registryKeyPath.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        nullptr,
        &hKey,
        nullptr
    );
    if (regStatus != ERROR_SUCCESS) {
        std::wcerr << L"RegCreateKeyExW failed: " << regStatus << L"\n";
        return false;
    }

    std::wstring ntImagePath = L"\\??\\" + resolvedPath;
    DWORD serviceType = SERVICE_KERNEL_DRIVER;
    DWORD startType = SERVICE_DEMAND_START;
    DWORD errorControl = SERVICE_ERROR_NORMAL;

    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(ntImagePath.c_str()), static_cast<DWORD>((ntImagePath.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&serviceType), sizeof(DWORD));
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&startType), sizeof(DWORD));
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&errorControl), sizeof(DWORD));
    RegCloseKey(hKey);
    m_registered = true;

    std::wstring ntRegistryPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + m_serviceName;
    UNICODE_STRING uService{};
    RtlInitUnicodeString(&uService, ntRegistryPath.c_str());

    NTSTATUS status = NtLoadDriver(&uService);
    if (!NT_SUCCESS(status) && status != STATUS_IMAGE_ALREADY_LOADED && status != STATUS_OBJECT_NAME_COLLISION) {
        std::wcerr << L"NtLoadDriver failed with NTSTATUS: 0x" << std::hex << status << std::dec << L"\n";
        UnloadAndRemove();
        return false;
    }

    m_loaded = true;
    return true;
}

bool ServiceManager::UnloadAndRemove() {
    bool ok = true;
    if (m_loaded && !m_serviceName.empty()) {
        std::wstring ntRegistryPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + m_serviceName;
        UNICODE_STRING uService{};
        RtlInitUnicodeString(&uService, ntRegistryPath.c_str());
        NTSTATUS st = NtUnloadDriver(&uService);
        if (!NT_SUCCESS(st)) {
            ok = false;
        }
        m_loaded = false;
    }
    if (m_registered && !m_registryKeyPath.empty()) {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, m_registryKeyPath.c_str());
        m_registered = false;
    }
    return ok;
}

} // namespace nocturne
