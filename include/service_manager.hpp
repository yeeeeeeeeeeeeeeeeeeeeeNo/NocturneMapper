#pragma once
#include <windows.h>
#include <string>
#include "config.hpp"

namespace nocturne {

class ServiceManager {
public:
    ServiceManager() = default;
    ~ServiceManager();

    ServiceManager(const ServiceManager&) = delete;
    ServiceManager& operator=(const ServiceManager&) = delete;

    bool EnablePrivilege(ULONG privilegeId);
    bool RegisterAndLoad(const std::wstring& driverDiskPath, const std::wstring& serviceName);
    bool UnloadAndRemove();

    const std::wstring& ActiveServiceName() const { return m_serviceName; }
    const std::wstring& ActiveDriverFileName() const { return m_driverFileName; }
    uint32_t ReadPeTimestamp(const std::wstring& driverDiskPath) const;

private:
    std::wstring m_serviceName;
    std::wstring m_driverFileName;
    std::wstring m_registryKeyPath;
    bool m_loaded = false;
    bool m_registered = false;
};

} // namespace nocturne
