#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <string>
#include "carrier_io.hpp"

namespace nocturne {

struct PiDDBCacheEntry {
    LIST_ENTRY list;
    UNICODE_STRING driverName;
    ULONG timeDateStamp;
    NTSTATUS loadStatus;
    char _0x0028[16];
};

struct MmUnloadedDriverEntry {
    UNICODE_STRING name;
    PVOID moduleStart;
    PVOID moduleEnd;
    ULONG64 unloadTime;
};

struct HashBucketEntry {
    struct HashBucketEntry* next;
    UNICODE_STRING driverName;
    ULONG certHash[5];
};

class TelemetrySanitizer {
public:
    TelemetrySanitizer(CarrierIo& io, const MapperConfig& cfg);

    bool SanitizeAll(const std::wstring& driverFileName, uint32_t timeDateStamp);
    bool ClearPiDDBCacheTable(const std::wstring& driverFileName, uint32_t timeDateStamp);
    bool ClearMmUnloadedDrivers(const std::wstring& driverFileName);
    bool ClearKernelHashBucketList(const std::wstring& driverFileName);

private:
    bool AcquireResourceExclusive(uint64_t resourcePtr, bool wait);
    bool ReleaseResource(uint64_t resourcePtr);

    CarrierIo& m_io;
    MapperConfig m_cfg;
};

} // namespace nocturne
