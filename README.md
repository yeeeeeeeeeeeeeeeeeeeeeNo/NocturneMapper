# NocturneMapper (x64 Ring-0 Manual Mapper)

Non-Intel multi-carrier x64 Windows kernel manual mapper written in modern C++20. Projects unsigned 64-bit PE drivers into Ring 0 using physical memory mapping (`\Device\PhysicalMemory`), full 4-level hardware page table walks (`CR3 -> PML4 -> PDPT -> PD -> PT`), exported contiguous independent page allocation (`MmAllocateContiguousMemory` + physical PTE `NX=0` strip), synchronous syscall redirection, and dynamic user-mode symbol pre-resolution across any Windows 10 / Windows 11 build.

---

## Key Architecture

* **Multi-Carrier Non-Intel Backend (`include/config.hpp`, `src/carrier_io.cpp`)**:
  * **ENE Technology (`ene.sys` / `\\.\EneIo`)** — Included in `bin/ene.sys` (`IOCTL 0x80102040` / `0x80102044`)
  * **ASRock /ene (`GLCKIO2.sys` / `\\.\GLCKIo2`)** — Included in `bin/GLCKIO2.sys`
  * **ASUSTeK (`ATSZIO64.sys` / `\\.\ATSZIO`)**
  * **AMI (`amifldrv64.sys` / `\\.\amifldrv0`)**
  * **Custom (`mapper.cfg`)** — Configurable IOCTLs, device links, and packet layouts
* **Hardware 4-Level Page Table Walk**:
  * Automatically locates the live `System CR3` (`PML4`) from the physical `PROCESSOR_START_BLOCK` low-memory stub (`0x1000..0xFFFF0`) and translates kernel virtual addresses to physical RAM to bypass `CR0.WP`.
* **Contiguous Independent Kernel Memory (`src/pe_loader.cpp`)**:
  * Allocates Ring-0 memory via exported `MmAllocateContiguousMemory` (outside `PoolBigPageTable`) and clears the hardware `NoExecute` (`NX`) bit directly on the physical leaf PTEs.
  * Scrubs PE/DOS headers (`MZ`, `PE\0\0`, section headers) and discardable sections (`.reloc`, `.pdata`, `INIT`) after `DriverEntry` execution.
* **Universal Dynamic OS Symbol Pre-Resolver (`ResolveLocalSystemSymbols`)**:
  * Pre-maps `C:\Windows\System32\ntoskrnl.exe` and `ci.dll` in user-mode to dynamically resolve `PiDDBLock`, `PiDDBCacheTable`, `MmUnloadedDrivers`, `MmLastUnloadedDriver`, `g_KernelHashBucketList`, and `g_HashCacheLock` in ~13ms across any Windows 10/11 build.
* **Full Forensic Table Sanitization (`src/telemetry_sanitizer.cpp`)**:
  * Scrubs `ntoskrnl!PiDDBCacheTable`, `ntoskrnl!MmUnloadedDrivers`, and `ci.dll!g_KernelHashBucketList` before unloading and deleting the temporary carrier service.

---

## Repository Structure

```text
NocturneMapper/
├── bin/
│   ├── NocturneMapper.exe    # Compiled x64 manual mapper
│   ├── payload_sample.sys    # Map-ready Ring-0 verification driver (captures CR3/CR4/LSTAR/ETHREAD)
│   ├── ene.sys               # Signed WHQL ENE Technology physical memory carrier
│   └── GLCKIO2.sys           # Signed WHQL GLCKIO2 physical memory carrier
├── include/
│   ├── config.hpp
│   ├── service_manager.hpp
│   ├── carrier_io.hpp
│   ├── pe_loader.hpp
│   └── telemetry_sanitizer.hpp
├── src/
│   ├── main.cpp
│   ├── service_manager.cpp
│   ├── carrier_io.cpp
│   ├── pe_loader.cpp
│   └── telemetry_sanitizer.cpp
├── payload/
│   └── payload_sample.cpp
├── mapper.cfg
└── build.bat
```

---

## Quick Start

### 1. Run (Administrator PowerShell)

```powershell
cd bin
.\NocturneMapper.exe --carrier ene --driver .\ene.sys --map .\payload_sample.sys
```

### 2. Offline PE64 Validation & Symbol Resolution Check

```powershell
.\bin\NocturneMapper.exe --map .\bin\payload_sample.sys --carrier ene --validate-only
```

### 3. Build from Source (Visual Studio 2022/2026 x64 MSVC)

```cmd
build.bat
```
