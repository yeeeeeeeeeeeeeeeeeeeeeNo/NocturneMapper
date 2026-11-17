#include <cstdint>
#include <intrin.h>

using NTSTATUS = long;

struct Ring0Telemetry {
    uint64_t magic;       // 0x4E4F435455524E45ULL ("NOCTURNE")
    uint64_t hwCr3;       // __readcr3()
    uint64_t hwCr4;       // __readcr4()
    uint64_t msrLstar;    // __readmsr(0xC0000082) -> KiSystemCall64
    uint64_t kthread;     // __readgsqword(0x188)  -> _ETHREAD*
    uint64_t irql;        // __readcr8()
    uint64_t tsc;         // __rdtsc()
};

// Map-ready kernel payload entry signature:
// Called directly via NocturneMapper's CallKernelFunction with:
//   rcx = mappedKernelBase
//   rdx = mappedImageSize
// Executes privileged Ring-0-only instructions (CR3, CR4, CR8, IA32_LSTAR MSR, KPCR._ETHREAD)
// and stamps them into the staging header slot (+0x300) before header scrubbing.
extern "C" NTSTATUS __stdcall CustomDriverEntry(uint64_t mappedKernelBase, uint64_t mappedImageSize) {
    if (!mappedKernelBase || !mappedImageSize) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }

    auto* proof = reinterpret_cast<volatile Ring0Telemetry*>(mappedKernelBase + 0x300);
    proof->magic    = 0x4E4F435455524E45ULL;
    proof->hwCr3    = __readcr3();
    proof->hwCr4    = __readcr4();
    proof->msrLstar = __readmsr(0xC0000082);
    proof->kthread  = __readgsqword(0x188);
    proof->irql     = __readcr8();
    proof->tsc      = __rdtsc();

    return static_cast<NTSTATUS>(0x13370001L);
}
