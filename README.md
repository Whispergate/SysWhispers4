# SysWhispers4

> **AV/EDR evasion via direct and indirect system calls**
> Windows NT 3.1 through Windows 11 24H2 · x64 · x86 · WoW64 · ARM64

SysWhispers4 is a Python-based syscall stub generator that produces C/ASM code for invoking NT kernel functions directly, bypassing user-mode hooks placed by AV/EDR products on `ntdll.dll`.

Built on the lineage of [SysWhispers](https://github.com/jthuraisamy/SysWhispers) → [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) → [SysWhispers3](https://github.com/klezVirus/SysWhispers3), this version adds the most comprehensive set of SSN resolution strategies, invocation methods, and evasion capabilities to date.

---

## Evolution: SysWhispers 1 → 4

### Feature Comparison Matrix

| Feature | SW1 | SW2 | SW3 | **SW4** |
|---|:-:|:-:|:-:|:-:|
| **SSN Resolution** | | | | |
| Static embedded table | ✅ | ✅ | ✅ | ✅ |
| Hell's Gate (runtime ntdll parse) | ❌ | ✅ | ✅ | ✅ |
| Halo's Gate (hook-neighbor scan) | ❌ | ❌ | ✅ | ✅ |
| Tartarus' Gate (near+far JMP) | ❌ | ❌ | Partial | ✅ |
| FreshyCalls (sort-by-VA) | ❌ | ❌ | ❌ | **✅ New** |
| Static + dynamic fallback | ❌ | ❌ | ❌ | **✅ New** |
| **Invocation Methods** | | | | |
| Embedded (direct `syscall`) | ✅ | ✅ | ✅ | ✅ |
| Indirect (jmp to ntdll gadget) | ❌ | ❌ | ✅ | ✅ |
| Randomized indirect (per-call entropy) | ❌ | ❌ | Partial† | **✅ Fixed** |
| Egg hunt (no static `0F 05` on disk) | ❌ | ❌ | ✅ | ✅ |
| **Architecture** | | | | |
| x64 | ✅ | ✅ | ✅ | ✅ |
| x86 (32-bit sysenter) | ❌ | ❌ | ✅ | ✅ |
| WoW64 (Heaven's Gate) | ❌ | ❌ | ✅ | ✅ |
| ARM64 (`SVC #0`, `w8`) | ❌ | ❌ | ❌ | **✅ New** |
| **Compiler Support** | | | | |
| MSVC (MASM) | ✅ | ✅ | ✅ | ✅ |
| MinGW / GCC (GAS inline) | ❌ | ❌ | ✅ | ✅ |
| Clang (GAS inline) | ❌ | ❌ | ✅ | ✅ |
| **Evasion / Obfuscation** | | | | |
| Function name hashing | ❌ | ✅ | ✅ | ✅ (DJB2) |
| Stub ordering randomization | ❌ | ❌ | ❌ | **✅ New** |
| Junk instruction injection | ❌ | ❌ | ❌ | **✅ New** |
| XOR-encrypted SSN at rest | ❌ | ❌ | ❌ | **✅ New** |
| Gadget pool (up to 64 gadgets) | ❌ | ❌ | ❌ | **✅ New** |
| Call stack spoof helper | ❌ | ❌ | ❌ | **✅ New** |
| User-mode ETW bypass | ❌ | ❌ | ❌ | **✅ New** |
| **Syscall Table** | | | | |
| Windows XP → Win10 20H2 | ✅ | ✅ | ✅ | ✅ |
| Windows 11 21H2–24H2 | ❌ | ❌ | Partial | **✅ Full** |
| Windows Server 2022/2025 | ❌ | ❌ | ❌ | **✅ New** |
| Auto-update from j00ru | ❌ | ❌ | ❌ | **✅ New** |
| **Tool** | | | | |
| Python version | 2/3 | 3 | 3 | **3.10+** |
| Type annotations | ❌ | ❌ | Partial | **✅ Full** |

> † SW3's randomized method had a register-corruption bug — `RDTSC` overwrites `edx` (arg2). SW4 correctly saves `rdx → r11` before `rdtsc` and restores it without touching the stack.

---

## What's New in SysWhispers4

### 1. FreshyCalls Resolution (New Default)
Sorts all `Nt*` exports from ntdll by virtual address. Sorted index = SSN. Does **not** read from potentially-hooked function bytes — the most hook-resistant method available.

```c
// FreshyCalls: sort ntdll Nt* exports by VA → index = SSN
// Works even when ALL Nt* stubs are hooked (pure address-order analysis)
SW4_FreshyCalls(pNtdll);
```

### 2. Full Tartarus' Gate
Handles **both** near JMPs (`E9`) and far JMPs (`FF 25`) that EDRs use. Scans up to 16 neighboring stubs in both directions with automatic SSN adjustment.

```c
// Detects hook pattern:
if (pFn[0] == 0xE9 ||                    // near jmp rel32
    (pFn[0] == 0xFF && pFn[1] == 0x25)   // jmp [rip+offset]
    ) { /* hooked — scan neighbors */ }
```

### 3. ARM64 Support (`SVC #0`)
New ARM64 stub generator for Windows on ARM devices. Uses the correct ARM64 syscall ABI: SSN in `w8`, arguments in `x0–x7`, instruction `SVC #0`.

```asm
SW4_NtAllocateVirtualMemory PROC
    adrp  x9, SW4_SsnTable
    add   x9, x9, :lo12:SW4_SsnTable
    ldr   w8, [x9, #N]    ; w8 = SSN
    svc   #0               ; ARM64 syscall
    ret
    ENDP
```

### 4. Randomized Indirect (Bug Fixed + Gadget Pool)
SW4 pre-builds a pool of up to **64 unique `syscall;ret` gadgets** from ntdll's `.text` section. Each call picks a random gadget via `RDTSC` entropy — no function call needed in the stub.

```asm
SW4_NtAllocateVirtualMemory PROC
    mov  r10, rcx          ; arg1 → r10 (syscall ABI)
    mov  r11, rdx          ; SAVE rdx — rdtsc trashes edx!
    rdtsc                   ; eax:edx = TSC (clobbers edx)
    xor  eax, edx           ; mix
    and  eax, 63            ; pool index (0..63)
    lea  rcx, [SW4_GadgetPool]
    mov  rcx, QWORD PTR [rcx + rax*8]   ; random gadget
    mov  rdx, r11           ; RESTORE rdx
    mov  eax, DWORD PTR [SW4_SsnTable + N*4]
    jmp  rcx               ; → random ntdll syscall;ret
SW4_NtAllocateVirtualMemory ENDP
```

### 5. XOR-Encrypted SSN Table
SSN values are stored XOR'd with a random compile-time key. Decrypted at runtime just before the syscall — no plaintext SSN appears in the binary at rest.

```c
#define SW4_XOR_KEY  0xDEADF00DU
#define SW4_DECRYPT(v)  ((v) ^ SW4_XOR_KEY)
// Usage in resolver:
SW4_SsnTable[fi] = sortedIndex ^ SW4_XOR_KEY;
// Usage in stub (auto-generated):
mov eax, DWORD PTR [SW4_SsnTable + N*4]  ; loads XOR'd value
; SW4_DECRYPT applied during init, not per-call
```

### 6. Call Stack Spoofing Helper
A trampoline that replaces the visible return address on the stack with a pointer into ntdll, making the call chain appear legitimate to stack-walking EDRs.

```asm
SW4_CallWithSpoofedStack PROC
    pop  r11               ; save real return address
    push [SW4_SpoofReturnAddr]  ; push ntdll address instead
    push r11               ; real address below (unreachable by walker)
    jmp  rax               ; execute target
SW4_CallWithSpoofedStack ENDP
```

### 7. ETW User-Mode Bypass
Optional patch for `ntdll!EtwEventWrite` that returns `STATUS_ACCESS_DENIED` immediately, suppressing user-mode ETW event delivery from the current process.

```c
// Patch: mov eax, 0xC0000022; ret
SW4_PatchEtw();   // call after SW4_Initialize()
```

> ⚠️ This does **not** bypass kernel-mode ETW-Ti callbacks. Use only in authorized engagements.

### 8. Auto-Update Syscall Table
Fetches the latest j00ru table directly from GitHub:

```bash
python scripts/update_syscall_table.py           # x64
python scripts/update_syscall_table.py --arch x64,x86
```

---

## Quick Start

```bash
git clone https://github.com/CyberSecurityUP/SysWhispers4
cd SysWhispers4

# Optional: update syscall table from j00ru (for --resolve static)
python scripts/update_syscall_table.py

# Common preset — FreshyCalls + direct syscall (recommended start)
python syswhispers.py --preset common

# Injection preset — indirect via Tartarus' Gate
python syswhispers.py --preset injection --method indirect --resolve tartarus

# Maximum evasion: randomized + XOR SSN + obfuscated + ETW bypass
python syswhispers.py --preset all \
    --method randomized --resolve tartarus \
    --obfuscate --encrypt-ssn --stack-spoof --etw-bypass

# Specific functions, egg hunt (no syscall opcode on disk)
python syswhispers.py \
    --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx \
    --method egg --resolve halos_gate

# ARM64 (Windows on ARM)
python syswhispers.py --preset common --arch arm64

# x86 / WoW64
python syswhispers.py --preset injection --arch x86

# MinGW / Clang (GAS inline assembly)
python syswhispers.py --preset common --compiler mingw
```

---

## Command-Line Reference

```
python syswhispers.py [OPTIONS]

Function selection (at least one required):
  -p, --preset PRESET      common | injection | evasion | token | all
  -f, --functions FUNCS    NtAllocateVirtualMemory,NtCreateThreadEx,...

Target:
  -a, --arch ARCH          x64 (default) | x86 | wow64 | arm64
  -c, --compiler COMPILER  msvc (default) | mingw | clang

Techniques:
  -m, --method METHOD      embedded (default) | indirect | randomized | egg
  -r, --resolve RESOLVE    freshycalls (default) | static | hells_gate |
                           halos_gate | tartarus

Evasion:
  --obfuscate              Randomize stub order + inject junk instructions
  --encrypt-ssn            XOR-encrypt SSN table at rest
  --stack-spoof            Include synthetic call stack frame helper
  --etw-bypass             Include optional user-mode ETW patch function

Output:
  --prefix PREFIX          Symbol prefix (default: SW4)
  -o, --out-file OUTFILE   Output filename base (default: SW4Syscalls)
  --out-dir OUTDIR         Output directory (default: .)

Info:
  --list-functions         Print all 48 supported NT functions and exit
  --list-presets           Print all preset definitions and exit
  -v, --verbose            Verbose output / traceback on error
```

---

## Generated Files

| File | Purpose |
|---|---|
| `SW4Syscalls_Types.h` | NT type definitions — structures, enums, typedefs |
| `SW4Syscalls.h` | Function prototypes + `SW4_Initialize()` declaration |
| `SW4Syscalls.c` | Runtime SSN resolution + helper functions |
| `SW4Syscalls.asm` | MASM syscall stubs (MSVC) |
| `SW4Syscalls_stubs.c` | GAS inline assembly stubs (MinGW / Clang) |

---

## Integration (MSVC)

1. Add all 4 files to your Visual Studio project
2. Enable MASM: **Project → Build Customizations → masm (.targets)**
3. Call `SW4_Initialize()` at startup

```c
#include "SW4Syscalls.h"

int main(void) {
    // Required for FreshyCalls / Hell's Gate / Halo's Gate / Tartarus
    // Not needed for --resolve static + --method embedded
    if (!SW4_Initialize()) return 1;

    // Optional: suppress user-mode ETW events
    // SW4_PatchEtw();

    // Egg method only: call hatcher instead of Initialize
    // SW4_HatchEggs();

    // Use NT functions directly — all via syscall, no API hooks
    PVOID base = NULL;
    SIZE_T size = 0x1000;
    NTSTATUS st = SW4_NtAllocateVirtualMemory(
        GetCurrentProcess(), &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    return NT_SUCCESS(st) ? 0 : 1;
}
```

---

## SSN Resolution Techniques

### Static
Embeds syscall numbers from the bundled j00ru table at generation time. No runtime ntdll parsing — fastest and simplest. An embedded table is a detection signal; use dynamic methods for stealth.

### FreshyCalls *(default — recommended)*
Sorts all `Nt*` exports from ntdll by virtual address. Sorted index = SSN. Works even if **every** `Nt*` stub is hooked — reads only VAs, not function bytes.

### Hell's Gate
Reads the `mov eax, <SSN>` opcode directly from each ntdll stub:
```
4C 8B D1 B8 [SSN_lo] [SSN_hi] 00 00
```
Fails when the stub's first bytes are overwritten by an EDR hook.

### Halo's Gate
Extends Hell's Gate: when a stub is hooked, scans neighboring stubs (±8) in the sorted export list and infers the SSN by ±offset arithmetic.

### Tartarus' Gate *(most robust)*
Extends Halo's Gate to detect **both** EDR hook patterns:
- `E9 xx xx xx xx` — near relative JMP
- `FF 25 00 00 00 00 ...` — far absolute JMP via memory

Scans up to 16 neighbors in both directions.

---

## Invocation Methods

### Embedded — Direct Syscall
`syscall` lives in your stub. At kernel entry, RIP points into your PE — detectable by EDRs checking non-ntdll RIP.

### Indirect
Jumps to a pre-located `syscall;ret` gadget **inside ntdll.dll**. At kernel entry, RIP appears to be inside ntdll — identical to a legitimate API call.

### Randomized Indirect
Like Indirect, but selects a **random** gadget from a pool of up to 64 on every call. Defeats EDR heuristics that whitelist specific ntdll gadget addresses. Uses `RDTSC` for entropy — no API call needed.

### Egg Hunt
Stubs contain an 8-byte random egg marker in place of `syscall`. `SW4_HatchEggs()` scans the `.text` section at startup and replaces each egg with `0F 05 90 90 90 90 90 90`. **No `syscall` opcode appears in the binary on disk.**

---

## EDR Detection Landscape

| Detection Vector | Embedded | Indirect | Randomized | Egg |
|---|:-:|:-:|:-:|:-:|
| User-mode hook bypass | ✅ | ✅ | ✅ | ✅ |
| RIP inside ntdll at syscall | ❌ | ✅ | ✅ | ❌ |
| No `0F 05` in binary on disk | ✅¹ | ✅ | ✅ | **✅** |
| Random gadget per call | ❌ | ❌ | **✅** | ❌ |
| Clean call stack | ❌ | ❌ | ❌ | ❌ |
| Kernel ETW-Ti bypass | ❌ | ❌ | ❌ | ❌ |

¹ The `syscall` opcode is in your PE's `.text` section — at your code address, not ntdll.

> **ETW-Ti** (`Microsoft-Windows-Threat-Intelligence`) fires inside the kernel regardless of invocation method. No user-mode technique bypasses it without kernel access.

---

## Supported Functions (48)

```bash
python syswhispers.py --list-functions
```

| Category | Functions |
|---|---|
| Memory | `NtAllocateVirtualMemory` · `NtAllocateVirtualMemoryEx` · `NtFreeVirtualMemory` · `NtWriteVirtualMemory` · `NtReadVirtualMemory` · `NtProtectVirtualMemory` · `NtQueryVirtualMemory` |
| Section/Mapping | `NtCreateSection` · `NtMapViewOfSection` · `NtUnmapViewOfSection` |
| Process | `NtOpenProcess` · `NtCreateProcess` · `NtCreateProcessEx` · `NtCreateUserProcess` · `NtTerminateProcess` · `NtSuspendProcess` · `NtResumeProcess` · `NtQueryInformationProcess` · `NtSetInformationProcess` |
| Thread | `NtCreateThreadEx` · `NtOpenThread` · `NtTerminateThread` · `NtSuspendThread` · `NtResumeThread` · `NtGetContextThread` · `NtSetContextThread` · `NtQueueApcThread` · `NtQueueApcThreadEx` · `NtQueryInformationThread` · `NtSetInformationThread` |
| Handle | `NtClose` · `NtDuplicateObject` · `NtWaitForSingleObject` · `NtWaitForMultipleObjects` · `NtSignalAndWaitForSingleObject` |
| File | `NtCreateFile` · `NtOpenFile` |
| Token | `NtOpenProcessToken` · `NtOpenThreadToken` · `NtQueryInformationToken` · `NtAdjustPrivilegesToken` · `NtDuplicateToken` · `NtImpersonateThread` |
| Misc | `NtDelayExecution` · `NtQuerySystemInformation` · `NtQueryObject` · `NtFlushInstructionCache` · `NtContinue` |

---

## Presets

| Preset | Functions | Use Case |
|---|:-:|---|
| `common` | 25 | General process/thread/memory operations |
| `injection` | 17 | Shellcode injection, DLL injection, process hollowing |
| `evasion` | 10 | AV/EDR evasion, process querying |
| `token` | 6 | Token manipulation, impersonation, privilege escalation |
| `all` | 48 | Everything |

---

## Syscall Table Coverage

Updated via `scripts/update_syscall_table.py` from [j00ru/windows-syscalls](https://github.com/j00ru/windows-syscalls):

| OS | Builds Covered |
|---|---|
| Windows 7 | SP1 (7601) |
| Windows 8 / 8.1 | RTM (9200, 9600) |
| Windows 10 | 1507 → 22H2 (10240 → 19045, 14 builds) |
| Windows 11 | 21H2 → 24H2 (22000 → 26100, 4 builds) |
| Windows Server | 2022 (20348), 2025 (26100) |

---

## Architecture Support

| Arch | Syscall Instruction | SSN Register | Status |
|---|:-:|:-:|---|
| x64 | `syscall` | `eax` | Full — all methods |
| x86 | `sysenter` | `eax` | Embedded + Egg |
| WoW64 | `syscall` (64-bit) | `eax` | x64 stubs from 32-bit PE |
| ARM64 | `svc #0` | `w8` | Embedded (new in SW4) |

---

## Security Notice

SysWhispers4 is a security research and authorized penetration testing tool. Use only:

- On systems you own or have explicit written authorization to test
- In CTF competitions
- For defensive research (understanding offensive techniques to improve detection)
- For developing security product signatures

Unauthorized use against systems you do not own is illegal in most jurisdictions.

---

## References & Credits

| Resource | Author(s) |
|---|---|
| [SysWhispers](https://github.com/jthuraisamy/SysWhispers) | Jackson T. (jthuraisamy) |
| [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) | Jackson T. (jthuraisamy) |
| [SysWhispers3](https://github.com/klezVirus/SysWhispers3) | klezVirus |
| [SysWhispers3 fork](https://github.com/RWXstoned/SysWhispers3) | RWXstoned |
| [Windows Syscall Tables](https://github.com/j00ru/windows-syscalls) | j00ru |
| [Hell's Gate](https://github.com/am0nsec/HellsGate) | am0nsec, RtlMclovin |
| [Halo's Gate](https://sektor7.net) | SEKTOR7 |
| [Tartarus' Gate](https://github.com/trickster0/TartarusGate) | trickster0 |
| [FreshyCalls](https://github.com/crummie5/FreshyCalls) | crummie5 |
| [RecycledGate](https://github.com/thefLink/RecycledGate) | thefLink |
| [LayeredSyscall](https://whiteknightlabs.com/2024/07/31/layeredsyscall-abusing-veh-to-bypass-edrs/) | White Knight Labs |
| [Call Stack Spoofing](https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs) | WithSecure Labs |
| [SysWhispers Evolution Analysis](https://sudosiddharths.medium.com/analyzing-the-evolution-and-execution-of-syswhispers-1-3-74cbbcdaf397) | Siddharth S. |
