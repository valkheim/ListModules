#pragma comment(lib, "aux_klib.lib")
#include <ntddk.h>
#include <aux_klib.h>
#include <intrin.h> // __readmsr
#include "nt.h"

// https://github.com/vxcute/WindowsInternals/blob/main/Misc/Snippets/KernelMode/KmGetNtosImageBase.cpp
// https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo

EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
EXTERN_C_END

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

constexpr ULONG TAG = 'kedr';
// Target RIP for the called procedure when SYSCALL is executed in 64-bit mode.
constexpr auto IA32_LSTAR = 0xC0000082;
constexpr auto SystemModuleInformation = 0xb;

template <class T>
auto GetRoutineAddress(_In_ PUNICODE_STRING routineName) -> T
{
    __try {
        T routineAddress = (T)MmGetSystemRoutineAddress( // Can only be used for routines exported by the kernil or HAL
            routineName
        );
        if (!routineAddress)
        {
            DbgPrint("Cannot get system routine '%wZ'", routineName);
            return nullptr;
        }

        return routineAddress;
    }
    __except (1) {}
}

typedef NTSTATUS (*_ZwQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS GetNtOsKrnlWithQuerySystemInformation(VOID)
{
    auto status = STATUS_SUCCESS;
    __try {

        ULONG modulesSize = 0;
        PSYSTEM_MODULE_INFORMATION modules = nullptr;
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation"); // gone from win8 orly?
        // auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        auto ZwQuerySystemInformation = GetRoutineAddress<_ZwQuerySystemInformation>(&routineName);
        // Get the accurate size for the system module information
        status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &modulesSize);
        if (status != STATUS_INFO_LENGTH_MISMATCH || modulesSize == 0)
        {
            DbgPrint("Cannot determine modules size with status 0x%x and modules size = 0x%x\n", status, modulesSize);
            goto Exit;
        }

        modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, modulesSize, TAG);
        if (modules == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        RtlZeroMemory(modules, modulesSize);
        // Get the actual system modules information into `modules`
        status = ZwQuerySystemInformation(SystemModuleInformation, modules, modulesSize, nullptr);
        if (!NT_SUCCESS(status))
            goto Exit;

        for (ULONG i = 0; i < modules->ModulesCount; ++i)
        {
            auto module = modules->Modules[i];
            DbgPrint("0x%02x: %s\n", i, module.Name + module.ModuleNameOffset);
            DbgPrint("  Path: %s\n", module.Name);
            DbgPrint("  Base: %p\n", module.ImageBaseAddress);
            DbgPrint("  Size: 0x%x\n", module.ImageSize);
        }

    Exit:
        if (modules != nullptr)
            ExFreePoolWithTag(modules, TAG);

        return status;
    }
    __except (1) {}
}

NTSTATUS GetNtOsKrnlWithAuxKlib(VOID)
{
    ULONG modulesSize = 0;
    ULONG moduleSize = sizeof(AUX_MODULE_EXTENDED_INFO);
    PAUX_MODULE_EXTENDED_INFO modules = nullptr;
    auto status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Cannot init klib with status 0x%x\n", status);
        goto Exit;
    }

    status = AuxKlibQueryModuleInformation(&modulesSize, moduleSize, nullptr);
    if (!NT_SUCCESS(status) || modulesSize == 0)
    {
        DbgPrint("Cannot determine modules size with status 0x%x\n", status);
        goto Exit;
    }

    modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(NonPagedPool, modulesSize, TAG);
    if (modules == nullptr)
    {
        DbgPrint("Cannot allocate memory\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(modules, modulesSize);
    status = AuxKlibQueryModuleInformation(&modulesSize, moduleSize, modules);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Cannot fetch modules infos with status 0x%x\n", status);
        goto Exit;
    }

    for (ULONG i = 0; i < modulesSize / moduleSize; ++i)
    {
        auto module = modules[i];
        DbgPrint("0x%02x: %s\n", i, module.FullPathName + module.FileNameOffset);
        DbgPrint("  Path: %s\n", module.FullPathName);
        DbgPrint("  Base: %p\n", module.BasicInfo.ImageBase);
        DbgPrint("  Size: 0x%x\n", module.ImageSize);
        /*
        auto exportDirectory = AuxKlibGetImageExportDirectory(module.BasicInfo.ImageBase);
        if (exportDirectory == nullptr)
            continue;
        */
    }

Exit:
    if (modules != nullptr)
        ExFreePoolWithTag(modules, TAG);

    return status;
}

typedef PVOID (*_RtlLookupFunctionEntry)(DWORD64 ControlPc, PDWORD64 ImageBase, PVOID /* PUNWIND_HISTORY_TABLE */ HistoryTable);
PVOID GetNtOsKrnlWithPC(VOID)
{
    __try {
        UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlLookupFunctionEntry");
        auto RtlLookupFunctionEntry = GetRoutineAddress<_RtlLookupFunctionEntry>(&RoutineName);
        DWORD64 NtImageBase = 0;
        RtlLookupFunctionEntry( // Searches the active function tables for an entry that corresponds to the specified PC value.
            (DWORD64)&MmFreeContiguousMemorySpecifyCache,
            &NtImageBase,
            nullptr
        );
        if (NtImageBase == 0)
        {
            DbgPrint("Cannot get base address\n");
            return nullptr;
        }

        DbgPrint("ntoskrnl.exe at 0x%p\n", NtImageBase);
        return (PVOID)NtImageBase;

    }
    __except (1) {}
}

typedef PVOID(*_RtlPcToFileHeader)(PVOID PcValue, PVOID* BasoOfImage);
PVOID GetNtOsKrnlWithPC2(VOID)
{
    __try {
        UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
        auto RtlPcToFileHeader = GetRoutineAddress<_RtlPcToFileHeader>(&RoutineName);
        PVOID NtImageBase = nullptr;
        RtlPcToFileHeader( // Retrieve the base address of the image that contains the specified PC value.
            &MmFreeContiguousMemorySpecifyCache,
            &NtImageBase
        );
        if (NtImageBase == nullptr)
        {
            DbgPrint("Cannot get base address\n");
            return nullptr;
        }

        DbgPrint("ntoskrnl.exe at 0x%p\n", NtImageBase);
        return NtImageBase;
    }
    __except (1) {}
}

/*
PVOID GetNtOsKrnlWithMsr(VOID)
{
    auto page = PAGE_ALIGN(__readmsr(IA32_LSTAR));// &~(PAGE_SIZE - 1); // PC page

    do {
        auto addr = *(USHORT *)(page);
        if (addr == IMAGE_DOS_SIGNATURE) // M Z header
        {
            for (auto i = page; i < page + PTE_ENTRY_COUNT_32; i += 8) {
                if (*reinterpret_cast<ULONG64*>(i) == PAGELK) // find PAGELK section
                    return reinterpret_cast<PVOID>(page);
            }
        }
        page -= PAGE_SIZE;
    } while (true);

    return nullptr;
}
*/

void Unload(PDRIVER_OBJECT)
{
    DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
    DbgPrint("Driver loaded\n");

    DbgPrint("* GetNtOsKrnlWithAuxLib\n");
    GetNtOsKrnlWithAuxKlib();
    DbgPrint("* GetNtOsKrnlWithQuerySystemInformation\n");
    GetNtOsKrnlWithQuerySystemInformation();
    DbgPrint("* GetNtOsKrnlWithPC\n");
    GetNtOsKrnlWithPC();
    DbgPrint("* GetNtOsKrnlWithPC2\n");
    GetNtOsKrnlWithPC2();

    DriverObject->DriverUnload = Unload;
    return STATUS_SUCCESS;
}