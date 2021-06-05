#pragma comment(lib, "aux_klib.lib")
#include <ntddk.h>
#include <aux_klib.h>
#include "nt.h"

// https://github.com/vxcute/WindowsInternals/blob/main/Misc/Snippets/KernelMode/KmGetNtosImageBase.cpp

EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
EXTERN_C_END

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

constexpr ULONG TAG = 'kedr';

template <class T>
auto GetRoutineAddress(_In_ PUNICODE_STRING routineName) -> T
{
    __try {
        T routineAddress = (T)MmGetSystemRoutineAddress(routineName);
        if (!routineAddress)
            return nullptr;

        return routineAddress;
    }
    __except (1) {}
}


typedef NTSTATUS (*_ZwQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS ListModulesWithQuerySystemInformation(VOID)
{
    auto status = STATUS_SUCCESS;
    __try {

        ULONG modulesSize = 0;
        PSYSTEM_MODULE_INFORMATION modules = nullptr;
        auto SystemModuleInformation = 0xb;
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");

        // auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        auto ZwQuerySystemInformation = GetRoutineAddress<_ZwQuerySystemInformation>(&routineName);
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
        status = ZwQuerySystemInformation(SystemModuleInformation, modules, modulesSize, nullptr);
        if (!NT_SUCCESS(status))
            goto Exit;

        DbgPrint("modules:");
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

NTSTATUS ListModulesWithAuxKlib(VOID)
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

    DbgPrint("modules:\n");
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

void Unload(PDRIVER_OBJECT)
{
    DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
    DbgPrint("Driver loaded\n");

    //ListModulesWithAuxKlib();
    ListModulesWithQuerySystemInformation();

    DriverObject->DriverUnload = Unload;
    return STATUS_SUCCESS;
}