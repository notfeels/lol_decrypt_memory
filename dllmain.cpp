#include <Windows.h>
#include <cstdint>
#include <Psapi.h>

namespace packman {
    inline void trigger_veh(uint64_t address) {
        static auto deref_pointer_in_game_space_fn =
            (uint64_t(__fastcall*)(uint64_t))((uint64_t)GetModuleHandleA(NULL) + 0x1033110);
        deref_pointer_in_game_space_fn(address - 0x8);
    }

    inline void suspend_process(HANDLE process_handle) {
        typedef LONG(NTAPI* nt_suspend_process)(IN HANDLE);
        static nt_suspend_process nt_suspend_process_fn =
            (nt_suspend_process)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
        nt_suspend_process_fn(process_handle);
    }

    inline void decrypt_memory_pages_for_dump() {
        HANDLE process = GetCurrentProcess();

        SYSTEM_INFO sysInfo = { 0 };
        GetSystemInfo(&sysInfo);

        MODULEINFO module_info = { 0 };
        K32GetModuleInformation(process, GetModuleHandleA(NULL), &module_info, sizeof(MODULEINFO));

        uint64_t current_chunk = (uint64_t)module_info.lpBaseOfDll + 0x2000;
        while (current_chunk < (uint64_t)sysInfo.lpMaximumApplicationAddress) {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (!VirtualQueryEx(process, (LPCVOID)current_chunk, &mbi, sizeof(mbi)))
                break;

            uint64_t address = (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
            __try {
                trigger_veh(address);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}

            current_chunk = address;
        }

        suspend_process(process);
        MessageBoxA(0, "should never show", NULL, 0);
    }
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        packman::decrypt_memory_pages_for_dump();
        break;
    default:
        break;
    }
    return TRUE;
}