#include "pe.hpp"

#include <TlHelp32.h> // must be included after Windows.h

auto WINAPI mMessageBoxW(const HWND hWnd, const wchar_t* const lpText, const wchar_t* const lpCaption, UINT uType) -> int {
    const auto hacked_message = L"This MessageBox was Hacked!!";
    return MessageBoxW(hWnd, hacked_message, lpCaption, uType | MB_ICONERROR);
}

auto hook_imports(const HMODULE self) -> void {
    auto module_entry = MODULEENTRY32W{sizeof(MODULEENTRY32W), 0};
    const auto snapshot     = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    for (auto is_next = Module32FirstW(snapshot, &module_entry); is_next; is_next = Module32NextW(snapshot, &module_entry)) {
        if(module_entry.hModule == self) {
            continue;
        }
        auto pe = PEFile(module_entry.hModule);
        pe.hook_import_symbol(&MessageBoxW, &mMessageBoxW);
    }
    if(snapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(snapshot);
    }
}

extern "C" auto WINAPI DllMain(const HINSTANCE module_handle, const DWORD reason, const LPVOID reserved) -> BOOL {
    if(reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    hook_imports(module_handle);
    return TRUE;
}
