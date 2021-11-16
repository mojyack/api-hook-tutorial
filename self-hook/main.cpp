#include "../include/pe.hpp"

#include <TlHelp32.h> // must be included after Windows.h

auto WINAPI mMessageBoxW(const HWND hWnd, const wchar_t* const lpText, const wchar_t* const lpCaption, UINT uType) -> int {
    const auto hacked_message = "This MessageBox was Hacked!!";
    return MessageBoxA(hWnd, hacked_message, "Caution", uType | MB_ICONERROR);
}

auto hook_imports() -> void {
    auto       module_entry = MODULEENTRY32W{sizeof(MODULEENTRY32W), 0};
    const auto snapshot     = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    for(auto is_next = Module32FirstW(snapshot, &module_entry); is_next; is_next = Module32NextW(snapshot, &module_entry)) {
        auto pe = PEFile(module_entry.hModule);
        pe.hook_import_symbol(&MessageBoxW, &mMessageBoxW);
    }
    if(snapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(snapshot);
    }
}

auto main() -> int {
    MessageBoxW(NULL, L"Hello, This is Messenger!", L"Message", MB_OK);

    hook_imports();

    MessageBoxW(NULL, L"Hello, This is Messenger!", L"Message", MB_OK);
    return 0;
}
