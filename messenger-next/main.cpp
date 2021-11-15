#include <Windows.h>

auto main() -> int {
    const auto addr        = GetProcAddress(GetModuleHandleW(L"User32.dll"), "MessageBoxW");
    const auto message_box = reinterpret_cast<decltype(&MessageBoxW)>(addr);
    
    message_box(NULL, L"Hello, This is Messenger!", L"Message", MB_OK);
    return 0;
}