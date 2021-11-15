#include <filesystem>
#include <string>
#include <vector>

#include <Windows.h>

auto execute(PROCESS_INFORMATION& info, const wchar_t* const path) -> bool {
    auto startup = STARTUPINFOW{0};
    return CreateProcessW(
               path,
               NULL,
               NULL,
               NULL,
               FALSE,
               CREATE_SUSPENDED,
               NULL,
               NULL,
               &startup,
               &info) != FALSE;
}

auto search_hackers() -> std::vector<std::wstring> {
    auto r = std::vector<std::wstring>();
    for(const auto& f : std::filesystem::directory_iterator(".")) {
        if(!f.is_regular_file()) {
            continue;
        }
        const auto& name = f.path().filename().wstring();
        if(name.starts_with(L"hacker") && name.ends_with(L".dll")) {
            r.emplace_back(name);
        }
    }
    return r;
}

auto inject(const HANDLE process) -> bool {
    const auto hackers = search_hackers();
    if(hackers.size() != 1) {
        return false;
    }
    const auto& hacker     = hackers[0];
    const auto  size_bytes = (hacker.size() + 1) * sizeof(hacker[0]);
    const auto  remote_mem = VirtualAllocEx(process, NULL, size_bytes, MEM_COMMIT, PAGE_READWRITE);
    if(remote_mem == NULL) {
        return false;
    }

    auto written = SIZE_T(0);
    if(WriteProcessMemory(process, remote_mem, hacker.data(), size_bytes, &written) != TRUE) {
        return false;
    }

    auto       thread_id     = DWORD(0);
    const auto thread_handle = CreateRemoteThread(process, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryW), remote_mem, 0, &thread_id);
    if(thread_handle == NULL) {
        return false;
    }

    WaitForSingleObject(thread_handle, INFINITE);
    auto exit_code = DWORD(0);
    GetExitCodeThread(thread_handle, &exit_code);

    CloseHandle(thread_handle);
    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    return true;
}

auto wmain(const int argc, const wchar_t* const argv[]) -> int {
    if(argc != 2) {
        return 1;
    }

    auto info = PROCESS_INFORMATION{0};
    if(!execute(info, argv[1])) {
        return 2;
    }
    if(!inject(info.hProcess)) {
        return 3;
    }
    ResumeThread(info.hThread);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return 0;
}