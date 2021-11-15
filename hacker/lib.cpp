#include <vector>
#include <string_view>

#include <Windows.h>

#include <TlHelp32.h>

struct ImportSymbol {
    size_t rva;
    void** iat;
    WORD   hint;
    union {
        struct {
            WORD by_name;
            WORD ordinal;
        } ordinal;
        const char* name;
    };
};

class PEFile {
  private:
    template <typename T>
    auto get_data_pointer(const size_t rva) const -> T {
        return reinterpret_cast<T>(load_base + rva);
    }
    BYTE* load_base;
    IMAGE_DOS_HEADER* dos_header;
    IMAGE_NT_HEADERS* nt_headers;
    IMAGE_SECTION_HEADER* section_table;

  public:
    struct DirectoryEntry {
        const BYTE* address;
        size_t      size;
    };
    auto get_load_base() const -> BYTE* {
        return load_base;
    }
    auto get_dos_header() const -> IMAGE_DOS_HEADER* {
        return dos_header;
    }
    auto get_nt_headers() const -> IMAGE_NT_HEADERS* {
        return nt_headers;
    }
    auto get_file_header() const -> IMAGE_FILE_HEADER* {
        return &nt_headers->FileHeader;
    }
    auto get_optional_header() const -> IMAGE_OPTIONAL_HEADER* {
        return &nt_headers->OptionalHeader;
    }
    auto get_section_header(const int index) const -> IMAGE_SECTION_HEADER* {
        return &section_table[index];
    }
    auto get_dir_entry(const int index) const -> DirectoryEntry {
        const auto& d = get_optional_header()->DataDirectory[index];
        if(d.VirtualAddress && d.Size) {
            return {load_base + d.VirtualAddress, d.Size};
        } else {
            return {nullptr, 0};
        }
    }
    auto get_import_dir_entry() const -> const IMAGE_IMPORT_DESCRIPTOR* {
        const auto de = get_dir_entry(IMAGE_DIRECTORY_ENTRY_IMPORT);
        return reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(de.address);
    }
    auto get_import_dll_names() const -> std::vector<const char*> {
        auto r = std::vector<const char*>();
        const auto imports = get_import_dir_entry();
        for(auto i = 0; imports[i].FirstThunk != 0; i += 1) {
            r.emplace_back(get_data_pointer<const char*>(imports[i].Name));
        }
        return r;
    }
    auto get_import_symbols(const char* dll_name) -> std::vector<ImportSymbol> {
        auto r = std::vector<ImportSymbol>();
        const auto name    = std::string_view(dll_name);
        const auto imports = get_import_dir_entry();
        if(!imports[0].OriginalFirstThunk) {
            return r;
        }
        for(auto i = 0; imports[i].FirstThunk != 0; i += 1) {
            const auto& d = imports[i];
            if(name != get_data_pointer<const char*>(d.Name)) {
                continue;
            }
            const auto iat_pointer = get_data_pointer<IMAGE_THUNK_DATA*>(d.FirstThunk);
            const auto int_pointer = d.OriginalFirstThunk ? get_data_pointer<IMAGE_THUNK_DATA*>(d.OriginalFirstThunk) : iat_pointer;
            for(auto i = size_t(0);; i += 1) {
                const auto address = (reinterpret_cast<size_t*>(int_pointer))[i];
                if(address == 0) {
                    break;
                }
                if(address >= get_optional_header()->SizeOfImage) {
                    continue;
                }
                const auto rva = d.FirstThunk + sizeof(DWORD) * i;
                const auto iat = reinterpret_cast<void**>(&iat_pointer[i]);
                if(IMAGE_SNAP_BY_ORDINAL(reinterpret_cast<size_t*>(int_pointer)[i])) {
                    const auto ordinal = static_cast<WORD>(IMAGE_ORDINAL(address));
                    r.emplace_back(ImportSymbol{.rva = rva, .iat = iat, .hint = 0, .ordinal = {.by_name = 0, .ordinal = ordinal}});
                } else {
                    const auto name = get_data_pointer<IMAGE_IMPORT_BY_NAME*>(address);
                    r.emplace_back(ImportSymbol{.rva = rva, .iat = iat, .hint = name->Hint, .name = reinterpret_cast<char*>(name->Name)});
                }
            }
        }
        return r;
    }
    auto hook_import_symbol(const void* const original, const void* const inject) -> void {
        const auto imports = get_import_dir_entry();
        if(imports == nullptr) {
            return;
        }
        for(auto i = 0; imports[i].FirstThunk != 0; i += 1) {
            const auto& d = imports[i];
            const auto  iat = get_data_pointer<void**>(d.FirstThunk);
            for(auto i = 0; iat[i] != 0; i += 1) {
                if(iat[i] != reinterpret_cast<FARPROC>(original)) {
                    continue;
                }
                auto protect = DWORD(0);
                VirtualProtect(&iat[i], sizeof(FARPROC), PAGE_READWRITE, &protect);
                iat[i] = reinterpret_cast<FARPROC>(inject);
                VirtualProtect(&iat[i], sizeof(FARPROC), protect, &protect);
            }
        }
    }
    PEFile(const HMODULE module_handle) {
        load_base = reinterpret_cast<BYTE*>(module_handle);
        dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(load_base);
        nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(load_base + dos_header->e_lfanew);
        section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_headers + 1);
    }
};

auto WINAPI mMessageBoxW(const HWND hWnd, const wchar_t* const lpText, const wchar_t* const lpCaption, UINT uType) -> int {
    const auto hacked_message = L"This MessageBox was Hacked!!";
    return MessageBoxW(hWnd, hacked_message, lpCaption, uType);
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