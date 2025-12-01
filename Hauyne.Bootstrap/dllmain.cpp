/*
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
 * Mozilla Public License, v. 2.0.
 * 
 */

#include <Windows.h>
#include <filesystem>
#include <string>

#include "includes/hostfxr.h"
#include "includes/coreclr_delegates.h"

using string_t = std::basic_string<char_t>;

typedef int (CORECLR_DELEGATE_CALLTYPE* load_assembly_fn)(
    const char_t* assembly_path,
    void* load_context,
    void* reserved
);

hostfxr_initialize_for_runtime_config_fn hostfxr_init = nullptr;
hostfxr_get_runtime_delegate_fn hostfxr_get_delegate = nullptr;
hostfxr_close_fn hostfxr_close = nullptr;

std::wstring find_hostfxr_path()
{
    const wchar_t* base = L"C:\\Program Files\\dotnet\\host\\fxr";

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((std::wstring(base) + L"\\*").c_str(), &findData);

    std::wstring latestVersion;
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && findData.cFileName[0] != '.')
                latestVersion = findData.cFileName;
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    return std::wstring(base) + L"\\" + latestVersion + L"\\hostfxr.dll";
}

bool load_hostfxr()
{
    std::wstring path = find_hostfxr_path();
    HMODULE lib = LoadLibraryW(path.c_str());
    if (!lib)
        return false;

    hostfxr_init = (hostfxr_initialize_for_runtime_config_fn)GetProcAddress(lib, "hostfxr_initialize_for_runtime_config");
    hostfxr_get_delegate = (hostfxr_get_runtime_delegate_fn)GetProcAddress(lib, "hostfxr_get_runtime_delegate");
    hostfxr_close = (hostfxr_close_fn)GetProcAddress(lib, "hostfxr_close");

    return hostfxr_init && hostfxr_get_delegate && hostfxr_close;
}

void load_payload()
{
    if (!load_hostfxr())
        return;

    wchar_t module_path[MAX_PATH];
    // TODO: make this an argument
    GetModuleFileNameW(GetModuleHandleW(L"Hauyne.Bootstrap.dll"), module_path, MAX_PATH);

    std::filesystem::path base = std::filesystem::path(module_path).parent_path();
    string_t config = (base / L"Hauyne.Payload.runtimeconfig.json").wstring();
    string_t assembly = (base / L"Hauyne.Payload.dll").wstring();

    hostfxr_handle ctx = nullptr;
    int rc = hostfxr_init(config.c_str(), nullptr, &ctx);

    // ALARM WE ARE WITHOUT A CONFIG
    if (rc == 0x80008093 || ctx == nullptr)
        rc = hostfxr_init(nullptr, nullptr, &ctx);

    if (!ctx)
        return;
    
    load_assembly_fn load_asm = nullptr;
    rc = hostfxr_get_delegate(ctx, hdt_load_assembly, (void**)&load_asm);
    if (rc != 0 || !load_asm)
    {
        hostfxr_close(ctx);
        return;
    }

    rc = load_asm(assembly.c_str(), nullptr, nullptr);
    if (rc != 0)
    {
        hostfxr_close(ctx);
        return;
    }
    
    get_function_pointer_fn get_fn = nullptr;
    rc = hostfxr_get_delegate(ctx, hdt_get_function_pointer, (void**)&get_fn);
    if (rc != 0 || !get_fn)
    {
        hostfxr_close(ctx);
        return;
    }

    typedef void (CORECLR_DELEGATE_CALLTYPE* entry_point_fn)();
    entry_point_fn entry = nullptr;

    rc = get_fn(
        L"Hauyne.Payload.Entrypoint, Hauyne.Payload",
        L"Initialize",
        UNMANAGEDCALLERSONLY_METHOD,
        nullptr,
        nullptr,
        (void**)&entry
    );

    if (rc == 0 && entry)
        entry();

    hostfxr_close(ctx);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            load_payload();
            FreeLibraryAndExitThread((HMODULE)param, 0);
        }, hModule, 0, nullptr);
    }
    return TRUE;
}