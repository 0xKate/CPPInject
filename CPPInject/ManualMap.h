// manualmap_helpers.h  (drop into your project)
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstdio>
#include <cassert>
#include "Injector.h"

namespace CPPInject {

    struct ModuleHeader {
        IMAGE_DOS_HEADER* Dos{};
#ifdef _WIN64
        IMAGE_NT_HEADERS64* NT{};
#else
        IMAGE_NT_HEADERS32* NT{};
#endif
    };

    // -----------------------------------------------------------------------------
    // Read file to buffer
    // -----------------------------------------------------------------------------
    inline bool ReadModule(const std::filesystem::path& modulePath, std::vector<uint8_t>& buffer)
    {
        if (modulePath.empty() || !std::filesystem::exists(modulePath))
            return false;

        std::ifstream file(modulePath, std::ios::binary | std::ios::ate);
        if (!file) return false;

        size_t size = static_cast<size_t>(file.tellg());
        file.seekg(0);

        buffer.resize(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);

        return true;
    }

    // -----------------------------------------------------------------------------
    // Validate PE and return SizeOfImage via moduleSize (by-ref). Also fill headers.
    // -----------------------------------------------------------------------------
    inline bool ValidatePE(std::vector<uint8_t>& buffer, ModuleHeader& outHeaders, size_t& moduleSize)
    {
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        // bounds check the e_lfanew
        if (buffer.size() < static_cast<size_t>(dos->e_lfanew) + sizeof(uint32_t)) return false;

#ifdef _WIN64
        IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
        moduleSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);

        outHeaders.Dos = dos;
        outHeaders.NT = nt;
#else
        IMAGE_NT_HEADERS32* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;
        moduleSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);

        outHeaders.Dos = dos;
        outHeaders.NT = nt;
#endif

        return true;
    }

    // -----------------------------------------------------------------------------
     // Remote allocation with preferred-base attempt. Returns remote base or nullptr.
    // -----------------------------------------------------------------------------
    inline PVOID RemoteAllocate(HANDLE hProcess, ModuleHeader const& headers, SIZE_T size, bool& outNeedsRelocation)
    {
        outNeedsRelocation = false;
#ifdef _WIN64
        ULONGLONG preferred = headers.NT->OptionalHeader.ImageBase;
#else
        DWORD preferred = headers.NT->OptionalHeader.ImageBase;
#endif

        PVOID remote = VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(preferred), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!remote) {
            remote = VirtualAllocEx(hProcess, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!remote) return nullptr;
            outNeedsRelocation = true;
        }
        return remote;
    }

    // -----------------------------------------------------------------------------
     // Helper: find a module base in remote process using Toolhelp Snapshot.
    // -----------------------------------------------------------------------------
    inline HMODULE GetRemoteModuleBase(DWORD pid, const std::wstring& modName)
    {
        HMODULE ret = nullptr;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE)
            return nullptr;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        auto toLower = [](std::wstring s) {
            std::transform(s.begin(), s.end(), s.begin(),
                [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
            return s;
            };

        std::wstring wantLower = toLower(modName);

        if (Module32FirstW(snap, &me)) {
            do {
                std::wstring curLower = toLower(me.szModule);
                if (curLower == wantLower) {
                    ret = reinterpret_cast<HMODULE>(me.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snap, &me));
        }

        CloseHandle(snap);
        return ret;
    }

    // -----------------------------------------------------------------------------
     // Perform relocations by walking IMAGE_DIRECTORY_ENTRY_BASERELOC
     // This function patches the values *in the remote process* directly.
     // You must call it if remoteBase != preferred ImageBase.
     // -----------------------------------------------------------------------------
    inline bool PerformRelocations(HANDLE hProcess, DWORD pid, ModuleHeader const& headers, PVOID remoteBase, std::vector<uint8_t> const& fileBuffer)
    {
#ifdef _WIN64
        using reloc_t = IMAGE_BASE_RELOCATION;
        const auto imageBasePref = headers.NT->OptionalHeader.ImageBase;
        const auto delta = reinterpret_cast<uint64_t>(remoteBase) - imageBasePref;
#else
        using reloc_t = IMAGE_BASE_RELOCATION;
        const auto imageBasePref = headers.NT->OptionalHeader.ImageBase;
        const auto delta = reinterpret_cast<uintptr_t>(remoteBase) - imageBasePref;
#endif

        if (delta == 0) return true; // nothing to do

        auto& opt = headers.NT->OptionalHeader;
        const auto relocDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
            // no reloc table but we need one -> fail
            return false;
        }

        const BYTE* base = fileBuffer.data();
        const BYTE* relocBase = base + relocDir.VirtualAddress;
        const BYTE* relocEnd = relocBase + relocDir.Size;
        const BYTE* cur = relocBase;

        while (cur < relocEnd) {
            auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(cur);
            if (block->SizeOfBlock == 0) break;
            const DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD* entries = reinterpret_cast<const WORD*>(cur + sizeof(IMAGE_BASE_RELOCATION));
            const DWORD pageRVA = block->VirtualAddress;

            for (DWORD i = 0; i < entryCount; ++i) {
                WORD entry = entries[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0x0FFF;
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;

#ifdef _WIN64
                if (type == IMAGE_REL_BASED_DIR64) {
                    // address to patch = remoteBase + pageRVA + offset
                    uintptr_t patchAddrRemote = reinterpret_cast<uintptr_t>(remoteBase) + pageRVA + offset;
                    uint64_t originalValue = 0;
                    // read original value from remote (optional; we can compute from file but safer to read)
                    SIZE_T read = 0;
                    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patchAddrRemote), &originalValue, sizeof(originalValue), &read) || read != sizeof(originalValue)) return false;
                    uint64_t patched = originalValue + static_cast<uint64_t>(delta);
                    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(patchAddrRemote), &patched, sizeof(patched), nullptr)) return false;
                }
#else
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uintptr_t patchAddrRemote = reinterpret_cast<uintptr_t>(remoteBase) + pageRVA + offset;
                    uint32_t originalValue = 0;
                    SIZE_T read = 0;
                    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patchAddrRemote), &originalValue, sizeof(originalValue), &read) || read != sizeof(originalValue)) return false;
                    uint32_t patched = originalValue + static_cast<uint32_t>(delta);
                    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(patchAddrRemote), &patched, sizeof(patched), nullptr)) return false;
                }
#endif
                // Note: other relocation types exist; this handles the common ones.
            }

            cur += block->SizeOfBlock;
        }

        return true;
    }

    // -----------------------------------------------------------------------------
     // Resolve imports: for each IMAGE_IMPORT_DESCRIPTOR, ensure the DLL is loaded into
     // the remote process (RemoteLoadLibraryIfNeeded) then compute the function address
     // in the remote by using local LoadLibrary/GetProcAddress + remote module base
     // and write that address into the IAT in the remote image.
    //
    // Important: this assumes the imported DLL on disk in local environment matches
    // the remote loaded image layout (typical on same-arch Windows).
    // -----------------------------------------------------------------------------
    inline bool ResolveImports(HANDLE hProcess, DWORD pid, ModuleHeader const& headers, PVOID remoteBase, std::vector<uint8_t> const& fileBuffer)
    {
        auto& opt = headers.NT->OptionalHeader;
        auto importDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0) return true; // nothing to do

        const BYTE* base = fileBuffer.data();
        const IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);

        while (importDesc->Name) {
            const char* dllName = reinterpret_cast<const char*>(base + importDesc->Name);

            // Convert char* (ANSI) to std::wstring (UTF-16)
            int len = MultiByteToWideChar(CP_ACP, 0, dllName, -1, nullptr, 0);
            std::wstring dllNameW(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, dllName, -1, &dllNameW[0], len);

            // remove the trailing null terminator because std::wstring already handles it
            if (!dllNameW.empty() && dllNameW.back() == L'\0')
                dllNameW.pop_back();


            // ensure remote module is loaded
            //if (!RemoteLoadLibraryIfNeeded(hProcess, pid, dllNameStr)) {
            //    fprintf(stderr, "Failed to load dependency remotely: %s\n", dllNameStr.c_str());
            //    return false;
            //}

            // Get remote module base
            HMODULE remoteMod = GetRemoteModuleBase(pid, dllNameW);
            if (!remoteMod) {
                fprintf(stderr, "Failed to find remote module base for %s\n", dllName);
                return false;
            }

            // Get local handle to compute offset of exported functions
            HMODULE localMod = LoadLibraryA(dllName); // increases refcount in our process; acceptable for mapper
            if (!localMod) {
                fprintf(stderr, "Failed to load local module for %s\n", dllName);
                return false;
            }

            // Resolve thunks
            // FirstThunk is the IAT in the image where pointers live (we must write remote addresses here)
            // OriginalFirstThunk points to names/ordinals (may be null, in that case FirstThunk has names)
#ifdef _WIN64
            const IMAGE_THUNK_DATA* oft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + importDesc->OriginalFirstThunk);
            const IMAGE_THUNK_DATA* ft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + importDesc->FirstThunk);
#else
            const IMAGE_THUNK_DATA* oft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + importDesc->OriginalFirstThunk);
            const IMAGE_THUNK_DATA* ft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + importDesc->FirstThunk);
#endif

            // If OriginalFirstThunk is 0, use FirstThunk for names (some linkers do that)
            if (importDesc->OriginalFirstThunk == 0) {
                oft = ft;
            }

            for (; oft->u1.AddressOfData; ++oft, ++ft) {
#ifdef _WIN64
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    // ordinal
                    WORD ordinal = static_cast<WORD>(oft->u1.Ordinal & 0xFFFF);
                    FARPROC localAddr = GetProcAddress(localMod, reinterpret_cast<LPCSTR>(ordinal));
                    if (!localAddr) { FreeLibrary(localMod); return false; }
                    // compute remote address = remoteMod + (localAddr - localMod)
                    uintptr_t localBase = reinterpret_cast<uintptr_t>(localMod);
                    uintptr_t localProc = reinterpret_cast<uintptr_t>(localAddr);
                    uintptr_t offset = localProc - localBase;
                    uintptr_t remoteProc = reinterpret_cast<uintptr_t>(remoteMod) + offset;
                    // write to remote IAT
                    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + (reinterpret_cast<BYTE*>(ft) - base)), &remoteProc, sizeof(remoteProc), nullptr)) {
                        FreeLibrary(localMod); return false;
                    }
                }
                else {
                    auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + oft->u1.AddressOfData);
                    const char* funcName = reinterpret_cast<const char*>(importByName->Name);
                    FARPROC localAddr = GetProcAddress(localMod, funcName);
                    if (!localAddr) { FreeLibrary(localMod); return false; }
                    uintptr_t localBase = reinterpret_cast<uintptr_t>(localMod);
                    uintptr_t localProc = reinterpret_cast<uintptr_t>(localAddr);
                    uintptr_t offset = localProc - localBase;
                    uintptr_t remoteProc = reinterpret_cast<uintptr_t>(remoteMod) + offset;
                    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + (reinterpret_cast<BYTE*>(ft) - base)), &remoteProc, sizeof(remoteProc), nullptr)) {
                        FreeLibrary(localMod); return false;
                    }
                }
#else
                // x86: same logic but 32-bit pointer
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    WORD ordinal = static_cast<WORD>(oft->u1.Ordinal & 0xFFFF);
                    FARPROC localAddr = GetProcAddress(localMod, reinterpret_cast<LPCSTR>(ordinal));
                    if (!localAddr) { FreeLibrary(localMod); return false; }
                    uintptr_t localBase = reinterpret_cast<uintptr_t>(localMod);
                    uintptr_t localProc = reinterpret_cast<uintptr_t>(localAddr);
                    uintptr_t offset = localProc - localBase;
                    uintptr_t remoteProc = reinterpret_cast<uintptr_t>(remoteMod) + offset;
                    uint32_t remote32 = static_cast<uint32_t>(remoteProc);
                    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + (reinterpret_cast<const BYTE*>(ft) - base)), &remote32, sizeof(remote32), nullptr)) {
                        FreeLibrary(localMod); return false;
                    }
                }
                else {
                    const auto importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + oft->u1.AddressOfData);
                    const char* funcName = reinterpret_cast<const char*>(importByName->Name);
                    FARPROC localAddr = GetProcAddress(localMod, funcName);
                    if (!localAddr) { FreeLibrary(localMod); return false; }
                    uintptr_t localBase = reinterpret_cast<uintptr_t>(localMod);
                    uintptr_t localProc = reinterpret_cast<uintptr_t>(localAddr);
                    uintptr_t offset = localProc - localBase;
                    uintptr_t remoteProc = reinterpret_cast<uintptr_t>(remoteMod) + offset;
                    uint32_t remote32 = static_cast<uint32_t>(remoteProc);
                    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + (reinterpret_cast<const BYTE*>(ft) - base)), &remote32, sizeof(remote32), nullptr)) {
                        FreeLibrary(localMod); return false;
                    }
                }
#endif
            }

            FreeLibrary(localMod);
            ++importDesc;
        }

        return true;
    }

    inline int ManualMapInjection(DWORD dwPID, std::filesystem::path modulePath)
    {
        std::vector<uint8_t> buffer{};
        if (!ReadModule(modulePath, buffer)) {
            fprintf(stderr, "Unable to read module: %s\n", modulePath.string().c_str());
            return -1;
        }

        ModuleHeader headers{};
        size_t size = 0;
        if (!ValidatePE(buffer, headers, size)) {
            fprintf(stderr, "Unable to validate PE Header for module: %s\n", modulePath.string().c_str());
            return -1;
        }

        HANDLE hProcess = Injector::GetProcessHandle(dwPID);
        if (hProcess == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Unable to obtain HANDLE for PID: %d\n", dwPID);
            return -1;
        }

        PVOID remoteBase = nullptr;
        bool relocationNeeded = false;
        if (!(remoteBase = RemoteAllocate(hProcess, headers, size, relocationNeeded))) {
            fprintf(stderr, "Unable to allocate remote memory in PID: %d\n", dwPID);
            return -1;
        }

        // Step 1: Relocations (if base != preferred base)
        if (relocationNeeded)
        if (!PerformRelocations(hProcess, dwPID, headers, remoteBase, buffer)) {
            fprintf(stderr, "Failed to apply relocations.\n");
            return -1;
        }

        // Step 2: Resolve imports (load dependencies, patch IAT)
        if (!ResolveImports(hProcess, dwPID, headers, remoteBase, buffer)) {
            fprintf(stderr, "Failed to resolve imports.\n");
            return -1;
        }

        // Step 3: Write headers
        if (!WriteProcessMemory(hProcess, remoteBase,
            buffer.data(),
            headers.NT->OptionalHeader.SizeOfHeaders, nullptr))
        {
            fprintf(stderr, "Failed to write PE headers.\n");
            return -1;
        }

        // Step 4: Write sections
        auto sectionHeader = IMAGE_FIRST_SECTION(headers.NT);
        for (WORD i = 0; i < headers.NT->FileHeader.NumberOfSections; i++, sectionHeader++) {
            LPVOID base = (BYTE*)remoteBase + sectionHeader->VirtualAddress;
            LPVOID buff = buffer.data() + sectionHeader->PointerToRawData;
            if (!WriteProcessMemory(hProcess, base, buff, sectionHeader->SizeOfRawData, nullptr)) {
                fprintf(stderr, "Failed to write section %d\n", i);
                return -1;
            }
        }

        // Step 5: TLS callbacks (if any exist)
        //if (!InvokeTLS(hProcess, remoteBase, headers)) {
        //    fprintf(stderr, "Failed to invoke TLS callbacks.\n");
        //    return -1;
        //}

        // stub code for x86: push reserved, push reason, push hModule, call entry, ret
        unsigned char stubTemplate[] = {
            0x6A, 0x00,             // push 0 (reserved)
            0x6A, 0x01,             // push 1 (DLL_PROCESS_ATTACH)
            0x68, 0,0,0,0,          // push hModule (placeholder)
            0xE8, 0,0,0,0,          // call entrypoint (relative, placeholder)
            0xC3                    // ret
        };

        // Allocate stub memory in remote process
        LPVOID stubMem = VirtualAllocEx(hProcess, nullptr, sizeof(stubTemplate),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // Patch hModule (remoteBase) into stub
        DWORD hModuleVal = (DWORD)remoteBase;
        memcpy(&stubTemplate[4], &hModuleVal, sizeof(DWORD));

        // Patch call relative offset
        DWORD callOffset = (DWORD)remoteBase + headers.NT->OptionalHeader.AddressOfEntryPoint - ((DWORD)stubMem + 9); // 9 = offset of next instruction after E8
        memcpy(&stubTemplate[9], &callOffset, sizeof(DWORD));

        // Write stub into remote process
        WriteProcessMemory(hProcess, stubMem, stubTemplate, sizeof(stubTemplate), nullptr);

        // Run the stub
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)stubMem,
            nullptr, 0, nullptr);

        if (!hThread) {
            fprintf(stderr, "Failed to create remote thread.\n");
            return -1;
        }

        // Optionally wait until DllMain finishes
        //WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return 0; // success
    }

} // namespace CPPInject
