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
    inline bool ReadModule(const std::filesystem::path& modulePath, std::vector<uint8_t>& buffer) {
        if (modulePath.empty() || !std::filesystem::exists(modulePath)) return false;
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
    inline bool ValidatePE(std::vector<uint8_t>& buffer, ModuleHeader& outHeaders, size_t& moduleSize) {
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
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
    // Remote allocation with preferred-base attempt
    // -----------------------------------------------------------------------------
    inline PVOID RemoteAllocate(HANDLE hProcess, ModuleHeader const& headers, SIZE_T size, bool& outNeedsRelocation) {
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
    // Helper: RVA -> raw file offset
    // -----------------------------------------------------------------------------
    inline size_t RvaToOffset(ModuleHeader const& headers, size_t rva) {
        auto section = IMAGE_FIRST_SECTION(headers.NT);
        for (WORD i = 0; i < headers.NT->FileHeader.NumberOfSections; i++, section++) {
            if (rva >= section->VirtualAddress &&
                rva < section->VirtualAddress + section->SizeOfRawData) {
                return rva - section->VirtualAddress + section->PointerToRawData;
            }
        }
        return SIZE_MAX; // invalid
    }

    // -----------------------------------------------------------------------------
    // Perform relocations (safe RVA->offset)
    // -----------------------------------------------------------------------------
    inline bool PerformRelocations(HANDLE hProcess, ModuleHeader const& headers, PVOID remoteBase, std::vector<uint8_t> const& fileBuffer) {
#ifdef _WIN64
        using addr_t = uint64_t;
#else
        using addr_t = uint32_t;
#endif
        const auto imageBasePref = headers.NT->OptionalHeader.ImageBase;
        const addr_t delta = reinterpret_cast<addr_t>(remoteBase) - imageBasePref;
        if (delta == 0) return true;

        const auto& opt = headers.NT->OptionalHeader;
        const auto& relocDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
            fprintf(stderr, "No relocation table but relocation is needed\n");
            return false;
        }

        size_t relocOffset = RvaToOffset(headers, relocDir.VirtualAddress);
        if (relocOffset == SIZE_MAX || relocOffset + relocDir.Size > fileBuffer.size()) {
            fprintf(stderr, "Relocation directory out of bounds\n");
            return false;
        }

        const BYTE* base = fileBuffer.data();
        const BYTE* cur = base + relocOffset;
        const BYTE* end = cur + relocDir.Size;

        while (cur < end) {
            if (cur + sizeof(IMAGE_BASE_RELOCATION) > end) break;
            auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(cur);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD* entries = reinterpret_cast<const WORD*>(cur + sizeof(IMAGE_BASE_RELOCATION));
            DWORD pageRVA = block->VirtualAddress;

            if (reinterpret_cast<const BYTE*>(entries + entryCount) > end) return false;

            for (DWORD i = 0; i < entryCount; i++) {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;

                addr_t patchAddrRemote = reinterpret_cast<addr_t>(remoteBase) + pageRVA + offset;

#ifdef _WIN64
                if (type != IMAGE_REL_BASED_DIR64) continue;
                addr_t original = 0; SIZE_T read = 0;
                if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patchAddrRemote), &original, sizeof(original), &read) || read != sizeof(original)) return false;
                addr_t patched = original + delta;
                if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(patchAddrRemote), &patched, sizeof(patched), nullptr)) return false;
#else
                if (type != IMAGE_REL_BASED_HIGHLOW) continue;
                addr_t original = 0; SIZE_T read = 0;
                if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patchAddrRemote), &original, sizeof(original), &read) || read != sizeof(original)) return false;
                addr_t patched = static_cast<uint32_t>(original + delta);
                if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(patchAddrRemote), &patched, sizeof(uint32_t), nullptr)) return false;
#endif
            }
            cur += block->SizeOfBlock;
        }
        return true;
    }


    // -----------------------------------------------------------------------------
    // Resolve imports (safe RVA -> offset)
    // -----------------------------------------------------------------------------
    inline bool ResolveImports(HANDLE hProcess, DWORD pid, ModuleHeader const& headers, PVOID remoteBase, std::vector<uint8_t> const& fileBuffer) {
        const auto& opt = headers.NT->OptionalHeader;
        auto importDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0) return true;

        size_t importOffset = RvaToOffset(headers, importDir.VirtualAddress);
        if (importOffset == SIZE_MAX) return false;

        const BYTE* base = fileBuffer.data();
        auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + importOffset);

        while (importDesc->Name) {
            size_t nameOffset = RvaToOffset(headers, importDesc->Name);
            if (nameOffset == SIZE_MAX) return false;
            const char* dllName = reinterpret_cast<const char*>(base + nameOffset);

            int len = MultiByteToWideChar(CP_ACP, 0, dllName, -1, nullptr, 0);
            std::wstring dllNameW(len, L'\0');
            MultiByteToWideChar(CP_ACP, 0, dllName, -1, &dllNameW[0], len);
            if (!dllNameW.empty() && dllNameW.back() == L'\0') dllNameW.pop_back();

            HMODULE remoteMod = GetRemoteModuleBase(pid, dllNameW);
            if (!remoteMod) return false;

            HMODULE localMod = LoadLibraryA(dllName);
            if (!localMod) return false;

#ifdef _WIN64
            const IMAGE_THUNK_DATA* oft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + RvaToOffset(headers, importDesc->OriginalFirstThunk));
            const IMAGE_THUNK_DATA* ft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + RvaToOffset(headers, importDesc->FirstThunk));
            if (importDesc->OriginalFirstThunk == 0) oft = ft;
#else
            const IMAGE_THUNK_DATA* oft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + RvaToOffset(headers, importDesc->OriginalFirstThunk));
            const IMAGE_THUNK_DATA* ft = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + RvaToOffset(headers, importDesc->FirstThunk));
            if (importDesc->OriginalFirstThunk == 0) oft = ft;
#endif

            for (; oft->u1.AddressOfData; ++oft, ++ft) {
                FARPROC localAddr = nullptr;
#ifdef _WIN64
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    localAddr = GetProcAddress(localMod, reinterpret_cast<LPCSTR>(oft->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + RvaToOffset(headers, oft->u1.AddressOfData));
                    localAddr = GetProcAddress(localMod, byName->Name);
                }
                if (!localAddr) { FreeLibrary(localMod); return false; }
                uintptr_t remoteProc = reinterpret_cast<uintptr_t>(remoteMod) + (reinterpret_cast<uintptr_t>(localAddr) - reinterpret_cast<uintptr_t>(localMod));
                WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + (reinterpret_cast<const BYTE*>(ft) - base)), &remoteProc, sizeof(remoteProc), nullptr);
#else
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    localAddr = GetProcAddress(localMod, reinterpret_cast<LPCSTR>(oft->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + RvaToOffset(headers, oft->u1.AddressOfData));
                    localAddr = GetProcAddress(localMod, byName->Name);
                }
                if (!localAddr) { FreeLibrary(localMod); return false; }
                uint32_t remoteProc = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(remoteMod) + (reinterpret_cast<uintptr_t>(localAddr) - reinterpret_cast<uintptr_t>(localMod)));
                WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(remoteBase) + (reinterpret_cast<const BYTE*>(ft) - base)), &remoteProc, sizeof(remoteProc), nullptr);
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
        fprintf(stdout, "Module parsed to buffer: %s\n", modulePath.string().c_str());

        ModuleHeader headers{};
        size_t size = 0;
        if (!ValidatePE(buffer, headers, size)) {
            fprintf(stderr, "Unable to validate PE Header for module: %s\n", modulePath.string().c_str());
            return -1;
        }
        fprintf(stdout, "PE header validated: %s\n", modulePath.string().c_str());


        HANDLE hProcess = Injector::GetProcessHandle(dwPID);
        if (hProcess == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Unable to obtain HANDLE for PID: %d\n", dwPID);
            return -1;
        }
        fprintf(stdout, "Got Process Handle\n");


        PVOID remoteBase = nullptr;
        bool relocationNeeded = false;
        if (!(remoteBase = RemoteAllocate(hProcess, headers, size, relocationNeeded))) {
            fprintf(stderr, "Unable to allocate remote memory in PID: %d\n", dwPID);
            return -1;
        }
        fprintf(stdout, "Got remote base\n");


        // Step 1: Relocations (if base != preferred base)
        if (relocationNeeded)
        if (!PerformRelocations(hProcess, headers, remoteBase, buffer)) {
            fprintf(stderr, "Failed to apply relocations.\n");
            return -1;
        }
        fprintf(stdout, "Performed relocations\n");


        // Step 2: Resolve imports (load dependencies, patch IAT)
        if (!ResolveImports(hProcess, dwPID, headers, remoteBase, buffer)) {
            fprintf(stderr, "Failed to resolve imports.\n");
            return -1;
        }
        fprintf(stdout, "Resolved Imports\n");


        // Step 3: Write headers
        if (!WriteProcessMemory(hProcess, remoteBase,
            buffer.data(),
            headers.NT->OptionalHeader.SizeOfHeaders, nullptr))
        {
            fprintf(stderr, "Failed to write PE headers.\n");
            return -1;
        }
        fprintf(stdout, "Wrote Headers\n");


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
        fprintf(stdout, "Wrote sections\n");


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
        if (!stubMem)
            return -1;

        DWORD entryRVA = headers.NT->OptionalHeader.AddressOfEntryPoint;
        DWORD entryRemote = (DWORD)remoteBase + entryRVA;
        DWORD relativeCall = entryRemote - ((DWORD)stubMem + 9);
        memcpy(&stubTemplate[9], &relativeCall, sizeof(DWORD));

        // Write stub into remote process
        WriteProcessMemory(hProcess, stubMem, stubTemplate, sizeof(stubTemplate), nullptr);

        // Run the stub
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)stubMem,
            nullptr, 0, nullptr);

        fprintf(stdout, "Called stub loader!\n");


        if (!hThread) {
            fprintf(stderr, "Failed to create remote thread.\n");
            return -1;
        }

        // Optionally wait until DllMain finishes
        //WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        fprintf(stdout, "ManualMapped succesfully\n");


        return 0; // success
    }

} // namespace CPPInject
