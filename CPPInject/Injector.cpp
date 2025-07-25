/*
   _____ _____  _____ _____       _           _
  / ____|  __ \|  __ \_   _|     (_)         | |
 | |    | |__) | |__) || |  _ __  _  ___  ___| |_
 | |    |  ___/|  ___/ | | | '_ \| |/ _ \/ __| __|
 | |____| |    | |    _| |_| | | | |  __/ (__| |_
  \_____|_|    |_|   |_____|_| |_| |\___|\___|\__|
                                _/ |
                               |__/
*/
/*
    Copyright (C) 2023 0xKate

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef _DEBUG
#define DEBUG(x) 
#else
#define DEBUG(x) do { std::cerr << x << std::endl; } while (0)
#endif

#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <shlwapi.h>
#include <processthreadsapi.h>
#include <aclapi.h>
#include "Injector.h"

Injector::Injector(std::string dllPath)
    : dllPath(std::move(dllPath)), handlesClosed(FALSE) {
}

HANDLE Injector::GetProcessHandle(DWORD dwPID)
{
    DWORD flags = PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_QUERY_INFORMATION
        | PROCESS_CREATE_THREAD;

    DEBUG("Attempting to open target process with simple rights");
    HANDLE hProcess = OpenProcess(flags, false, dwPID);

    if (hProcess == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
        printf("Failed! Access was denied!");

        PACL ppDACL;
        PSECURITY_DESCRIPTOR ppSecurityDescriptor;
        DWORD errorCode;
        DEBUG("Getting Injectors security descriptor and ACL...");
        errorCode = GetSecurityInfo(GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            &ppDACL,
            NULL,
            &ppSecurityDescriptor);

        if (errorCode != ERROR_SUCCESS) {
            fprintf(stderr, "Failed to obtain security info for Injector!!");
            return INVALID_HANDLE_VALUE;
        }

        DEBUG("Opening target process with WRITE_DAC permissions...");
        hProcess = OpenProcess(WRITE_DAC, FALSE, dwPID);

        if (hProcess == NULL) {
            fprintf(stderr, "Failed to obtain process with WRITE_DAC permissions!!");
            LocalFree(ppSecurityDescriptor);
            return INVALID_HANDLE_VALUE;
        }

        errorCode = SetSecurityInfo(hProcess,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION |
            UNPROTECTED_DACL_SECURITY_INFORMATION,
            0,
            0,
            ppDACL,
            0);

        if (errorCode != ERROR_SUCCESS) {
            fprintf(stderr, "Failed to override target process security info!! ErrorCode: %u\n", errorCode);
            CloseHandle(hProcess);
            LocalFree(ppSecurityDescriptor);
            return INVALID_HANDLE_VALUE;
        }

        CloseHandle(hProcess);
        LocalFree(ppSecurityDescriptor);

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    }

    if (hProcess == NULL) {
        fprintf(stderr, "Fatal error, completely failed to obtain handle!");
        return INVALID_HANDLE_VALUE;
    }

    return hProcess;
}
int Injector::Inject(DWORD dwPID)
{
    if (!std::filesystem::exists(this->dllPath) || !std::filesystem::is_regular_file(this->dllPath)) {
        std::cerr << "Error: DLL file does not exist or is invalid." << std::endl;
        return -1;
    }

    std::filesystem::path fsAbsPath = std::filesystem::absolute(this->dllPath);
    std::string absPath = fsAbsPath.string();
    SIZE_T pathSize = absPath.size() + 1;

    HANDLE hProcess = GetProcessHandle(dwPID);
    if (hProcess == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to obtain HANDLE for PID: %d\n", dwPID);
        return -1;
    }

    LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBuffer == NULL) {
        fprintf(stderr, "Failed to allocate buffer!\n");
        CloseHandle(hProcess);
        return -1;
    }

    printf("Writing path to memory: %s\n", absPath.c_str());
    BOOL errorCode = WriteProcessMemory(hProcess, lpBuffer, absPath.c_str(), pathSize, NULL);
    if (errorCode == NULL) {
        fprintf(stderr, "Failed to Write path to memory! %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    HMODULE hMod = GetModuleHandleA("KERNEL32.dll");
    if (hMod == NULL) {
        fprintf(stderr, "Could not find KERNEL32 Module! %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    LPVOID lpLoadLibraryAddress = (LPVOID)GetProcAddress(hMod, "LoadLibraryA");
    if (lpLoadLibraryAddress == NULL) {
        fprintf(stderr, "Could not find LoadLibraryA address %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpLoadLibraryAddress), lpBuffer, 0, NULL);
    if (hThread == NULL) {
        fprintf(stderr, "Unable to create remote thread!\n");
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("DLL Injected!\n");

    return 1;
}
int Injector::LaunchAndInject(std::string exePath)
{
    STARTUPINFOA sInfo;
    PROCESS_INFORMATION pInfo;

    ZeroMemory(&sInfo, sizeof(sInfo));
    sInfo.cb = sizeof(sInfo);
    ZeroMemory(&pInfo, sizeof(pInfo));

    if (CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &sInfo, &pInfo)) {
        std::cout << "Process created!" << std::endl;
        CloseHandle(pInfo.hThread);
        CloseHandle(pInfo.hProcess);
    }
    else {
        std::cerr << "Falied to create process! (" << GetLastError() << ")" << std::endl;
        return -1;
    }

    this->Inject(pInfo.dwProcessId);

    return 0;
}
