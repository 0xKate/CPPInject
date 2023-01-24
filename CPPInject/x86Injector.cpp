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
#include "x86Injector.h"

x86Injector::x86Injector(std::string dllPath) {
    this->dllPath = dllPath;
}
HANDLE x86Injector::GetProcessHandle(DWORD dwPID)
{
    int flags = PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_QUERY_INFORMATION
        | PROCESS_CREATE_THREAD;

    // Attempt to open the process
    DEBUG("Attempting to open target process with simple rights");
    HANDLE hProcess = OpenProcess(flags, false, dwPID);

    // If it failed, attempt to upgrade security rights.
    if (hProcess == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
        printf("Failed! Access was denied!");

        //// ---- Get the access control descriptor of the injector
        PACL ppDACL;
        PSECURITY_DESCRIPTOR ppSecurityDescriptor;
        // If the function succeeds, the return value is ERROR_SUCCESS.
        DWORD errorCode;
        //The pseudo handle from GetCurrentProcess need not be closed when it is no longer needed.
        DEBUG("Getting Injectors security descriptor and ACL...");
        errorCode = GetSecurityInfo(GetCurrentProcess(),
            SE_KERNEL_OBJECT, // Indicates a local kernel object.
            DACL_SECURITY_INFORMATION, // The DACL of the object is being referenced.
            NULL,
            NULL,
            &ppDACL,
            NULL,
            &ppSecurityDescriptor);

        if (errorCode != ERROR_SUCCESS) {
            fprintf(stderr, "Failed to obtain security info for Injector!!");
            return INVALID_HANDLE_VALUE;
        }

        ///// ---- Override processs permissions with Injectors permissions
        // Attempt now to open the process with WRITE_DAC:
        // "The right to modify the discretionary access control list (DACL)
        // in the object's security descriptor."
        DEBUG("Opening target process with WRITE_DAC permissions...");
        hProcess = OpenProcess(WRITE_DAC, FALSE, dwPID);

        if (hProcess == NULL) {
            fprintf(stderr, "Failed to obtain process with WRITE_DAC permissions!!");
            LocalFree(ppSecurityDescriptor);
            return INVALID_HANDLE_VALUE;
        }

        // Set the DACL of the target process to the one we obtained from the injector
        errorCode = SetSecurityInfo(hProcess,
            SE_KERNEL_OBJECT, // Indicates a local kernel object.
            DACL_SECURITY_INFORMATION | // The DACL of the object is being referenced.
            UNPROTECTED_DACL_SECURITY_INFORMATION, // Forces The DACL to inherit ACEs from the parent object.
            0,
            0,
            ppDACL, // The DACL from the Injector
            0);

        if (errorCode != ERROR_SUCCESS) {
            fprintf(stderr, "Failed to override target process security info!! ErrorCode: %u\n", errorCode);
            CloseHandle(hProcess);
            LocalFree(ppSecurityDescriptor);
            return INVALID_HANDLE_VALUE;
        }

        // Cleanup 
        CloseHandle(hProcess);
        LocalFree(ppSecurityDescriptor);

        // Security Descriptor has been overriden, time to open with all access
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    }

    if (hProcess == NULL) {
        fprintf(stderr, "Fatal error, completely failed to obtain handle!");
        return INVALID_HANDLE_VALUE;
    }

    return hProcess;
}
int x86Injector::Inject(DWORD dwPID)
{
    // Check if DLL exists
    if (PathFileExistsA(this->dllPath.c_str()) == FALSE) {
        printf("Error: DLL does not exist!");
        return -1;
    }

    // Get absolute path to DLL and size of path string
    std::filesystem::path fsAbsPath = std::filesystem::absolute(this->dllPath);
    std::string absPath = fsAbsPath.string();
    size_t pathSize = strlen(absPath.c_str());

    // Get a handle to the process
    HANDLE hProcess = GetProcessHandle(dwPID);
    if (hProcess == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to obtain HANDLE for PID: %d\n", dwPID);
        return -1;
    }

    // Allocate a buffer in the target processes memory for the dll path argument
    LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBuffer == NULL) {
        fprintf(stderr, "Failed to allocate buffer!\n");
        CloseHandle(hProcess);
        return -1;
    }

    // Write the DLL path to the memory we just allocated
    printf("Writing path to memory: %s\n", absPath.c_str());
    BOOL errorCode = WriteProcessMemory(hProcess, lpBuffer, absPath.c_str(), pathSize, NULL);
    if (errorCode == NULL) {
        fprintf(stderr, "Failed to Write path to memory! %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Get a handle to the KERNEL32.dll module (this type of handle need not be closed)
    HMODULE hMod = GetModuleHandleA("KERNEL32.dll");
    if (hMod == NULL) {
        fprintf(stderr, "Could not find KERNEL32 Module! %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Get the address of LoadLibraryA inside target process
    FARPROC lpLoadLibraryAddress = GetProcAddress(hMod, "LoadLibraryA");
    if (lpLoadLibraryAddress == NULL) {
        fprintf(stderr, "Could not find LoadLibraryA address %lu\n", GetLastError());
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Start a remote thread in the injected process,
    // thread will call function at the address of LoadLibraryA
    // with the buffer we wrote the dll path to.
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)lpLoadLibraryAddress, lpBuffer, 0, NULL);
    if (hThread == NULL) {
        fprintf(stderr, "Unable to create remote thread!\n");
        VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Wait for LoadLibraryA to finish or else thread will crash
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("DLL Injected!\n");

    return 1;
}
int x86Injector::LaunchAndInject(std::string exePath)
{
    STARTUPINFO  sInfo;
    PROCESS_INFORMATION  pInfo;

    ZeroMemory(&sInfo, sizeof(sInfo));
    sInfo.cb = sizeof(sInfo); // The size of the structure, in bytes.
    ZeroMemory(&pInfo, sizeof(pInfo));

    if (CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOA)&sInfo, &pInfo)) {
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