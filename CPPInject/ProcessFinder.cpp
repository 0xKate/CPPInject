#include "ProcessFinder.h"
#include <tlhelp32.h>
#include <vector>
#include <algorithm>

namespace ProcessFinder {

    struct ProcessInfo {
        DWORD pid;
        FILETIME creationTime;
    };

    bool GetProcessCreationTime(DWORD pid, FILETIME& outTime) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) return false;

        FILETIME ct, et, kt, ut;
        if (GetProcessTimes(hProcess, &ct, &et, &kt, &ut)) {
            outTime = ct;
            CloseHandle(hProcess);
            return true;
        }

        CloseHandle(hProcess);
        return false;
    }

    bool iequals(const std::wstring& a, const std::wstring& b) {
        return _wcsicmp(a.c_str(), b.c_str()) == 0;
    }

    std::optional<DWORD> GetMainProcessId(const std::wstring& processName) {
        std::vector<ProcessInfo> matches;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return std::nullopt;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (iequals(pe.szExeFile, processName)) {
                    FILETIME creationTime = {};
                    if (GetProcessCreationTime(pe.th32ProcessID, creationTime)) {
                        matches.push_back({ pe.th32ProcessID, creationTime });
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);

        if (matches.empty()) {
            return std::nullopt;
        }

        std::sort(matches.begin(), matches.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
            return CompareFileTime(&a.creationTime, &b.creationTime) < 0;
            });

        return matches[0].pid; // Earliest-started process
    }
}
