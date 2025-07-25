#pragma once
#include <string>
#include <optional>
#include <windows.h>

namespace ProcessFinder {
    // Returns the PID of the earliest-launched process matching the given name (e.g., "myapp.exe")
    // Returns std::nullopt if not found or an error occurs
    std::optional<DWORD> GetMainProcessId(const std::wstring& processName);
}