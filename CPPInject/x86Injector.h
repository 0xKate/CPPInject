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

#pragma once

#include <windows.h>
#include <string>

class x86Injector
{
private:
    std::string dllPath;
    BOOL handlesClosed;
public:
    x86Injector(std::string dllPath);
    HANDLE GetProcessHandle(DWORD dwPID);
    int Inject(DWORD dwPID);
    int LaunchAndInject(std::string exePath);
};