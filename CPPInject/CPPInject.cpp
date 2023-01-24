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

#include <iostream>
#include <windows.h>
#include <Shlwapi.h>
#include "x86Injector.h"

int main(int argc, char** argv)
{
    SetConsoleTitleA("CPPInject");
    printf("CPPInject Copyright(C) 2023 0xKate\n");
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it under certain conditions.\n");
    printf("CPP Injector is distributed under the GNU GPLv3 license.\n");
    printf("See https://github.com/0xKate/CPPInject/LICENSE.txt for more info.\n");
    printf("Source code @: https://github.com/0xKate/CPPInject\n\n");

    if (argc == 3)
    {
        if (PathFileExistsA(argv[1]) == FALSE) {
            fprintf(stderr, "Error: Invalid path to DLL!\n");
            return EXIT_FAILURE;
        }

        if (PathFileExistsA(argv[2]) == FALSE) {
            fprintf(stderr, "Error: Invalid path to target executable!\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        fprintf(stderr, "Invalid number of arguments!\n");
        fprintf(stderr, "Argument1: DllPath\nArgument2: PathToTargetExe\n");
        return EXIT_FAILURE;
    }

    x86Injector injector = x86Injector(argv[1]);
    injector.LaunchAndInject(argv[2]);

    return EXIT_SUCCESS;
}

