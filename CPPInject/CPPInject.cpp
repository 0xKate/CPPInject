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
#include "cxxopts.hpp"

//#include "argparse.hpp"

int main(int argc, char** argv)
{
    SetConsoleTitleA("CPPInject");
    printf("CPPInject Copyright(C) 2023 0xKate\n");
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it under certain conditions.\n");
    printf("CPP Injector is distributed under the GNU GPLv3 license.\n");
    printf("See https://github.com/0xKate/CPPInject/LICENSE.txt for more info.\n");
    printf("Source code @: https://github.com/0xKate/CPPInject\n");

    cxxopts::Options argParser("CPPInject.exe");

    argParser.add_options()
        ("p,pid", "The process id of the target process to be injectd. Incompatible with --exe", cxxopts::value<int>())
        ("d,dll", "A path to the dll to be injected. ie. \"file.dll\" or \"D:\\path\\to\\file.dll\" Incompatible with --pid", cxxopts::value<std::string>())
        ("e,exe", "A path to the target exe to be launched and injected. ie. \"file.exe\" or \"D:\\path\\to\\file.exe\"", cxxopts::value<std::string>())
        ("v,verbose", "Show more detailed logs", cxxopts::value<bool>()->default_value("false"))
        ("h,help", "Print usage")
        ;

    std::string sourceDLL;
    std::string targetEXE;
    INT targetPID;

    auto argResult = argParser.parse(argc, argv);
    auto verbose = argResult["verbose"].as<bool>();

    if (argResult.count("help"))
    {
        std::cout << argParser.help() << std::endl;
        return 101;
    }

    if (argResult.count("exe") + argResult.count("pid") > 1)
    {
        std::cerr << "Input Error: --pid and --exe cannot be used at the same time!\n\n";
        std::cout << argParser.help() << std::endl;
        return -1;
    }

    if (argResult.count("pid")) {
        targetPID = argResult["pid"].as<INT>();
        if (verbose)
            std::cout << "PID: " << targetPID << std::endl;
    }

    if (argResult.count("exe")) {
        targetEXE = argResult["exe"].as<std::string>();
        if (verbose)
            std::cout << "EXE Path: " << targetEXE << std::endl;
    }

    if (argResult.count("dll")) {
        sourceDLL = argResult["dll"].as<std::string>();
        if (verbose)
            std::cout << "DLL Path: " << sourceDLL << std::endl;
    }

    x86Injector injector = x86Injector(sourceDLL);

    if (targetPID != NULL) {
        injector.Inject(targetPID);
    }

    if (!targetEXE.empty()) {
        injector.LaunchAndInject(targetEXE);
    }

    return EXIT_SUCCESS;

}
