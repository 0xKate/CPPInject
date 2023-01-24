# CPPInject

CPPInject is a DLL injector for use on the cmd line.
Currently only offering LoadLibrary based injection.

## Usage

Currently only provides LaunchAndInject, so it does not work with already running processes.

Run from the command line with 1st argument as DLL path and second argument as target exe to launch and inject.



### Batch Script

For a one click launch and inject of something you can use make a .bat file and use this batch script.

```batch
start "" .\Injector.exe "./MyDll.dll" "D:/Path/To/Some/Executable.exe"
```
