# CPPInject

CPPInject is a DLL injector for use on the cmd line.
Currently only offering LoadLibrary based injection.

## Usage

Run from cmd or powershell, you cannot combine --pid and --exe.

If you use with --exe it will automatically launch the target program and inject the dll provided with --dll.

Provide --dll and --pid to inject to a running process.

```
Usage:
  CPPInject.exe [OPTION...]

  -p, --pid arg  The process id of the target process to be injectd.  
                 Incompatible with --exe  
  -d, --dll arg  A path to the dll to be injected. ie. "file.dll" or  
                 "D:\path\to\file.dll" Incompatible with --pid  
  -e, --exe arg  A path to the target exe to be launched and injected. ie.  
                 "file.exe" or "D:\path\to\file.exe"  
  -v, --verbose  Show more detailed logs  
  -h, --help     Print usage  

```


### Batch Script

For a one click launch and inject of something you can make a .bat file and use this batch script.

```batch
start "" .\CPPInject.exe --dll "C:\path\to\file.dll" --exe "D:\path\to\file.exe"
```
```batch
start "" .\CPPInject.exe --dll "D:\path\to\file.dll" --pid 11111
```
