# DLL Loading API

This category covers Windows API functions commonly related to loading libraries, resolving exported functions, and releasing loaded modules.

DLL loading APIs should be interpreted as behavioral indicators during PE malware analysis. A single DLL loading API should not be treated as proof of malicious behavior.

## LoadLibraryA / LoadLibraryW

### General Purpose

Loads a specified DLL into the address space of the calling process.

### Analysis Meaning

When `LoadLibraryA` or `LoadLibraryW` appears in a PE import table, it may indicate that the program loads a library at runtime.

This API becomes more meaningful when DLL names appear in strings or when it is used together with `GetProcAddress`.

### What to Review

- Check whether DLL names appear in the strings output.
- Review whether the DLL name is hardcoded or built at runtime.
- Check whether `GetProcAddress` is also imported.
- Compare the imported API with actual call references in the disassembler.

## GetProcAddress

### General Purpose

Retrieves the address of an exported function from a loaded DLL.

### Analysis Meaning

`GetProcAddress` may indicate that the program resolves function addresses at runtime instead of relying only on the static import table.

This API is common in normal applications. It should be reviewed together with the DLL name, function name, and surrounding code flow.

### What to Review

- Check whether function names appear in strings.
- Review which DLL handle is passed to the API.
- Check whether the resolved function is called later.
- Compare the resolved function names with the static import table.

## GetModuleHandleA / GetModuleHandleW

### General Purpose

Retrieves a module handle for a loaded module.

### Analysis Meaning

`GetModuleHandleA` or `GetModuleHandleW` may indicate that the program checks whether a module is already loaded.

This API is common in normal software and should not be treated as suspicious by itself.

### What to Review

- Check which module name is requested.
- Review whether the returned handle is passed to `GetProcAddress`.
- Check whether module names appear in strings.
- Compare the usage with DLL loading or function resolution logic.

## FreeLibrary

### General Purpose

Releases a loaded DLL module from the calling process.

### Analysis Meaning

`FreeLibrary` may indicate that the program unloads a library after using it.

This is common in normal applications and should be interpreted with the surrounding DLL loading logic.

### What to Review

- Check which module is being released.
- Review whether the module was loaded earlier with `LoadLibraryA` or `LoadLibraryW`.
- Check whether function resolution happens before the library is released.
- Avoid making a conclusion from this API alone.