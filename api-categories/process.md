# Process API

This category covers Windows API functions commonly related to process creation, process access, process information, and process termination.

Process APIs should be interpreted as behavioral indicators during PE malware analysis. A single process-related API should not be treated as proof of malicious behavior.

## CreateProcessA / CreateProcessW

### General Purpose

Creates a new process and starts the specified program.

### Analysis Meaning

When `CreateProcessA` or `CreateProcessW` appears in a PE import table, it may indicate that the program can start another executable or command.

This API becomes more meaningful when command-line strings, file paths, or child process names are visible in the binary.

### What to Review

- Check whether executable names appear in the strings output.
- Review whether command-line arguments are present.
- Check whether the process is started from a user directory, temporary directory, or system directory.
- Compare the imported API with decompiler output to confirm whether it is actually called.

## OpenProcess

### General Purpose

Opens an existing process object and returns a handle that can be used by other process-related APIs.

### Analysis Meaning

`OpenProcess` may indicate that the program interacts with another running process.

The presence of this API alone is not enough to make a final conclusion. It should be reviewed together with the requested access rights and the surrounding code flow.

### What to Review

- Identify which process is being targeted.
- Review the requested access rights.
- Check whether the target process name appears in strings.
- Compare the API usage with other process-related imports.

## GetCurrentProcess

### General Purpose

Returns a handle to the current process.

### Analysis Meaning

`GetCurrentProcess` is commonly used in normal applications. It usually indicates that the program needs a reference to its own process.

This API is not suspicious by itself.

### What to Review

- Check why the current process handle is needed.
- Review which API receives the returned handle.
- Compare this usage with memory, token, or process information APIs.
- Avoid making a conclusion from this API alone.

## TerminateProcess

### General Purpose

Terminates the specified process.

### Analysis Meaning

`TerminateProcess` may indicate process shutdown or process control behavior.

It can be used by normal applications, installers, updaters, or administrative tools. The context of the target process is important.

### What to Review

- Identify which process may be terminated.
- Check whether the process name appears in strings.
- Review whether termination happens during cleanup, error handling, or normal execution.
- Compare this behavior with process creation and process access APIs.

## GetExitCodeProcess

### General Purpose

Retrieves the termination status of a process.

### Analysis Meaning

`GetExitCodeProcess` may indicate that the program monitors another process or checks whether a child process has finished.

This API is often used in normal process management logic.

### What to Review

- Check whether the process was created by the same program.
- Review whether the result affects the control flow.
- Check whether the program waits for another process before continuing.
- Compare this API with process creation or process waiting APIs.