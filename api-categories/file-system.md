# File System API

This category covers Windows API functions commonly related to file creation, file reading, file writing, and file deletion.

These APIs should be interpreted as behavioral indicators during PE malware analysis. A single file system API should not be treated as proof of malicious behavior.

## CreateFileA / CreateFileW

### General Purpose

Opens or creates a file, device, or other file system object.

### Analysis Meaning

When `CreateFileA` or `CreateFileW` appears in a PE import table, it may indicate file access or file creation behavior.

This API becomes more meaningful when it appears together with APIs such as `WriteFile`, `ReadFile`, or `DeleteFile`.

### What to Review

- Check whether file paths appear in the strings output.
- Check whether the filename is hardcoded.
- Check whether directories such as Temp, AppData, or System32 appear in related strings.
- Review whether `WriteFile` or `ReadFile` is also imported.

## ReadFile

### General Purpose

Reads data from an opened file or input handle.

### Analysis Meaning

`ReadFile` may indicate file content reading behavior. It can be used for configuration loading, data collection, or normal application file handling.

### What to Review

- Identify which file handle is being read.
- Check whether it is used after `CreateFileA` or `CreateFileW`.
- Review whether the read data is passed to another function.
- Compare the API usage with visible file path strings.

## WriteFile

### General Purpose

Writes data to an opened file or output handle.

### Analysis Meaning

`WriteFile` may indicate file creation, file modification, or output writing behavior.

It should be reviewed together with `CreateFileA` or `CreateFileW` to understand what file object may be affected.

### What to Review

- Identify where the written data comes from.
- Check whether the target filename appears in strings.
- Review whether the program creates a new file or modifies an existing file.
- Check whether the written file is later executed, deleted, or referenced again.

## DeleteFileA / DeleteFileW

### General Purpose

Deletes a specified file.

### Analysis Meaning

`DeleteFileA` or `DeleteFileW` may indicate cleanup behavior, temporary file handling, or file removal activity.

The presence of this API alone is not enough to make a final conclusion.

### What to Review

- Check which file path is passed to the API.
- Review whether the program deletes a file it created earlier.
- Check whether deletion happens during error handling or normal execution.
- Compare the deletion behavior with file creation and writing APIs.