# Windows API Behavior Map

Windows API Behavior Map is a documentation project for mapping commonly observed Windows API functions to behavior categories used during PE malware analysis.

The goal is not to label a file as malicious based on a single API function. The goal is to help analysts understand what behavior category should be reviewed when specific API functions appear in a PE import table.

## Purpose

During PE malware analysis, imported Windows API functions can provide useful behavioral hints.

This project documents:

- what an API function is generally used for
- which behavior category it belongs to
- what an analyst should review when the API appears
- which related APIs may provide additional context
- how the API can be mentioned in an analysis report

## Behavior Categories

Initial categories:

- [File System API](api-categories/file-system.md)
- [Registry API](api-categories/registry.md)
- [Process API](api-categories/process.md)
- [Memory API](api-categories/memory.md)
- [Network API](api-categories/network.md)
- [DLL Loading API](api-categories/dll-loading.md)

The current version includes initial notes for the main API behavior categories.

## Analysis Rule

A single API function should not be treated as proof of malicious behavior.

Correct analysis language:

```text
This API may indicate file system activity and should be reviewed together with related APIs and strings.
```

Incorrect analysis language:

```text
This single API call is enough to make a final conclusion.
```

## Repository Structure

```text
api-categories/
  file-system.md
  registry.md
  process.md
  memory.md
  network.md
  dll-loading.md

examples/
  import-table-example.md
```

## Safety Scope

This repository does not contain executable samples or offensive implementation details.

It is only a defensive documentation project for learning PE import table interpretation and malware analysis reporting.

## Current Status

Initial documentation has been added for:

- File System API behavior notes
- Registry API behavior notes
- Process API behavior notes
- Memory API behavior notes
- Network API behavior notes
- DLL Loading API behavior notes
- Import table interpretation example

## Next Steps

Planned improvements:

- Add behavior summary templates
- Add more import table interpretation examples
- Add report-friendly API grouping tables
- Add references for common Windows DLLs