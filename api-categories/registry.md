# Registry API

This category covers Windows API functions commonly related to reading, writing, and managing Windows Registry keys and values.

Registry APIs should be interpreted as behavioral indicators during PE malware analysis. A single Registry API should not be treated as proof of malicious behavior.

## RegOpenKeyExA / RegOpenKeyExW

### General Purpose

Opens an existing Registry key.

### Analysis Meaning

When `RegOpenKeyExA` or `RegOpenKeyExW` appears in a PE import table, it may indicate that the program reads or prepares access to Registry data.

This API becomes more meaningful when it appears together with APIs such as `RegQueryValueExA`, `RegSetValueExA`, or `RegCreateKeyExA`.

### What to Review

- Check which Registry path is being accessed.
- Review whether startup-related paths are referenced.
- Check whether the API is followed by Registry read or write operations.
- Compare Registry paths with strings found in the binary.

## RegQueryValueExA / RegQueryValueExW

### General Purpose

Reads the data associated with a Registry value.

### Analysis Meaning

`RegQueryValueExA` or `RegQueryValueExW` may indicate configuration reading, environment checking, or system information lookup behavior.

### What to Review

- Identify which Registry value is being read.
- Check whether the read value affects program control flow.
- Review whether the value is compared against hardcoded strings.
- Check whether the result is used before file, process, or network activity.

## RegSetValueExA / RegSetValueExW

### General Purpose

Writes or updates a Registry value.

### Analysis Meaning

`RegSetValueExA` or `RegSetValueExW` may indicate Registry modification behavior.

This API should be reviewed carefully when it appears together with startup-related Registry paths or other persistence-related indicators.

### What to Review

- Identify the Registry path and value name being modified.
- Check whether the written value contains a file path or command.
- Review whether the program writes under user-level or system-level Registry paths.
- Compare the Registry write with related file or process behavior.

## RegCreateKeyExA / RegCreateKeyExW

### General Purpose

Creates a new Registry key or opens an existing one.

### Analysis Meaning

`RegCreateKeyExA` or `RegCreateKeyExW` may indicate that the program prepares a Registry location for later use.

It should be reviewed together with Registry value writing APIs.

### What to Review

- Check which Registry key is created or opened.
- Review whether values are written after the key is created.
- Compare the key path with known application or startup locations.
- Check whether the key is used to store configuration or execution-related data.