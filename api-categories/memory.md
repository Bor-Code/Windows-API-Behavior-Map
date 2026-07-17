# Memory API

This category covers Windows API functions commonly related to memory allocation, memory protection, memory copying, and heap usage.

Memory APIs should be interpreted as behavioral indicators during PE malware analysis. A single memory-related API should not be treated as proof of malicious behavior.

## VirtualAlloc

### General Purpose

Reserves, commits, or changes a region of memory in the virtual address space of the current process.

### Analysis Meaning

When `VirtualAlloc` appears in a PE import table, it may indicate that the program allocates memory at runtime.

This API is common in normal applications. It becomes more meaningful when it appears together with memory protection changes, buffer copying, or unusual runtime data handling.

### What to Review

- Check whether the allocated memory is later written to.
- Review the requested memory protection flags.
- Compare the API usage with decompiler output.
- Avoid making a conclusion from this API alone.

## VirtualProtect

### General Purpose

Changes the protection on a region of memory in the virtual address space of the current process.

### Analysis Meaning

`VirtualProtect` may indicate that the program changes memory permissions during execution.

This can appear in normal software, packers, protectors, or runtime code handling. The surrounding code flow is important.

### What to Review

- Review which memory region is being modified.
- Check the requested protection flags.
- Look for nearby memory allocation or memory copy operations.
- Compare the imported API with actual call references in the disassembler.

## HeapAlloc

### General Purpose

Allocates a block of memory from a heap.

### Analysis Meaning

`HeapAlloc` is a common memory management API used by many normal applications.

It usually indicates dynamic memory allocation and should not be considered suspicious by itself.

### What to Review

- Check what type of data is stored in the allocated memory.
- Review whether the allocated buffer is used for strings, file data, or network data.
- Compare this API with related heap management functions.
- Avoid making a conclusion from this API alone.

## GetProcessHeap

### General Purpose

Returns a handle to the default heap of the current process.

### Analysis Meaning

`GetProcessHeap` is commonly used before heap allocation or heap management operations.

It is usually part of normal application memory management.

### What to Review

- Check whether the returned heap handle is passed to `HeapAlloc` or related functions.
- Review what data is stored in heap-allocated buffers.
- Compare heap usage with string, file, or parsing logic.
- Treat this API as context, not as a final indicator.

## RtlMoveMemory

### General Purpose

Copies memory from one location to another.

### Analysis Meaning

`RtlMoveMemory` may indicate buffer copying or data transformation behavior.

It is common in normal applications and should be reviewed together with the source and destination buffers.

### What to Review

- Identify where the source data comes from.
- Check where the copied data is used next.
- Review whether the copied data is related to files, strings, or runtime buffers.
- Compare the memory copy operation with surrounding code flow.