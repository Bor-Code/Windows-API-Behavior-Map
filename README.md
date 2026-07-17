# Windows API Behavior Map

Windows API Behavior Map is a defensive documentation and tooling project for mapping commonly observed Windows API functions to behavior categories used during PE malware analysis.

The project helps analysts review Windows PE import tables, group imported APIs by behavior category, and write careful static analysis notes.

It does not label a file as malicious based on a single API function or a score.

## Purpose

During PE malware analysis, imported Windows API functions can provide useful behavioral hints.

This project documents and supports:

- common Windows API behavior categories
- PE import table interpretation
- static review scoring for manual triage
- single-file PE review
- folder-based batch PE review
- report export for analysis notes

## Safety Scope

This repository is a defensive learning and analysis project.

It does not contain:

- malware samples
- payloads
- exploit code
- bypass instructions
- offensive implementation details

The tooling only reads PE metadata and import tables for static review.

## Current Features

### API Behavior Documentation

The repository includes behavior notes for:

- File System API
- Registry API
- Process API
- Memory API
- Network API
- DLL Loading API

Each category explains what the APIs are generally used for, what an analyst should review, and why a single API should not be treated as proof of malicious behavior.

### API Behavior Mapper CLI

The CLI mapper groups a text list of imported APIs by behavior category.

Example:

```powershell
python .\src\api_behavior_mapper.py --imports .\sample-inputs\imports.txt