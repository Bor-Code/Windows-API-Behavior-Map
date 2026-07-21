# Windows API Behavior Map

Windows API Behavior Map is a defensive static analysis project for reviewing Windows PE files without executing them.

The project helps analysts inspect PE import tables, map imported Windows APIs to behavior categories, review PE metadata and static indicators, and produce a static review priority score for manual triage.

The score is not a malware verdict.

## Purpose

During PE malware analysis, imported Windows API functions and PE metadata can provide useful behavioral hints.

This project supports:

- Windows API behavior category mapping
- PE import table interpretation
- PE metadata review
- PE section review
- imported DLL review
- static string indicator review
- single-file PE review
- folder-based PE batch review
- CSV, JSON, and text report export
- static review priority scoring for manual triage

## Safety Scope

This repository is a defensive learning and analysis project.

It does not contain:

- malware samples
- payloads
- exploit code
- bypass instructions
- offensive implementation details

The tooling only reads PE files statically. It does not execute analyzed files.

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