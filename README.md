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
```

### PE Static Review Scorer GUI

The GUI supports:

- single PE file analysis
- folder-based PE batch analysis
- `.exe`, `.dll`, `.scr`, and `.lnk` input handling
- scan limit support for folder analysis
- PE metadata extraction
- section entropy and flag review notes
- imported DLL summary and review notes
- static string indicator extraction
- static review priority scoring
- CSV export
- JSON export
- text report export

Run the GUI:

```powershell
python .\src\pe_suspicion_scorer_gui.py
```

## Static Review Priority

The static review priority score is a manual triage aid.

It should be used to decide which files deserve closer review first. It does not classify a file as malicious or benign.

A higher score means the file has more static indicators that may deserve analyst attention.

## Project Status

Windows API Behavior Map is in a foundation-complete state.

The project includes defensive documentation, a CLI API behavior mapper, a GUI PE static review tool, metadata and section review, imported DLL context, string indicator extraction, batch scan summaries, and exportable reports.

Future work can focus on expanding API mappings, improving scoring weights, adding more report templates, and building a broader static triage workflow.

## Requirements

Install dependencies with:

```powershell
pip install -r .\requirements.txt
```

## Final Scope Note

This project should be treated as a defensive PE static review assistant.

It does not execute files, classify files as malicious, or replace full malware analysis.