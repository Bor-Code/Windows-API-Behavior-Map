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
## Project Status

Windows API Behavior Map is now in a foundation-complete state.

The project includes:

- Windows API behavior category documentation
- API behavior mapper CLI
- PE Static Review Scorer GUI
- single-file PE review
- folder-based PE batch review
- CSV export
- JSON export
- scan limit support
- static review reasoning output
- score legend and review priority explanation
- usage guide
- Python requirements file

Future work should focus on extending API mappings, improving report templates, and starting a broader PE static triage project.

## Final Scope Note

This project should be treated as a defensive PE import table review assistant.

It does not execute files, classify files as malicious, or replace full malware analysis.

The next project should build on this foundation by adding PE metadata review, section analysis, strings review, entropy checks, and structured triage reporting.
