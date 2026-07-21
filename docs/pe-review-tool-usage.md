# PE Review Tool Usage Guide

This guide explains how to use the PE Static Review Scorer GUI.

The tool is designed for defensive static analysis. It reads PE metadata, section data, import tables, imported DLLs, and static string indicators without executing the analyzed file.

The score is not a malware verdict. It is a manual review priority score.

## Run the Tool

```powershell
python .\src\pe_suspicion_scorer_gui.py
```

## Single File Review

Use single file review when you want to analyze one PE file.

Supported inputs include:

- `.exe`
- `.dll`
- `.scr`
- `.lnk`

The tool extracts static PE information, groups imported APIs by behavior category, calculates a static review priority score, and shows review reasoning.

## Folder Batch Review

Use folder batch review when you want to analyze multiple PE files from one folder.

The scan limit helps prevent accidentally scanning too many files at once.

The batch summary includes:

- discovered PE files
- scan limit
- scanned files
- successful analyses
- failed analyses
- skipped files
- highest score
- priority distribution
- most common detected category

## Export Options

The GUI supports:

- text report export
- CSV export
- JSON export

Text reports are useful for human-readable analysis notes.

CSV exports are useful for comparing many files in a table.

JSON exports are useful for structured review data.

## Analyst Notes

Review the score together with:

- imported API categories
- unknown APIs
- PE metadata
- section entropy and flags
- imported DLL notes
- static string indicators
- review reasoning

Do not use the score alone as a malware verdict.