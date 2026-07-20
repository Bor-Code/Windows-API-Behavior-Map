# PE Review Tool Usage Guide

This guide explains how to use the PE Static Review Scorer GUI.

The tool is designed for defensive static analysis. It reads PE import tables, groups imported APIs by behavior category, and produces a review priority score.

The score is not a malware verdict.

## Run the Tool

```powershell
python .\src\pe_suspicion_scorer_gui.py

Analyze a Single File
Click Browse File.
Select an .exe, .dll, .scr, or .lnk file.
Click Analyze Selected File.
Review the detected categories, score, review reasons, and next review steps.
Analyze a Folder
Click Browse Folder.
Select a folder that contains PE files.
Set the max file scan limit.
Click Analyze Selected Folder.
Review the batch report.
## Export Reports

The GUI supports:

Save Report
Save CSV
Save JSON
## Review Priority

The score ranges from 0 to 10000.

Low Review Priority: fewer mapped indicators were detected
Medium Review Priority: several categories should be reviewed
High Review Priority: deeper manual review is recommended

The score should always be reviewed with analyst judgment.

## Limitations

The tool only reviews static PE import table indicators.

It does not execute files.

It does not prove malicious intent.

It does not replace full malware analysis.
