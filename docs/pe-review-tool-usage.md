# PE Review Tool Usage Guide

This guide explains how to use the PE Static Review Scorer GUI.

The tool is designed for defensive static analysis. It reads PE metadata, section data, import tables, imported DLLs, and static string indicators without executing the analyzed file.

The score is not a malware verdict. It is a manual review priority score.

## Run the Tool

```powershell
python .\src\pe_suspicion_scorer_gui.py
