# PE Review Tool Usage Guide

This guide explains how to use the PE Static Review Scorer GUI.

The tool is designed for defensive static analysis. It reads PE import tables, groups imported APIs by behavior category, and produces a review priority score.

The score is not a malware verdict.

## Run the Tool

```powershell
python .\src\pe_suspicion_scorer_gui.py
```
