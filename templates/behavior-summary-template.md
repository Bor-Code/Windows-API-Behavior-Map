# Behavior Summary Template

This template is used to write short behavior summaries based on PE import table analysis.

The goal is not to make a final conclusion from imported APIs alone. The goal is to summarize which behavior categories should be reviewed during analysis.

## Sample Metadata

```text
Sample Name:
SHA256:
Analysis Date:
Analyst:
```

## Observed API Categories

```text
File System:
Registry:
Process:
Memory:
Network:
DLL Loading:
```

## Observed APIs

```text
List the relevant imported APIs here.
```

## Behavior Summary

Use careful analysis language.

Example:

```text
The import table suggests file system, Registry, and process-related behavior. This does not prove malicious behavior by itself. These categories should be reviewed together with strings, call references, and controlled runtime observations.
```

## Supporting Evidence

```text
Strings:
Import Table:
Decompiler Notes:
Runtime Notes:
```

## Analyst Notes

Use this section to explain what should be checked next.

## Conclusion

Use a short and careful conclusion.

Example:

```text
The observed imports provide behavioral hints but are not enough for a final verdict. Further static and dynamic analysis is required.
```