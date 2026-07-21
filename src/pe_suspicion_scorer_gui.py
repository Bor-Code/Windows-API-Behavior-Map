import csv
from collections import Counter
import hashlib
import json
import re
import subprocess
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

import pefile


MAX_SCORE = 10000

PE_MACHINE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

CATEGORY_BREADTH_WEIGHT = 120
DEFAULT_SCAN_LIMIT = 50
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATEGORIES_PATH = PROJECT_ROOT / "data" / "api_categories.json"
SCANNABLE_PE_EXTENSIONS = {".exe", ".dll", ".scr"}
MAX_STRING_SCAN_BYTES = 8 * 1024 * 1024
STRING_INDICATOR_LIMIT = 12

API_SIGNAL_WEIGHTS = {
    "CreateFileA": 40,
    "CreateFileW": 40,
    "ReadFile": 30,
    "WriteFile": 70,
    "DeleteFileA": 80,
    "DeleteFileW": 80,
    "RegOpenKeyExA": 60,
    "RegOpenKeyExW": 60,
    "RegQueryValueExA": 60,
    "RegQueryValueExW": 60,
    "RegCreateKeyExA": 80,
    "RegCreateKeyExW": 80,
    "RegSetValueExA": 100,
    "RegSetValueExW": 100,
    "GetCurrentProcess": 20,
    "CreateProcessA": 180,
    "CreateProcessW": 180,
    "TerminateProcess": 160,
    "GetProcessHeap": 20,
    "HeapAlloc": 30,
    "VirtualAlloc": 130,
    "VirtualProtect": 180,
    "WriteProcessMemory": 700,
    "CreateRemoteThread": 900,
    "InternetOpenA": 60,
    "InternetOpenW": 60,
    "HttpOpenRequestA": 100,
    "HttpOpenRequestW": 100,
    "HttpSendRequestA": 130,
    "HttpSendRequestW": 130,
    "InternetReadFile": 100,
    "WSAStartup": 40,
    "connect": 180,
    "send": 150,
    "recv": 150,
    "LoadLibraryA": 80,
    "LoadLibraryW": 80,
    "FreeLibrary": 30,
    "GetModuleHandleA": 30,
    "GetModuleHandleW": 30,
    "GetProcAddress": 120,
}

COMBINATION_WEIGHTS = {
    ("Network", "File System"): 250,
    ("Network", "Registry"): 250,
    ("Memory", "DLL Loading"): 250,
    ("Process", "Memory"): 250,
}


@dataclass
class AnalysisResult:
    selected_path: Path
    analyzed_path: Path
    pe_metadata: dict[str, str]
    pe_sections: list[dict[str, object]]
    imported_dlls: list[str]
    grouped_apis: dict[str, list[str]]
    score: int
    priority: str
    mapped_api_count: int
    unknown_api_count: int
    reason_lines: list[str]
    string_indicators: dict[str, list[str]]
    detected_categories: list[str]


def load_api_categories(categories_path: Path) -> dict[str, str]:
    with categories_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def resolve_shortcut(shortcut_path: Path) -> Path:
    escaped_path = str(shortcut_path).replace("'", "''")

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "$shell = New-Object -ComObject WScript.Shell; "
            f"$shortcut = $shell.CreateShortcut('{escaped_path}'); "
            "$shortcut.TargetPath"
        ),
    ]

    completed_process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    target_path = completed_process.stdout.strip()

    if not target_path:
        raise ValueError("Shortcut target could not be resolved.")

    return Path(target_path)


def normalize_selected_path(selected_path: Path) -> Path:
    if selected_path.suffix.lower() == ".lnk":
        return resolve_shortcut(selected_path)

    return selected_path


def extract_imported_apis(pe_path: Path) -> list[str]:
    pe = pefile.PE(str(pe_path))
    imported_apis: list[str] = []

    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imported_apis

        for import_entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imported_symbol in import_entry.imports:
                if imported_symbol.name:
                    api_name = imported_symbol.name.decode(
                        "utf-8",
                        errors="ignore",
                    )
                    imported_apis.append(api_name)
    finally:
        pe.close()

    return sorted(set(imported_apis))


def group_apis_by_category(
    imported_apis: list[str],
    api_categories: dict[str, str],
) -> dict[str, list[str]]:
    grouped_apis: dict[str, list[str]] = {}

    for api_name in imported_apis:
        category = api_categories.get(api_name, "Unknown")
        grouped_apis.setdefault(category, []).append(api_name)

    return grouped_apis


def calculate_static_review_score(grouped_apis: dict[str, list[str]]) -> int:
    detected_categories = set(grouped_apis) - {"Unknown"}
    score = len(detected_categories) * CATEGORY_BREADTH_WEIGHT

    for category, api_names in grouped_apis.items():
        if category == "Unknown":
            continue

        for api_name in api_names:
            score += API_SIGNAL_WEIGHTS.get(api_name, 20)

    for category_a, category_b in COMBINATION_WEIGHTS:
        if category_a in detected_categories and category_b in detected_categories:
            score += COMBINATION_WEIGHTS[(category_a, category_b)]

    return min(score, MAX_SCORE)


def get_review_priority(score: int) -> str:
    if score >= 6500:
        return "High Review Priority"
    if score >= 3000:
        return "Medium Review Priority"
    return "Low Review Priority"


def get_category_summary(grouped_apis: dict[str, list[str]]) -> list[str]:
    known_categories = {
        category: api_names
        for category, api_names in grouped_apis.items()
        if category != "Unknown"
    }

    mapped_api_count = sum(len(api_names) for api_names in known_categories.values())
    unknown_api_count = len(grouped_apis.get("Unknown", []))

    if known_categories:
        top_category, top_apis = max(
            known_categories.items(),
            key=lambda item: len(item[1]),
        )
        top_category_text = f"{top_category} ({len(top_apis)} APIs)"
    else:
        top_category_text = "None"

    detected_categories = ", ".join(sorted(known_categories)) or "None"

    return [
        f"Detected Categories: {detected_categories}",
        f"Mapped APIs: {mapped_api_count}",
        f"Unknown APIs: {unknown_api_count}",
        f"Top Category: {top_category_text}",
    ]





def build_score_legend() -> list[str]:
    return [
        "0-3499: Low Review Priority",
        "3500-6999: Medium Review Priority",
        "7000-10000: High Review Priority",
        "The score is based only on static import table indicators.",
        "The score is not a malware verdict.",
    ]


def get_top_weighted_apis(grouped_apis: dict[str, list[str]], limit: int = 8) -> list[str]:
    weighted_apis: list[tuple[int, str]] = []

    for category, api_names in grouped_apis.items():
        if category == "Unknown":
            continue

        for api_name in api_names:
            weight = API_SIGNAL_WEIGHTS.get(api_name, 0)
            if weight > 0:
                weighted_apis.append((weight, api_name))

    weighted_apis.sort(key=lambda item: item[0], reverse=True)
    return [api_name for _, api_name in weighted_apis[:limit]]


def build_analysis_summary(result: AnalysisResult) -> list[str]:
    detected_categories = sorted(set(result.grouped_apis) - {"Unknown"})
    top_apis = get_top_weighted_apis(result.grouped_apis)

    lines: list[str] = []
    lines.append(f"Mapped API Count: {result.mapped_api_count}")
    lines.append(f"Unknown API Count: {result.unknown_api_count}")
    lines.append(f"Detected Category Count: {len(detected_categories)}")

    if detected_categories:
        lines.append("Detected Categories: " + ", ".join(detected_categories))
    else:
        lines.append("Detected Categories: None")

    if top_apis:
        lines.append("Highest Signal APIs: " + ", ".join(top_apis))
    else:
        lines.append("Highest Signal APIs: None")

    return lines


def build_review_reasons(grouped_apis: dict[str, list[str]]) -> list[str]:
    reasons: list[str] = []
    detected_categories = sorted(set(grouped_apis) - {"Unknown"})

    if detected_categories:
        reasons.append(
            "Mapped imports were found in these behavior categories: "
            + ", ".join(detected_categories)
            + "."
        )

    for category in detected_categories:
        api_names = grouped_apis.get(category, [])
        weighted_apis = [
            api_name
            for api_name in api_names
            if API_SIGNAL_WEIGHTS.get(api_name, 0) >= 100
        ]

        if weighted_apis:
            reasons.append(
                f"{category} review priority increased because higher-signal APIs were detected: "
                + ", ".join(weighted_apis[:8])
                + "."
            )
        elif api_names:
            reasons.append(
                f"{category} activity should be reviewed because mapped APIs were detected: "
                + ", ".join(api_names[:8])
                + "."
            )

    for category_a, category_b in COMBINATION_WEIGHTS:
        if category_a in detected_categories and category_b in detected_categories:
            reasons.append(
                f"{category_a} and {category_b} indicators appear together, so their combined behavior should be reviewed."
            )

    unknown_count = len(grouped_apis.get("Unknown", []))
    if unknown_count:
        reasons.append(
            f"{unknown_count} imported APIs are not mapped yet. They are shown for visibility but do not increase the score."
        )

    if not reasons:
        reasons.append(
            "No mapped behavior categories were detected from the current import table mapping."
        )

    reasons.append(
        "The score is a static review priority, not a malware verdict."
    )

    return reasons


def build_next_review_steps(grouped_apis: dict[str, list[str]]) -> list[str]:
    steps: list[str] = []
    detected_categories = set(grouped_apis) - {"Unknown"}

    if "File System" in detected_categories:
        steps.append("Review strings for file paths, created files, deleted files, and write targets.")
    if "Registry" in detected_categories:
        steps.append("Review Registry paths, Run/RunOnce keys, configuration values, and persistence-related strings.")
    if "Process" in detected_categories:
        steps.append("Review process creation, command-line strings, child process names, and termination behavior.")
    if "Memory" in detected_categories:
        steps.append("Review memory allocation and protection changes together with process and DLL loading indicators.")
    if "Network" in detected_categories:
        steps.append("Review URLs, domains, IP addresses, HTTP paths, and socket-related strings.")
    if "DLL Loading" in detected_categories:
        steps.append("Review loaded DLL names, dynamically resolved functions, and GetProcAddress usage.")

    if not steps:
        steps.append("Review the file with strings, metadata, sections, and other static analysis checks.")

    steps.append("Use dynamic analysis only in a controlled lab if static indicators need confirmation.")
    return steps



def extract_printable_strings(pe_path: Path) -> list[str]:
    with pe_path.open("rb") as file:
        data = file.read(MAX_STRING_SCAN_BYTES)

    raw_strings = re.findall(rb"[\x20-\x7e]{5,180}", data)

    decoded_strings: list[str] = []
    seen_strings: set[str] = set()

    for raw_string in raw_strings:
        decoded_string = raw_string.decode("latin-1", errors="ignore").strip()

        if decoded_string and decoded_string not in seen_strings:
            decoded_strings.append(decoded_string)
            seen_strings.add(decoded_string)

        if len(decoded_strings) >= 3000:
            break

    return decoded_strings


def add_string_indicator(
    indicators: dict[str, list[str]],
    category: str,
    value: str,
) -> None:
    if len(indicators[category]) >= STRING_INDICATOR_LIMIT:
        return

    if value not in indicators[category]:
        indicators[category].append(value)


def looks_like_ip_address(value: str) -> bool:
    match = re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value)

    if not match:
        return False

    return all(0 <= int(part) <= 255 for part in value.split("."))


def classify_string_indicators(strings: list[str]) -> dict[str, list[str]]:
    indicators: dict[str, list[str]] = {
        "URLs": [],
        "IP Addresses": [],
        "Registry Paths": [],
        "Windows Paths": [],
        "Command Line Indicators": [],
        "DLL Names": [],
        "File Names": [],
    }

    command_keywords = (
        "cmd.exe",
        "powershell",
        "rundll32",
        "regsvr32",
        "schtasks",
        "wscript",
        "cscript",
        "mshta",
        " /c ",
        " -enc",
    )

    file_extensions = (
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".tmp",
        ".dat",
        ".txt",
    )

    for value in strings:
        cleaned_value = value.strip()
        lower_value = cleaned_value.lower()

        if re.search(r"https?://|www\.", lower_value):
            add_string_indicator(indicators, "URLs", cleaned_value)

        for ip_candidate in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", cleaned_value):
            if looks_like_ip_address(ip_candidate):
                add_string_indicator(indicators, "IP Addresses", ip_candidate)

        if (
            "hkey_" in lower_value
            or "hkcu\\" in lower_value
            or "hklm\\" in lower_value
            or "\\software\\microsoft\\windows\\currentversion" in lower_value
        ):
            add_string_indicator(indicators, "Registry Paths", cleaned_value)

        if re.search(r"[a-zA-Z]:\\", cleaned_value) or "\\windows\\" in lower_value:
            add_string_indicator(indicators, "Windows Paths", cleaned_value)

        if any(keyword in lower_value for keyword in command_keywords):
            add_string_indicator(indicators, "Command Line Indicators", cleaned_value)

        dll_matches = re.findall(r"\b[\w.\-]+\.dll\b", cleaned_value, flags=re.IGNORECASE)
        for dll_name in dll_matches:
            add_string_indicator(indicators, "DLL Names", dll_name)

        if any(extension in lower_value for extension in file_extensions):
            add_string_indicator(indicators, "File Names", cleaned_value)

    return indicators


def summarize_string_indicators(indicators: dict[str, list[str]]) -> str:
    summary_parts = [
        f"{category}: {len(values)}"
        for category, values in indicators.items()
        if values
    ]

    if not summary_parts:
        return "No string indicators found"

    return "; ".join(summary_parts)


def append_string_indicators(
    lines: list[str],
    indicators: dict[str, list[str]],
) -> None:
    lines.append("\nString Indicators")
    lines.append("-----------------")

    if not any(indicators.values()):
        lines.append("No notable string indicators were found in the scanned data.")
        return

    for category, values in indicators.items():
        if not values:
            continue

        lines.append(f"\n{category}")
        for value in values:
            lines.append(f"- {value}")

    lines.append(
        "\nString indicators are static review hints and do not prove malicious behavior."
    )


def format_pe_timestamp(timestamp: int) -> str:
    if not timestamp:
        return "Not available"

    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (OverflowError, OSError, ValueError):
        return "Invalid timestamp"


def get_machine_name(machine_value: int) -> str:
    machine_name = PE_MACHINE_TYPES.get(machine_value)

    if machine_name:
        return machine_name

    return f"Unknown ({hex(machine_value)})"


def calculate_sha256(pe_path: Path) -> str:
    digest = hashlib.sha256()

    with pe_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def extract_pe_metadata(pe_path: Path) -> dict[str, str]:
    pe = pefile.PE(str(pe_path), fast_load=True)

    try:
        optional_header = pe.OPTIONAL_HEADER
        file_header = pe.FILE_HEADER

        return {
            "file_name": pe_path.name,
            "file_size": str(pe_path.stat().st_size),
            "sha256": calculate_sha256(pe_path),
            "machine": get_machine_name(file_header.Machine),
            "section_count": str(file_header.NumberOfSections),
            "compile_timestamp": format_pe_timestamp(file_header.TimeDateStamp),
            "entry_point": hex(optional_header.AddressOfEntryPoint),
            "image_base": hex(optional_header.ImageBase),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(
                optional_header.Subsystem,
                str(optional_header.Subsystem),
            ),
        }
    finally:
        pe.close()


def append_pe_metadata(lines: list[str], metadata: dict[str, str]) -> None:
    lines.append("")
    lines.append("PE Metadata")
    lines.append("-----------")
    lines.append(f"File Name: {metadata.get('file_name', 'Unknown')}")
    lines.append(f"File Size: {metadata.get('file_size', 'Unknown')} bytes")
    lines.append(f"SHA256: {metadata.get('sha256', 'Unknown')}")
    lines.append(f"Machine: {metadata.get('machine', 'Unknown')}")
    lines.append(f"Section Count: {metadata.get('section_count', 'Unknown')}")
    lines.append(f"Compile Timestamp: {metadata.get('compile_timestamp', 'Unknown')}")
    lines.append(f"Entry Point: {metadata.get('entry_point', 'Unknown')}")
    lines.append(f"Image Base: {metadata.get('image_base', 'Unknown')}")
    lines.append(f"Subsystem: {metadata.get('subsystem', 'Unknown')}")


def clean_section_name(raw_name: bytes) -> str:
    return raw_name.rstrip(b"\x00").decode("utf-8", errors="replace") or "unnamed"


def extract_pe_sections(pe_path: Path) -> list[dict[str, object]]:
    pe = pefile.PE(str(pe_path), fast_load=True)

    try:
        sections: list[dict[str, object]] = []

        for section in pe.sections:
            sections.append(
                {
                    "name": clean_section_name(section.Name),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
                    "entropy": round(float(section.get_entropy()), 2),
                    "readable": bool(section.IMAGE_SCN_MEM_READ),
                    "writable": bool(section.IMAGE_SCN_MEM_WRITE),
                    "executable": bool(section.IMAGE_SCN_MEM_EXECUTE),
                }
            )

        return sections
    finally:
        pe.close()


def summarize_pe_sections(sections: list[dict[str, object]]) -> str:
    if not sections:
        return "No PE sections found"

    names = [str(section.get("name", "unknown")) for section in sections[:8]]
    summary = ", ".join(names)

    if len(sections) > 8:
        summary += f", +{len(sections) - 8} more"

    return summary


def describe_section_flags(section: dict[str, object]) -> str:
    flags: list[str] = []

    if section.get("readable"):
        flags.append("read")
    if section.get("writable"):
        flags.append("write")
    if section.get("executable"):
        flags.append("execute")

    if not flags:
        return "none"

    return ", ".join(flags)


def get_section_review_notes(sections: list[dict[str, object]]) -> list[str]:
    notes: list[str] = []

    for section in sections:
        name = section.get("name", "unknown")
        entropy = section.get("entropy", 0)

        if section.get("writable") and section.get("executable"):
            notes.append(
                f"Section {name} is both writable and executable, so it should be reviewed carefully."
            )

        if isinstance(entropy, float) and entropy >= 7.0:
            notes.append(
                f"Section {name} has high entropy ({entropy}), so packing or compression should be reviewed."
            )

    return notes


def append_section_review_notes(lines: list[str], sections: list[dict[str, object]]) -> None:
    notes = get_section_review_notes(sections)

    lines.append("")
    lines.append("Section Review Notes")
    lines.append("--------------------")

    if not notes:
        lines.append("No section-level review notes were generated.")
        return

    for note in notes:
        lines.append(f"- {note}")


def append_pe_sections(lines: list[str], sections: list[dict[str, object]]) -> None:
    lines.append("")
    lines.append("PE Sections")
    lines.append("-----------")

    if not sections:
        lines.append("No PE sections found.")
        return

    for section in sections:
        lines.append(
            "- "
            f"{section.get('name', 'unknown')} | "
            f"VA: {section.get('virtual_address', 'unknown')} | "
            f"Virtual Size: {section.get('virtual_size', 'unknown')} | "
            f"Raw Size: {section.get('raw_size', 'unknown')} | "
            f"Entropy: {section.get('entropy', 'unknown')} | "
            f"Flags: {describe_section_flags(section)}"
        )


def extract_imported_dlls(pe_path: Path) -> list[str]:
    pe = pefile.PE(str(pe_path))
    imported_dlls: list[str] = []

    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imported_dlls

        for import_entry in pe.DIRECTORY_ENTRY_IMPORT:
            if import_entry.dll:
                dll_name = import_entry.dll.decode("utf-8", errors="ignore")
                imported_dlls.append(dll_name)
    finally:
        pe.close()

    return sorted(set(imported_dlls))


def append_imported_dlls(lines: list[str], imported_dlls: list[str]) -> None:
    lines.append("")
    lines.append("Imported DLLs")
    lines.append("-------------")

    if not imported_dlls:
        lines.append("No imported DLLs found.")
        return

    for dll_name in imported_dlls:
        lines.append(f"- {dll_name}")


def get_imported_dll_review_notes(imported_dlls: list[str]) -> list[str]:
    normalized_dlls = {dll_name.lower() for dll_name in imported_dlls}
    notes: list[str] = []

    if {"wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll"} & normalized_dlls:
        notes.append(
            "Network-related DLLs were imported, so URL, domain, IP address, and network API usage should be reviewed."
        )

    if "advapi32.dll" in normalized_dlls:
        notes.append(
            "ADVAPI32.dll was imported, so Registry, service, credential, or security-related API usage should be reviewed."
        )

    if {"psapi.dll", "tlhelp32.dll"} & normalized_dlls:
        notes.append(
            "Process inspection related DLLs were imported, so process enumeration behavior should be reviewed."
        )

    if {"crypt32.dll", "bcrypt.dll", "ncrypt.dll"} & normalized_dlls:
        notes.append(
            "Crypto-related DLLs were imported, so encryption, certificate, hashing, or decoding behavior should be reviewed."
        )

    if {"shell32.dll", "shlwapi.dll"} & normalized_dlls:
        notes.append(
            "Shell-related DLLs were imported, so shortcut handling, path handling, and shell execution context should be reviewed."
        )

    if {"ntdll.dll", "kernel32.dll"} <= normalized_dlls:
        notes.append(
            "Core Windows runtime DLLs were imported, so low-level process, memory, file, and synchronization APIs should be reviewed in context."
        )

    return notes


def append_imported_dll_review_notes(lines: list[str], imported_dlls: list[str]) -> None:
    notes = get_imported_dll_review_notes(imported_dlls)

    lines.append("")
    lines.append("Imported DLL Review Notes")
    lines.append("-------------------------")

    if not notes:
        lines.append("No imported DLL review notes were generated.")
        return

    for note in notes:
        lines.append(f"- {note}")


def build_contextual_review_reasons(
    base_reasons: list[str],
    sections: list[dict[str, object]],
    imported_dlls: list[str],
    string_indicators: dict[str, list[str]],
) -> list[str]:
    reasons = list(base_reasons)

    section_notes = get_section_review_notes(sections)
    dll_notes = get_imported_dll_review_notes(imported_dlls)
    string_summary = summarize_string_indicators(string_indicators)

    if section_notes:
        reasons.append(
            "Section-level indicators were found, so PE section permissions and entropy should be reviewed."
        )

    if dll_notes:
        reasons.append(
            "Imported DLL context generated review notes, so DLL usage should be checked with imported APIs."
        )

    if string_summary != "No notable string indicators":
        reasons.append(
            f"String indicators were found: {string_summary}."
        )

    if section_notes or dll_notes or string_summary != "No notable string indicators":
        reasons.append(
            "The review priority combines import categories with metadata, section, DLL, and string context."
        )

    return reasons


def append_review_reasons(lines: list[str], reasons: list[str]) -> None:
    lines.append("")
    lines.append("Review Reasons")
    lines.append("--------------")

    if not reasons:
        lines.append("No review reasons were generated.")
        return

    for reason in reasons:
        lines.append(f"- {reason}")


def analyze_path_data(
    selected_path: Path,
    api_categories: dict[str, str],
) -> AnalysisResult:
    analyzed_path = normalize_selected_path(selected_path)

    if not analyzed_path.exists():
        raise FileNotFoundError(f"Analyzed file does not exist: {analyzed_path}")

    pe_metadata = extract_pe_metadata(analyzed_path)
    pe_sections = extract_pe_sections(analyzed_path)
    imported_dlls = extract_imported_dlls(analyzed_path)
    imported_apis = extract_imported_apis(analyzed_path)
    grouped_apis = group_apis_by_category(imported_apis, api_categories)
    score = calculate_static_review_score(grouped_apis)
    reason_lines = build_review_reasons(grouped_apis)
    printable_strings = extract_printable_strings(analyzed_path)
    string_indicators = classify_string_indicators(printable_strings)
    reason_lines = build_contextual_review_reasons(
        reason_lines,
        pe_sections,
        imported_dlls,
        string_indicators,
    )

    known_categories = {
        category: api_names
        for category, api_names in grouped_apis.items()
        if category != "Unknown"
    }

    mapped_api_count = sum(len(api_names) for api_names in known_categories.values())
    unknown_api_count = len(grouped_apis.get("Unknown", []))

    return AnalysisResult(
        selected_path=selected_path,
        analyzed_path=analyzed_path,
        pe_metadata=pe_metadata,
        pe_sections=pe_sections,
        imported_dlls=imported_dlls,
        grouped_apis=grouped_apis,
        score=score,
        priority=get_review_priority(score),
        mapped_api_count=mapped_api_count,
        unknown_api_count=unknown_api_count,
        reason_lines=reason_lines,
        string_indicators=string_indicators,
        detected_categories=sorted(known_categories),
    )


def build_report(result: AnalysisResult) -> str:
    lines: list[str] = []

    lines.append("PE Static Review Report")
    lines.append("=======================")
    lines.append("")
    lines.append(f"Selected File: {result.selected_path}")
    lines.append(f"Analyzed File: {result.analyzed_path}")
    lines.append(f"Static Review Score: {result.score} / {MAX_SCORE}")
    lines.append(f"Review Priority: {result.priority}")
    append_pe_metadata(lines, result.pe_metadata)
    append_pe_sections(lines, result.pe_sections)
    append_section_review_notes(lines, result.pe_sections)
    append_imported_dlls(lines, result.imported_dlls)
    append_imported_dll_review_notes(lines, result.imported_dlls)

    lines.append("")
    lines.append("Analysis Summary")
    lines.append("----------------")
    lines.extend(get_category_summary(result.grouped_apis))
    append_review_reasons(lines, result.reason_lines)

    lines.append("")
    lines.append("Detected Categories")
    lines.append("-------------------")

    for category, api_names in result.grouped_apis.items():
        if category == "Unknown":
            continue

        lines.append("")
        lines.append(category)
        lines.append("-" * len(category))

        for api_name in api_names:
            lines.append(f"- {api_name}")

    lines.append("")
    lines.append("Unknown APIs")
    lines.append("------------")
    lines.append(f"{result.unknown_api_count} imported APIs were not mapped.")
    lines.append("Unknown APIs are listed for visibility but do not increase the score.")
    lines.append("")
    lines.append("Suggested Manual Review Checklist")
    lines.append("---------------------------------")
    lines.append("- Review imported API categories and unknown APIs.")
    lines.append("- Review PE metadata, compile timestamp, subsystem, and entry point.")
    lines.append("- Review section entropy, writable/executable flags, and unusual section names.")
    lines.append("- Review imported DLL notes and static string indicators.")
    lines.append("- Use the score to prioritize manual review, not to decide a final verdict.")
    lines.append("")
    lines.append("Analysis Note")
    lines.append("-------------")
    lines.append("This result is based only on static PE import table indicators.")
    lines.append("It does not prove malicious behavior by itself.")
    lines.append("Use the score as a manual review priority signal, not as a final verdict.")

    return "\n".join(lines)


def find_pe_files(folder_path: Path) -> list[Path]:
    return sorted(
        path
        for path in folder_path.rglob("*")
        if path.is_file() and path.suffix.lower() in SCANNABLE_PE_EXTENSIONS
    )


def build_batch_summary(
    discovered_count: int,
    scan_limit: int,
    results: list[AnalysisResult],
    failures: list[tuple[Path, str]],
) -> list[str]:
    lines: list[str] = []
    scanned_count = len(results) + len(failures)
    skipped_count = max(discovered_count - scanned_count, 0)

    priority_counts = Counter(result.priority for result in results)
    category_counts: Counter[str] = Counter()

    for result in results:
        category_counts.update(result.detected_categories)

    highest_result = max(results, key=lambda result: result.score, default=None)
    top_category = category_counts.most_common(1)

    lines.append("Batch Summary")
    lines.append("-------------")
    lines.append(f"Discovered PE Files: {discovered_count}")
    lines.append(f"Scan Limit: {scan_limit}")
    lines.append(f"Scanned Files: {scanned_count}")
    lines.append(f"Successful Analyses: {len(results)}")
    lines.append(f"Failed Analyses: {len(failures)}")
    lines.append(f"Skipped By Limit: {skipped_count}")

    if highest_result:
        lines.append(
            "Highest Score: "
            f"{highest_result.score} / {MAX_SCORE} "
            f"({highest_result.priority}) - {highest_result.analyzed_path.name}"
        )
    else:
        lines.append("Highest Score: None")

    if priority_counts:
        priority_text = ", ".join(
            f"{priority}: {count}"
            for priority, count in sorted(priority_counts.items())
        )
        lines.append(f"Priority Distribution: {priority_text}")
    else:
        lines.append("Priority Distribution: None")

    if top_category:
        category, count = top_category[0]
        lines.append(f"Most Common Category: {category} ({count} files)")
    else:
        lines.append("Most Common Category: None")

    return lines


def build_batch_report(
    folder_path: Path,
    discovered_count: int,
    scan_limit: int,
    results: list[AnalysisResult],
    failures: list[tuple[Path, str]],
) -> str:
    lines: list[str] = []
    sorted_results = sorted(results, key=lambda result: result.score, reverse=True)

    lines.append("PE Batch Static Review Report")
    lines.append("=============================")
    lines.append("")

    lines.extend(
        build_batch_summary(
            discovered_count=discovered_count,
            scan_limit=scan_limit,
            results=results,
            failures=failures,
        )
    )
    lines.append("")
    lines.append(f"Selected Folder: {folder_path}")

    lines.append("")
    lines.append("Batch Review Results")
    lines.append("--------------------")

    if not sorted_results:
        lines.append("No PE files were analyzed.")
    else:
        for index, result in enumerate(sorted_results, start=1):
            category_text = (
                ", ".join(result.detected_categories)
                if result.detected_categories
                else "None"
            )

            lines.append("")
            lines.append(f"{index}. {result.analyzed_path.name}")
            lines.append(f"   Path: {result.analyzed_path}")
            lines.append(f"   Static Review Score: {result.score} / {MAX_SCORE}")
            lines.append(f"   Review Priority: {result.priority}")
            lines.append(f"   Detected Categories: {category_text}")
            lines.append(f"   Mapped APIs: {result.mapped_api_count}")
            lines.append(f"   Unknown APIs: {result.unknown_api_count}")

        lines.append("")
        lines.append("Suggested Batch Review Checklist")
        lines.append("--------------------------------")
        lines.append("- Start with the highest score files first.")
        lines.append("- Review files with high priority before low priority files.")
        lines.append("- Compare detected categories across files in the same folder.")
        lines.append("- Review unknown APIs and failed analyses separately.")
        lines.append("- Use batch results for triage, not as final malware verdicts.")


    if failures:
        lines.append("")
        lines.append("Failed Files")
        lines.append("------------")

        for failed_path, error_message in failures:
            lines.append(f"- {failed_path}: {error_message}")

    lines.append("")
    lines.append("Analysis Note")
    lines.append("-------------")
    lines.append("This batch report is based only on static PE import table indicators.")
    lines.append("It does not prove malicious behavior by itself.")
    lines.append("Use the scores to prioritize manual review, not as final verdicts.")

    return "\n".join(lines)


def analyze_file(selected_path: Path) -> tuple[str, list[AnalysisResult], list[tuple[Path, str]]]:
    api_categories = load_api_categories(DEFAULT_CATEGORIES_PATH)
    result = analyze_path_data(selected_path, api_categories)
    return build_report(result), [result], []


def analyze_folder(
    folder_path: Path,
    scan_limit: int,
) -> tuple[str, list[AnalysisResult], list[tuple[Path, str]]]:
    api_categories = load_api_categories(DEFAULT_CATEGORIES_PATH)
    pe_files = find_pe_files(folder_path)
    selected_pe_files = pe_files[:scan_limit]

    results: list[AnalysisResult] = []
    failures: list[tuple[Path, str]] = []

    for pe_path in selected_pe_files:
        try:
            results.append(analyze_path_data(pe_path, api_categories))
        except Exception as error:
            failures.append((pe_path, str(error)))

    report = build_batch_report(
        folder_path=folder_path,
        discovered_count=len(pe_files),
        scan_limit=scan_limit,
        results=results,
        failures=failures,
    )

    return report, results, failures


def write_results_csv(
    csv_path: Path,
    results: list[AnalysisResult],
    failures: list[tuple[Path, str]],
) -> None:
    with csv_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "file_name",
                "file_path",
                "score",
                "priority",
                "detected_categories",
                "mapped_api_count",
                "unknown_api_count",
                "string_indicator_summary",
                "analysis_status",
                "error",
            ],
        )

        writer.writeheader()

        for result in sorted(results, key=lambda item: item.score, reverse=True):
            writer.writerow(
                {
                    "file_name": result.analyzed_path.name,
                    "file_path": str(result.analyzed_path),
                    "score": result.score,
                    "priority": result.priority,
                    "detected_categories": "; ".join(result.detected_categories),
                    "mapped_api_count": result.mapped_api_count,
                    "unknown_api_count": result.unknown_api_count,
                    "string_indicator_summary": summarize_string_indicators(result.string_indicators),
        "review_reasons": result.reason_lines,
        "next_review_steps": build_next_review_steps(result.grouped_apis),
        "analysis_summary": build_analysis_summary(result),
        "score_legend": build_score_legend(),
                    "analysis_status": "analyzed",
                    "error": "",
                }
            )

        for failed_path, error_message in failures:
            writer.writerow(
                {
                    "file_name": failed_path.name,
                    "file_path": str(failed_path),
                    "score": "",
                    "priority": "",
                    "detected_categories": "",
                    "mapped_api_count": "",
                    "unknown_api_count": "",
                    "analysis_status": "failed",
                    "error": error_message,
                }
            )


def analysis_result_to_dict(result: AnalysisResult) -> dict[str, object]:
    return {
        "file_name": result.analyzed_path.name,
        "file_path": str(result.analyzed_path),
        "selected_path": str(result.selected_path),
        "pe_metadata": result.pe_metadata,
        "pe_sections": result.pe_sections,
        "imported_dlls": result.imported_dlls,
        "imported_dll_review_notes": get_imported_dll_review_notes(result.imported_dlls),
        "section_summary": summarize_pe_sections(result.pe_sections),
        "section_review_notes": get_section_review_notes(result.pe_sections),
        "score": result.score,
        "priority": result.priority,
        "detected_categories": result.detected_categories,
        "mapped_api_count": result.mapped_api_count,
        "unknown_api_count": result.unknown_api_count,
        "string_indicator_summary": summarize_string_indicators(result.string_indicators),
        "string_indicators": result.string_indicators,
        "grouped_apis": result.grouped_apis,
        "analysis_status": "analyzed",
    }


def write_results_json(
    json_path: Path,
    results: list[AnalysisResult],
    failures: list[tuple[Path, str]],
) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "result_count": len(results),
        "failure_count": len(failures),
        "max_score": MAX_SCORE,
        "safety_note": (
            "This output is based only on static import table indicators. "
            "It does not prove malicious behavior by itself."
        ),
        "results": [
            analysis_result_to_dict(result)
            for result in sorted(results, key=lambda item: item.score, reverse=True)
        ],
        "failures": [
            {
                "file_name": failed_path.name,
                "file_path": str(failed_path),
                "analysis_status": "failed",
                "error": error_message,
            }
            for failed_path, error_message in failures
        ],
    }

    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


class PEStaticReviewScorerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PE Static Review Scorer")
        self.root.geometry("960x720")

        self.selected_file = tk.StringVar()
        self.selected_folder = tk.StringVar()
        self.status_text = tk.StringVar(value="Ready")
        self.summary_text = tk.StringVar(value="No analysis completed yet.")
        self.scan_limit_text = tk.StringVar(value=str(DEFAULT_SCAN_LIMIT))

        self.latest_results: list[AnalysisResult] = []
        self.latest_failures: list[tuple[Path, str]] = []
        self.is_analyzing = False

        self.build_layout()

    def build_layout(self) -> None:
        container = tk.Frame(self.root, padx=16, pady=16)
        container.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(
            container,
            text="PE Static Review Scorer",
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        )
        title_label.pack(fill=tk.X)

        description_label = tk.Label(
            container,
            text=(
                "Select an executable, DLL, SCR, shortcut file, or folder "
                "for static import table review scoring."
            ),
            font=("Segoe UI", 10),
            anchor="w",
        )
        description_label.pack(fill=tk.X, pady=(8, 16))

        file_row = tk.Frame(container)
        file_row.pack(fill=tk.X)

        file_entry = tk.Entry(file_row, textvariable=self.selected_file)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.browse_file_button = tk.Button(
            file_row,
            text="Browse File",
            command=self.select_file,
        )
        self.browse_file_button.pack(side=tk.LEFT, padx=(8, 0))

        folder_row = tk.Frame(container)
        folder_row.pack(fill=tk.X, pady=(8, 0))

        folder_entry = tk.Entry(folder_row, textvariable=self.selected_folder)
        folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.browse_folder_button = tk.Button(
            folder_row,
            text="Browse Folder",
            command=self.select_folder,
        )
        self.browse_folder_button.pack(side=tk.LEFT, padx=(8, 0))

        scan_limit_row = tk.Frame(container)
        scan_limit_row.pack(fill=tk.X, pady=(8, 0))

        scan_limit_label = tk.Label(
            scan_limit_row,
            text="Max files per folder scan",
            font=("Segoe UI", 10),
            anchor="w",
        )
        scan_limit_label.pack(side=tk.LEFT)

        self.scan_limit_entry = tk.Entry(
            scan_limit_row,
            textvariable=self.scan_limit_text,
            width=8,
        )
        self.scan_limit_entry.pack(side=tk.LEFT, padx=(8, 0))

        button_row = tk.Frame(container)
        button_row.pack(anchor="w", pady=(12, 8))

        self.analyze_file_button = tk.Button(
            button_row,
            text="Analyze Selected File",
            command=self.analyze_selected_file,
        )
        self.analyze_file_button.pack(side=tk.LEFT)

        self.analyze_folder_button = tk.Button(
            button_row,
            text="Analyze Selected Folder",
            command=self.analyze_selected_folder,
        )
        self.analyze_folder_button.pack(side=tk.LEFT, padx=(8, 0))

        self.save_report_button = tk.Button(
            button_row,
            text="Save Report",
            command=self.save_report,
        )
        self.save_report_button.pack(side=tk.LEFT, padx=(8, 0))

        self.save_csv_button = tk.Button(
            button_row,
            text="Save CSV",
            command=self.save_csv,
        )
        self.save_csv_button.pack(side=tk.LEFT, padx=(8, 0))

        self.save_json_button = tk.Button(
            button_row,
            text="Save JSON",
            command=self.save_json,
        )
        self.save_json_button.pack(side=tk.LEFT, padx=(8, 0))

        summary_frame = tk.LabelFrame(
            container,
            text="Review Summary",
            padx=8,
            pady=6,
        )
        summary_frame.pack(fill=tk.X, pady=(0, 8))

        summary_label = tk.Label(
            summary_frame,
            textvariable=self.summary_text,
            font=("Segoe UI", 10),
            justify=tk.LEFT,
            anchor="w",
        )
        summary_label.pack(fill=tk.X)

        status_label = tk.Label(
            container,
            textvariable=self.status_text,
            font=("Segoe UI", 10),
            anchor="w",
        )
        status_label.pack(fill=tk.X, pady=(0, 8))

        self.output = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            font=("Consolas", 10),
        )
        self.output.pack(fill=tk.BOTH, expand=True)

    def get_scan_limit(self) -> int | None:
        scan_limit_text = self.scan_limit_text.get().strip()

        try:
            scan_limit = int(scan_limit_text)
        except ValueError:
            messagebox.showwarning(
                "Invalid scan limit",
                "Max files must be a positive number.",
            )
            return None

        if scan_limit <= 0:
            messagebox.showwarning(
                "Invalid scan limit",
                "Max files must be greater than zero.",
            )
            return None

        return scan_limit

    def set_controls_enabled(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED

        self.browse_file_button.config(state=state)
        self.browse_folder_button.config(state=state)
        self.scan_limit_entry.config(state=state)
        self.analyze_file_button.config(state=state)
        self.analyze_folder_button.config(state=state)
        self.save_report_button.config(state=state)
        self.save_csv_button.config(state=state)
        self.save_json_button.config(state=state)

    def start_analysis(
        self,
        status_message: str,
        analysis_callback,
    ) -> None:
        if self.is_analyzing:
            return

        self.is_analyzing = True
        self.status_text.set(status_message)
        self.set_controls_enabled(False)

        thread = threading.Thread(
            target=self.run_analysis_worker,
            args=(analysis_callback,),
            daemon=True,
        )
        thread.start()

    def run_analysis_worker(self, analysis_callback) -> None:
        try:
            report, results, failures = analysis_callback()
        except Exception as error:
            error_message = str(error)
            self.root.after(0, lambda: self.finish_analysis_error(error_message))
            return

        self.root.after(
            0,
            lambda: self.finish_analysis_success(report, results, failures),
        )

    def build_gui_summary(
        self,
        results: list[AnalysisResult],
        failures: list[tuple[Path, str]],
    ) -> str:
        if not results and not failures:
            return "No analysis results available."

        analyzed_count = len(results)
        failed_count = len(failures)
        highest_result = max(results, key=lambda result: result.score, default=None)

        if highest_result is None:
            highest_score_text = "Highest Score: None"
        else:
            highest_score_text = (
                f"Highest Score: {highest_result.score} / {MAX_SCORE} "
                f"({highest_result.priority})"
            )

        priority_counts = Counter(result.priority for result in results)
        priority_text = ", ".join(
            f"{priority}: {count}"
            for priority, count in sorted(priority_counts.items())
        )

        if not priority_text:
            priority_text = "None"

        return (
            f"Analyzed: {analyzed_count} | Failed: {failed_count} | "
            f"{highest_score_text} | Priority Distribution: {priority_text}"
        )

    def finish_analysis_success(
        self,
        report: str,
        results: list[AnalysisResult],
        failures: list[tuple[Path, str]],
    ) -> None:
        self.latest_results = results
        self.latest_failures = failures
        self.summary_text.set(self.build_gui_summary(results, failures))

        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, report)

        self.status_text.set("Analysis complete")
        self.is_analyzing = False
        self.set_controls_enabled(True)

    def finish_analysis_error(self, error_message: str) -> None:
        self.status_text.set("Analysis failed")
        self.summary_text.set("Analysis failed. No summary available.")
        self.is_analyzing = False
        self.set_controls_enabled(True)
        messagebox.showerror("Analysis failed", error_message)

    def select_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select PE File",
            filetypes=[
                ("Supported files", "*.exe *.dll *.scr *.lnk"),
                ("Executable files", "*.exe"),
                ("DLL files", "*.dll"),
                ("Screen saver files", "*.scr"),
                ("Shortcut files", "*.lnk"),
                ("All files", "*.*"),
            ],
        )

        if file_path:
            self.selected_file.set(file_path)

    def select_folder(self) -> None:
        folder_path = filedialog.askdirectory(
            title="Select Folder to Scan",
        )

        if folder_path:
            self.selected_folder.set(folder_path)

    def analyze_selected_file(self) -> None:
        selected_path_text = self.selected_file.get().strip()

        if not selected_path_text:
            messagebox.showwarning("Missing file", "Please select a file first.")
            return

        selected_path = Path(selected_path_text)

        if not selected_path.exists():
            messagebox.showerror("Invalid file", "The selected file does not exist.")
            return

        self.start_analysis(
            status_message="Analyzing selected file...",
            analysis_callback=lambda: analyze_file(selected_path),
        )

    def analyze_selected_folder(self) -> None:
        selected_folder_text = self.selected_folder.get().strip()

        if not selected_folder_text:
            messagebox.showwarning("Missing folder", "Please select a folder first.")
            return

        selected_folder = Path(selected_folder_text)

        if not selected_folder.exists() or not selected_folder.is_dir():
            messagebox.showerror("Invalid folder", "The selected folder does not exist.")
            return

        scan_limit = self.get_scan_limit()

        if scan_limit is None:
            return

        self.start_analysis(
            status_message="Scanning folder...",
            analysis_callback=lambda: analyze_folder(selected_folder, scan_limit),
        )

    def save_report(self) -> None:
        report = self.output.get("1.0", tk.END).strip()

        if not report:
            messagebox.showwarning(
                "No report",
                "Please analyze a file or folder before saving a report.",
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Markdown files", "*.md"),
                ("All files", "*.*"),
            ],
        )

        if not save_path:
            return

        Path(save_path).write_text(report, encoding="utf-8")
        messagebox.showinfo("Report saved", "The analysis report was saved successfully.")

    def save_csv(self) -> None:
        if not self.latest_results and not self.latest_failures:
            messagebox.showwarning(
                "No results",
                "Please analyze a file or folder before saving CSV output.",
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Save CSV Results",
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )

        if not save_path:
            return

        write_results_csv(
            csv_path=Path(save_path),
            results=self.latest_results,
            failures=self.latest_failures,
        )

        messagebox.showinfo("CSV saved", "The CSV results were saved successfully.")

    def save_json(self) -> None:
        if not self.latest_results and not self.latest_failures:
            messagebox.showwarning(
                "No results",
                "Please analyze a file or folder before saving JSON output.",
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Save JSON Results",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )

        if not save_path:
            return

        write_results_json(
            json_path=Path(save_path),
            results=self.latest_results,
            failures=self.latest_failures,
        )

        messagebox.showinfo("JSON saved", "The JSON results were saved successfully.")


def main() -> None:
    root = tk.Tk()
    PEStaticReviewScorerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()