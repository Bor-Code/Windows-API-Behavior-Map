import csv
import json
import subprocess
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

import pefile


MAX_SCORE = 10000
CATEGORY_BREADTH_WEIGHT = 120
DEFAULT_SCAN_LIMIT = 50
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATEGORIES_PATH = PROJECT_ROOT / "data" / "api_categories.json"
SCANNABLE_PE_EXTENSIONS = {".exe", ".dll", ".scr"}

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
    grouped_apis: dict[str, list[str]]
    score: int
    priority: str
    mapped_api_count: int
    unknown_api_count: int
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


def analyze_path_data(
    selected_path: Path,
    api_categories: dict[str, str],
) -> AnalysisResult:
    analyzed_path = normalize_selected_path(selected_path)

    if not analyzed_path.exists():
        raise FileNotFoundError(f"Analyzed file does not exist: {analyzed_path}")

    imported_apis = extract_imported_apis(analyzed_path)
    grouped_apis = group_apis_by_category(imported_apis, api_categories)
    score = calculate_static_review_score(grouped_apis)

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
        grouped_apis=grouped_apis,
        score=score,
        priority=get_review_priority(score),
        mapped_api_count=mapped_api_count,
        unknown_api_count=unknown_api_count,
        detected_categories=sorted(known_categories),
    )


def build_report(result: AnalysisResult) -> str:
    lines: list[str] = []

    lines.append(f"Selected File: {result.selected_path}")
    lines.append(f"Analyzed File: {result.analyzed_path}")
    lines.append(f"Static Review Score: {result.score} / {MAX_SCORE}")
    lines.append(f"Review Priority: {result.priority}")

    lines.append("")
    lines.append("Analysis Summary")
    lines.append("----------------")
    lines.extend(get_category_summary(result.grouped_apis))

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
    lines.append("Analysis Note")
    lines.append("-------------")
    lines.append("This score is based only on static import table indicators.")
    lines.append("It does not prove malicious behavior by itself.")
    lines.append("The score only shows how much manual review may be useful.")

    return "\n".join(lines)


def find_pe_files(folder_path: Path) -> list[Path]:
    return sorted(
        path
        for path in folder_path.rglob("*")
        if path.is_file() and path.suffix.lower() in SCANNABLE_PE_EXTENSIONS
    )


def build_batch_report(
    folder_path: Path,
    discovered_count: int,
    scan_limit: int,
    results: list[AnalysisResult],
    failures: list[tuple[Path, str]],
) -> str:
    lines: list[str] = []
    sorted_results = sorted(results, key=lambda result: result.score, reverse=True)

    attempted_count = len(results) + len(failures)
    skipped_by_limit = max(discovered_count - attempted_count, 0)

    lines.append(f"Selected Folder: {folder_path}")
    lines.append(f"Discovered PE Files: {discovered_count}")
    lines.append(f"Analyzed PE Files: {len(results)}")
    lines.append(f"Failed Files: {len(failures)}")
    lines.append(f"Scan Limit: {scan_limit}")
    lines.append(f"Skipped by Limit: {skipped_by_limit}")

    if sorted_results:
        top_result = sorted_results[0]
        lines.append(f"Highest Review Priority File: {top_result.analyzed_path}")
        lines.append(f"Highest Static Review Score: {top_result.score} / {MAX_SCORE}")

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

    if failures:
        lines.append("")
        lines.append("Failed Files")
        lines.append("------------")

        for failed_path, error_message in failures:
            lines.append(f"- {failed_path}: {error_message}")

    lines.append("")
    lines.append("Analysis Note")
    lines.append("-------------")
    lines.append("This batch report is based only on static import table indicators.")
    lines.append("It does not prove malicious behavior by itself.")
    lines.append("The score only shows which files may deserve more manual review.")

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
        "score": result.score,
        "priority": result.priority,
        "detected_categories": result.detected_categories,
        "mapped_api_count": result.mapped_api_count,
        "unknown_api_count": result.unknown_api_count,
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

    def finish_analysis_success(
        self,
        report: str,
        results: list[AnalysisResult],
        failures: list[tuple[Path, str]],
    ) -> None:
        self.latest_results = results
        self.latest_failures = failures

        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, report)

        self.status_text.set("Analysis complete")
        self.is_analyzing = False
        self.set_controls_enabled(True)

    def finish_analysis_error(self, error_message: str) -> None:
        self.status_text.set("Analysis failed")
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