import json
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

import pefile


MAX_SCORE = 10000
CATEGORY_BREADTH_WEIGHT = 120
DEFAULT_CATEGORIES_PATH = Path("data/api_categories.json")

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

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    target = result.stdout.strip()

    if not target:
        raise ValueError("Shortcut target could not be resolved.")

    return Path(target)


def normalize_selected_path(selected_path: Path) -> Path:
    if selected_path.suffix.lower() == ".lnk":
        return resolve_shortcut(selected_path)

    return selected_path


def extract_imported_apis(pe_path: Path) -> list[str]:
    pe = pefile.PE(str(pe_path))
    imported_apis: list[str] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imported_apis

    for import_entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imported_symbol in import_entry.imports:
            if imported_symbol.name:
                api_name = imported_symbol.name.decode("utf-8", errors="ignore")
                imported_apis.append(api_name)

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

    for category in detected_categories:
        for api_name in grouped_apis[category]:
            score += API_SIGNAL_WEIGHTS.get(api_name, 25)

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


def build_report(
    selected_path: Path,
    analyzed_path: Path,
    grouped_apis: dict[str, list[str]],
    score: int,
) -> str:
    lines: list[str] = []

    lines.append(f"Selected File: {selected_path}")
    lines.append(f"Analyzed File: {analyzed_path}")
    lines.append(f"Static Review Score: {score} / {MAX_SCORE}")
    lines.append(f"Review Priority: {get_review_priority(score)}")
    lines.append("")
    lines.append("Detected Categories")
    lines.append("-------------------")

    known_categories = [
        category for category in grouped_apis
        if category != "Unknown"
    ]

    if not known_categories:
        lines.append("No mapped behavior categories were detected.")

    for category in known_categories:
        lines.append("")
        lines.append(category)
        lines.append("-" * len(category))

        for api_name in grouped_apis[category]:
            lines.append(f"- {api_name}")

    unknown_apis = grouped_apis.get("Unknown", [])

    if unknown_apis:
        lines.append("")
        lines.append("Unknown APIs")
        lines.append("------------")
        lines.append(f"{len(unknown_apis)} imported APIs were not mapped.")
        lines.append("Unknown APIs are listed for visibility but do not increase the score.")

    lines.append("")
    lines.append("Analysis Note")
    lines.append("-------------")
    lines.append("This score is based only on static import table indicators.")
    lines.append("It does not prove malicious behavior by itself.")
    lines.append("The score only shows how much manual review may be useful.")

    return "\n".join(lines)


def analyze_file(selected_path: Path) -> str:
    analyzed_path = normalize_selected_path(selected_path)
    api_categories = load_api_categories(DEFAULT_CATEGORIES_PATH)
    imported_apis = extract_imported_apis(analyzed_path)
    grouped_apis = group_apis_by_category(imported_apis, api_categories)
    score = calculate_static_review_score(grouped_apis)

    return build_report(
        selected_path=selected_path,
        analyzed_path=analyzed_path,
        grouped_apis=grouped_apis,
        score=score,
    )


class PEStaticReviewScorerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PE Static Review Scorer")
        self.root.geometry("960x720")

        self.selected_file = tk.StringVar()
        self.current_report = ""

        self.build_layout()

    def build_layout(self) -> None:
        container = tk.Frame(self.root, padx=16, pady=16)
        container.pack(fill=tk.BOTH, expand=True)

        title = tk.Label(
            container,
            text="PE Static Review Scorer",
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        )
        title.pack(fill=tk.X)

        description = tk.Label(
            container,
            text="Select an executable, DLL, SCR, or shortcut file for static import table review scoring.",
            font=("Segoe UI", 10),
            anchor="w",
        )
        description.pack(fill=tk.X, pady=(8, 16))

        file_row = tk.Frame(container)
        file_row.pack(fill=tk.X)

        file_entry = tk.Entry(file_row, textvariable=self.selected_file)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_button = tk.Button(
            file_row,
            text="Browse",
            command=self.select_file,
        )
        browse_button.pack(side=tk.LEFT, padx=(8, 0))

        button_row = tk.Frame(container)
        button_row.pack(anchor="w", pady=(12, 16))

        analyze_button = tk.Button(
            button_row,
            text="Analyze Selected File",
            command=self.analyze_selected_file,
        )
        analyze_button.pack(side=tk.LEFT)

        save_button = tk.Button(
            button_row,
            text="Save Report",
            command=self.save_report,
        )
        save_button.pack(side=tk.LEFT, padx=(8, 0))

        self.output = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            font=("Consolas", 10),
        )
        self.output.pack(fill=tk.BOTH, expand=True)

    def select_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select PE File",
            filetypes=[
                ("Portable Executable files", "*.exe *.dll *.scr"),
                ("Shortcut files", "*.lnk"),
                ("All files", "*.*"),
            ],
        )

        if file_path:
            self.selected_file.set(file_path)

    def analyze_selected_file(self) -> None:
        selected_path_text = self.selected_file.get().strip()

        if not selected_path_text:
            messagebox.showwarning("Missing file", "Please select a file first.")
            return

        selected_path = Path(selected_path_text)

        if not selected_path.exists():
            messagebox.showerror("File not found", "The selected file does not exist.")
            return

        try:
            report = analyze_file(selected_path)
        except Exception as error:
            messagebox.showerror("Analysis failed", str(error))
            return

        self.current_report = report
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, report)

    def save_report(self) -> None:
        report = self.output.get("1.0", tk.END).strip()

        if not report:
            messagebox.showwarning("No report", "Please analyze a file before saving a report.")
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


def main() -> None:
    root = tk.Tk()
    app = PEStaticReviewScorerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()