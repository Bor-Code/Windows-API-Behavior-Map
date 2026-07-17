import argparse
import json
from pathlib import Path


def load_api_categories(categories_path: Path) -> dict[str, str]:
    with categories_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_imports(imports_path: Path) -> list[str]:
    with imports_path.open("r", encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip()
        ]


def group_imports_by_category(
    imports: list[str],
    api_categories: dict[str, str],
) -> dict[str, list[str]]:
    grouped_imports: dict[str, list[str]] = {}

    for api_name in imports:
        category = api_categories.get(api_name, "Unknown")
        grouped_imports.setdefault(category, []).append(api_name)

    return grouped_imports


def print_grouped_imports(grouped_imports: dict[str, list[str]]) -> None:
    for category, api_names in grouped_imports.items():
        print(f"\n{category}")
        print("-" * len(category))

        for api_name in api_names:
            print(f"- {api_name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Group Windows API imports by behavior category.",
    )
    parser.add_argument(
        "--imports",
        required=True,
        help="Path to a text file containing one API name per line.",
    )
    parser.add_argument(
        "--categories",
        default="data/api_categories.json",
        help="Path to the API category mapping JSON file.",
    )

    args = parser.parse_args()

    imports_path = Path(args.imports)
    categories_path = Path(args.categories)

    api_categories = load_api_categories(categories_path)
    imports = load_imports(imports_path)
    grouped_imports = group_imports_by_category(imports, api_categories)

    print_grouped_imports(grouped_imports)


if __name__ == "__main__":
    main()