"""
Packaging script: Bundles the entire NSAT project into a clean ZIP archive.
Excludes virtual environments, cache files, and local session databases.
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_ZIP = ROOT_DIR / "network-security-assessment-toolkit.zip"

EXCLUDED_DIRS = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
    ".idea",
    ".vscode",
}

EXCLUDED_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".swp",
}


def create_archive():
    print(f"[*] Packaging NSAT into: {OUTPUT_ZIP.name}")
    count = 0
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT_DIR):
            # Modify dirs in-place to prevent os.walk from recursing into excluded folders
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

            for file in files:
                file_path = Path(root) / file
                # Skip self-archive and excluded files
                if file_path == OUTPUT_ZIP:
                    continue
                if file_path.suffix in EXCLUDED_EXTENSIONS:
                    continue
                if "instance" in file_path.parts and file_path.suffix in (".db", ".sqlite"):
                    continue

                rel_path = file_path.relative_to(ROOT_DIR)
                zipf.write(file_path, arcname=str(rel_path))
                count += 1

    size_mb = round(OUTPUT_ZIP.stat().st_size / (1024 * 1024), 2)
    print(f"[+] Package created successfully! Archived {count} files ({size_mb} MB).")
    return OUTPUT_ZIP


if __name__ == "__main__":
    create_archive()
