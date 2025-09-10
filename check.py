#!/usr/bin/env python3
import os
import json
import argparse

def load_vulnerable_packages(vuln_file):
    """Load vulnerable package names from text file."""
    with open(vuln_file, "r") as f:
        return {line.strip() for line in f if line.strip()}

def scan_file(filepath, vulnerable_packages):
    """Check a single package.json or package-lock.json file for vulnerable packages."""
    found_packages = set()

    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        deps = set()
        if "dependencies" in data:
            deps.update(data["dependencies"].keys())
        if "devDependencies" in data:
            deps.update(data["devDependencies"].keys())
        if "packages" in data:  # package-lock.json v2+
            deps.update(data["packages"].keys())

        found = deps.intersection(vulnerable_packages)
        found_packages.update(found)

    except Exception as e:
        print(f"[!] Failed to parse {filepath}: {e}")

    return found_packages

def scan_folder_recursive(base_folder, vuln_file):
    """Recursively scan folders for vulnerable packages in package.json/package-lock.json."""
    vulnerable_packages = load_vulnerable_packages(vuln_file)
    results = {}

    for root, _, files in os.walk(base_folder):
        for filename in ("package.json", "package-lock.json"):
            if filename in files:
                filepath = os.path.join(root, filename)
                found = scan_file(filepath, vulnerable_packages)
                if found:
                    folder_name = os.path.basename(root)
                    results[folder_name] = results.get(folder_name, set()).union(found)

    if results:
        print("\n⚠️ Vulnerable packages found:")
        for folder, pkgs in results.items():
            print(f"  {folder}: {', '.join(pkgs)}")
    else:
        print("✅ No vulnerable packages found in any folder.")

    return results


def main():
    parser = argparse.ArgumentParser(description="Recursively check Node.js packages against a vulnerable list")
    parser.add_argument("--list", required=True, help="Path to vulnerable package list (txt file)")
    parser.add_argument("--folder", required=True, help="Path to base folder to scan")
    args = parser.parse_args()

    scan_folder_recursive(args.folder, args.list)


if __name__ == "__main__":
    main()
