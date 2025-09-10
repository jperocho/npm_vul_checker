#!/usr/bin/env python3
import os
import json
import argparse

def load_vulnerable_packages(vuln_file):
    """Load vulnerable package names from text file."""
    with open(vuln_file, "r") as f:
        return {line.strip() for line in f if line.strip()}

def scan_file(filepath, vulnerable_packages):
    """Check a single package.json or package-lock.json file for vulnerable packages and their versions."""
    found_packages = {}

    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        deps = {}
        # For package.json
        for dep_type in ("dependencies", "devDependencies"):
            if dep_type in data:
                for pkg, ver in data[dep_type].items():
                    if pkg in vulnerable_packages:
                        deps[pkg] = ver
        # For package-lock.json
        if "packages" in data:  # package-lock.json v2+
            for pkg_path, pkg_info in data["packages"].items():
                pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
                if pkg_name in vulnerable_packages:
                    ver = pkg_info.get("version", "?")
                    deps[pkg_name] = ver
        elif "dependencies" in data:  # package-lock.json v1
            for pkg, info in data["dependencies"].items():
                if pkg in vulnerable_packages:
                    ver = info.get("version", "?")
                    deps[pkg] = ver

        found_packages.update(deps)

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
                    results[root] = results.get(root, {})
                    results[root].update(found)

    if results:
        print("\n⚠️ Vulnerable packages found:")
        for folder, pkgs in results.items():
            pkg_str = ", ".join(f"{pkg}:{ver}" for pkg, ver in pkgs.items())
            print(f"  {folder}: {pkg_str}")
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
