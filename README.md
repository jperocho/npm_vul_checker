# NPM Package Vulnerable Checker

A simple Python tool to recursively scan a project (or monorepo) for vulnerable NPM packages listed in a custom text file. This helps you quickly identify if your project contains compromised or risky dependencies.

> ⚠️ Inspired by recent NPM supply-chain incidents such as the debug and chalk package compromise:
> [NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)

## Features

Recursively scans a folder and all its subfolders for:
- `package.json`
- `package-lock.json`
- `yarn.lock`

Checks against a custom vulnerable package list (e.g., `vulv.txt`).

Reports vulnerable packages along with the folder they were found in, including:
- The version found in your project
- The vulnerable version listed in `vulv.txt`
- Flags if your version matches or is below the vulnerable version

## Installation

Clone this repository:

```bash
git clone git@github.com:jperocho/npm_vul_checker.git
cd npm_vul_checker
```

No extra dependencies are required — just Python 3.7+.

## Usage

Create a `vulv.txt` file containing package names and vulnerable versions to flag (one per line):

```text
chalk:5.6.1
debug:4.4.2
ansi-regex:6.2.1
supports-color:10.2.1
```

You can also list just the package name (without a version) to flag all versions.

Run the checker:

```bash
python check.py --list=./vulv.txt --folder=/path/to/your/project
```

### Example Output

```
⚠️ Vulnerable packages found:
  my-app: chalk:5.6.1 (vuln:5.6.1), ansi-regex:6.2.1 (vuln:6.2.1)
  utils-lib: debug:4.4.2 (vuln:4.4.2)
```

If no vulnerable packages are detected:

```
✅ No vulnerable packages found in any folder.
```

## Why?

NPM packages are a common attack vector in supply-chain security. This script helps teams identify quickly whether their project depends on known compromised or high-risk packages.

Read more about real-world incidents in this article:

👉 [NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
