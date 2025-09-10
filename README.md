# NPM Package Vulnerable Checker

A simple Python tool to recursively scan a project (or monorepo) for vulnerable NPM packages listed in a custom text file. This helps you quickly identify if your project contains compromised or risky dependencies.

> ⚠️ Inspired by recent NPM supply-chain incidents such as the debug and chalk package compromise:
> [NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)

## Features

Recursively scans a folder and all its subfolders for:
- `package.json`
- `package-lock.json`

Checks against a custom vulnerable package list (e.g., `vulv.txt`).

Reports vulnerable packages along with the folder they were found in.

## Installation

Clone this repository:

```bash
git clone git@github.com:jperocho/npm_vul_checker.git
cd npm_vul_checker
```

No extra dependencies are required — just Python 3.7+.

## Usage

Create a `vulv.txt` file containing package names to flag (one per line):

```text
chalk
debug
ansi-regex
supports-color
```

Run the checker:

```bash
python check.py --list=./vulv.txt --folder=/path/to/your/project
```

### Example Output

```
⚠️ Vulnerable packages found:
  my-app: chalk, ansi-regex
  utils-lib: debug
```

If no vulnerable packages are detected:

```
✅ No vulnerable packages found in any folder.
```

## Why?

NPM packages are a common attack vector in supply-chain security. This script helps teams identify quickly whether their project depends on known compromised or high-risk packages.

Read more about real-world incidents in this article:

👉 [NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
