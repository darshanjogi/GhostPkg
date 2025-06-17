# 🕵️‍♂️ GhostPkg

**GhostPkg** is a command-line tool to detect potential **Dependency Confusion** vulnerabilities in public repositories of any GitHub organization.

It scans for unreleased or missing package references in NPM, PyPI, and Go module ecosystems — helping security researchers, bug bounty hunters, and dev teams proactively spot supply chain risks.

> ✅ Educational & responsible use only. Do **not** use this tool on organizations you don't have permission to test.

---

## 🎯 Features

- 🔍 Searches public code on GitHub in a given organization
- 📦 Extracts suspicious internal/private package names
- 🧪 Checks if these packages are missing on:
  - NPM registry
  - PyPI index
  - Go module proxy
- 🪵 Optional output to file
- 🧠 Minimal dependencies (pure Python)

---

## 📦 Supported Ecosystems

| Language   | Registry            | Example Reference Pattern              |
|------------|---------------------|----------------------------------------|
| JavaScript | NPM                 | `@org/internal-pkg`                    |
| Python     | PyPI                | `import org_internal_something`       |
| Go         | Go Proxy            | `import "org.internal/pkg"`           |

---

## 🛠 Installation

```bash
git clone https://github.com/darshanjogi/GhostPkg
cd GhostPkg
```

## 🛠 Use

```bash
python3 GhostPkg.py --org <org_name> [--output result.txt]

eg. python3 GhostPkg.py --org google --output googlepkg.txt
```

## ✍️ Author
 [**Darshan Jogi**](https://darshanjogi.github.io/)
