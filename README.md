# 🔐 Password Strength Checker

**DecodeLabs Cyber Security Industrial Training Kit — Project 1 (Defensive Logic Track)**

A Python tool that evaluates whether a password is **Weak**, **Medium**, or **Strong**
using string handling, conditional logic, and a few "security analyst" extras.

## Features

- ✅ Length verification (configurable minimum, default 8 characters)
- ✅ Character variety checks: lowercase, uppercase, digits, symbols
- ✅ Weak / Medium / Strong classification with a numeric score
- ✅ Bonus: rough entropy estimate (bits) based on character pool size
- ✅ Bonus: checks against a bundled list of common/leaked passwords
- ✅ Actionable feedback (tells you exactly what to fix)
- ✅ CLI with hidden password input (`getpass`) or single-shot argument mode
- ✅ Unit tested with `unittest`

## Project structure

```
password-strength-checker/
├── main.py                          # CLI entry point
├── password_checker/
│   ├── __init__.py
│   ├── checker.py                   # Core strength-checking logic
│   └── common_passwords.txt         # Bundled common/leaked password list
├── tests/
│   └── test_checker.py              # Unit tests
├── requirements.txt
└── README.md
```

## Getting started

No third-party dependencies are required — everything uses the Python standard library.

```bash
git clone https://github.com/<your-username>/password-strength-checker.git
cd password-strength-checker
python3 main.py
```

### Usage

```bash
# Interactive, hidden input
python3 main.py

# Check a password directly (useful for scripting/demos)
python3 main.py "MyP@ssw0rd!"

# Require a longer minimum length
python3 main.py --min-length 12 "Short1!"
```

Example output:

```
Strength   : Strong
Score      : 6/6
Length     : 14
Entropy    : ~91.8 bits
Lowercase  : yes
Uppercase  : yes
Digit      : yes
Symbol     : yes
Common pw  : no
Feedback   :
  - Looks good! No issues found.
```

### Running tests

```bash
python3 -m unittest discover -s tests -v
```

## How scoring works

| Check                          | Points |
|---------------------------------|--------|
| Length ≥ 8                      | 1      |
| Length ≥ 12                     | 1      |
| Has lowercase letter            | 1      |
| Has uppercase letter            | 1      |
| Has digit                       | 1      |
| Has symbol                      | 1      |

- **0–2 points, or under 8 characters → Weak**
- **3–4 points → Medium**
- **5–6 points → Strong**
- Any password found in the common/leaked password list is automatically
  capped at **Weak**, regardless of composition.

## Key skills demonstrated

String handling, conditional logic, basic security/entropy concepts —
built as the first milestone of the DecodeLabs Cyber Security Industrial
Training Kit (Project 1 of 2026 Batch).

## License

MIT — see [LICENSE](LICENSE).
