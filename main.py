#!/usr/bin/env python3
"""
DecodeLabs Cyber Security — Project 1
Password Strength Checker (CLI)

Usage:
    python main.py                # interactive mode, hidden input
    python main.py "MyP@ssw0rd!"  # check a single password non-interactively
    python main.py --min-length 10
"""

from __future__ import annotations

import argparse
import getpass
import sys

from password_checker.checker import DEFAULT_MIN_LENGTH, check_password

BANNER = r"""
==============================================
  DecodeLabs :: Password Strength Checker
  Project 1 - Defensive Logic Track
==============================================
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check password strength.")
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to check. If omitted, you'll be prompted (input hidden).",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=DEFAULT_MIN_LENGTH,
        help=f"Minimum acceptable length (default: {DEFAULT_MIN_LENGTH}).",
    )
    parser.add_argument(
        "--show-input",
        action="store_true",
        help="Echo the password while typing instead of hiding it.",
    )
    return parser.parse_args()


def get_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password
    if args.show_input:
        return input("Enter password to check: ")
    return getpass.getpass("Enter password to check (hidden): ")


def main() -> int:
    args = parse_args()
    print(BANNER)

    password = get_password(args)
    if not password:
        print("No password entered. Exiting.")
        return 1

    report = check_password(password, min_length=args.min_length)
    print()
    print(report)
    print()

    return 0 if report.strength.value != "Weak" else 2


if __name__ == "__main__":
    sys.exit(main())
