"""
checker.py
----------
Core logic for the DecodeLabs Password Strength Checker (Project 1).

Design notes (matches the project brief):
- Length verification: < 8 chars is an immediate fail.
- Pattern recognition: checks for lowercase, uppercase, digits, and symbols
  using Pythonic `any(... for ...)` generator checks (short-circuiting,
  C-optimized) rather than manual index loops.
- Validation is O(n): a single linear pass over the password string.
- Includes a bonus "leaked password" check against a small common-password
  list, and a rough entropy estimate, per the brief's suggestion to
  "experiment with unique solutions."
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Strength(str, Enum):
    WEAK = "Weak"
    MEDIUM = "Medium"
    STRONG = "Strong"


DEFAULT_MIN_LENGTH = 8
STRONG_LENGTH = 12
SYMBOLS = string.punctuation

_COMMON_PASSWORDS_PATH = Path(__file__).parent / "common_passwords.txt"


def _load_common_passwords(path: Path = _COMMON_PASSWORDS_PATH) -> frozenset[str]:
    """Load the bundled list of known-leaked/common passwords."""
    if not path.exists():
        return frozenset()
    with path.open(encoding="utf-8") as f:
        return frozenset(line.strip().lower() for line in f if line.strip())


COMMON_PASSWORDS = _load_common_passwords()


@dataclass
class PasswordReport:
    """Structured result of checking a single password."""

    password_length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    is_common: bool
    score: int
    strength: Strength
    entropy_bits: float
    feedback: list[str] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - convenience only
        lines = [
            f"Strength   : {self.strength.value}",
            f"Score      : {self.score}/6",
            f"Length     : {self.password_length}",
            f"Entropy    : ~{self.entropy_bits:.1f} bits",
            f"Lowercase  : {'yes' if self.has_lower else 'no'}",
            f"Uppercase  : {'yes' if self.has_upper else 'no'}",
            f"Digit      : {'yes' if self.has_digit else 'no'}",
            f"Symbol     : {'yes' if self.has_symbol else 'no'}",
            f"Common pw  : {'yes (!)' if self.is_common else 'no'}",
        ]
        if self.feedback:
            lines.append("Feedback   :")
            lines.extend(f"  - {tip}" for tip in self.feedback)
        return "\n".join(lines)


def _character_pool_size(has_lower: bool, has_upper: bool, has_digit: bool, has_symbol: bool) -> int:
    """Return the size of the character set the password is drawn from."""
    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += len(SYMBOLS)
    return pool


def estimate_entropy_bits(password: str) -> float:
    """
    Rough Shannon-style entropy estimate: log2(pool_size ** length).
    This is a simplification (real entropy depends on randomness of choice,
    not just the alphabet used) but is a useful, explainable heuristic.
    """
    if not password:
        return 0.0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in SYMBOLS for c in password)
    pool = _character_pool_size(has_lower, has_upper, has_digit, has_symbol) or 1
    return len(password) * math.log2(pool)


def check_password(password: str, min_length: int = DEFAULT_MIN_LENGTH) -> PasswordReport:
    """
    Analyze a password and return a PasswordReport with a Weak/Medium/Strong
    classification plus actionable feedback.
    """
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in SYMBOLS for c in password)
    is_common = password.lower() in COMMON_PASSWORDS

    feedback: list[str] = []

    # --- Gatekeeper rule: length is checked first -------------------------
    if length < min_length:
        feedback.append(f"Use at least {min_length} characters.")

    if not has_lower:
        feedback.append("Add a lowercase letter.")
    if not has_upper:
        feedback.append("Add an uppercase letter.")
    if not has_digit:
        feedback.append("Add a number.")
    if not has_symbol:
        feedback.append("Add a symbol (e.g. !, @, #, $).")
    if is_common:
        feedback.append("This password appears in common/leaked password lists — avoid it.")

    # --- Scoring -------------------------------------------------------
    score = 0
    if length >= min_length:
        score += 1
    if length >= STRONG_LENGTH:
        score += 1
    score += sum([has_lower, has_upper, has_digit, has_symbol])

    # A known-common password is capped at Weak regardless of composition.
    if is_common:
        strength = Strength.WEAK
        score = min(score, 1)
    elif length < min_length or score <= 2:
        strength = Strength.WEAK
    elif score <= 4:
        strength = Strength.MEDIUM
    else:
        strength = Strength.STRONG

    if not feedback:
        feedback.append("Looks good! No issues found.")

    return PasswordReport(
        password_length=length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        is_common=is_common,
        score=score,
        strength=strength,
        entropy_bits=estimate_entropy_bits(password),
        feedback=feedback,
    )
