#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import sqlite3
import string
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import List

COMMON_WORDS = {
    "password",
    "passw0rd",
    "admin",
    "qwerty",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "login",
    "abc123",
    "111111",
    "secret",
    "password1",
    "test",
    "user",
    "root",
}

KEYBOARD_SEQS = ("qwerty", "asdf", "zxcv", "12345", "09876", "1q2w3e", "qaz", "wsx")
SEQUENCE_BASES = (
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
)

PBKDF2_ITERS = 200_000
SALT_BYTES = 16


@dataclass
class AnalysisResult:
    score: int
    rating: str
    issues: List[str]
    suggestions: List[str]
    entropy_bits_est: float


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def rating_for_score(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"


def estimate_entropy_bits(pw: str) -> float:
    charset = 0
    if re.search(r"[a-z]", pw):
        charset += 26
    if re.search(r"[A-Z]", pw):
        charset += 26
    if re.search(r"[0-9]", pw):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        charset += 33
    if charset == 0:
        return 0.0
    import math

    return len(pw) * math.log2(charset)


def has_repeats(pw: str) -> bool:
    return bool(re.search(r"(.)\1{3,}", pw))


def has_simple_sequence(pw: str) -> bool:
    for base in SEQUENCE_BASES:
        for i in range(len(base) - 4):
            seq = base[i : i + 5]
            if seq in pw or seq[::-1] in pw:
                return True
    return False


def has_keyboard_sequence(pw: str) -> bool:
    low = pw.lower()
    return any(seq in low for seq in KEYBOARD_SEQS)


def contains_common_word(pw: str) -> bool:
    low = pw.lower()
    if low in COMMON_WORDS:
        return True
    return any(w in low for w in COMMON_WORDS if len(w) >= 5)


def dedupe(xs: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in xs:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def analyze_password(pw: str) -> AnalysisResult:
    if not pw:
        return AnalysisResult(
            score=0,
            rating="Very Weak",
            issues=["Password is empty."],
            suggestions=["Enter a password with at least 12–16 characters."],
            entropy_bits_est=0.0,
        )

    issues: List[str] = []
    suggestions: List[str] = []

    score = 50
    length = len(pw)
    entropy = estimate_entropy_bits(pw)

    if length < 8:
        score -= 25
        issues.append("Too short (< 8 characters).")
        suggestions.append("Use at least 12–16 characters (longer is better).")
    elif length < 12:
        score -= 10
        issues.append("Short (8–11 characters).")
        suggestions.append("Increase length to at least 12–16 characters.")
    elif length < 16:
        score += 5
    else:
        score += 10

    classes = 0
    if re.search(r"[a-z]", pw):
        classes += 1
    else:
        issues.append("Missing lowercase letters.")
        suggestions.append("Add lowercase letters (a–z).")

    if re.search(r"[A-Z]", pw):
        classes += 1
    else:
        issues.append("Missing uppercase letters.")
        suggestions.append("Add uppercase letters (A–Z).")

    if re.search(r"[0-9]", pw):
        classes += 1
    else:
        issues.append("Missing digits.")
        suggestions.append("Add digits (0–9).")

    if re.search(r"[^a-zA-Z0-9]", pw):
        classes += 1
    else:
        issues.append("Missing symbols.")
        suggestions.append("Add symbols (e.g., !@#$%^&*).")

    if classes <= 1:
        score -= 20
        issues.append("Very low character variety.")
        suggestions.append("Mix upper/lowercase, digits, and symbols.")
    elif classes == 2:
        score -= 8
    elif classes == 3:
        score += 5
    else:
        score += 10

    if has_repeats(pw):
        score -= 10
        issues.append("Contains repeated characters (e.g., 'aaaa', '1111').")
        suggestions.append("Avoid long repeated character runs.")

    if has_simple_sequence(pw):
        score -= 12
        issues.append("Contains simple sequences (e.g., 'abcde', '12345').")
        suggestions.append("Avoid sequential patterns.")

    if has_keyboard_sequence(pw):
        score -= 12
        issues.append("Contains common keyboard patterns (e.g., 'qwerty', 'asdf').")
        suggestions.append("Avoid keyboard-walk patterns.")

    if contains_common_word(pw):
        score -= 18
        issues.append("Contains common password words/patterns.")
        suggestions.append("Avoid common words (password/admin/welcome/etc.).")

    if re.search(r"p@ssw0rd|pa\$\$w0rd", pw.lower()):
        score -= 15
        issues.append("Looks like a common 'password' substitution variant.")
        suggestions.append("Use a unique passphrase not based on 'password' variants.")

    if entropy < 35:
        score -= 10
        issues.append("Low estimated entropy.")
        suggestions.append("Increase length and randomness (or use a passphrase).")
    elif entropy > 60:
        score += 5

    score = clamp(score, 0, 100)
    return AnalysisResult(
        score=score,
        rating=rating_for_score(score),
        issues=dedupe(issues),
        suggestions=dedupe(suggestions),
        entropy_bits_est=entropy,
    )


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    pools: List[str] = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")

    if not pools:
        raise ValueError("No character sets selected.")

    chars = [secrets.choice(p) for p in pools]
    allchars = "".join(pools)
    while len(chars) < length:
        chars.append(secrets.choice(allchars))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(num_words: int = 4) -> str:
    words = [
        "orbit",
        "candle",
        "river",
        "forest",
        "hammer",
        "galaxy",
        "piano",
        "velvet",
        "signal",
        "mango",
        "crystal",
        "tunnel",
        "rocket",
        "silver",
        "ember",
        "harbor",
        "falcon",
        "meadow",
        "quantum",
        "lunar",
        "zephyr",
        "saffron",
        "cobalt",
        "atlas",
    ]
    chosen = [secrets.choice(words) for _ in range(num_words)]
    return "-".join(chosen) + secrets.choice(string.digits) + secrets.choice("!@#?")


def pbkdf2_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                salt BLOB NOT NULL,
                hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(username)"
        )
        conn.commit()
    finally:
        conn.close()


def check_reuse(db_path: str, username: str, password: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT salt, hash FROM password_history WHERE username = ?", (username,)
        ).fetchall()
        for salt, h in rows:
            if pbkdf2_hash(password, salt) == h:
                return True
        return False
    finally:
        conn.close()


def store_password(db_path: str, username: str, password: str) -> None:
    salt = os.urandom(SALT_BYTES)
    h = pbkdf2_hash(password, salt)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO password_history (username, salt, hash, created_at) VALUES (?, ?, ?, ?)",
            (username, salt, h, datetime.utcnow().isoformat(timespec="seconds") + "Z"),
        )
        conn.commit()
    finally:
        conn.close()


def prompt_password_masked(prompt: str = "Enter password: ") -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    password_chars: List[str] = []

    try:
        import msvcrt  # type: ignore

        while True:
            ch = msvcrt.getwch()

            if ch == "\r":
                sys.stdout.write("\n")
                sys.stdout.flush()
                return "".join(password_chars)

            if ch == "\003":
                sys.stdout.write("\n")
                sys.stdout.flush()
                raise KeyboardInterrupt

            if ch in ("\b", "\x7f"):
                if password_chars:
                    password_chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue

            if ch in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue

            password_chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()

    except ImportError:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)

                if ch in ("\n", "\r"):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    return "".join(password_chars)

                if ch == "\x03":
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    raise KeyboardInterrupt

                if ch in ("\x7f", "\b"):
                    if password_chars:
                        password_chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue

                password_chars.append(ch)
                sys.stdout.write("*")
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Password Strength Analyzer (CLI)")
    p.add_argument(
        "--password", help="Password to analyze (not recommended; use --prompt)."
    )
    p.add_argument("--prompt", action="store_true", help="Prompt for password input.")

    p.add_argument(
        "--suggest", action="store_true", help="Print suggested alternatives."
    )
    p.add_argument(
        "--num-suggestions", type=int, default=3, help="Number of suggestions."
    )

    p.add_argument("--user", help="Username for reuse check/store (enables history).")
    p.add_argument(
        "--history-db",
        default="password_history.sqlite",
        help="SQLite DB path for password history.",
    )
    p.add_argument(
        "--prevent-reuse", action="store_true", help="Fail if used before for --user."
    )
    p.add_argument(
        "--store", action="store_true", help="Store password hash in history."
    )
    return p


def main(argv: List[str]) -> int:
    args = build_parser().parse_args(argv)

    if not args.password and not args.prompt:
        args.prompt = True

    pw = (
        prompt_password_masked("Enter password: ")
        if args.prompt
        else (args.password or "")
    )
    print("", flush=True)
    result = analyze_password(pw)

    if args.user and (args.prevent_reuse or args.store):
        init_db(args.history_db)

    reused = False
    if args.user and args.prevent_reuse:
        reused = check_reuse(args.history_db, args.user, pw)

    print(f"Score: {result.score}/100")
    print(f"Rating: {result.rating}")
    print(f"Estimated entropy: {result.entropy_bits_est:.1f} bits")

    if args.user and args.prevent_reuse:
        print(
            "Uniqueness: FAILED (password was used before for this user)"
            if reused
            else "Uniqueness: OK (not found in local history)"
        )

    if result.issues:
        print("\nIssues found:")
        for i in result.issues:
            print(f" - {i}")

    if result.suggestions:
        print("\nHow to improve:")
        for s in result.suggestions:
            print(f" - {s}")

    if args.user and args.prevent_reuse and reused:
        return 2

    if args.suggest:
        n = clamp(args.num_suggestions, 1, 20)
        print("\nSuggested alternatives:")
        for i in range(n):
            if i % 2 == 0:
                print(f" - passphrase: {generate_passphrase(num_words=4)}")
            else:
                print(f" - random:     {generate_password(length=20)}")

    if args.user and args.store:
        if not reused:
            store_password(args.history_db, args.user, pw)
            print("\nStored password hash in history database.")
        else:
            print("\nNot storing: password already exists in history.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
