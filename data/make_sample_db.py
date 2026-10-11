"""Generate a deterministic sample 'phone message' SQLite database.

The data is entirely fictional. It is large enough (about 300 rows) to span
several b-tree pages, so the independent parser has to walk interior pages too.
"""
import random
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "sample_messages.db"

NAMES = ["Asha", "Ravi", "Meena", "Kiran", "Dev", "Lakshmi", "Imran", "Sara"]
PHRASES = [
    "Are we still meeting later today?",
    "Please send me the document when you can",
    "Running a few minutes late, start without me",
    "Did you see the news this morning?",
    "Thanks, that really helped a lot",
    "Call me when you reach home",
    "Lunch at the usual place at one",
    "I will transfer the notes tonight",
    "Happy birthday, have a great year ahead",
    "Reminder: submission deadline is on Sunday",
]


def build(path=DB_PATH, n_messages=300, seed=42):
    path = Path(path)
    if path.exists():
        path.unlink()
    rng = random.Random(seed)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=4096")
    con.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)")
    con.execute(
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, "
        "recipient TEXT, body TEXT, sent_at TEXT, direction TEXT)"
    )
    phones = []
    for i, name in enumerate(NAMES, start=1):
        phone = f"+91-90000-{1000 + i * 37:05d}"
        phones.append(phone)
        con.execute("INSERT INTO contacts VALUES (?, ?, ?)", (i, name, phone))

    owner = "+91-90000-00000"
    start = datetime(2026, 3, 1, 8, 0, 0)
    for i in range(1, n_messages + 1):
        other = rng.choice(phones)
        direction = rng.choice(["in", "out"])
        sender, recipient = (other, owner) if direction == "in" else (owner, other)
        body = f"{rng.choice(PHRASES)} (ref {i})"
        if i == 77:
            body = "Café meeting moved to 6 pm"  # non-ASCII text
        if i == 150:
            body = None  # NULL body
        sent_at = (start + timedelta(minutes=17 * i)).isoformat(timespec="seconds")
        con.execute(
            "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?)",
            (i, sender, recipient, body, sent_at, direction),
        )
    con.commit()
    con.close()
    return path


if __name__ == "__main__":
    p = build()
    print(f"Sample database written to {p} ({p.stat().st_size} bytes)")
    sys.exit(0)
