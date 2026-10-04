"""A durable budget ledger: every reservation and every charge, summed rather than remembered.

Two problems need one structure. Concurrent reviews in the same process were checking a balance that no
attempt had yet updated, and a second process - a server and the CLI - shared no state at all, so both
could be admitted against the same money. Counting reservations in memory fixed neither. An append-only
file, updated under an exclusive lock, gives every process the same answer and keeps the history.

It is also what makes the ceiling meaningful across a restart. A request that failed twice and then
succeeded is two paid attempts, and a request whose attempts all failed is still two paid attempts; both
have to reappear here, or a crash quietly refunds the budget.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

USD_PER_MILLION_TOKENS = 2.50

class BudgetLedger:
    """Append-only accounting shared by every process that shares the data directory."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # -- reading ----------------------------------------------------------------------------------
    def totals(self) -> tuple[int, int, int, float]:
        """`(calls, input_tokens, output_tokens, spend_usd)`, recomputed from the file every time."""
        calls = tokens_in = tokens_out = 0
        spend = 0.0
        for entry in self.entries():
            spend += float(entry.get("reserved_usd", 0.0))
            # One call, one reservation. The settle line that follows carries the tokens and must not be
            # counted as a second attempt, or every review spends two units of the call budget.
            if str(entry.get("kind", "")).startswith("reserve"):
                calls += 1
            tokens_in += _count(entry.get("input_tokens"))
            tokens_out += _count(entry.get("output_tokens"))
        return calls, tokens_in, tokens_out, spend

    @property
    def calls(self) -> int:
        return self.totals()[0]

    @property
    def input_tokens(self) -> int:
        return self.totals()[1]

    @property
    def output_tokens(self) -> int:
        return self.totals()[2]

    @property
    def spend_usd(self) -> float:
        return self.totals()[3]

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue  # a partial final line from a crash: the attempt is not yet countable
            if isinstance(row, dict):
                rows.append(row)
        return rows

    # -- writing ----------------------------------------------------------------------------------
    def admit(self, amount: float, *, kind: str, max_calls: int, max_spend: float) -> tuple[bool, str]:
        """Check the ceiling and append the reservation, in one critical section.

        Reading the balance outside the lock and writing inside it is precisely the race that let two
        concurrent calls pass one ceiling, so the check and the record are the same operation. Returns
        `(admitted, reason)`; the reason is what the caller reports when the ceiling was reached.
        """
        with _exclusive(self.path):
            calls, _tokens_in, _tokens_out, spend = self.totals()
            if calls >= max_calls:
                return False, f"model call budget exhausted ({max_calls} calls)"
            if max_spend and spend + amount > max_spend:
                return False, (f"this call could cost up to ${amount:.4f} and would take the total to "
                               f"${spend + amount:.4f}, over budget_usd=${max_spend:.2f}")
            _append(self.path, {"reserved_usd": round(amount, 8), "input_tokens": 0, "output_tokens": 0,
                                "kind": kind, "at": round(time.time(), 3)})
            return True, ""

    def reconcile(self, reserved_usd: float, *, kind: str, input_tokens: int, output_tokens: int) -> None:
        """Replace a reservation with what the attempt actually cost.

        The reservation is what bounded the call; the charge is what the ceiling is ultimately measured
        against. Both are recorded, so an attempt that failed still shows what it reserved.
        """
        with _exclusive(self.path):
            _append(self.path, {"reserved_usd": 0.0, "input_tokens": int(input_tokens),
                                "output_tokens": int(output_tokens), "kind": f"{kind}:settled",
                                "at": round(time.time(), 3)})


@contextlib.contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """One writer at a time across processes, by creating the lock file exclusively."""
    lock = path.with_suffix(".lock")
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    while True:
        try:
            handle = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # A lock left behind by a crash must not wedge the ledger forever.
            with contextlib.suppress(OSError):
                if time.time() - lock.stat().st_mtime > 60:
                    lock.unlink()
            time.sleep(0.01)
            continue
        break
    try:
        yield
    finally:
        os.close(handle)
        with contextlib.suppress(OSError):
            lock.unlink()


def _append(path: Path, row: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0
