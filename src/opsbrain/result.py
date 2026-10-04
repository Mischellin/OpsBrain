"""The result of one command execution.

Its own module so both the executor and the review runners can use it without importing each other:
`executor` needs the top-level config, and the review runner must stay clear of it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Result:
    rc: int
    out: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out
