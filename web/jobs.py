"""Asking the host to run something, from inside the container.

The container serves HTML and never executes anything from the toolkit; `web/worker.sh` on the
host does that, and owns the whitelist. This module is the half of that conversation that lives in
the container, and the whole protocol is four files in `.cache/web-jobs/`:

    <id>.req      what to run, as a KIND and named values -- never a command line
    <id>.state    queued | running | done | failed | timeout | refused
    <id>.log      stdout and stderr interleaved, in the order they happened
    <id>.rc       the exit status

A directory and four files is not a message queue, and that is the point: there is one reader and
one writer, both on the same machine, and a restart that loses in-flight state costs a re-run. The
alternative -- a socket, a broker, a daemon protocol -- is three more things that can be down.

Note what a request cannot say. There is no field here that names a program, a path, or a flag
string that the worker passes through: `kind` selects one of the worker's own hard-coded argv
builders, and everything else is a value that builder validates. The container is not trusted, and
this module is written as though it were already compromised.

Pure stdlib. `python3 web/jobs.py` runs the self-check (it plays both halves; no worker needed).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from pathlib import Path

from cache import CACHE

JOBS = CACHE / "web-jobs"

TERMINAL = frozenset({"done", "failed", "timeout", "refused", "gone"})

ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")

# Job files are small, but a busy week is thousands of them and nothing else ever deletes one.
PRUNE_AFTER = 24 * 3600


def _new_id() -> str:
    # Sortable by name AND by mtime, so `ls -tr` in the worker and a sort here agree. The random
    # tail avoids a collision between two submissions in the same second.
    return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


def _path(job_id: str, ext: str) -> Path | None:
    """A job file path, or None. The id is validated because it arrives from a URL."""
    if not ID_RE.match(job_id or ""):
        return None
    return JOBS / f"{job_id}.{ext}"


def submit(kind: str, **fields) -> str:
    """Ask for a job. Returns its id immediately; nothing has run yet."""
    JOBS.mkdir(parents=True, exist_ok=True)
    prune()
    job_id = _new_id()
    body = {"kind": kind, "at": time.time(), **{k: v for k, v in fields.items() if v is not None}}

    # State first: a worker that claims the request between the two writes must never find a job
    # with no state at all.
    (JOBS / f"{job_id}.state").write_text("queued\n")
    # Written to a temp name and renamed, because rename is atomic on one filesystem -- the worker
    # can therefore never read a half-written request.
    tmp = JOBS / f"{job_id}.req.tmp"
    tmp.write_text(json.dumps(body))
    os.replace(tmp, JOBS / f"{job_id}.req")
    return job_id


def state(job_id: str) -> str:
    p = _path(job_id, "state")
    if p is None:
        return "gone"
    try:
        return p.read_text().strip() or "queued"
    except OSError:
        return "gone"


def rc(job_id: str) -> int | None:
    p = _path(job_id, "rc")
    if p is None:
        return None
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return None


def log(job_id: str) -> str:
    p = _path(job_id, "log")
    if p is None:
        return ""
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def queued() -> list[str]:
    """Ids waiting to start, oldest first — the queue depth the UI shows."""
    if not JOBS.is_dir():
        return []
    return sorted(p.stem for p in JOBS.glob("*.state") if _read(p) == "queued")


def running() -> str | None:
    if not JOBS.is_dir():
        return None
    return next((p.stem for p in sorted(JOBS.glob("*.state")) if _read(p) == "running"), None)


def _read(p: Path) -> str:
    try:
        return p.read_text().strip()
    except OSError:
        return ""


async def stream(job_id: str, poll: float = 0.15):
    """Every line of the log, from the beginning, then each new one as it is written.

    Replaying from byte 0 is what makes a browser reload cheap and a late subscriber correct: the
    page never has to have been open since the scan started to show the whole scan.

    A worker that dies mid-job leaves the state at `running` forever, so this also gives up when
    the log has stopped growing well past any plausible pause. Ending a stream is cosmetic; a job
    is only ever finished by its state file.
    """
    p = _path(job_id, "log")
    if p is None:
        return
    pos, idle, buf = 0, 0.0, ""
    while True:
        try:
            with p.open(errors="replace") as fh:
                fh.seek(pos)
                chunk = fh.read()
                pos = fh.tell()
        except OSError:
            chunk = ""
        if chunk:
            idle = 0.0
            buf += chunk
            *lines, buf = buf.split("\n")
            for line in lines:
                yield line
        else:
            idle += poll
        st = state(job_id)
        if st in TERMINAL and not chunk:
            if buf:
                yield buf          # a final line with no trailing newline
            return
        if st == "running" and idle > 1200:
            yield "-- the worker stopped reporting; is ./web/worker.sh still running? --"
            return
        if st == "queued":
            idle = 0.0             # waiting for a slot is not a stall
        await asyncio.sleep(poll)


def prune(older_than: int = PRUNE_AFTER) -> int:
    """Delete finished job files past their age. Returns how many went."""
    if not JOBS.is_dir():
        return 0
    cutoff, n = time.time() - older_than, 0
    for p in JOBS.iterdir():
        try:
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink()
                n += 1
        except OSError:
            pass
    return n


# --- self-check: python3 web/jobs.py ------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import tempfile

    async def main() -> int:
        global JOBS
        fails = 0

        def check(name, got, want):
            nonlocal fails
            if got == want:
                print(f"ok   {name}")
            else:
                fails += 1
                print(f"FAIL {name}: want {want!r}, got {got!r}")

        with tempfile.TemporaryDirectory() as tmp:
            JOBS = Path(tmp)

            job = submit("scan", url="https://example.com/", flags="-t", model=None)
            check("id is well formed", bool(ID_RE.match(job)), True)
            check("starts queued", state(job), "queued")
            check("queue depth", queued(), [job])

            body = json.loads((JOBS / f"{job}.req").read_text())
            check("request carries the kind", body["kind"], "scan")
            check("request carries values", (body["url"], body["flags"]), ("https://example.com/", "-t"))
            check("None fields are omitted, not sent as null", "model" in body, False)
            check("no field names a program", [k for k in body if k in ("argv", "cmd", "exec")], [])

            # An id arrives from a url, so a bad one must never become a path.
            check("traversal id -> gone", state("../../etc/passwd"), "gone")
            check("traversal id has no path", _path("../../etc/passwd", "log"), None)
            check("empty id -> gone", state(""), "gone")

            # play the worker: run, write two lines, finish
            (JOBS / f"{job}.state").write_text("running\n")
            (JOBS / f"{job}.log").write_text("first\nsecond\n")

            async def finish():
                await asyncio.sleep(0.3)
                with (JOBS / f"{job}.log").open("a") as fh:
                    fh.write("third\n")
                (JOBS / f"{job}.rc").write_text("0\n")
                (JOBS / f"{job}.state").write_text("done\n")

            asyncio.create_task(finish())
            got = [ln async for ln in stream(job, poll=0.05)]
            check("streams from the beginning, then live", got, ["first", "second", "third"])
            check("exit status", rc(job), 0)
            check("finished state", state(job), "done")

            # a late subscriber gets the whole thing
            check("late subscriber replays all",
                  [ln async for ln in stream(job, poll=0.05)], ["first", "second", "third"])

            # a refused job is terminal and says why in its log, rather than hanging the page
            bad = submit("exec", url="-rf /")
            (JOBS / f"{bad}.log").write_text("refused: unknown job kind\n")
            (JOBS / f"{bad}.state").write_text("refused\n")
            check("refused is terminal",
                  [ln async for ln in stream(bad, poll=0.05)], ["refused: unknown job kind"])

            # a final line with no trailing newline is not dropped
            part = submit("report")
            (JOBS / f"{part}.log").write_text("no newline at the end")
            (JOBS / f"{part}.state").write_text("done\n")
            check("unterminated last line", [ln async for ln in stream(part, poll=0.05)],
                  ["no newline at the end"])

            check("prune keeps fresh jobs", prune(older_than=3600), 0)
            check("prune clears old ones", prune(older_than=-1) > 0, True)

        print()
        print("failed" if fails else "self-test ok")
        return 1 if fails else 0

    sys.exit(asyncio.run(main()))
