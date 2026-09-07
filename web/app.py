"""scope — a local dashboard over the phishing detection toolkit.

Runs in a container (`web/Dockerfile`), bound to 127.0.0.1, with the repo mounted READ-ONLY and
only `.cache/` writable. It serves HTML and reads files. It does not execute anything from the
toolkit: it writes a job request, and `web/worker.sh` on the host decides whether to run it.

Three properties hold everywhere in this file, and each one is a failure mode rather than a
preference:

  * **Nothing is trusted into HTML.** Page titles, console text, form actions and ledger notes are
    written by the people whose kits we are reading. Jinja autoescape is on, `|safe` appears
    nowhere, and the CSP allows no remote origin and no inline script.
  * **A live phishing url is never a link.** `|inert` renders it as text with a copy control. One
    stray click on a href opens the kit, with the recipient's token still in the query string.
  * **Cached artifacts are served as text.** See `cache.content_type_for`: an image is an image and
    everything else is text/plain with nosniff. There is no route that serves a scanned page as
    itself.
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import cache
import jobs as jobq

HERE = Path(__file__).resolve().parent
STARTED = time.time()

# No remote origin, no inline script, no framing, and nothing may be loaded as a document from
# somewhere else. `form-action 'self'` matters more than it looks: a template bug that put a
# scanned page's form action into our own form would otherwise post to the kit.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)

app = FastAPI(title="scope", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.autoescape = True          # the default; stated because everything here depends on it


def inert(url: str) -> str:
    """A url as text you can read and copy, never as something you can click.

    These urls are live phishing pages and they carry the recipient's own address and reset token.
    A middle-click on an anchor is enough to open one, so there is no anchor.
    """
    safe = html.escape(url or "", quote=True)
    return (
        f'<span class="u"><code>{safe}</code>'
        f'<button class="copy" type="button" data-copy="{safe}" title="copy">copy</button></span>'
    )


# The category vocabulary has exactly one owner (VERDICT_CATEGORIES in verdict.sh). Read it from
# there rather than restating it: a list that drifts is a set of rows that will not group when the
# ledger is mined later. The worker validates against the same source, so a stale copy here can
# only ever produce a refused job, never a bad row.
def _categories() -> list[str]:
    try:
        text = (cache.ROOT / "verdict.sh").read_text()
        line = next(ln for ln in text.splitlines() if ln.startswith("VERDICT_CATEGORIES="))
        return sorted(line.split("=", 1)[1].strip().strip('"\'').split())
    except (OSError, StopIteration, IndexError):
        return []


CATEGORIES = _categories()

templates.env.filters["inert"] = inert
templates.env.filters["shortnum"] = lambda n: "-" if n in (None, "") else n


@app.middleware("http")
async def fence(request: Request, call_next):
    response = await call_next(request)
    # setdefault, not assignment: the artifact route sets a STRICTER policy of its own
    # ("default-src 'none'; sandbox") and this used to overwrite it with the page policy -- which
    # is the wrong direction for the one response that carries a kit's own bytes.
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    # This dashboard shows victim addresses and live kit screenshots. Nothing about it should ever
    # sit in a shared cache, and there is no shared cache, but say so anyway.
    response.headers["Cache-Control"] = "no-store"
    return response


def render(request: Request, template: str, **ctx) -> HTMLResponse:
    """One place where the chrome's own context is added, so no page can forget it.

    A page that carries a `job` also gets that job's current state, so the first paint is already
    right and the stream only has to deliver what happens next.
    """
    base = {"queue_depth": len(jobq.queued()), "running": jobq.running(),
            "worker_up": worker_up(), "state": None, "rc": None, "log": "", "h": None,
            "categories": CATEGORIES}
    job = ctx.get("job")
    if job:
        base |= {"state": jobq.state(job), "rc": jobq.rc(job), "log": jobq.log(job)}
    return templates.TemplateResponse(request, template, base | ctx)


def worker_up() -> bool:
    """Has the host worker touched its heartbeat recently?

    Worth its own indicator: with the worker down, every job sits at `queued` forever and the page
    looks merely slow. "The other half is not running" is the answer, and the page should say it
    rather than let someone wait.
    """
    try:
        return (time.time() - (jobq.JOBS / "heartbeat").stat().st_mtime) < 15
    except OSError:
        return False


# --- pages ---------------------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # The triage queue is plan 05; until then the landing surface says so honestly rather than
    # showing an empty box that looks broken.
    return render(request, "triage.html", scans=cache.scans()[:12])


@app.get("/scan", response_class=HTMLResponse)
async def scan_form(request: Request):
    return render(request, "scan.html", job=None, url="")


@app.post("/scan", response_class=HTMLResponse)
async def scan_start(request: Request, url: str = Form(...), flags: list[str] = Form(default=[]),
                     model: str = Form(default="auto")):
    # No validation here beyond shape: the worker owns the whitelist, and a second opinion in the
    # container would be a second thing to keep in step with it. What this does is refuse to submit
    # obvious nonsense so the user gets an answer now instead of a refused job in a second.
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return render(request, "scan.html", job=None, url=url,
                      error="Needs a http:// or https:// url.")
    job = jobq.submit("scan", url=url, flags=" ".join(flags), model=model or None)
    # The cache directory is a pure function of the url, so the workbench link exists before the
    # scan does. That is what lets the live view hand over to the record view the moment it ends,
    # instead of making the reader go and find the scan they just ran.
    return render(request, "scan.html", job=job, url=url, h=cache.url_hash(url))


@app.get("/ledger", response_class=HTMLResponse)
async def ledger(request: Request, host: str = "", apex: str = "", campaign: str = ""):
    """The report nobody remembers to run, plus the rollups the queue links into.

    The numbers come from `feedback-report.sh --json` rather than being recomputed here. That is
    not politeness: a dashboard with its own idea of the agreement rate is two answers to "how
    accurate is this", and only one of them ever gets fixed.
    """
    scope, key = next(((s, k) for s, k in
                       (("host", host), ("apex", apex), ("campaign", campaign)) if k), ("", ""))
    if key:
        # A rollup is already TSV, so it is read synchronously rather than shown as a job: the
        # queue links straight into it and a spinner between "3 settled DANGEROUS" and the three
        # rows would be the whole point of the link, wasted.
        return render(request, "ledger.html", scope=scope, key=key,
                      rollup=await sh_rows("rollup", scope=scope, key=key), report=None)
    return render(request, "ledger.html", scope="", key="",
                  report=await sh_json("report"), rollup=None)


async def sh_json(kind: str, **fields) -> dict | None:
    """Run a read-only job and parse its JSON. None when the worker is not there to run it."""
    out = await _await_job(kind, **fields)
    try:
        return json.loads(out)
    except (ValueError, TypeError):
        return None


async def sh_rows(kind: str, **fields) -> list[list[str]]:
    """Run a read-only job and split its TSV."""
    out = await _await_job(kind, **fields)
    return [ln.split("\t") for ln in (out or "").splitlines() if ln.strip()]


async def _await_job(kind: str, timeout: float = 20.0, **fields) -> str:
    """Submit and wait. Only ever for the cheap read-only kinds -- a scan is a job you watch.

    A worker that is down means this returns nothing rather than hanging the page; the chrome
    already shows "worker down", so the surface degrades to an empty panel with an explanation
    rather than a spinner that never resolves.
    """
    job = jobq.submit(kind, **fields)
    waited = 0.0
    while jobq.state(job) not in jobq.TERMINAL and waited < timeout:
        await asyncio.sleep(0.1)
        waited += 0.1
    return jobq.log(job) if jobq.state(job) == "done" else ""


@app.post("/ledger/record", response_class=HTMLResponse)
async def ledger_record(request: Request, url: str = Form(...), verdict: str = Form(...),
                        category: str = Form(default=""), note: str = Form(default=""),
                        back: str = Form(default="/")):
    """Write a corrected verdict into the ledger.

    The one write in this application, and it goes through `feedback-report.sh -i` in the worker --
    never near feedback.txt. Everything about the row shape, including the two-row disagreement
    form, belongs to that script; this only carries the four values a person typed.
    """
    job = jobq.submit("record", url=url.strip(), verdict=verdict,
                      category=category or None, note=note.strip() or None)
    return render(request, "recorded.html", job=job, url=url.strip(),
                  verdict=verdict, category=category, back=back)


@app.post("/inspect", response_class=HTMLResponse)
async def inspect(request: Request, url: str = Form(...), back: str = Form(default="/")):
    """The deep inspection: claude -p over the cached artifacts, read-only, no live fetch."""
    job = jobq.submit("inspect", url=url.strip())
    return render(request, "recorded.html", job=job, url=url.strip(),
                  verdict="", category="", back=back, inspecting=True)


@app.get("/tools", response_class=HTMLResponse)
async def tools(request: Request):
    return render(request, "tools.html")


@app.get("/scan/{h}", response_class=HTMLResponse)
async def scan_detail(request: Request, h: str):
    """One cached scan, read straight off disk. No subprocess, no re-fetch.

    This is the drill-in the triage queue opens with `enter`, so it must never start a scan: the
    alert was already scanned to produce its verdict, and the artifacts are already here.
    """
    v = cache.verdict(h)
    if v is None and not cache.artifacts_present(h):
        return render(request, "notfound.html", what=f"scan {h}")
    pg = cache.page(h) or {}
    return render(
        request, "detail.html",
        h=h, v=v or {},
        page=pg,
        followed={k: cache.page(h, k) for k in ("page-login.json", "page-redirect.json")
                  if cache.artifact(h, k)},
        shots=cache.shots(h),
        rows=cache.ledger(h),
        artifacts=cache.artifacts_present(h),
        scripts=[a for a in cache.artifacts_present(h) if a.startswith("scripts/")],
        llm=cache.llm_answer(h),
        vision=(cache.artifact(h, "vision.txt").read_text(errors="replace")
                if cache.artifact(h, "vision.txt") else ""),
        legacy=v is None,
    )


# --- jobs ----------------------------------------------------------------------------------------

@app.get("/job/{job_id}/stream")
async def job_stream(job_id: str):
    """Server-sent events, one per output line.

    The scripts already print phase by phase over 18s-2min, and `-c mono` means what arrives is
    plain text -- so the live view is the script's own narration, not a second logging format
    invented for the web.
    """
    async def events():
        try:
            async for line in jobq.stream(job_id):
                yield f"data: {html.escape(line)}\n\n"
        except asyncio.CancelledError:      # the browser navigated away
            raise
        yield f"event: end\ndata: {jobq.state(job_id)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})


@app.get("/job/{job_id}", response_class=HTMLResponse)
async def job_status(request: Request, job_id: str):
    return render(request, "_job.html", job=job_id, state=jobq.state(job_id),
                  rc=jobq.rc(job_id), log=jobq.log(job_id))


# --- artifacts -----------------------------------------------------------------------------------

@app.get("/artifact/{h}/{name:path}")
async def artifact(h: str, name: str):
    """A file from one scan's cache directory. See the fence in cache.py.

    `name:path` lets `scripts/0.js` through as one segment; everything it could otherwise let
    through is refused by `cache.artifact`, which is the only thing here allowed to build a path.
    """
    path = cache.artifact(h, name)
    if path is None:
        return PlainTextResponse("no such artifact", status_code=404)
    ctype = cache.content_type_for(name)
    return FileResponse(
        path, media_type=ctype,
        headers={
            "X-Content-Type-Options": "nosniff",
            # Belt and braces on top of the content type: even if something upstream rewrote it,
            # a browser will not render this as a document.
            "Content-Disposition": f'inline; filename="{cache.HASH_RE.match(h).group()}-'
                                   f'{os.path.basename(name)}"',
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


@app.get("/health", response_class=PlainTextResponse)
async def health():
    return (f"scope ok\nuptime {int(time.time() - STARTED)}s\n"
            f"worker {'up' if worker_up() else 'DOWN'}\n"
            f"queued {len(jobq.queued())}\ncache {len(cache.scans())} scans\n")
