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
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
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

def triage_page(request: Request, job: str | None = None, note: str = "") -> HTMLResponse:
    """The LUCA queue, read from .cache/triage.json -- never through the worker.

    A page load must not wait behind a two-minute scan, so the list is whatever the last refresh
    wrote, stamped with when that was. Alerts ruled here since then are dropped, and only once the
    ledger row exists: the `ruled` flag is computed from the row, by the re-check that the record
    route queues behind the write.
    """
    t = cache.triage()
    alerts = [a for a in (t or {}).get("alerts", []) if not a.get("ruled")]
    return render(request, "triage.html", t=t, alerts=alerts, job=job, note=note,
                  ruled=len((t or {}).get("alerts", [])) - len(alerts),
                  unanswered=sum(1 for a in alerts if a.get("source") == "none"),
                  scans=[] if t else cache.scans()[:12])


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return triage_page(request)


@app.post("/triage/refresh", response_class=HTMLResponse)
async def triage_refresh(request: Request):
    # claude -p over Slack, ~20-40s a channel -- a job you watch, not a page that hangs.
    return triage_page(request, job=jobq.submit("triage"))


@app.post("/triage/recheck", response_class=HTMLResponse)
async def triage_recheck(request: Request):
    return triage_page(request, job=jobq.submit("triage-cached"))


@app.post("/triage/scan", response_class=HTMLResponse)
async def triage_scan(request: Request, url: str = Form(default="")):
    """Scan what the ledger could not answer: one url, or every unanswered one when none is given.

    Same flags next-alert.sh scans with (-m auto -t). The re-check is queued LAST, so the worker's
    one-at-a-time order runs it after the scans it depends on.
    """
    t = cache.triage() or {}
    open_alerts = [a for a in t.get("alerts", []) if not a.get("ruled")]
    if url:
        urls = [a["url"] for a in open_alerts if a.get("url") == url.strip()]
    else:
        urls = [a["url"] for a in open_alerts if a.get("source") == "none" and not a.get("scanned")]
    for u in urls:
        jobq.submit("scan", url=u, flags="-t", model="auto")
    job = jobq.submit("triage-cached") if urls else None
    return triage_page(request, job=job,
                       note=f"{len(urls)} scan(s) queued; the queue re-checks itself after the last one"
                       if urls else "nothing unanswered to scan")


@app.get("/scan", response_class=HTMLResponse)
async def scan_form(request: Request):
    return render(request, "scan.html", job=None, url="")


# The scan form speaks in steps that RUN, one meaning per tick. The CLI flags mix the two senses
# (-t and -r switch a step on, -V -D -H switch one off), and a form that copied them made a tick
# mean "on" in one row and "off" in the next. The flags themselves stay: benchmarks, next-alert.sh
# and every doc use them, and the worker's whitelist is still what decides.
STEP_ON = {"reputation": "-t", "refresh": "-r"}              # ticked -> add the flag
STEP_OFF = {"vision": "-V", "deobfuscation": "-D", "llm": "-H"}  # unticked -> add the flag


def scan_flags(steps: list[str]) -> str:
    return " ".join([f for s, f in STEP_ON.items() if s in steps] +
                    [f for s, f in STEP_OFF.items() if s not in steps])


@app.post("/scan", response_class=HTMLResponse)
async def scan_start(request: Request, url: str = Form(...), steps: list[str] = Form(default=[]),
                     model: str = Form(default="auto")):
    flags = scan_flags(steps)
    # No validation here beyond shape: the worker owns the whitelist, and a second opinion in the
    # container would be a second thing to keep in step with it. What this does is refuse to submit
    # obvious nonsense so the user gets an answer now instead of a refused job in a second.
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return render(request, "scan.html", job=None, url=url,
                      error="Needs a http:// or https:// url.")
    job = jobq.submit("scan", url=url, flags=flags, model=model or None)
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
        out, pending, as_of = await ledger_read("rollup", scope=scope, key=key)
        rows = [ln.split("\t") for ln in (out or "").splitlines() if ln.strip()]
        return render(request, "ledger.html", scope=scope, key=key, rollup=rows, report=None,
                      read=out is not None, pending=pending, as_of=as_of)
    out, pending, as_of = await ledger_read("report")
    try:
        report = json.loads(out) if out else None
    except ValueError:
        report = None
    return render(request, "ledger.html", scope="", key="", report=report, rollup=None,
                  read=out is not None, pending=pending, as_of=as_of)


async def ledger_read(kind: str, **fields) -> tuple[str | None, str | None, str | None]:
    """A ledger read that never waits behind a long job: (output, pending job, as-of time).

    The worker runs one job at a time, and a replay holds it for hours. Waiting for a fresh read
    then cost every visit the full 20s timeout, returned nothing, and left one more report queued
    per visit. So: reuse the last finished read while the ledger has not changed since; otherwise
    keep ONE read queued, wait for it only when the worker is free, and while it is busy show the
    last read with its time. No read at all is output None -- which the page must say, because
    "nothing settled" for a read that never ran is the empty-queue lie again.
    """
    last = jobq.find(kind, {"done"}, **fields)
    last_at = jobq.finished_at(last) if last else None
    if last and last_at and last_at >= cache.ledger_mtime():
        return jobq.log(last), None, None
    pending = jobq.find(kind, {"queued", "running"}, **fields) or jobq.submit(kind, **fields)
    if jobq.running() in (None, pending):
        waited = 0.0
        while jobq.state(pending) not in jobq.TERMINAL and waited < 20:
            await asyncio.sleep(0.1)
            waited += 0.1
        if jobq.state(pending) == "done":
            return jobq.log(pending), None, None
    stamp = time.strftime("%H:%M", time.localtime(last_at)) if last_at else None
    return (jobq.log(last) if last else None), pending, stamp


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
    # Ruled from the queue: re-check it behind the write, so the alert leaves the queue only once
    # its row exists. `back` only selects whether to queue this; nothing in it reaches the worker.
    if back == "/" or back.startswith("/#"):
        jobq.submit("triage-cached")
    return render(request, "recorded.html", job=job, url=url.strip(),
                  verdict=verdict, category=category, back=back)


@app.post("/inspect", response_class=HTMLResponse)
async def inspect(request: Request, url: str = Form(...), back: str = Form(default="/")):
    """The deep inspection: claude -p over the cached artifacts, read-only, no live fetch."""
    job = jobq.submit("inspect", url=url.strip())
    return render(request, "recorded.html", job=job, url=url.strip(),
                  verdict="", category="", back=back, inspecting=True)


# What the Tools page may ask the worker for. The worker is still the authority -- it refuses an
# unknown kind and validates every value -- this only keeps the form from offering one.
TOOL_KINDS = {"replay", "harvest-preview", "harvest", "intel", "intel-all", "scout",
              "tor-up", "tor-rotate", "tor-down"}

# Validated with the dataviz palette checker against --panel (#0e1114), dark mode: lightness band,
# chroma floor, CVD and normal-vision separation, contrast. Fixed order, never cycled: a fifth
# engine is drawn in muted grey rather than given a generated hue.
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500"]


def bench_chart(rows: list[dict]) -> dict:
    """Accuracy per replay, per engine, on one 0-100% axis.

    Time is a different scale, so it is NOT a second axis -- it is a column in the table under the
    chart. Replays are placed by order rather than by date: they are meant to be weekly, and a gap
    in the calendar is not a finding.
    """
    W, H, L, R, T, B = 640, 220, 40, 130, 14, 30
    stamps = sorted({r["ts"] for r in rows})
    engines = list(dict.fromkeys(r["engine"] for r in rows))
    pw, ph = W - L - R, H - T - B
    xs = {ts: L + (pw / 2 if len(stamps) == 1 else i * pw / (len(stamps) - 1))
          for i, ts in enumerate(stamps)}
    series = []
    for i, e in enumerate(engines):
        # Dodge each engine a few px sideways: two engines one point apart on the same replay
        # (58% vs 59%) otherwise print one dot on top of the other.
        dx = (i - (len(engines) - 1) / 2) * 10
        pts = [{"x": round(xs[r["ts"]] + dx, 1), "y": round(T + ph * (1 - r["accuracy"] / 100), 1), **r}
               for r in rows if r["engine"] == e]
        series.append({"engine": e, "color": SERIES[i] if i < len(SERIES) else "#79838f",
                       "points": pts, "path": " ".join(f"{p['x']},{p['y']}" for p in pts)})
    # Direct labels sit right of each line's last point; nudge apart any two closer than 13px.
    placed = sorted(series, key=lambda s: s["points"][-1]["y"])
    last = -1e9
    for s in placed:
        s["label_y"] = max(s["points"][-1]["y"] + 4, last + 13)
        last = s["label_y"]
    return {"W": W, "H": H, "L": L, "R": R, "T": T, "B": B, "right": W - R,
            "grid": [{"v": v, "y": round(T + ph * (1 - v / 100), 1)} for v in (0, 25, 50, 75, 100)],
            "stamps": [{"ts": ts, "x": round(xs[ts], 1)} for ts in stamps],
            "series": series}


def intel_items(log: str) -> list[dict]:
    """intel-feed.sh's output as items, the ones with NO MATCHING DETECTION first.

    Those are the only lines worth an hour; everything else is a mechanism we already have. The
    order within each group is the feed's own.
    """
    items = []
    for block in log.split("\n\n"):
        lines = [ln for ln in block.splitlines() if ln.strip()]
        if lines and lines[0].startswith("["):
            items.append({"lines": lines, "gap": any("NO MATCHING DETECTION" in ln for ln in lines)})
    return sorted(items, key=lambda it: not it["gap"])


@app.get("/tools", response_class=HTMLResponse)
async def tools(request: Request, job: str = ""):
    rows = cache.benchmark()
    k = jobq.kind(job) if job else ""
    done = job and jobq.state(job) == "done"
    return render(request, "tools.html", job=job or None, kind=k,
                  chart=bench_chart(rows) if rows else None, bench=rows,
                  intel=intel_items(jobq.log(job)) if done and k.startswith("intel") else None)


@app.post("/tools/run", response_class=HTMLResponse)
async def tools_run(request: Request, kind: str = Form(...), model: str = Form(default=""),
                    search: str = Form(default=""), maxb: str = Form(default=""),
                    cc: str = Form(default="")):
    if kind not in TOOL_KINDS:
        return PlainTextResponse("unknown tool", status_code=400)
    job = jobq.submit(kind, model=model.strip() or None, search=search.strip() or None,
                      maxb=maxb.strip() or None, cc=cc.strip().lower() or None)
    # Same page, as a GET: a reload re-attaches to the job instead of submitting it again.
    return RedirectResponse(f"/tools?job={job}", status_code=303)


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
