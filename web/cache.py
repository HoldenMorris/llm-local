"""Reading `.cache/` — and the fence around it.

Everything a scan found is already a file on disk: page.json, the followed login and interstitial
pages, a screenshot for each, meta.env, vision.txt, wayback.json, scripts/, deob-signals.txt, the
per-URL feedback ledger, and (since the verdict.json change) the scan's own answer. So the read
side of this application is a directory listing and some jq-shaped parsing. Nothing here shells
out; nothing here writes.

THE FENCE. This is the first thing in the repo that serves attacker-controlled files to a browser,
and two of the failure modes are severe enough to be worth naming:

  * A cached phishing page served as text/html is this dashboard delivering the kit it was built to
    analyse. `content_type_for` has no branch that returns text/html or any executable type: an
    image is an image and *everything else is text/plain*, with nosniff set by the caller.
  * `.cache/<hash>/<name>` looks like a path join, and a path join is a traversal. `artifact` takes
    a 16-hex hash and a name from a fixed allowlist, then resolves the result and confirms it is
    still inside the cache directory -- because an allowlist alone does not survive a symlink that
    a scanned page's own artifacts could, in principle, contain.

Pure stdlib. `python3 web/cache.py` runs the self-check.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path

# The container mounts the repo at /app; on the host the default lands beside this file.
ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"

HASH_RE = re.compile(r"^[0-9a-f]{16}$")

# What a scan writes, and therefore all a reader is ever allowed to ask for. Adding an artifact to
# the scan means adding it here too -- deliberately, because "serve whatever is in the directory"
# is how the next new artifact gets served without anyone deciding it should be.
ARTIFACTS = frozenset({
    "verdict.json",
    "page.json", "page-login.json", "page-redirect.json",
    "page.jpg", "login.jpg", "redirect.jpg",
    "vision.txt", "wayback.json", "deob-signals.txt",
    "virustotal.json", "urlscan.json",
    "feedback.txt",
})
SCRIPT_RE = re.compile(r"^scripts/[A-Za-z0-9_.-]{1,64}$")
# One per (model, prompt, context), so the name is a hash rather than a fixed string -- hence a
# pattern here instead of a member of ARTIFACTS.
LLM_RE = re.compile(r"^llm-[0-9a-f]{16}\.txt$")

# The screenshots the scan itself prefers, in the order url-analyze.sh picks them: the followed
# credential page beats the followed interstitial beats the landing shell, because on a kit with a
# marketing front page the landing shell is the one screenshot that shows nothing.
SHOTS = ("login.jpg", "redirect.jpg", "page.jpg")


def url_hash(url: str) -> str:
    """The cache directory name for a url.

    Must stay identical to url-analyze.sh:
        printf '%s' "$URL" | sha256sum | cut -c1-16
    """
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def artifact(h: str, name: str) -> Path | None:
    """A readable path inside one scan's cache directory, or None. Never raises on bad input."""
    if not HASH_RE.match(h or ""):
        return None
    if (name not in ARTIFACTS and not SCRIPT_RE.match(name or "")
            and not LLM_RE.match(name or "")):
        return None
    base = (CACHE / h).resolve()
    try:
        path = (base / name).resolve()
    except (OSError, RuntimeError):
        return None
    # An allowlisted name can still point outside once a symlink is in the way.
    if not path.is_file() or base != CACHE.resolve() / h or not str(path).startswith(str(base) + "/"):
        return None
    return path


def content_type_for(name: str) -> str:
    """Images are images. Everything else is text, whatever it claims to be.

    There is deliberately no text/html, no application/javascript, and no
    application/octet-stream branch: a cached kit's own markup or scripts rendered as themselves
    would make this page the delivery mechanism.
    """
    lowered = name.lower()
    if lowered.endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    if lowered.endswith(".png"):
        return "image/png"
    return "text/plain; charset=utf-8"


# --- readers -------------------------------------------------------------------------------------

def _json(path: Path) -> dict | None:
    try:
        with path.open() as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def verdict(h: str) -> dict | None:
    """The scan's own answer, or None for a scan that predates verdict.json.

    None means "scanned before this existed", not "error" -- 427 cache directories are older than
    the writer, and a reader falls back to the other artifacts rather than showing a failure.
    """
    p = artifact(h, "verdict.json")
    return _json(p) if p else None


def page(h: str, which: str = "page.json") -> dict | None:
    p = artifact(h, which)
    return _json(p) if p else None


def meta(host_port: str) -> dict[str, str]:
    """The per-host fact cache (`.cache/host/<host>:<port>/meta.env`).

    It is a file of `KEY=value` written by printf %q for the shell to source back, so shlex is the
    right reader: it undoes the quoting without executing anything.
    """
    safe = re.sub(r"[^a-zA-Z0-9.:_-]", "_", host_port)
    path = CACHE / "host" / safe / "meta.env"
    out: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            key, _, raw = line.partition("=")
            if not _ or not key.isidentifier():
                continue
            parts = shlex.split(raw)
            out[key] = parts[0] if parts else ""
    except (OSError, ValueError):
        return {}
    return out


def ledger(h: str) -> list[dict]:
    """The per-URL feedback rows, oldest first.

    Tab-separated and append-only, and the LATEST row wins -- so a reader keeps the order rather
    than collapsing it: an inspection supersedes a flag, and a later re-flag reopens the url.
    Columns grew over time, so a short row is a valid old row, never a parse failure.
    """
    p = artifact(h, "feedback.txt")
    if not p:
        return []
    rows = []
    try:
        for line in p.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            f = line.split("\t")
            rows.append({
                "at": f[0] if len(f) > 0 else "",
                "verdict": f[1] if len(f) > 1 else "",
                "action": f[2] if len(f) > 2 else "",
                "url": f[3] if len(f) > 3 else "",
                "note": f[4] if len(f) > 4 else "",
                "category": f[5] if len(f) > 5 else "",
            })
    except OSError:
        return []
    return rows


def shot(h: str) -> str | None:
    """The screenshot worth showing, by the scan's own order of preference."""
    return next((s for s in SHOTS if artifact(h, s)), None)


def shots(h: str) -> list[str]:
    """Every screenshot present, preferred first. The workbench shows them all: the landing shell
    beside the followed credential page is the comparison that explains a login-gated floor."""
    return [s for s in SHOTS if artifact(h, s)]


def llm_answer(h: str) -> str:
    """The verdict model's own words, from whichever llm-<hash>.txt this scan wrote.

    More than one can accumulate in a directory as models or prompts change; the newest is the one
    that produced the verdict on screen.
    """
    base = CACHE / h
    if not HASH_RE.match(h or "") or not base.is_dir():
        return ""
    files = [p for p in base.iterdir() if p.is_file() and LLM_RE.match(p.name)]
    if not files:
        return ""
    newest = max(files, key=lambda p: p.stat().st_mtime)
    try:
        return newest.read_text(errors="replace")
    except OSError:
        return ""


def artifacts_present(h: str) -> list[str]:
    """What is actually on disk for one scan, allowlist-filtered. Never a raw listing."""
    base = CACHE / h
    if not HASH_RE.match(h or "") or not base.is_dir():
        return []
    found = [n for n in sorted(ARTIFACTS) if (base / n).is_file()]
    found += sorted(p.name for p in base.iterdir() if p.is_file() and LLM_RE.match(p.name))
    scripts = base / "scripts"
    if scripts.is_dir():
        found += sorted(
            f"scripts/{p.name}" for p in scripts.iterdir()
            if p.is_file() and SCRIPT_RE.match(f"scripts/{p.name}")
        )
    return found


def scans() -> list[dict]:
    """Every cached scan, newest first, as much as each one can say about itself."""
    if not CACHE.is_dir():
        return []
    out = []
    for d in CACHE.iterdir():
        if not d.is_dir() or not HASH_RE.match(d.name):
            continue
        v = verdict(d.name) or {}
        try:
            mtime = d.stat().st_mtime
        except OSError:
            mtime = 0.0
        out.append({
            "hash": d.name,
            "mtime": mtime,
            "url": v.get("url", ""),
            "verdict": v.get("verdict", ""),
            "category": v.get("category") or "",
            "has_record": bool(v),
        })
    out.sort(key=lambda s: s["mtime"], reverse=True)
    return out


# --- self-check: python3 web/cache.py ------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import tempfile

    fails = 0

    def check(name, got, want):
        global fails
        if got == want:
            print(f"ok   {name}")
        else:
            fails += 1
            print(f"FAIL {name}: want {want!r}, got {got!r}")

    # The hash has to agree with the shell, or every read misses by one directory.
    check("hash matches sha256sum|cut -c1-16",
          url_hash("https://example.com/"),
          hashlib.sha256(b"https://example.com/").hexdigest()[:16])

    # -- the fence, on a throwaway cache -----------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        CACHE = Path(tmp)                                  # noqa: F811 - rebinding for the test
        h = "0123456789abcdef"
        d = CACHE / h
        (d / "scripts").mkdir(parents=True)
        (d / "page.json").write_text('{"title":"hi","counts":{"forms":1}}')
        (d / "page.jpg").write_bytes(b"\xff\xd8\xff")
        (d / "scripts" / "0.js").write_text("alert(1)")
        (d / "secret.txt").write_text("not allowlisted")
        (CACHE / "outside.txt").write_text("above the scan dir")
        try:
            (d / "escape.json").symlink_to(CACHE / "outside.txt")
        except OSError:
            pass

        check("allowlisted file resolves", artifact(h, "page.json") is not None, True)
        check("allowlisted script resolves", artifact(h, "scripts/0.js") is not None, True)
        check("a real file that is not allowlisted", artifact(h, "secret.txt"), None)
        check("traversal in the name", artifact(h, "../outside.txt"), None)
        check("absolute path as the name", artifact(h, "/etc/passwd"), None)
        check("traversal in the script name", artifact(h, "scripts/../../outside.txt"), None)
        check("symlink out of the scan dir", artifact(h, "escape.json"), None)
        check("hash must be 16 hex", artifact("../host", "page.json"), None)
        check("hash must be lowercase hex", artifact("0123456789ABCDEF", "page.json"), None)
        check("empty name", artifact(h, ""), None)

        check("jpg is an image", content_type_for("page.jpg"), "image/jpeg")
        check("json is text", content_type_for("page.json"), "text/plain; charset=utf-8")
        check("a kit's script is text", content_type_for("scripts/0.js"), "text/plain; charset=utf-8")
        check("nothing is ever html", "html" in content_type_for("page-login.json"), False)

        check("reads page.json", (page(h) or {}).get("title"), "hi")
        check("missing verdict.json is None, not an error", verdict(h), None)
        check("listing is allowlist-filtered",
              artifacts_present(h), ["page.jpg", "page.json", "scripts/0.js"])
        check("preferred screenshot", shot(h), "page.jpg")

        (d / "llm-0123456789abcdef.txt").write_text("VERDICT: SAFE")
        check("llm answer is allowlisted by pattern",
              artifact(h, "llm-0123456789abcdef.txt") is not None, True)
        check("a made-up llm name is not", artifact(h, "llm-zz.txt"), None)
        check("reads the llm answer", llm_answer(h), "VERDICT: SAFE")
        check("llm answer is served as text",
              content_type_for("llm-0123456789abcdef.txt"), "text/plain; charset=utf-8")
        (d / "login.jpg").write_bytes(b"\xff\xd8\xff")
        check("all shots, preferred first", shots(h), ["login.jpg", "page.jpg"])

        # a ledger row from before a column existed is an old row, not a broken one
        (d / "feedback.txt").write_text(
            "2026-01-01T00:00:00Z\t\tagree\thttps://x.com\n"
            "2026-02-01T00:00:00Z\tSAFE\tinspected\thttps://x.com\tlooked\tcontent\n")
        rows = ledger(h)
        check("ledger keeps order", [r["action"] for r in rows], ["agree", "inspected"])
        check("short row is not a failure", rows[0]["category"], "")
        check("full row parses", rows[1]["category"], "content")

    print()
    print("failed" if fails else "self-test ok")
    sys.exit(1 if fails else 0)
