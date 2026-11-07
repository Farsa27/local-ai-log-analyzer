"""FastAPI backend: upload, start, progress, report, system stats."""
import os
import time
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from . import analyzer, config, llm

try:
    import psutil
except ImportError:  # optional
    psutil = None

app = FastAPI(title="Local AI Security Log Analyzer")
STATIC = config.BASE_DIR / "static"


@app.on_event("startup")
def _startup():
    analyzer.start_worker()


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    name = Path(file.filename or "").name
    if Path(name).suffix.lower() not in config.ALLOWED_EXT:
        raise HTTPException(400, "Only .log or .txt files are accepted.")
    dest = config.UPLOAD_DIR / f"{int(time.time())}_{name}"
    size = 0
    with open(dest, "wb") as out:  # stream to disk in 64 KB pieces; no full copy in RAM
        while chunk := await file.read(65536):
            size += len(chunk)
            if size > config.MAX_UPLOAD_BYTES:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"File too large (max {config.MAX_UPLOAD_BYTES // 1048576} MB).")
            if b"\x00" in chunk:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(400, "File looks binary, not a text log.")
            out.write(chunk)
    if size == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "File is empty.")
    job = analyzer.new_job(name, dest)
    return {"job_id": job["id"], "bytes": size}


@app.post("/api/jobs/{job_id}/start")
def start(job_id: str):
    job = _get(job_id)
    if job["status"] in ("queued", "planning", "running", "reporting"):
        return {"status": job["status"]}
    if not llm.health()["ok"]:
        raise HTTPException(503, f"Local model server is not reachable at {config.LLM_URL}. Start llama-server first.")
    if job["status"] in ("done", "cancelled", "failed") and job["chunks"]:
        analyzer.retry_failed(job)  # resumes from the first unfinished part
        return {"status": "queued"}
    job["status"] = "queued"
    analyzer.save_job(job)
    analyzer.enqueue(job_id)
    return {"status": "queued"}


@app.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    _get(job_id)
    analyzer.cancel(job_id)
    return {"ok": True}


@app.get("/api/jobs/{job_id}")
def status(job_id: str):
    job = _get(job_id)
    job.pop("events", None)  # keep progress responses small
    job.pop("error", None)
    return job


@app.get("/api/jobs/{job_id}/report")
def report(job_id: str):
    job = _get(job_id)
    if not job.get("report"):
        raise HTTPException(404, "Report not ready yet.")
    return JSONResponse(job["report"], headers={"Content-Disposition": f'inline; filename="report_{job_id}.json"'})


@app.get("/api/jobs")
def jobs():
    return analyzer.list_jobs()


@app.get("/api/system")
def system():
    info = {"model_server": llm.health(), "model": llm.model_name(), "llm_url": config.LLM_URL,
            "ctx_limit": config.CTX_LIMIT}
    if psutil:
        me = psutil.Process(os.getpid())
        backend = me.memory_info().rss
        model = 0
        for p in psutil.process_iter(["name", "memory_info"]):
            try:
                if "llama" in (p.info["name"] or "").lower() and p.info["memory_info"]:
                    model += p.info["memory_info"].rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        info["ram_mb"] = {"backend": round(backend / 1048576), "model_server": round(model / 1048576),
                          "total": round((backend + model) / 1048576), "limit": 4096}
    return info


def _get(job_id: str) -> dict:
    job = analyzer.load_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    return job
