"""
CyberCheck API (Phase 5).

Thin wrapper over the existing engine:

    request -> validate -> scanners -> risk engine -> JSON

No detection or scoring logic lives here.

Run (from the backend/ folder):
    uvicorn main:app --reload
Interactive docs:
    http://127.0.0.1:8000/docs
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from scan import SCANNERS, run_all
from scoring.risk import impact_effort_label, prioritize
from scoring.score import calculate_score
from validation import assert_public_host, normalize_domain

app = FastAPI(title="CyberCheck API", version="0.5.0")

# Allow the React dev server to call this API. Tighten for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253,
                        examples=["example.com"])
    only: list[str] | None = Field(
        default=None,
        description=f"Optional subset of scanners: {', '.join(SCANNERS)}",
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# Plain `def` (not async) on purpose: the scanners use blocking network
# calls, so FastAPI runs this in a worker thread instead of freezing the
# whole server while a scan is in progress.
@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    try:
        domain = normalize_domain(req.domain)
        assert_public_host(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if req.only:
        unknown = [s for s in req.only if s not in SCANNERS]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown scanner(s): {', '.join(unknown)}",
            )

    findings = run_all(domain, req.only)
    score = calculate_score(findings)

    top = []
    for f in prioritize(findings, limit=3):
        item = f.to_dict()
        item["impact_effort"] = impact_effort_label(f)
        top.append(item)

    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score.to_dict(),
        "top_priorities": top,
        "findings": [f.to_dict() for f in findings],
    }
