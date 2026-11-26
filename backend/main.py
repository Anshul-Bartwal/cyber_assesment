"""
CyberCheck API (Phase 5 + questionnaire).

Flow:
    POST /scan                     -> technical scan; returns a scan_id
    GET  /questionnaire            -> the questions to show the business owner
    POST /scan/{scan_id}/answers   -> combine questionnaire answers with the
                                      saved scan and return the updated score
                                      (no need to re-scan)

No detection or scoring logic lives here.

Run (from the backend/ folder):
    python -m uvicorn main:app --reload
Interactive docs: http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from questionnaire.questions import (
    evaluate_answers, public_questions, validate_answers,
)
from scan import SCANNERS, run_all
from scoring.risk import impact_effort_label, prioritize
from scoring.score import calculate_score
from validation import assert_public_host, normalize_domain

app = FastAPI(title="CyberCheck API", version="0.6.0")

# Allow the React dev server to call this API. Tighten for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory store of recent scans, so submitting questionnaire answers does
# not require a 30-second re-scan. Nothing is written to disk; results vanish
# when the server restarts (the frontend then asks the user to scan again).
# ---------------------------------------------------------------------------
_MAX_STORED_SCANS = 200
_SCANS: "OrderedDict[str, dict]" = OrderedDict()
_LOCK = threading.Lock()


def _remember_scan(domain: str, scanned_at: str, findings: list) -> str:
    scan_id = uuid.uuid4().hex
    with _LOCK:
        _SCANS[scan_id] = {
            "domain": domain,
            "scanned_at": scanned_at,
            "findings": findings,
        }
        while len(_SCANS) > _MAX_STORED_SCANS:
            _SCANS.popitem(last=False)
    return scan_id


def _build_response(scan_id: str, entry: dict, answers: dict | None) -> dict:
    technical = entry["findings"]
    questionnaire = evaluate_answers(answers) if answers else []
    everything = technical + questionnaire

    top = []
    for f in prioritize(everything, limit=3):
        item = f.to_dict()
        item["impact_effort"] = impact_effort_label(f)
        top.append(item)

    return {
        "scan_id": scan_id,
        "domain": entry["domain"],
        "scanned_at": entry["scanned_at"],
        "score": calculate_score(everything).to_dict(),
        # Score from the technical scan alone, so the UI can show how much
        # the questionnaire changed the result.
        "previous_overall": calculate_score(technical).overall if answers else None,
        "questionnaire_answered": len(questionnaire),
        "top_priorities": top,
        "findings": [f.to_dict() for f in everything],
    }


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253,
                        examples=["example.com"])
    only: list[str] | None = Field(
        default=None,
        description=f"Optional subset of scanners: {', '.join(SCANNERS)}",
    )


class AnswersRequest(BaseModel):
    answers: dict[str, Literal["yes", "no", "unsure"]]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/questionnaire")
def questionnaire() -> dict:
    return {"questions": public_questions()}


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
    scanned_at = datetime.now(timezone.utc).isoformat()
    scan_id = _remember_scan(domain, scanned_at, findings)
    return _build_response(scan_id, _SCANS[scan_id], None)


@app.post("/scan/{scan_id}/answers")
def submit_answers(scan_id: str, req: AnswersRequest) -> dict:
    with _LOCK:
        entry = _SCANS.get(scan_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail="This scan has expired. Please run the assessment again.",
        )
    try:
        validate_answers(req.answers)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return _build_response(scan_id, entry, req.answers)
