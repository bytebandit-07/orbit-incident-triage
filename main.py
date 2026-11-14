"""
main.py
=======
FastAPI application entrypoint for the Orbit Logistics Security Incident Triage Assistant.
Serves the dark-mode SOC dashboard and exposes the /api/triage and /api/pack endpoints.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load environment variables early
load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from backend import config
from backend.data_loader import get_loader
from backend.triage_engine import TriageEngine, get_engine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(
    title="Orbit Logistics SOC Incident Triage Assistant",
    description="Autonomous AI-powered Security Incident Correlation & Triage Engine",
    version="3.2.0",
)

# CORS enabled for development / judges
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
STATIC_DIR = FRONTEND_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class TriageRequest(BaseModel):
    query: str
    mode: Optional[str] = "report"
    api_key: Optional[str] = None


@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon():
    """Serve the customized Orbit SOC logo favicon."""
    fav = STATIC_DIR / "favicon.ico"
    if fav.exists():
        return FileResponse(fav)
    fav_svg = STATIC_DIR / "favicon.svg"
    if fav_svg.exists():
        return FileResponse(fav_svg, media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="Favicon not found")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serve the partner's Alpine.js + Tailwind SOC dashboard."""
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html template not found")
    content = index_file.read_text(encoding="utf-8")
    return HTMLResponse(content=content)


@app.get("/api/health")
async def health_check():
    """Healthcheck endpoint for Docker & judge test automation."""
    return {"status": "ok", "app": "Orbit Triage Engine", "version": "3.2.0"}


@app.get("/api/pack")
async def get_data_pack():
    """
    Returns the preloaded 20 files formatted into the D dictionary structure
    expected by the frontend slide-in drawer and file inspection.
    """
    loader = get_loader()
    loader.preload_all()

    d_dict: Dict[str, Any] = {}
    for spec in config.FILE_SPECS:
        doc = loader.load(spec.filename)
        z_label = "UTC" if spec.time_mode == config.LogTimeMode.UTC_Z else ("PKT" if spec.time_mode == config.LogTimeMode.PKT_NAIVE else "Offset")
        
        entry: Dict[str, Any] = {"z": z_label}
        if doc.log_lines:
            entry["l"] = list(doc.log_lines)
        if doc.tables:
            table_rows: Dict[str, Any] = {}
            for t in doc.tables:
                for r in t.rows:
                    if r.key:
                        table_rows[r.key] = r.data
            if table_rows:
                entry["r"] = table_rows
        d_dict[spec.filename] = entry

    return {
        "files_count": len(d_dict),
        "files": [s.filename for s in config.FILE_SPECS],
        "D": d_dict,
    }


@app.post("/api/triage")
async def run_triage(req: TriageRequest):
    """
    Execute end-to-end incident triage:
    1. Deterministic preflight change calendar matching
    2. Context packing with exact line numbers
    3. LLM generation with rate-limit retries
    4. Citation validation and structured extraction
    """
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    engine = get_engine()

    # If user provided a custom API key from the UI header, configure it dynamically
    if req.api_key and req.api_key.strip():
        os.environ["GEMINI_API_KEY"] = req.api_key.strip()
        os.environ["GOOGLE_API_KEY"] = req.api_key.strip()
        # Reset cached engine to pick up new key
        engine._llm = None

    try:
        result = await engine.analyze_async(query=req.query, mode=req.mode or "report")
        
        trail = [
            {"l": e.get("s", "Sensor"), "v": e.get("x", "Activity"), "c": e.get("c", "")}
            for e in (result.timeline_events or [])
            if isinstance(e, dict) and e.get("c")
        ][:5]

        return {
            "status": "success",
            "report": result.markdown_report,
            "timeline_events": result.timeline_events,
            "evidence_trail": trail,
            "brief": result.brief,
            "chat_segments": result.chat_segments,
            "citation_checks": result.citation_checks,
            "provider_used": result.provider_used,
            "short_circuited": result.short_circuited,
            "warnings": result.warnings,
        }
    except Exception as exc:
        logger.error("Triage analysis failed: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(exc)},
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
