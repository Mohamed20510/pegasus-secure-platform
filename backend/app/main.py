import asyncio
import os
import shutil
import tempfile
import time
import zipfile
from typing import List
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from .database import engine, Base, get_db
from .models import Project, Scan, Finding
from .schemas import ProjectOut, ScanOut, FindingOut
from .worker import execute_scan_task
from .engines.ai_fixer import (
    generate_code_repair,
    generate_markdown_report,
    apply_patches_and_build_zip
)

# ---------------------------------------------------------
# 1. Database Initialization & Automatic Schema Migration
# ---------------------------------------------------------
MAX_RETRIES = 12
RETRY_DELAY = 2

for attempt in range(1, MAX_RETRIES + 1):
    try:
        with engine.connect() as connection:
            print("[Database] Successfully connected to database engine!")
            break
    except OperationalError as err:
        if attempt == MAX_RETRIES:
            print(f"[Database Error] Could not connect after {MAX_RETRIES} attempts: {err}")
            raise err
        print(f"[Database] Waiting for database (attempt {attempt}/{MAX_RETRIES})... Retrying in {RETRY_DELAY}s")
        time.sleep(RETRY_DELAY)

# Create tables if they do not exist
Base.metadata.create_all(bind=engine)

# In-place auto-migration for SQLite / PostgreSQL schema additions
try:
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE findings ADD COLUMN category VARCHAR(50) DEFAULT 'SYSTEM'"))
            conn.commit()
            print("[Database] Column 'category' verified/added in findings table.")
        except Exception:
            pass

        try:
            conn.execute(text("ALTER TABLE findings ADD COLUMN ai_fix JSON DEFAULT '{}'"))
            conn.commit()
            print("[Database] Column 'ai_fix' verified/added in findings table.")
        except Exception:
            pass

        try:
            conn.execute(text("UPDATE findings SET category = 'SYSTEM' WHERE category IS NULL"))
            conn.execute(text("UPDATE findings SET ai_fix = '{}' WHERE ai_fix IS NULL"))
            conn.commit()
        except Exception:
            pass
except Exception as mig_err:
    print(f"[Database Notice] Auto-migration check completed: {mig_err}")

# ---------------------------------------------------------
# 2. FastAPI Application Setup
# ---------------------------------------------------------
app = FastAPI(
    title="PEGASUS Secure Software Intelligence API",
    description="Automated Secure Code Review, Forensics, AI Remediation & Educational Guidance Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# 3. Utility: Safe Archive Extraction (Prevents Zip Slip)
# ---------------------------------------------------------
def safe_extract_zip(zip_path: str, target_dir: str):
    """
    Safely extracts zip archive while preventing path traversal attacks.
    Uses commonpath evaluation to prevent partial prefix match exploits.
    """
    target_abs = os.path.abspath(target_dir)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # Skip metadata and OS artifacts
            if member.startswith("__MACOSX") or member.endswith(".DS_Store"):
                continue

            destination = os.path.abspath(os.path.join(target_dir, member))
            try:
                common = os.path.commonpath([target_abs, destination])
            except ValueError:
                # Occurs if paths cross drive boundaries on Windows
                raise ValueError(f"Security error: Path traversal cross-drive attempt: {member}")

            if common.lower() != target_abs.lower():
                raise ValueError(f"Security error: Archive attempted path traversal outside target: {member}")

        zip_ref.extractall(target_dir)

# ---------------------------------------------------------
# 4. Core API Endpoints
# ---------------------------------------------------------
@app.get("/")
def root():
    return {
        "platform": "PEGASUS Secure Software Intelligence Platform",
        "status": "online",
        "endpoints": {
            "interactive_docs": "/docs",
            "health_check": "/api/health",
            "projects": "/api/projects"
        }
    }


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "pegasus-backend"}


@app.get("/api/projects", response_model=List[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.id.desc()).all()


@app.post("/api/projects/upload")
async def upload_code_archive(
    project_name: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip repository archives are supported.")

    # 1. Create Project entry
    project = Project(name=project_name.strip() or "Untitled Security Audit")
    db.add(project)
    db.commit()
    db.refresh(project)

    # 2. Create Scan entry
    scan = Scan(project_id=project.id, status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 3. Save and extract archive in cross-platform temp storage
    base_temp = os.path.join(tempfile.gettempdir(), "pegasus_scans")
    os.makedirs(base_temp, exist_ok=True)
    temp_dir = os.path.join(base_temp, f"scan_{scan.id}")
    backup_dir = os.path.join(base_temp, f"source_{scan.id}")
    os.makedirs(temp_dir, exist_ok=True)
    zip_path = os.path.join(temp_dir, file.filename)

    try:
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        safe_extract_zip(zip_path, temp_dir)
        if os.path.exists(zip_path):
            os.remove(zip_path)

        # Retain a dedicated source copy for on-demand AI code repair & zip downloads
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir, ignore_errors=True)
        shutil.copytree(temp_dir, backup_dir)

    except Exception as e:
        scan.status = "FAILED"
        scan.summary = {"error": f"Failed to extract uploaded archive: {str(e)}"}
        db.commit()
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Archive extraction failed: {str(e)}")

    # 4. Dispatch scan in background
    background_tasks.add_task(execute_scan_task, scan.id, temp_dir)

    return {
        "project_id": project.id,
        "scan_id": scan.id,
        "status": "QUEUED"
    }


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan


@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingOut])
def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    return db.query(Finding).filter(Finding.scan_id == scan_id).all()


# ---------------------------------------------------------
# 5. AI Auto-Remediation, Report & Download Endpoints
# ---------------------------------------------------------

@app.post("/api/findings/{finding_id}/autofix")
async def autofix_finding(finding_id: int, db: Session = Depends(get_db)):
    """Generates an AI secure code replacement patch for a single finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    if finding.ai_fix and isinstance(finding.ai_fix, dict) and "fixed_code" in finding.ai_fix:
        return {"status": "cached", "fix": finding.ai_fix}

    finding_dict = {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "severity": finding.severity,
        "file_path": finding.file_path,
        "code_snippet": finding.code_snippet,
        "message": finding.message
    }

    fix_result = await generate_code_repair(finding_dict)
    finding.ai_fix = fix_result
    flag_modified(finding, "ai_fix")
    db.commit()

    return {"status": "success", "fix": fix_result}


@app.post("/api/scans/{scan_id}/remediate-all")
async def remediate_all_findings(scan_id: int, db: Session = Depends(get_db)):
    """Applies concurrent AI automated remediation across all findings in the project."""
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found for this scan.")

    semaphore = asyncio.Semaphore(5)
    unpatched = [f for f in findings if not (f.ai_fix and isinstance(f.ai_fix, dict) and "fixed_code" in f.ai_fix)]

    async def patch_worker(f):
        async with semaphore:
            finding_dict = {
                "id": f.id,
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "severity": f.severity,
                "file_path": f.file_path,
                "code_snippet": f.code_snippet,
                "message": f.message
            }
            fix = await generate_code_repair(finding_dict)
            f.ai_fix = fix
            flag_modified(f, "ai_fix")

    if unpatched:
        await asyncio.gather(*(patch_worker(f) for f in unpatched))
        db.commit()

    return {
        "status": "completed",
        "total_findings": len(findings),
        "newly_generated": len(unpatched)
    }


@app.get("/api/scans/{scan_id}/report")
def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    """Returns the full Security Remediation Audit Report text for online viewing."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    report_md = generate_markdown_report(scan, findings)
    return {"report_markdown": report_md}


@app.get("/api/scans/{scan_id}/download-report")
def download_scan_report_file(scan_id: int, db: Session = Depends(get_db)):
    """Downloads the Security Remediation Audit Report as a Markdown (.md) document."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    report_md = generate_markdown_report(scan, findings)

    filename = f"PEGASUS_Security_Report_Scan_{scan_id}.md"
    return PlainTextResponse(
        content=report_md,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/scans/{scan_id}/download-fixed-code")
async def download_fixed_project_zip(scan_id: int, db: Session = Depends(get_db)):
    """Applies all generated secure patches and downloads the cleaned repository as a .zip file."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Automatically patch any remaining unpatched findings in parallel before packaging
    semaphore = asyncio.Semaphore(5)
    unpatched = [f for f in findings if not (f.ai_fix and isinstance(f.ai_fix, dict) and "fixed_code" in f.ai_fix)]

    async def pre_patch_worker(f):
        async with semaphore:
            f.ai_fix = await generate_code_repair({
                "id": f.id,
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "severity": f.severity,
                "file_path": f.file_path,
                "code_snippet": f.code_snippet,
                "message": f.message
            })
            flag_modified(f, "ai_fix")

    if unpatched:
        await asyncio.gather(*(pre_patch_worker(f) for f in unpatched))
        db.commit()

    base_storage = os.path.join(tempfile.gettempdir(), "pegasus_scans")
    os.makedirs(base_storage, exist_ok=True)

    scan_dir = os.path.join(base_storage, f"scan_{scan.id}")
    backup_dir = os.path.join(base_storage, f"source_{scan.id}")

    # Restore source files from backup if scan workspace was cleaned
    if not os.path.exists(scan_dir) and os.path.exists(backup_dir):
        shutil.copytree(backup_dir, scan_dir)
    elif not os.path.exists(scan_dir):
        os.makedirs(scan_dir, exist_ok=True)
        for f in findings:
            f_path = os.path.join(scan_dir, f.file_path)
            os.makedirs(os.path.dirname(f_path), exist_ok=True)
            if not os.path.exists(f_path):
                with open(f_path, "w", encoding="utf-8") as out:
                    out.write(f.code_snippet or "")

    zip_file = apply_patches_and_build_zip(scan.id, findings, base_storage)
    if not os.path.exists(zip_file):
        raise HTTPException(status_code=500, detail="Failed to build patched zip archive.")

    return FileResponse(
        path=zip_file,
        filename=f"PEGASUS_Patched_Project_{scan_id}.zip",
        media_type="application/zip"
    )