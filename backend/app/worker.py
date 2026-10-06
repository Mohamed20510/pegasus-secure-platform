import asyncio
import os
import shutil
import traceback
from typing import Any, Dict, List
from celery import Celery

from .database import SessionLocal
from .models import Scan, Finding
from .engines.sast import run_sast_scan
from .engines.forensics import analyze_directory_forensics
from .engines.scorer import calculate_security_score
from .engines.ai_tutor import generate_educational_guidance

# ---------------------------------------------------------
# Celery Configuration
# ---------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("ssp_worker", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.broker_connection_retry_on_startup = True
celery_app.conf.task_track_started = True


# ---------------------------------------------------------
# Asynchronous Educational Enrichment Helper
# ---------------------------------------------------------
async def enrich_findings_with_ai(findings: List[Dict[str, Any]], max_concurrent: int = 5) -> List[Dict[str, Any]]:
    """
    Enriches findings with educational guides with safe timeouts.
    Deep AI explanations are prioritized for the top findings, while remainder
    findings use instant local reference material to ensure quick completion.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    # Prioritize findings by severity: CRITICAL -> HIGH -> MEDIUM -> LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "LOW"), 3))

    async def fetch_guide(item: Dict[str, Any], index: int):
        # Generate deep AI analysis for top 25 findings; fallback for remainder
        if index < 25:
            async with semaphore:
                try:
                    guide = await asyncio.wait_for(generate_educational_guidance(item), timeout=3.5)
                except Exception:
                    guide = {
                        "title": item.get("rule_id", "Security Issue"),
                        "explanation": item.get("message", "Potential security weakness detected in source file."),
                        "risk": "Flaws in this category could allow unauthorized operations or data exposure.",
                        "remediation": "Audit the flagged line, validate untrusted inputs, and apply defensive coding practices.",
                        "reference": f"https://cwe.mitre.org/data/definitions/{str(item.get('cwe', 'Other')).replace('CWE-', '')}.html"
                    }
        else:
            guide = {
                "title": item.get("rule_id", "Security Issue"),
                "explanation": item.get("message", "Code pattern matches known vulnerability patterns."),
                "risk": "Potential security or quality issue.",
                "remediation": "Apply safe coding conventions and defense-in-depth measures.",
                "reference": "https://owasp.org/"
            }

        return {**item, "educational_guide": guide}

    tasks = [fetch_guide(item, idx) for idx, item in enumerate(sorted_findings)]
    enriched_results = await asyncio.gather(*tasks, return_exceptions=False)
    return enriched_results


# ---------------------------------------------------------
# Target Directory Normalizer (Handles Nested Zip Roots)
# ---------------------------------------------------------
def get_effective_code_root(base_dir: str) -> str:
    """
    If a zip file contains a single top-level folder (e.g. DVWA-master/),
    points the scan directly to that folder to guarantee full file traversal.
    """
    if not os.path.exists(base_dir):
        return base_dir

    entries = [os.path.join(base_dir, e) for e in os.listdir(base_dir) if not e.startswith("__MACOSX")]
    if len(entries) == 1 and os.path.isdir(entries[0]):
        return entries[0]
    return base_dir


# ---------------------------------------------------------
# Main Scan Execution Task
# ---------------------------------------------------------
@celery_app.task
def execute_scan_task(scan_id: int, target_dir: str):
    """
    Executes automated SAST & Forensics review and persists findings.
    Compatible with both Celery (.delay) and FastAPI native BackgroundTasks.
    """
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        print(f"[Worker Error] Scan ID {scan_id} not found in database.")
        db.close()
        return

    scan.status = "RUNNING"
    db.commit()

    loop = None
    try:
        # Determine actual code directory (handles nested folders like DVWA-master/)
        code_root = get_effective_code_root(target_dir)

        # 1. Run Automated SAST Code Review (Semgrep + Multi-language Heuristics)
        sast_findings = run_sast_scan(code_root)

        # 2. Run Digital Forensics & Secret Detection
        forensic_findings = analyze_directory_forensics(code_root)

        all_findings = sast_findings + forensic_findings

        # 3. Calculate Security Posture Score, Letter Grade, and Remediation Debt
        score, grade, summary = calculate_security_score(all_findings)
        scan.risk_score = score
        scan.grade = grade
        scan.summary = summary

        # 4. Asynchronously generate AI Educational Guidance
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        enriched_findings = loop.run_until_complete(enrich_findings_with_ai(all_findings))

        # 5. Persist Findings to Database (includes category mapping)
        db_records = [
            Finding(
                scan_id=scan.id,
                engine_type=str(item.get("engine_type", "SAST"))[:50],
                category=str(item.get("category", "SYSTEM"))[:50],
                rule_id=str(item.get("rule_id", "audit-finding"))[:240],
                severity=str(item.get("severity", "MEDIUM"))[:20],
                file_path=str(item.get("file_path", "unknown"))[:950],
                line_number=int(item.get("line_number", 1)),
                code_snippet=str(item.get("code_snippet", ""))[:500],
                message=str(item.get("message", "")),
                cwe=str(item.get("cwe", "CWE-Other"))[:140],
                educational_guide=item.get("educational_guide", {})
            )
            for item in enriched_findings
        ]

        if db_records:
            db.add_all(db_records)

        scan.status = "COMPLETED"
        db.commit()
        print(f"[Scan {scan_id} Success] Completed with {len(db_records)} findings. Grade: {grade}, Score: {score}")

    except Exception as e:
        db.rollback()
        error_trace = traceback.format_exc()
        print(f"[Scan {scan_id} Error]:\n{error_trace}")
        scan.status = "FAILED"
        scan.summary = {"error": str(e)}
        db.commit()

    finally:
        if loop and not loop.is_closed():
            loop.close()
        db.close()

        # Clean up temporary extracted folder
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)