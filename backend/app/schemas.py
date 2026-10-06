from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class FindingOut(BaseModel):
    id: int
    scan_id: Optional[int] = None
    engine_type: str
    category: str = "SYSTEM"  # WEB, MALWARE, SYSTEM, SECRET, OTHER
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str = ""
    message: str
    cwe: str = "CWE-Other"
    educational_guide: Dict[str, Any] = {}
    ai_fix: Optional[Dict[str, Any]] = {}  # Stores generated secure code patches

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    project_id: int
    status: str
    risk_score: float
    grade: str
    summary: Dict[str, Any] = {}
    created_at: datetime
    findings: List[FindingOut] = []

    class Config:
        from_attributes = True


class ProjectOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    scans: List[ScanOut] = []

    class Config:
        from_attributes = True