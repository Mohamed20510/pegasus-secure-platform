from datetime import datetime, timezone
from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from .database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    status = Column(String(50), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    risk_score = Column(Float, default=100.0)
    grade = Column(String(2), default="A")
    summary = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    engine_type = Column(String(50))  # SAST, FORENSICS_SECRET, FORENSICS_ANOMALY
    category = Column(String(50), default="SYSTEM")  # WEB, MALWARE, SYSTEM, SECRET, OTHER
    rule_id = Column(String(255))
    severity = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path = Column(String(1000))
    line_number = Column(Integer, default=1)
    code_snippet = Column(Text, default="")
    message = Column(Text)
    cwe = Column(String(150), default="CWE-Other")
    educational_guide = Column(JSON, default=dict)
    ai_fix = Column(JSON, default=dict)  # Stores generated secure code patches

    scan = relationship("Scan", back_populates="findings")