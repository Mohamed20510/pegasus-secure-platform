from typing import Any, Dict, List, Tuple


def calculate_security_score(findings: List[Dict[str, Any]]) -> Tuple[float, str, Dict[str, Any]]:
    """
    Computes a deterministic security posture score (0-100),
    letter grade (A-F), and categorical counts.
    """
    weights = {
        "CRITICAL": 25.0,
        "HIGH": 12.0,
        "MEDIUM": 5.0,
        "LOW": 1.5,
        "INFO": 0.5
    }

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_penalty = 0.0

    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
        total_penalty += weights.get(sev, 1.0)

    score = max(0.0, min(100.0, 100.0 - total_penalty))

    if score >= 90.0:
        grade = "A"
    elif score >= 80.0:
        grade = "B"
    elif score >= 70.0:
        grade = "C"
    elif score >= 60.0:
        grade = "D"
    else:
        grade = "F"

    summary = {
        "total_findings": len(findings),
        "breakdown": counts,
        "estimated_remediation_hours": round(
            counts["CRITICAL"] * 4.0 + counts["HIGH"] * 2.5 + counts["MEDIUM"] * 1.0 + counts["LOW"] * 0.5, 1
        )
    }

    return score, grade, summary