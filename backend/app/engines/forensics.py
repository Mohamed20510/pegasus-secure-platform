import math
import os
import re
from collections import Counter
from typing import Any, Dict, List
import git

# High-risk secret and credential patterns
SECRET_PATTERNS = [
    (r'(?i)aws_access_key_id\s*=\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "AWS Access Key", "CWE-798"),
    (r'(r?i)aws_secret_access_key\s*=\s*["\']?([0-9a-zA-Z/+]{40})["\']?', "AWS Secret Key", "CWE-798"),
    (r'(?i)(?:api_key|apikey|secret|token)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Generic API Secret", "CWE-798"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Exposed RSA Private Key", "CWE-312"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", "CWE-798"),
    # Flag and challenge secret detection (e.g., in server.c)
    (r'(?i)#define\s+(?:FLAG|SECRET|TOKEN|KEY)\s+["\']([^"\']+)["\']', "Hardcoded Secret / Flag", "CWE-798"),
    (r'(?i)(?:flag|ctf_flag|secret_token)\s*[:=]\s*["\']([a-zA-Z0-9_{}\-!]+)["\']', "Hardcoded Flag / Secret", "CWE-798"),
    (r'(?i)(?:password|passwd|db_pass)\s*=\s*["\']([^"\']{6,})["\']', "Hardcoded Plaintext Password", "CWE-259"),
]

# Unicode BiDi Trojan Source characters (CVE-2021-42574)
BIDI_CHARS = [
    '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
    '\u2066', '\u2067', '\u2068', '\u2069'
]

# File extensions to ignore for forensics analysis
SKIP_FORENSIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".tar.gz", ".pdf", ".exe", ".o", ".pyc"
}


def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to quantify randomness/information density."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def analyze_directory_forensics(target_dir: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1. Content Forensics: Secrets, Obfuscated Payloads & Trojan Source
    for root, dirs, files in os.walk(target_dir):
        if ".git" in root:
            continue

        # Skip third-party dependencies during forensics
        dirs[:] = [d for d in dirs if d not in {"node_modules", "vendor", "dist", "build", ".next", "venv", ".venv"}]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SKIP_FORENSIC_EXTS:
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_dir).replace("\\", "/")

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, 1):
                        clean_line = line.strip()
                        if not clean_line:
                            continue

                        # A. Detect Leaked Secrets / Keys
                        for regex, label, cwe in SECRET_PATTERNS:
                            if re.search(regex, line):
                                findings.append({
                                    "engine_type": "FORENSICS_SECRET",
                                    "category": "SECRET",
                                    "rule_id": f"forensic-secret-{label.lower().replace(' ', '-')}",
                                    "severity": "CRITICAL",
                                    "file_path": rel_path,
                                    "line_number": line_idx,
                                    "code_snippet": clean_line[:120],
                                    "message": f"Hardcoded Secret / Credential Leak: {label} committed in plaintext.",
                                    "cwe": cwe,
                                })

                        # B. Detect Trojan Source Characters
                        for bidi in BIDI_CHARS:
                            if bidi in line:
                                findings.append({
                                    "engine_type": "FORENSICS_ANOMALY",
                                    "category": "MALWARE",
                                    "rule_id": "forensic-trojan-source-bidi",
                                    "severity": "CRITICAL",
                                    "file_path": rel_path,
                                    "line_number": line_idx,
                                    "code_snippet": repr(clean_line)[:120],
                                    "message": "Trojan Source (CVE-2021-42574): Bidirectional Unicode override character disguised in source file.",
                                    "cwe": "CWE-838",
                                })

                        # C. Detect High Shannon Entropy (Packed / Obfuscated Shellcode & Blobs)
                        tokens = re.split(r'[\s",\';=]+', clean_line)
                        for token in tokens:
                            if len(token) > 45 and shannon_entropy(token) > 4.6:
                                findings.append({
                                    "engine_type": "FORENSICS_ANOMALY",
                                    "category": "MALWARE",
                                    "rule_id": "forensic-high-entropy-string",
                                    "severity": "HIGH",
                                    "file_path": rel_path,
                                    "line_number": line_idx,
                                    "code_snippet": token[:80] + "...",
                                    "message": f"Suspicious Obfuscation / Malware: High Shannon Entropy ({shannon_entropy(token):.2f}) indicates packed payload or encrypted backdoor data.",
                                    "cwe": "CWE-506",
                                })
                                break
            except Exception:
                continue

    # 2. Git History Forensics
    git_dir = os.path.join(target_dir, ".git")
    if os.path.exists(git_dir):
        try:
            repo = git.Repo(target_dir)
            for commit in repo.iter_commits(max_count=100):
                # Detect suspicious commit messages
                if re.search(r'(?i)(fix bug|temp|emergency|bypass|disable auth|backdoor)', commit.message):
                    findings.append({
                        "engine_type": "FORENSICS_GIT",
                        "category": "MALWARE",
                        "rule_id": "forensic-suspicious-commit",
                        "severity": "MEDIUM",
                        "file_path": f"Commit: {commit.hexsha[:7]}",
                        "line_number": 0,
                        "code_snippet": commit.message.strip()[:150],
                        "message": "Suspicious Commit Message: Forensic timeline flagged commit message suggesting bypass or emergency tampering.",
                        "cwe": "CWE-1200",
                    })
        except Exception:
            pass

    return findings