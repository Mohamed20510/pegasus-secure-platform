import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Set

# Directories and files ignored to prevent scanning build artifacts and third-party bloat
EXCLUDED_DIRS: Set[str] = {
    "node_modules", "vendor", ".git", "dist", "build", ".next",
    "venv", ".venv", "__pycache__", "coverage", "assets", "public"
}

EXCLUDED_EXTS: Set[str] = {
    ".min.js", ".min.css", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".zip", ".tar.gz", ".o", ".exe"
}

EXCLUDED_CLI_FLAGS = [
    "--exclude=node_modules",
    "--exclude=vendor",
    "--exclude=.git",
    "--exclude=dist",
    "--exclude=build",
    "--exclude=.next",
    "--exclude=venv",
    "--exclude=.venv",
    "--exclude=*.min.js",
    "--exclude=*.min.css",
]

# Comprehensive multi-language vulnerability signatures categorized by threat domain
HEURISTIC_RULES = [
    # =========================================================================
    # 1. WEB APPLICATION VULNERABILITIES (category: "WEB")
    # =========================================================================
    {
        "id": "dvwa-php-sqli-interpolated-query",
        "category": "WEB",
        "extensions": {".php", ".inc"},
        # Matches: $query = "SELECT ... $id" or $sql = 'SELECT ... ' . $var
        "regex": r'(?is)\$[a-zA-Z0-9_]*\s*=\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"\';]*(?:\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*|\.\s*\$)',
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "message": "SQL Injection (CWE-89): Dynamic SQL statement constructed with unescaped variable concatenation.",
    },
    {
        "id": "php-mysqli-unparameterized",
        "category": "WEB",
        "extensions": {".php", ".inc"},
        # Matches: mysqli_query($conn, $query) or mysqli_query($GLOBALS["..."], $query)
        "regex": r'(?is)(?:mysqli_query|mysql_query|pg_query)\s*\([^,]+,\s*\$[a-zA-Z0-9_]+',
        "cwe": "CWE-89",
        "severity": "HIGH",
        "message": "Unparameterized SQL Execution (CWE-89): Query dispatched without prepared statements.",
    },
    {
        "id": "juice-shop-sequelize-sqli",
        "category": "WEB",
        "extensions": {".ts", ".js"},
        # Matches Juice Shop search.ts: sequelize.query(`SELECT ... ${criteria}`)
        "regex": r'(?is)(?:sequelize|db|connection|models)\.query\s*\(\s*`[^`]*(?:SELECT|WHERE|AND|OR)[^`]*\$\{.+?\}[^`]*`',
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "message": "SQL Injection (CWE-89): Template literal interpolated into Sequelize query (Juice Shop search pattern).",
    },
    {
        "id": "node-sqlite-concatenation",
        "category": "WEB",
        "extensions": {".ts", ".js"},
        "regex": r'(?is)(?:query|execute|all|get)\s*\(\s*["\'][^"\']*(?:SELECT|UPDATE|INSERT|WHERE)[^"\']*["\']\s*\+\s*[a-zA-Z0-9_.]+',
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "message": "SQL Injection (CWE-89): Query string constructed using dynamic string concatenation.",
    },
    {
        "id": "python-sqli-format",
        "category": "WEB",
        "extensions": {".py"},
        "regex": r'(?is)cursor\.execute\s*\(\s*(?:f["\'].*?(?:WHERE|SELECT|INSERT|UPDATE)|["\'].*?(?:WHERE|SELECT|INSERT).*?%\s*\(|.*?\.(?:format|%)\()',
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "message": "SQL Injection (CWE-89): Python database cursor executed with formatted string interpolation.",
    },
    {
        "id": "java-sqli-executequery",
        "category": "WEB",
        "extensions": {".java"},
        "regex": r'(?is)(?:executeQuery|executeUpdate|execute)\s*\(\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+',
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "message": "SQL Injection (CWE-89): Dynamic SQL string concatenation in Java JDBC execution.",
    },
    {
        "id": "dvwa-php-reflected-xss",
        "category": "WEB",
        "extensions": {".php", ".inc"},
        # Matches: echo '<pre>Hello ' . $_GET['name'] or print $_POST[...]
        "regex": r'(?is)(?:echo|print)\s+(?:["\'][^"\']*["\']\s*\.\s*)?\$_(?:GET|POST|REQUEST)\s*\[',
        "cwe": "CWE-79",
        "severity": "HIGH",
        "message": "Reflected Cross-Site Scripting (CWE-79): HTTP request variable directly output to HTML.",
    },
    {
        "id": "juice-shop-dom-xss",
        "category": "WEB",
        "extensions": {".ts", ".js", ".html"},
        # Matches: bypassSecurityTrustHtml, innerHTML, dangerouslySetInnerHTML
        "regex": r'(?is)(?:bypassSecurityTrustHtml|innerHTML|dangerouslySetInnerHTML)\s*\(?\s*=?\s*[^;,\n]+',
        "cwe": "CWE-79",
        "severity": "HIGH",
        "message": "Cross-Site Scripting (CWE-79): Angular DOM security trust bypass or raw innerHTML assignment.",
    },
    {
        "id": "dvwa-php-lfi",
        "category": "WEB",
        "extensions": {".php", ".inc"},
        # Matches: include($file); or include $file; or require($_GET['page'])
        "regex": r'(?is)(?:include|require|include_once|require_once)\s*(?:\(\s*|\s+)(?:\$_|\$[a-zA-Z0-9_]+)',
        "cwe": "CWE-98",
        "severity": "CRITICAL",
        "message": "File Inclusion (CWE-98): Dynamic file inclusion path without strict validation (DVWA fi pattern).",
    },
    {
        "id": "node-path-traversal",
        "category": "WEB",
        "extensions": {".ts", ".js"},
        "regex": r'(?is)fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:req\.|[a-zA-Z0-9_]+\s*\+)',
        "cwe": "CWE-22",
        "severity": "HIGH",
        "message": "Path Traversal (CWE-22): Filesystem read invoked using user-controlled parameters.",
    },
    {
        "id": "jwt-algorithm-none",
        "category": "WEB",
        "extensions": {".ts", ".js", ".py", ".php"},
        "regex": r'(?is)["\']?algorithms?["\']?\s*:\s*\[?[^\]]*["\']none["\']',
        "cwe": "CWE-345",
        "severity": "CRITICAL",
        "message": "Broken Authentication (CWE-345): JWT configured with algorithm 'none', allowing signature bypass.",
    },

    # =========================================================================
    # 2. SYSTEM & MEMORY FLAWS (category: "SYSTEM")
    # =========================================================================
    {
        "id": "c-format-string-snprintf",
        "category": "SYSTEM",
        "extensions": {".c", ".cpp", ".cc", ".h"},
        # Matches snprintf(dest, size, dynamic_variable, ...) where format arg is not a string literal (e.g. server.c)
        "regex": r'(?is)\bsnprintf\s*\(\s*[^,]+,\s*[^,]+,\s*(?!\s*["\'])\s*[a-zA-Z0-9_]+',
        "cwe": "CWE-134",
        "severity": "CRITICAL",
        "message": "Format String Vulnerability (CWE-134): Non-literal format string passed to snprintf(). Allows arbitrary memory read/write.",
    },
    {
        "id": "c-format-string-printf",
        "category": "SYSTEM",
        "extensions": {".c", ".cpp", ".cc", ".h"},
        # Matches printf(variable) or sprintf(buf, variable) without literal format
        "regex": r'(?is)\b(?:printf|vprintf)\s*\(\s*(?!\s*["\'])\s*[a-zA-Z0-9_]+|\b(?:sprintf|fprintf|dprintf)\s*\(\s*[^,]+,\s*(?!\s*["\'])\s*[a-zA-Z0-9_]+',
        "cwe": "CWE-134",
        "severity": "CRITICAL",
        "message": "Format String Vulnerability (CWE-134): Externally controlled format string in printf/sprintf. Use format specifier like '%s'.",
    },
    {
        "id": "c-insecure-gets-strcpy",
        "category": "SYSTEM",
        "extensions": {".c", ".cpp", ".cc", ".h"},
        "regex": r'(?is)\b(?:gets|strcpy|strcat)\s*\(',
        "cwe": "CWE-120",
        "severity": "HIGH",
        "message": "Buffer Overflow Risk (CWE-120): Legacy unbounded memory function. Replace with safer alternatives (fgets, strncpy, strlcpy).",
    },
    {
        "id": "dvwa-php-command-injection",
        "category": "SYSTEM",
        "extensions": {".php", ".inc"},
        # Matches: shell_exec( 'ping ' . $target ) or exec($cmd)
        "regex": r'(?is)(?:shell_exec|exec|system|passthru|popen)\s*\(\s*[^)]*\$[a-zA-Z0-9_]+[^)]*\)',
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "message": "OS Command Injection (CWE-78): Shell command executed with dynamic variable argument (DVWA ping pattern).",
    },
    {
        "id": "node-child-process-command-injection",
        "category": "SYSTEM",
        "extensions": {".ts", ".js"},
        "regex": r'(?is)(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\']\s*\+)',
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "message": "Command Injection (CWE-78): child_process execution using dynamic string input.",
    },
    {
        "id": "python-subprocess-shell-true",
        "category": "SYSTEM",
        "extensions": {".py"},
        "regex": r'(?is)(?:subprocess\.(?:check_output|Popen|run|call)|os\.system)\s*\(.*?shell\s*=\s*True',
        "cwe": "CWE-78",
        "severity": "HIGH",
        "message": "Command Injection (CWE-78): Subprocess spawned with shell=True and dynamic arguments.",
    },
    {
        "id": "java-runtime-exec-injection",
        "category": "SYSTEM",
        "extensions": {".java"},
        "regex": r'(?is)Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\']\s*\+|[a-zA-Z0-9_]+\s*\+)',
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "message": "Command Injection (CWE-78): Runtime.getRuntime().exec() with dynamic command string.",
    },
    {
        "id": "weak-md5-sha1-hash",
        "category": "SYSTEM",
        "extensions": {".php", ".ts", ".js", ".py", ".c", ".cpp"},
        "regex": r'(?is)(?:md5|sha1)\s*\(\s*(?:\$[a-zA-Z0-9_]*pass|\w*password)',
        "cwe": "CWE-328",
        "severity": "MEDIUM",
        "message": "Weak Cryptographic Hash (CWE-328): Obsolete MD5/SHA1 hashing used for password security.",
    },

    # =========================================================================
    # 3. MALWARE & BACKDOORS (category: "MALWARE")
    # =========================================================================
    {
        "id": "javascript-eval-rce",
        "category": "MALWARE",
        "extensions": {".ts", ".js"},
        "regex": r'(?is)(?:\beval\s*\(|new\s+Function\s*\(|vm\.runInContext\s*\()\s*[^"\'\s)]+',
        "cwe": "CWE-95",
        "severity": "CRITICAL",
        "message": "Arbitrary Code Execution (CWE-95): Dynamic code execution via eval() or vm sandbox bypass.",
    },
    {
        "id": "php-unserialize-object-injection",
        "category": "MALWARE",
        "extensions": {".php"},
        "regex": r'(?is)unserialize\s*\(\s*[^)]+\)',
        "cwe": "CWE-502",
        "severity": "HIGH",
        "message": "Insecure Deserialization (CWE-502): Arbitrary object deserialization via unserialize().",
    },
    {
        "id": "python-pickle-deserialization",
        "category": "MALWARE",
        "extensions": {".py"},
        "regex": r'(?is)pickle\.(?:loads|load)\s*\(',
        "cwe": "CWE-502",
        "severity": "HIGH",
        "message": "Insecure Deserialization (CWE-502): Unsafe pickle deserialization allows remote code execution.",
    }
]


def _categorize_cwe(cwe_str: str) -> str:
    """Helper to map CWE IDs from Semgrep to PEGASUS categories."""
    cwe = cwe_str.upper()
    if any(k in cwe for k in ["89", "79", "98", "22", "345", "434", "352"]):
        return "WEB"
    if any(k in cwe for k in ["95", "502", "506", "838"]):
        return "MALWARE"
    if any(k in cwe for k in ["798", "312"]):
        return "SECRET"
    return "SYSTEM"


def _run_native_heuristics(target_dir: str, seen_keys: Set[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(target_dir):
        # Exclude directories on the fly
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if any(file.endswith(ig) for ig in EXCLUDED_EXTS):
                continue

            matching_rules = [r for r in HEURISTIC_RULES if ext in r["extensions"]]
            if not matching_rules:
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, target_dir).replace("\\", "/")

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for rule in matching_rules:
                    for match in re.finditer(rule["regex"], content):
                        line_number = content[:match.start()].count("\n") + 1
                        snippet = match.group(0).strip()[:180]
                        dedup_key = f"{rel_path}:{line_number}:{rule['id']}"

                        if dedup_key not in seen_keys:
                            seen_keys.add(dedup_key)
                            findings.append({
                                "engine_type": "SAST",
                                "category": rule.get("category", "WEB"),
                                "rule_id": rule["id"],
                                "severity": rule["severity"],
                                "file_path": rel_path,
                                "line_number": line_number,
                                "code_snippet": snippet,
                                "message": rule["message"],
                                "cwe": rule["cwe"],
                            })
            except Exception:
                continue

    return findings


def run_sast_scan(target_dir: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()

    # 1. Run Semgrep if CLI binary is installed
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin:
        cmd = [
            semgrep_bin,
            "scan",
            "--config=auto",
            "--metrics=off",
            "--disable-version-check",
            "--json",
            "--quiet",
            *EXCLUDED_CLI_FLAGS,
            target_dir,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = proc.stdout.strip()
            if output:
                data = json.loads(output)
                sev_map = {
                    "ERROR": "HIGH",
                    "WARNING": "MEDIUM",
                    "INFO": "LOW",
                    "EXPERIMENT": "LOW",
                }

                for res in data.get("results", []):
                    raw_path = res.get("path", "")
                    rel_path = os.path.relpath(raw_path, target_dir) if raw_path.startswith(target_dir) else raw_path
                    rel_path = rel_path.replace("\\", "/")
                    line_no = res.get("start", {}).get("line", 1)
                    rule_id = res.get("check_id", "sast-rule")

                    dedup_key = f"{rel_path}:{line_no}:{rule_id}"
                    if dedup_key in seen_keys:
                        continue

                    seen_keys.add(dedup_key)

                    raw_sev = res.get("extra", {}).get("severity", "WARNING")
                    mapped_sev = sev_map.get(raw_sev, "MEDIUM")

                    metadata = res.get("extra", {}).get("metadata", {})
                    cwe_list = metadata.get("cwe", [])
                    cwe_tag = cwe_list[0] if cwe_list else "CWE-General"

                    findings.append({
                        "engine_type": "SAST",
                        "category": _categorize_cwe(cwe_tag),
                        "rule_id": rule_id,
                        "severity": mapped_sev,
                        "file_path": rel_path,
                        "line_number": line_no,
                        "code_snippet": res.get("extra", {}).get("lines", "")[:180],
                        "message": res.get("extra", {}).get("message", "Security issue detected."),
                        "cwe": cwe_tag,
                    })
        except subprocess.TimeoutExpired:
            print("[SAST Notice] Semgrep timed out; using native heuristic rules.")
        except Exception as err:
            print(f"[SAST Notice] Semgrep halted ({err}); using native heuristic rules.")

    # 2. Run built-in heuristic pattern matcher
    native_findings = _run_native_heuristics(target_dir, seen_keys)
    findings.extend(native_findings)

    return findings