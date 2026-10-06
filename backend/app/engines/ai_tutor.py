import os
import re
import json
import httpx
from typing import Any, Dict

FALLBACK_KNOWLEDGE_BASE = {
    "CWE-134": {
        "title": "Use of Externally-Controlled Format String",
        "explanation": "Untrusted user input is passed directly as the format string argument in printf/sprintf/snprintf functions without a static format specifier.",
        "risk": "Attackers can read arbitrary memory addresses off the stack (leaking passwords or keys via %s/%p) or write to memory (%n) to achieve remote code execution.",
        "remediation": "Never pass dynamic variables as the format parameter. Always use hardcoded format literals, for example: snprintf(buffer, sizeof(buffer), \"%s\", user_input);",
        "reference": "https://cwe.mitre.org/data/definitions/134.html"
    },
    "CWE-89": {
        "title": "SQL Injection (SQLi)",
        "explanation": "Untrusted user inputs are concatenated directly into database queries, allowing attackers to manipulate query logic and execute arbitrary database commands.",
        "risk": "Attackers can bypass authentication, steal credentials, read sensitive database tables, or drop entire databases.",
        "remediation": "Always use parameterized queries, prepared statements, or an Object-Relational Mapper (ORM) instead of raw string concatenation.",
        "reference": "https://cwe.mitre.org/data/definitions/89.html"
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "explanation": "Unvalidated user input is passed directly to system shell execution functions (such as system, exec, or subprocess with shell=True).",
        "risk": "Allows attackers to execute arbitrary system commands, spawn reverse shells, download malware, or seize complete control of the host server.",
        "remediation": "Avoid shell invocation APIs. Pass command arguments as discrete lists with shell=False, and validate all inputs against strict allowlists.",
        "reference": "https://cwe.mitre.org/data/definitions/78.html"
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "explanation": "Untrusted user input is echoed directly into the HTML response or DOM without contextual entity escaping or sanitization.",
        "risk": "Attackers can hijack user sessions, steal sensitive session tokens and cookies, or redirect victims to phishing sites.",
        "remediation": "Contextually encode all dynamic data before outputting to HTML (e.g. using htmlspecialchars in PHP or safe innerText assignments in JavaScript).",
        "reference": "https://cwe.mitre.org/data/definitions/79.html"
    },
    "CWE-98": {
        "title": "Improper Control of Filename for Include/Require (LFI/RFI)",
        "explanation": "File inclusion paths are constructed directly from dynamic user parameters without strict validation or allowlisting.",
        "risk": "Attackers can supply path traversal sequences (../) to read sensitive system files (like /etc/passwd) or execute remote code.",
        "remediation": "Never construct file paths directly from user input. Validate requested pages against a strict hardcoded allowlist.",
        "reference": "https://cwe.mitre.org/data/definitions/98.html"
    },
    "CWE-798": {
        "title": "Use of Hard-coded Credentials",
        "explanation": "Sensitive security tokens, passwords, API keys, or private certificates are committed in plaintext directly inside the source code repository.",
        "risk": "Anyone with read access to the repository or binary can extract the secret and compromise external cloud infrastructure or database accounts.",
        "remediation": "Store all secrets in environment variables or cloud secret managers (e.g. AWS Secrets Manager, HashiCorp Vault) and add secret files to .gitignore.",
        "reference": "https://cwe.mitre.org/data/definitions/798.html"
    },
    "CWE-838": {
        "title": "Inappropriate Encoding - Trojan Source",
        "explanation": "Invisible Unicode directional formatting characters (BiDi) alter the visual display order of tokens in code editors while compilers interpret them differently.",
        "risk": "Adversaries can craft code that visually looks like a harmless comment or function but actually executes malicious backdoor logic.",
        "remediation": "Strip all bidirectional control characters from source code and configure CI linters to reject non-ASCII control characters.",
        "reference": "https://cwe.mitre.org/data/definitions/838.html"
    },
    "CWE-502": {
        "title": "Deserialization of Untrusted Data",
        "explanation": "Unvalidated serialized byte streams (like Python pickle or PHP unserialize) are loaded directly from untrusted client sources.",
        "risk": "Attackers can construct malicious serialized object payloads that execute arbitrary operating system commands during deserialization.",
        "remediation": "Avoid using dangerous native serialization libraries for client data. Use safe, language-neutral formats like JSON or Protocol Buffers.",
        "reference": "https://cwe.mitre.org/data/definitions/502.html"
    },
    "CWE-120": {
        "title": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "explanation": "Data is copied into a fixed-size memory buffer without checking whether the input size exceeds the destination capacity.",
        "risk": "Can cause memory corruption, segmentation faults (Denial of Service), or arbitrary shellcode execution via instruction pointer overwrite.",
        "remediation": "Replace unbounded legacy functions (gets, strcpy, strcat, sprintf) with bounded alternatives (fgets, strncpy, snprintf).",
        "reference": "https://cwe.mitre.org/data/definitions/120.html"
    },
    "CWE-345": {
        "title": "Insufficient Verification of Data Authenticity (JWT 'none' Algorithm)",
        "explanation": "Cryptographic tokens (JWTs) are accepted with the signature algorithm set to 'none', bypassing cryptographic signature verification.",
        "risk": "Attackers can modify token claims (such as user ID or admin role) and bypass application authentication entirely.",
        "remediation": "Explicitly configure the token verifier to reject unsigned tokens and only permit secure algorithms (e.g. ['HS256', 'RS256']).",
        "reference": "https://cwe.mitre.org/data/definitions/345.html"
    }
}


def _extract_json(text: str) -> Dict[str, Any]:
    """Safely extracts JSON from an LLM response even if wrapped in markdown quotes."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
    return None


async def generate_educational_guidance(finding: Dict[str, Any]) -> Dict[str, Any]:
    cwe = finding.get("cwe", "CWE-General")
    rule_id = finding.get("rule_id", "Security Issue")
    snippet = finding.get("code_snippet", "")
    message = finding.get("message", "")

    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()

    prompt = (
        "You are an elite cybersecurity educator and secure coding mentor.\n"
        "Explain this detected vulnerability clearly to a junior developer or student.\n"
        f"Rule ID: {rule_id}\n"
        f"CWE: {cwe}\n"
        f"Message: {message}\n\n"
        "--- VULNERABLE CODE SNIPPET ---\n"
        f"{snippet}\n"
        "--- END SNIPPET ---\n\n"
        "Respond ONLY with a valid JSON object matching this schema:\n"
        "{\n"
        '  "title": "Clear beginner-friendly vulnerability title",\n'
        '  "explanation": "What went wrong in simple, intuitive technical terms (2 sentences)",\n'
        '  "risk": "Why is this dangerous in production? What could an attacker achieve? (2 sentences)",\n'
        '  "remediation": "Clear step-by-step code guidance on how to patch it",\n'
        f'  "reference": "https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-", "")}.html"\n'
        "}"
    )

    # 1. Query Groq Cloud (Ultra-Fast 70B Model)
    if groq_key and groq_key != "mock-key":
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"}
                    }
                )
                if res.status_code == 200:
                    parsed = _extract_json(res.json()["choices"][0]["message"]["content"])
                    if parsed and "explanation" in parsed:
                        return parsed
        except Exception:
            pass

    # 2. Query OpenAI (Fallback)
    if openai_key and openai_key != "mock-key":
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"}
                    }
                )
                if res.status_code == 200:
                    parsed = _extract_json(res.json()["choices"][0]["message"]["content"])
                    if parsed and "explanation" in parsed:
                        return parsed
        except Exception:
            pass

    # 3. Built-in Offline Fallback
    cwe_clean = cwe if cwe in FALLBACK_KNOWLEDGE_BASE else "CWE-89"
    return FALLBACK_KNOWLEDGE_BASE.get(cwe_clean, {
        "title": f"Security Weakness ({rule_id})",
        "explanation": message or "A potential code quality or cybersecurity flaw was identified.",
        "risk": "Flaws in this category allow attackers to compromise application integrity or data privacy.",
        "remediation": "Audit the flagged line, validate untrusted inputs, and follow OWASP best practices.",
        "reference": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if "CWE-" in cwe else "https://owasp.org/"
    })