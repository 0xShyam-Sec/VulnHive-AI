"""
Report Engine — Professional HTML and JSON security report generation.

Generates three report types:
  1. Executive Summary (HTML) — one-page management overview with risk gauge and charts
  2. Technical Report (HTML) — detailed findings for security teams with PoC and remediation
  3. JSON Report — machine-readable for CI/CD pipeline integration

All HTML reports are fully self-contained (inline CSS, inline SVG) with no external
dependencies. Designed for client delivery in a commercial penetration testing product.

Usage:
    from report_engine import ReportEngine

    engine = ReportEngine(
        target="http://example.com",
        scan_time="2026-03-13 18:17:20",
        findings=[...],  # list of finding dicts
    )
    paths = engine.generate_all("./reports")
"""

import json
import math
import os
import hashlib
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse


# ── CWE / OWASP Mapping ─────────────────────────────────────────────

VULN_CLASSIFICATION = {
    "sqli": {
        "cwe": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "category": "SQL Injection",
    },
    "xss": {
        "cwe": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "category": "Cross-Site Scripting",
    },
    "command_injection": {
        "cwe": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "category": "Command Injection",
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
        "owasp": "A01:2021",
        "owasp_name": "Broken Access Control",
        "category": "Path Traversal",
    },
    "csrf": {
        "cwe": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery",
        "owasp": "A01:2021",
        "owasp_name": "Broken Access Control",
        "category": "Cross-Site Request Forgery",
    },
    "idor": {
        "cwe": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "owasp": "A01:2021",
        "owasp_name": "Broken Access Control",
        "category": "Insecure Direct Object Reference",
    },
    "open_redirect": {
        "cwe": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site",
        "owasp": "A01:2021",
        "owasp_name": "Broken Access Control",
        "category": "Open Redirect",
    },
    "ssrf": {
        "cwe": "CWE-918",
        "cwe_name": "Server-Side Request Forgery",
        "owasp": "A10:2021",
        "owasp_name": "Server-Side Request Forgery",
        "category": "Server-Side Request Forgery",
    },
    "security_headers": {
        "cwe": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "owasp": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "category": "Missing Security Headers",
    },
    "sensitive_data": {
        "cwe": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "category": "Sensitive Data Exposure",
    },
    "file_upload": {
        "cwe": "CWE-434",
        "cwe_name": "Unrestricted Upload of File with Dangerous Type",
        "owasp": "A04:2021",
        "owasp_name": "Insecure Design",
        "category": "Unrestricted File Upload",
    },
    "cors": {
        "cwe": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "owasp": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "category": "CORS Misconfiguration",
    },
}

# Normalized vuln_type strings from scanner → classification key
_VULN_TYPE_ALIASES = {
    "sql injection": "sqli",
    "sql injection (error-based)": "sqli",
    "sql injection (blind boolean-based)": "sqli",
    "sql injection (union-based)": "sqli",
    "cross-site scripting": "xss",
    "cross-site scripting (reflected xss)": "xss",
    "cross-site scripting (stored xss)": "xss",
    "cross-site scripting (dom-based)": "xss",
    "cross-site scripting (potential)": "xss",
    "dom xss": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "path traversal": "path_traversal",
    "path traversal / local file inclusion": "path_traversal",
    "local file inclusion": "path_traversal",
    "lfi": "path_traversal",
    "cross-site request forgery": "csrf",
    "cross-site request forgery (csrf)": "csrf",
    "csrf": "csrf",
    "insecure direct object reference": "idor",
    "insecure direct object reference (idor)": "idor",
    "idor": "idor",
    "open redirect": "open_redirect",
    "open redirect (via page content)": "open_redirect",
    "server-side request forgery": "ssrf",
    "server-side request forgery (ssrf)": "ssrf",
    "ssrf": "ssrf",
    "missing security headers": "security_headers",
    "security headers": "security_headers",
    "sensitive data exposure": "sensitive_data",
    "sensitive data": "sensitive_data",
    "information disclosure": "sensitive_data",
    "unrestricted file upload": "file_upload",
    "file upload": "file_upload",
    "cors misconfiguration": "cors",
    "cors": "cors",
}


# ── Remediation Code Examples ────────────────────────────────────────

REMEDIATION = {
    "sqli": {
        "description": (
            "Use parameterized queries (prepared statements) for all database interactions. "
            "Never concatenate user input into SQL strings. Apply input validation as a "
            "defense-in-depth measure, but do not rely on it as the primary protection."
        ),
        "examples": {
            "PHP (PDO)": (
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n'
                '$stmt->execute([\'id\' => $_GET[\'id\']]);\n'
                '$user = $stmt->fetch();'
            ),
            "Python (psycopg2)": (
                'cursor.execute(\n'
                '    "SELECT * FROM users WHERE id = %s",\n'
                '    (request.args.get("id"),)\n'
                ')'
            ),
            "Python (SQLAlchemy)": (
                'from sqlalchemy import text\n'
                'result = db.session.execute(\n'
                '    text("SELECT * FROM users WHERE id = :id"),\n'
                '    {"id": request.args.get("id")}\n'
                ')'
            ),
            "Node.js (mysql2)": (
                'const [rows] = await connection.execute(\n'
                '    "SELECT * FROM users WHERE id = ?",\n'
                '    [req.query.id]\n'
                ');'
            ),
            "Java (JDBC)": (
                'PreparedStatement stmt = conn.prepareStatement(\n'
                '    "SELECT * FROM users WHERE id = ?"\n'
                ');\n'
                'stmt.setInt(1, Integer.parseInt(request.getParameter("id")));\n'
                'ResultSet rs = stmt.executeQuery();'
            ),
        },
    },
    "xss": {
        "description": (
            "Encode all user-supplied data before rendering it in HTML context. Use "
            "context-aware output encoding (HTML entity encoding for HTML body, JavaScript "
            "encoding for script context, URL encoding for URL parameters). Implement a "
            "Content Security Policy (CSP) as defense-in-depth."
        ),
        "examples": {
            "PHP": (
                '// Always encode output\n'
                'echo htmlspecialchars($userInput, ENT_QUOTES, \'UTF-8\');\n\n'
                '// In attributes\n'
                '<input value="<?= htmlspecialchars($val, ENT_QUOTES, \'UTF-8\') ?>">'
            ),
            "Python (Jinja2 / Flask)": (
                '# Jinja2 auto-escapes by default in Flask\n'
                '{{ user_input }}  {# auto-escaped #}\n\n'
                '# For manual escaping:\n'
                'from markupsafe import escape\n'
                'safe_value = escape(user_input)'
            ),
            "React / JSX": (
                '// JSX auto-escapes by default\n'
                '<div>{userInput}</div>  // Safe — auto-escaped\n\n'
                '// NEVER use dangerouslySetInnerHTML with user input\n'
                '// If you must render HTML, use DOMPurify:\n'
                'import DOMPurify from "dompurify";\n'
                '<div dangerouslySetInnerHTML={{\n'
                '    __html: DOMPurify.sanitize(userInput)\n'
                '}} />'
            ),
            "Content-Security-Policy Header": (
                "Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; "
                "connect-src 'self'; frame-ancestors 'none'"
            ),
        },
    },
    "command_injection": {
        "description": (
            "Avoid calling OS commands with user-supplied input entirely. If system commands "
            "are necessary, use language-native libraries instead of shell execution. When "
            "shell execution is unavoidable, use parameterized command execution and strict "
            "input validation with allowlists."
        ),
        "examples": {
            "PHP": (
                '// Use escapeshellarg() for arguments\n'
                '$ip = escapeshellarg($_POST["ip"]);\n'
                '$output = shell_exec("ping -c 4 " . $ip);\n\n'
                '// Better: use native PHP functions\n'
                'if (filter_var($_POST["ip"], FILTER_VALIDATE_IP)) {\n'
                '    $output = shell_exec("ping -c 4 " . escapeshellarg($_POST["ip"]));\n'
                '}'
            ),
            "Python": (
                '# Use subprocess with list args (no shell=True)\n'
                'import subprocess\n'
                'result = subprocess.run(\n'
                '    ["ping", "-c", "4", user_input],\n'
                '    capture_output=True, text=True,\n'
                '    timeout=10\n'
                ')\n\n'
                '# NEVER do this:\n'
                '# os.system("ping -c 4 " + user_input)  # VULNERABLE'
            ),
            "Node.js": (
                '// Use execFile instead of exec (no shell interpolation)\n'
                'const { execFile } = require("child_process");\n'
                'execFile("ping", ["-c", "4", userInput], (err, stdout) => {\n'
                '    res.send(stdout);\n'
                '});\n\n'
                '// NEVER do this:\n'
                '// exec("ping -c 4 " + userInput);  // VULNERABLE'
            ),
        },
    },
    "path_traversal": {
        "description": (
            "Use allowlist-based validation for file paths. Resolve the canonical path and "
            "verify it falls within the expected directory. Never use user input directly in "
            "file system operations without validation."
        ),
        "examples": {
            "PHP": (
                '$base_dir = "/var/www/uploads/";\n'
                '$requested = realpath($base_dir . basename($_GET["file"]));\n\n'
                '// Verify the resolved path is within the base directory\n'
                'if ($requested && strpos($requested, $base_dir) === 0) {\n'
                '    readfile($requested);\n'
                '} else {\n'
                '    http_response_code(403);\n'
                '    die("Access denied");\n'
                '}'
            ),
            "Python": (
                'import os\n'
                'BASE_DIR = "/var/www/uploads"\n\n'
                'requested = os.path.realpath(\n'
                '    os.path.join(BASE_DIR, request.args.get("file", ""))\n'
                ')\n\n'
                'if not requested.startswith(BASE_DIR + os.sep):\n'
                '    abort(403)\n\n'
                'return send_file(requested)'
            ),
            "Node.js": (
                'const path = require("path");\n'
                'const BASE_DIR = "/var/www/uploads";\n\n'
                'const requested = path.resolve(\n'
                '    path.join(BASE_DIR, req.query.file)\n'
                ');\n\n'
                'if (!requested.startsWith(BASE_DIR + path.sep)) {\n'
                '    return res.status(403).send("Access denied");\n'
                '}\n'
                'res.sendFile(requested);'
            ),
        },
    },
    "csrf": {
        "description": (
            "Implement anti-CSRF tokens for all state-changing operations. Use the "
            "Synchronizer Token Pattern or the Double Submit Cookie pattern. Set SameSite "
            "cookie attribute to 'Strict' or 'Lax' as defense-in-depth."
        ),
        "examples": {
            "Django": (
                '<!-- In template -->\n'
                '<form method="POST">\n'
                '    {% csrf_token %}\n'
                '    <input type="text" name="username">\n'
                '    <button type="submit">Update</button>\n'
                '</form>\n\n'
                '# In settings.py — enabled by default\n'
                'MIDDLEWARE = [\n'
                '    "django.middleware.csrf.CsrfViewMiddleware",\n'
                '    ...\n'
                ']'
            ),
            "PHP (Manual Token)": (
                '// Generate token\n'
                'session_start();\n'
                'if (empty($_SESSION["csrf_token"])) {\n'
                '    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));\n'
                '}\n\n'
                '// In form\n'
                '<input type="hidden" name="csrf_token"\n'
                '       value="<?= $_SESSION[\'csrf_token\'] ?>">\n\n'
                '// Validate on submit\n'
                'if (!hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])) {\n'
                '    http_response_code(403);\n'
                '    die("CSRF validation failed");\n'
                '}'
            ),
            "Express.js (csurf)": (
                'const csrf = require("csurf");\n'
                'const csrfProtection = csrf({ cookie: true });\n\n'
                'app.get("/form", csrfProtection, (req, res) => {\n'
                '    res.render("form", { csrfToken: req.csrfToken() });\n'
                '});\n\n'
                'app.post("/submit", csrfProtection, (req, res) => {\n'
                '    // Token validated automatically\n'
                '    res.send("OK");\n'
                '});'
            ),
            "SameSite Cookie": (
                'Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly'
            ),
        },
    },
    "idor": {
        "description": (
            "Implement proper authorization checks on every request. Do not rely on "
            "object IDs being unguessable. Verify the authenticated user has permission "
            "to access the requested resource. Use indirect reference maps when possible."
        ),
        "examples": {
            "Python (Flask)": (
                '@app.route("/api/documents/<int:doc_id>")\n'
                '@login_required\n'
                'def get_document(doc_id):\n'
                '    doc = Document.query.get_or_404(doc_id)\n\n'
                '    # CRITICAL: verify ownership\n'
                '    if doc.owner_id != current_user.id:\n'
                '        abort(403)\n\n'
                '    return jsonify(doc.to_dict())'
            ),
            "Node.js (Express)": (
                'app.get("/api/orders/:id", authenticate, async (req, res) => {\n'
                '    const order = await Order.findById(req.params.id);\n'
                '    if (!order) return res.status(404).json({ error: "Not found" });\n\n'
                '    // Verify the order belongs to the requesting user\n'
                '    if (order.userId !== req.user.id) {\n'
                '        return res.status(403).json({ error: "Forbidden" });\n'
                '    }\n\n'
                '    res.json(order);\n'
                '});'
            ),
        },
    },
    "open_redirect": {
        "description": (
            "Validate redirect URLs against an allowlist of trusted domains. Use relative "
            "paths for internal redirects. Never pass user-controlled URLs directly to "
            "redirect functions without validation."
        ),
        "examples": {
            "Python (Flask)": (
                'from urllib.parse import urlparse\n\n'
                'ALLOWED_HOSTS = {"example.com", "www.example.com"}\n\n'
                '@app.route("/redirect")\n'
                'def safe_redirect():\n'
                '    url = request.args.get("url", "/")\n'
                '    parsed = urlparse(url)\n\n'
                '    # Only allow relative paths or trusted hosts\n'
                '    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n'
                '        abort(400, "Invalid redirect target")\n\n'
                '    return redirect(url)'
            ),
            "PHP": (
                '$allowed = ["example.com", "www.example.com"];\n'
                '$url = $_GET["redirect"] ?? "/";\n'
                '$parsed = parse_url($url);\n\n'
                'if (isset($parsed["host"]) && !in_array($parsed["host"], $allowed)) {\n'
                '    http_response_code(400);\n'
                '    die("Invalid redirect");\n'
                '}\n\n'
                'header("Location: " . $url);'
            ),
        },
    },
    "ssrf": {
        "description": (
            "Implement allowlist-based validation for all user-supplied URLs. Block requests "
            "to internal/private IP ranges. Use a dedicated HTTP client that does not follow "
            "redirects to internal addresses. Disable unnecessary URL schemes (file://, "
            "gopher://, dict://)."
        ),
        "examples": {
            "Python": (
                'import ipaddress\n'
                'from urllib.parse import urlparse\n\n'
                'BLOCKED_RANGES = [\n'
                '    ipaddress.ip_network("10.0.0.0/8"),\n'
                '    ipaddress.ip_network("172.16.0.0/12"),\n'
                '    ipaddress.ip_network("192.168.0.0/16"),\n'
                '    ipaddress.ip_network("127.0.0.0/8"),\n'
                '    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata\n'
                ']\n\n'
                'def is_safe_url(url: str) -> bool:\n'
                '    parsed = urlparse(url)\n'
                '    if parsed.scheme not in ("http", "https"):\n'
                '        return False\n'
                '    try:\n'
                '        ip = ipaddress.ip_address(parsed.hostname)\n'
                '        return not any(ip in net for net in BLOCKED_RANGES)\n'
                '    except ValueError:\n'
                '        # Hostname — resolve and check\n'
                '        import socket\n'
                '        resolved = socket.getaddrinfo(parsed.hostname, None)\n'
                '        for _, _, _, _, addr in resolved:\n'
                '            ip = ipaddress.ip_address(addr[0])\n'
                '            if any(ip in net for net in BLOCKED_RANGES):\n'
                '                return False\n'
                '        return True'
            ),
        },
    },
    "security_headers": {
        "description": (
            "Configure the web server or application framework to send all recommended "
            "security headers. Remove server version banners and technology disclosure headers."
        ),
        "examples": {
            "Nginx": (
                'add_header X-Frame-Options "DENY" always;\n'
                'add_header X-Content-Type-Options "nosniff" always;\n'
                'add_header X-XSS-Protection "1; mode=block" always;\n'
                'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
                'add_header Content-Security-Policy "default-src \'self\'" always;\n'
                'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;\n'
                'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n\n'
                '# Hide server version\n'
                'server_tokens off;'
            ),
            "Apache (.htaccess)": (
                'Header always set X-Frame-Options "DENY"\n'
                'Header always set X-Content-Type-Options "nosniff"\n'
                'Header always set Referrer-Policy "strict-origin-when-cross-origin"\n'
                'Header always set Content-Security-Policy "default-src \'self\'"\n'
                'Header always set Permissions-Policy "geolocation=(), camera=()"\n\n'
                '# Hide server version\n'
                'ServerTokens Prod\n'
                'ServerSignature Off'
            ),
            "Express.js (helmet)": (
                'const helmet = require("helmet");\n'
                'app.use(helmet());  // Sets all security headers with sensible defaults'
            ),
        },
    },
    "sensitive_data": {
        "description": (
            "Remove debug information, stack traces, and verbose error messages from "
            "production environments. Restrict access to sensitive pages (phpinfo, status "
            "pages). Ensure internal IP addresses and infrastructure details are not "
            "exposed in responses."
        ),
        "examples": {
            "PHP": (
                '// Disable error display in production\n'
                'ini_set("display_errors", "0");\n'
                'ini_set("log_errors", "1");\n'
                'ini_set("error_log", "/var/log/php_errors.log");\n\n'
                '// Remove phpinfo() pages\n'
                '// Delete or restrict access to phpinfo.php\n\n'
                '// Custom error handler\n'
                'set_exception_handler(function($e) {\n'
                '    error_log($e->getMessage());\n'
                '    http_response_code(500);\n'
                '    echo "An internal error occurred.";\n'
                '});'
            ),
            "Python (Flask)": (
                '# Disable debug mode in production\n'
                'app.config["DEBUG"] = False\n\n'
                '@app.errorhandler(500)\n'
                'def internal_error(error):\n'
                '    app.logger.error(f"Internal error: {error}")\n'
                '    return "An internal error occurred.", 500'
            ),
        },
    },
    "file_upload": {
        "description": (
            "Validate file type by checking magic bytes (not just extension). Store "
            "uploaded files outside the web root. Generate random filenames. Set restrictive "
            "permissions. Scan uploaded files for malware."
        ),
        "examples": {
            "Python (Flask)": (
                'import os, uuid\n'
                'from werkzeug.utils import secure_filename\n\n'
                'ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}\n'
                'UPLOAD_DIR = "/var/uploads"  # Outside web root\n\n'
                'def allowed_file(filename):\n'
                '    return "." in filename and \\\n'
                '           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS\n\n'
                '@app.route("/upload", methods=["POST"])\n'
                'def upload():\n'
                '    f = request.files["file"]\n'
                '    if not allowed_file(f.filename):\n'
                '        abort(400, "File type not allowed")\n\n'
                '    # Random filename to prevent overwrites\n'
                '    ext = f.filename.rsplit(".", 1)[1].lower()\n'
                '    safe_name = f"{uuid.uuid4().hex}.{ext}"\n'
                '    f.save(os.path.join(UPLOAD_DIR, safe_name))'
            ),
        },
    },
    "cors": {
        "description": (
            "Configure CORS to allow only trusted origins. Never use wildcard (*) with "
            "credentials. Validate the Origin header server-side before reflecting it "
            "in Access-Control-Allow-Origin."
        ),
        "examples": {
            "Express.js": (
                'const cors = require("cors");\n\n'
                'const allowedOrigins = [\n'
                '    "https://app.example.com",\n'
                '    "https://admin.example.com"\n'
                '];\n\n'
                'app.use(cors({\n'
                '    origin: (origin, callback) => {\n'
                '        if (!origin || allowedOrigins.includes(origin)) {\n'
                '            callback(null, true);\n'
                '        } else {\n'
                '            callback(new Error("CORS not allowed"));\n'
                '        }\n'
                '    },\n'
                '    credentials: true\n'
                '}));'
            ),
            "Nginx": (
                '# Only allow specific origins\n'
                'set $cors_origin "";\n'
                'if ($http_origin ~* "^https://(app|admin)\\.example\\.com$") {\n'
                '    set $cors_origin $http_origin;\n'
                '}\n'
                'add_header Access-Control-Allow-Origin $cors_origin always;\n'
                'add_header Access-Control-Allow-Credentials "true" always;'
            ),
        },
    },
}


# ── Severity configuration ───────────────────────────────────────────

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#2563eb",
    "Informational": "#6b7280",
}
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 25,
    "Medium": 10,
    "Low": 3,
    "Informational": 1,
}


# ── Utility functions ────────────────────────────────────────────────

def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _classify_finding(vuln_type: str) -> dict:
    """Map a finding's vuln_type string to its CWE/OWASP classification."""
    key = _VULN_TYPE_ALIASES.get(vuln_type.lower().strip())
    if key and key in VULN_CLASSIFICATION:
        return VULN_CLASSIFICATION[key]

    # Fuzzy match: check if any alias is a substring
    vt_lower = vuln_type.lower().strip()
    for alias, k in _VULN_TYPE_ALIASES.items():
        if alias in vt_lower or vt_lower in alias:
            if k in VULN_CLASSIFICATION:
                return VULN_CLASSIFICATION[k]

    return {
        "cwe": "N/A",
        "cwe_name": "Unknown",
        "owasp": "N/A",
        "owasp_name": "Unknown",
        "category": vuln_type,
    }


def _get_remediation_key(vuln_type: str) -> Optional[str]:
    """Get the remediation dict key for a vuln_type string."""
    key = _VULN_TYPE_ALIASES.get(vuln_type.lower().strip())
    if key and key in REMEDIATION:
        return key
    vt_lower = vuln_type.lower().strip()
    for alias, k in _VULN_TYPE_ALIASES.items():
        if alias in vt_lower or vt_lower in alias:
            if k in REMEDIATION:
                return k
    return None


def _finding_id(finding: dict) -> str:
    """Generate a stable short ID for a finding."""
    raw = "{}|{}|{}".format(
        finding.get("vuln_type", ""),
        finding.get("url", ""),
        finding.get("param_name", ""),
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


# ── Report Engine ────────────────────────────────────────────────────

class ReportEngine:
    """
    Generates professional penetration testing reports in HTML and JSON formats.

    Args:
        target: The target URL that was scanned.
        scan_time: Timestamp string of when the scan was performed.
        findings: List of finding dicts. Expected keys:
            vuln_type, url, param_name, method, payload, evidence, severity,
            source (optional), details (optional dict).
        exploit_chains: Optional list of exploit chain dicts describing
            multi-step attack paths. Each dict should have:
            name, steps (list of step descriptions), impact, findings (list of finding indices).
        previous_scan: Optional dict with previous scan data for trend comparison.
            Expected keys: scan_time, findings (list of finding dicts).
        scan_duration: Optional float — scan duration in seconds.
        tools_used: Optional list of tool/module names used during the scan.
    """

    def __init__(
        self,
        target: str,
        scan_time: str,
        findings: list,
        exploit_chains: Optional[list] = None,
        previous_scan: Optional[dict] = None,
        scan_duration: Optional[float] = None,
        tools_used: Optional[list] = None,
    ):
        self.target = target
        self.scan_time = scan_time
        self.findings = findings
        self.exploit_chains = exploit_chains or []
        self.previous_scan = previous_scan
        self.scan_duration = scan_duration
        self.tools_used = tools_used or ["Systematic Scanner", "Deterministic Validator"]

        # Parsed target info
        parsed = urlparse(target)
        self.target_host = parsed.hostname or target
        self.target_display = "{}://{}".format(parsed.scheme or "http", parsed.netloc or target)

        # Normalize severity on each finding
        for f in self.findings:
            sev = f.get("severity", "Medium")
            if sev not in SEVERITY_ORDER:
                sev = "Medium"
            f["severity"] = sev

        # Sort findings by severity
        self.findings.sort(key=lambda f: SEVERITY_ORDER.index(f.get("severity", "Medium")))

        # Compute statistics
        self.stats = self._compute_stats()

    def _compute_stats(self) -> dict:
        """Compute summary statistics from findings."""
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "Medium")
            counts[sev] = counts.get(sev, 0) + 1

        total = len(self.findings)
        risk_score = 0
        for sev, count in counts.items():
            risk_score += count * SEVERITY_WEIGHTS.get(sev, 1)
        risk_score = min(100, risk_score)

        # Unique vuln types
        vuln_types = set()
        for f in self.findings:
            vuln_types.add(f.get("vuln_type", "Unknown"))

        # Unique affected endpoints
        endpoints = set()
        for f in self.findings:
            endpoints.add(f.get("url", ""))

        return {
            "total": total,
            "by_severity": counts,
            "risk_score": risk_score,
            "unique_vuln_types": len(vuln_types),
            "unique_endpoints": len(endpoints),
        }

    # ── CSS Styles ───────────────────────────────────────────────────

    def _base_css(self) -> str:
        """Return the base CSS used across all HTML reports."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            color: #1e293b;
            background: #f8fafc;
            line-height: 1.6;
            font-size: 14px;
        }
        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
            color: #ffffff;
            padding: 32px 48px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
        .header .subtitle { color: #94a3b8; font-size: 13px; margin-top: 4px; }
        .header .meta { text-align: right; font-size: 13px; color: #cbd5e1; }
        .header .meta strong { color: #ffffff; }
        .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
        .section { margin-bottom: 36px; }
        .section-title {
            font-size: 18px; font-weight: 700; color: #0f172a;
            border-bottom: 2px solid #e2e8f0; padding-bottom: 8px;
            margin-bottom: 16px;
        }
        .badge {
            display: inline-block; padding: 2px 10px; border-radius: 4px;
            font-size: 11px; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.5px; color: #ffffff;
        }
        .badge-critical { background: #dc2626; }
        .badge-high { background: #ea580c; }
        .badge-medium { background: #ca8a04; }
        .badge-low { background: #2563eb; }
        .badge-informational { background: #6b7280; }
        .card {
            background: #ffffff; border-radius: 8px;
            border: 1px solid #e2e8f0; padding: 20px;
            margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }
        table {
            width: 100%; border-collapse: collapse; font-size: 13px;
        }
        th {
            background: #f1f5f9; text-align: left; padding: 10px 12px;
            font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0;
        }
        td {
            padding: 10px 12px; border-bottom: 1px solid #f1f5f9;
        }
        tr:nth-child(even) td { background: #f8fafc; }
        tr:hover td { background: #f1f5f9; }
        code, .code {
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 12px;
        }
        .code-block {
            background: #1e293b; color: #e2e8f0; padding: 16px;
            border-radius: 6px; overflow-x: auto; font-size: 12px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            line-height: 1.5; white-space: pre-wrap; word-break: break-all;
            margin: 8px 0;
        }
        .code-block .comment { color: #64748b; }
        .code-block .keyword { color: #38bdf8; }
        .stat-grid {
            display: grid; grid-template-columns: repeat(4, 1fr);
            gap: 16px; margin-bottom: 24px;
        }
        .stat-card {
            background: #ffffff; border-radius: 8px; padding: 20px;
            border: 1px solid #e2e8f0; text-align: center;
        }
        .stat-card .number { font-size: 32px; font-weight: 800; color: #0f172a; }
        .stat-card .label { font-size: 12px; color: #64748b; text-transform: uppercase;
                            letter-spacing: 0.5px; margin-top: 4px; }
        a { color: #2563eb; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .toc { list-style: none; padding: 0; }
        .toc li { padding: 4px 0; }
        .toc li a { color: #334155; font-size: 13px; }
        .toc li a:hover { color: #2563eb; }
        .finding-header {
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 12px;
        }
        .finding-header h3 { font-size: 16px; color: #0f172a; }
        .finding-meta { display: grid; grid-template-columns: 1fr 1fr;
                         gap: 8px; margin-bottom: 12px; font-size: 13px; }
        .finding-meta dt { font-weight: 600; color: #475569; }
        .finding-meta dd { color: #1e293b; word-break: break-all; }
        .remediation { background: #f0fdf4; border: 1px solid #bbf7d0;
                       border-radius: 6px; padding: 16px; margin-top: 12px; }
        .remediation h4 { color: #166534; margin-bottom: 8px; font-size: 14px; }
        .chain-step {
            display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px;
        }
        .chain-step-num {
            background: #0f172a; color: #fff; width: 28px; height: 28px;
            border-radius: 50%; display: flex; align-items: center;
            justify-content: center; font-size: 13px; font-weight: 700;
            flex-shrink: 0;
        }
        .chain-arrow {
            text-align: center; color: #94a3b8; font-size: 18px; margin: 4px 0 4px 8px;
        }
        .footer {
            text-align: center; padding: 24px; color: #94a3b8;
            font-size: 12px; border-top: 1px solid #e2e8f0; margin-top: 48px;
        }
        .finding-summary {
            background: #fffbeb; border: 1px solid #fde68a; border-left: 4px solid #f59e0b;
            border-radius: 6px; padding: 14px 16px; margin-bottom: 16px;
        }
        .finding-summary .summary-label {
            font-size: 11px; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.6px; color: #92400e; margin-bottom: 6px;
        }
        .finding-summary p {
            font-size: 13px; color: #1c1917; line-height: 1.65; margin: 0;
        }
        .finding-summary .narrative {
            font-size: 12px; color: #44403c; margin-top: 8px;
            border-top: 1px solid #fde68a; padding-top: 8px;
        }
        .validation-verdict {
            display: inline-flex; align-items: center; gap: 6px;
            border-radius: 4px; padding: 4px 10px;
            font-size: 11px; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .verdict-validated      { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .verdict-needs-proof    { background: #fef9c3; color: #854d0e; border: 1px solid #fde047; }
        .verdict-false-positive { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .validation-block {
            margin-top: 16px; padding: 12px 16px;
            background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
        }
        .validation-block .vb-title {
            font-size: 12px; font-weight: 700; color: #475569;
            text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 8px;
        }
        .validation-block .vb-row {
            font-size: 12px; color: #334155; margin-bottom: 5px; line-height: 1.5;
        }
        .validation-block .vb-label {
            font-weight: 600; color: #64748b;
        }
        .confidence-badge {
            display: inline-flex; align-items: center; gap: 6px;
            background: #f1f5f9; border: 1px solid #e2e8f0;
            border-radius: 20px; padding: 3px 10px;
            font-size: 11px; font-weight: 600; color: #475569;
            margin-left: 8px;
        }
        .confidence-dot {
            width: 8px; height: 8px; border-radius: 50%;
        }

        @media print {
            body { background: #fff; font-size: 11px; }
            .header { padding: 20px 24px; }
            .container { padding: 16px; }
            .card { break-inside: avoid; box-shadow: none; border: 1px solid #ccc; }
            .code-block { background: #f3f4f6; color: #1e293b; border: 1px solid #ccc; }
            .stat-grid { grid-template-columns: repeat(4, 1fr); }
            a { color: #1e293b; }
            .no-print { display: none; }
        }
        """

    # ── SVG Helpers ──────────────────────────────────────────────────

    def _risk_gauge_svg(self, score: int) -> str:
        """Generate an SVG risk score gauge (semicircle)."""
        # Gauge angle: 0 = left (good), 180 = right (bad)
        angle = (score / 100) * 180
        rad = math.radians(angle)

        # Arc from left (180deg) sweeping clockwise
        cx, cy, r = 100, 90, 70
        start_x = cx - r  # leftmost point
        start_y = cy
        end_x = cx + r * math.cos(math.pi - rad)
        end_y = cy - r * math.sin(math.pi - rad)

        large_arc = 1 if angle > 90 else 0

        if score <= 25:
            color = "#22c55e"
            label = "Low Risk"
        elif score <= 50:
            color = "#ca8a04"
            label = "Moderate Risk"
        elif score <= 75:
            color = "#ea580c"
            label = "High Risk"
        else:
            color = "#dc2626"
            label = "Critical Risk"

        return """
        <svg viewBox="0 0 200 120" width="220" height="132" xmlns="http://www.w3.org/2000/svg">
          <!-- Background arc -->
          <path d="M 30 90 A 70 70 0 0 1 170 90" fill="none" stroke="#e2e8f0" stroke-width="14"
                stroke-linecap="round"/>
          <!-- Score arc -->
          <path d="M {sx:.1f} {sy:.1f} A 70 70 0 {la} 1 {ex:.1f} {ey:.1f}"
                fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>
          <!-- Score text -->
          <text x="100" y="82" text-anchor="middle" font-size="36" font-weight="800"
                fill="{color}" font-family="-apple-system, sans-serif">{score}</text>
          <text x="100" y="98" text-anchor="middle" font-size="10" fill="#64748b"
                font-family="-apple-system, sans-serif">/ 100</text>
          <text x="100" y="116" text-anchor="middle" font-size="11" font-weight="600"
                fill="{color}" font-family="-apple-system, sans-serif">{label}</text>
        </svg>
        """.format(
            sx=start_x, sy=start_y, ex=end_x, ey=end_y,
            la=large_arc, color=color, score=score, label=label,
        )

    def _severity_pie_svg(self) -> str:
        """Generate an inline SVG pie chart of findings by severity."""
        counts = self.stats["by_severity"]
        total = self.stats["total"]
        if total == 0:
            return '<p style="color:#64748b;">No findings to chart.</p>'

        # Filter out zero-count severities
        slices = []
        for sev in SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c > 0:
                slices.append((sev, c, SEVERITY_COLORS[sev]))

        if not slices:
            return ""

        cx, cy, r = 120, 120, 100
        paths = []
        legend_items = []
        start_angle = -90  # start from top

        for sev, count, color in slices:
            pct = count / total
            sweep = pct * 360

            # Calculate arc
            start_rad = math.radians(start_angle)
            end_rad = math.radians(start_angle + sweep)

            x1 = cx + r * math.cos(start_rad)
            y1 = cy + r * math.sin(start_rad)
            x2 = cx + r * math.cos(end_rad)
            y2 = cy + r * math.sin(end_rad)

            large = 1 if sweep > 180 else 0

            if len(slices) == 1:
                # Full circle
                paths.append(
                    '<circle cx="{}" cy="{}" r="{}" fill="{}"/>'.format(cx, cy, r, color)
                )
            else:
                paths.append(
                    '<path d="M {cx} {cy} L {x1:.1f} {y1:.1f} '
                    'A {r} {r} 0 {la} 1 {x2:.1f} {y2:.1f} Z" fill="{color}"/>'.format(
                        cx=cx, cy=cy, x1=x1, y1=y1, x2=x2, y2=y2,
                        r=r, la=large, color=color,
                    )
                )

            legend_items.append(
                '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">'
                '<div style="width:12px;height:12px;border-radius:2px;background:{color};"></div>'
                '<span style="font-size:12px;color:#475569;">{sev}: {count} ({pct:.0f}%)</span>'
                '</div>'.format(color=color, sev=sev, count=count, pct=pct * 100)
            )

            start_angle += sweep

        svg = (
            '<div style="display:flex;align-items:center;gap:24px;">'
            '<svg viewBox="0 0 240 240" width="180" height="180" '
            'xmlns="http://www.w3.org/2000/svg">'
            '{paths}'
            '</svg>'
            '<div>{legend}</div>'
            '</div>'
        ).format(paths="\n".join(paths), legend="\n".join(legend_items))

        return svg

    # ── Executive Summary ────────────────────────────────────────────

    def generate_executive_html(self, output_path: str) -> str:
        """
        Generate an executive summary HTML report.

        Returns the absolute path to the generated file.
        """
        score = self.stats["risk_score"]
        counts = self.stats["by_severity"]
        total = self.stats["total"]

        # Top critical/high findings for the executive summary
        top_findings = []
        for f in self.findings:
            if f.get("severity") in ("Critical", "High") and len(top_findings) < 3:
                top_findings.append(f)
        if len(top_findings) < 3:
            for f in self.findings:
                if f not in top_findings and len(top_findings) < 3:
                    top_findings.append(f)

        # Trend comparison
        trend_html = ""
        if self.previous_scan:
            prev_findings = self.previous_scan.get("findings", [])
            prev_total = len(prev_findings)
            prev_counts = {s: 0 for s in SEVERITY_ORDER}
            for pf in prev_findings:
                sev = pf.get("severity", "Medium")
                prev_counts[sev] = prev_counts.get(sev, 0) + 1

            delta = total - prev_total
            direction = "increase" if delta > 0 else "decrease" if delta < 0 else "no change"
            delta_color = "#dc2626" if delta > 0 else "#22c55e" if delta < 0 else "#64748b"
            arrow = "&#9650;" if delta > 0 else "&#9660;" if delta < 0 else "&#8212;"

            trend_rows = []
            for sev in SEVERITY_ORDER:
                curr = counts.get(sev, 0)
                prev = prev_counts.get(sev, 0)
                d = curr - prev
                d_str = "+{}".format(d) if d > 0 else str(d)
                d_color = "#dc2626" if d > 0 else "#22c55e" if d < 0 else "#64748b"
                trend_rows.append(
                    "<tr><td>{sev}</td><td>{prev}</td><td>{curr}</td>"
                    '<td style="color:{dc};font-weight:600;">{ds}</td></tr>'.format(
                        sev=sev, prev=prev, curr=curr, dc=d_color, ds=d_str,
                    )
                )

            trend_html = """
            <div class="section">
                <h2 class="section-title">Trend Comparison</h2>
                <div class="card">
                    <p style="margin-bottom:12px;">
                        Compared to previous scan ({prev_time}): <strong>{total_delta}</strong>
                        findings ({direction})
                        <span style="color:{dc};font-weight:700;"> {arrow} {abs_delta}</span>
                    </p>
                    <table>
                        <thead><tr><th>Severity</th><th>Previous</th><th>Current</th><th>Delta</th></tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>
            </div>
            """.format(
                prev_time=_escape_html(self.previous_scan.get("scan_time", "N/A")),
                total_delta=abs(delta),
                direction=direction,
                dc=delta_color,
                arrow=arrow,
                abs_delta=abs(delta),
                rows="\n".join(trend_rows),
            )

        # Top findings HTML
        top_findings_html = ""
        for i, f in enumerate(top_findings, 1):
            cls = _classify_finding(f.get("vuln_type", ""))
            sev = f.get("severity", "Medium")
            badge_cls = "badge-{}".format(sev.lower())

            rk = _get_remediation_key(f.get("vuln_type", ""))
            impact_text = ""
            if rk and rk in REMEDIATION:
                impact_text = REMEDIATION[rk]["description"][:200]
            else:
                impact_text = "Requires immediate assessment and remediation."

            top_findings_html += """
            <div class="card">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                    <span style="font-size:18px;font-weight:800;color:#94a3b8;">#{i}</span>
                    <span class="badge {bc}">{sev}</span>
                    <strong style="font-size:14px;">{vt}</strong>
                </div>
                <p style="font-size:13px;color:#475569;margin-bottom:6px;">
                    <strong>Endpoint:</strong> {url}
                </p>
                <p style="font-size:13px;color:#475569;margin-bottom:6px;">
                    <strong>Classification:</strong> {cwe} &mdash; OWASP {owasp}
                </p>
                <p style="font-size:13px;color:#64748b;">{impact}</p>
            </div>
            """.format(
                i=i, bc=badge_cls, sev=_escape_html(sev),
                vt=_escape_html(f.get("vuln_type", "Unknown")),
                url=_escape_html(f.get("url", "N/A")),
                cwe=_escape_html(cls["cwe"]),
                owasp=_escape_html(cls["owasp"]),
                impact=_escape_html(impact_text),
            )

        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Executive Summary &mdash; Penetration Test Report</title>
<style>
{css}
.exec-grid {{ display: flex; gap: 32px; align-items: flex-start; margin-bottom: 24px; }}
.exec-gauge {{ flex-shrink: 0; }}
.exec-chart {{ flex-grow: 1; }}
</style>
</head>
<body>
<div class="header">
    <div>
        <h1>Penetration Test &mdash; Executive Summary</h1>
        <div class="subtitle">Confidential &mdash; For Authorized Recipients Only</div>
    </div>
    <div class="meta">
        <div><strong>Target:</strong> {target}</div>
        <div><strong>Date:</strong> {scan_time}</div>
        {duration_line}
    </div>
</div>
<div class="container">

    <!-- Stats -->
    <div class="stat-grid">
        <div class="stat-card">
            <div class="number">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#dc2626;">{critical}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#ea580c;">{high}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#ca8a04;">{medium}</div>
            <div class="label">Medium</div>
        </div>
    </div>

    <!-- Risk Score + Pie -->
    <div class="section">
        <h2 class="section-title">Risk Assessment</h2>
        <div class="exec-grid">
            <div class="exec-gauge">
                {gauge_svg}
            </div>
            <div class="exec-chart">
                {pie_svg}
            </div>
        </div>
    </div>

    <!-- Top Findings -->
    <div class="section">
        <h2 class="section-title">Top Critical Findings</h2>
        {top_findings}
    </div>

    {trend}

    <!-- Scope -->
    <div class="section">
        <h2 class="section-title">Engagement Scope</h2>
        <div class="card">
            <table>
                <tr><td style="font-weight:600;width:180px;">Target</td><td>{target}</td></tr>
                <tr><td style="font-weight:600;">Scan Time</td><td>{scan_time}</td></tr>
                {duration_row}
                <tr><td style="font-weight:600;">Unique Endpoints</td><td>{endpoints}</td></tr>
                <tr><td style="font-weight:600;">Vulnerability Types</td><td>{vuln_types}</td></tr>
                <tr><td style="font-weight:600;">Tools</td><td>{tools}</td></tr>
            </table>
        </div>
    </div>

</div>
<div class="footer">
    Generated by Pentest Agent &mdash; Confidential
</div>
</body>
</html>""".format(
            css=self._base_css(),
            target=_escape_html(self.target_display),
            scan_time=_escape_html(self.scan_time),
            duration_line=(
                "<div><strong>Duration:</strong> {:.0f}s</div>".format(self.scan_duration)
                if self.scan_duration else ""
            ),
            total=total,
            critical=counts.get("Critical", 0),
            high=counts.get("High", 0),
            medium=counts.get("Medium", 0),
            gauge_svg=self._risk_gauge_svg(score),
            pie_svg=self._severity_pie_svg(),
            top_findings=top_findings_html if top_findings_html else '<p style="color:#64748b;">No findings to display.</p>',
            trend=trend_html,
            duration_row=(
                "<tr><td style='font-weight:600;'>Duration</td><td>{:.1f} seconds</td></tr>".format(self.scan_duration)
                if self.scan_duration else ""
            ),
            endpoints=self.stats["unique_endpoints"],
            vuln_types=self.stats["unique_vuln_types"],
            tools=_escape_html(", ".join(self.tools_used)),
        )

        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return abs_path

    # ── Technical Report ─────────────────────────────────────────────

    def generate_technical_html(self, output_path: str) -> str:
        """
        Generate a detailed technical HTML report for the security team.

        Returns the absolute path to the generated file.
        """
        counts = self.stats["by_severity"]
        total = self.stats["total"]

        # Build TOC
        toc_items = []
        toc_items.append('<li><a href="#summary">Summary</a></li>')
        for sev in SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c > 0:
                toc_items.append(
                    '<li><a href="#sev-{sl}">{sev} ({c})</a></li>'.format(
                        sl=sev.lower(), sev=sev, c=c,
                    )
                )
        if self.exploit_chains:
            toc_items.append('<li><a href="#attack-chains">Attack Chains</a></li>')
        toc_items.append('<li><a href="#methodology">Methodology</a></li>')

        # Build findings grouped by severity
        findings_html_parts = []
        finding_counter = 0

        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in self.findings if f.get("severity") == sev]
            if not sev_findings:
                continue

            findings_html_parts.append(
                '<div class="section" id="sev-{sl}">'
                '<h2 class="section-title">{sev} Severity Findings ({c})</h2>'.format(
                    sl=sev.lower(), sev=sev, c=len(sev_findings),
                )
            )

            for f in sev_findings:
                finding_counter += 1
                fid = _finding_id(f)
                cls = _classify_finding(f.get("vuln_type", ""))
                badge_cls = "badge-{}".format(sev.lower())
                rk = _get_remediation_key(f.get("vuln_type", ""))

                # Build finding detail sections
                vuln_type = f.get("vuln_type", "Unknown")
                url = f.get("url", "N/A")
                method = f.get("method", "N/A")
                param = f.get("param_name", "")
                payload = f.get("payload", "N/A")
                evidence = f.get("evidence", "N/A")
                source = f.get("source", "N/A")
                details = f.get("details", {})

                # Affected endpoints (from deduplicator)
                affected_eps = f.get("affected_endpoints", [])
                dedup_count = f.get("dedup_count", 0)
                confidence_score = f.get("confidence_score")
                confidence_label = f.get("confidence_label", "")
                attack_narrative = f.get("attack_narrative", "")
                # Validation fields (Phase 3 validator output)
                val_verdict    = f.get("validation_verdict", "")
                val_confidence = f.get("validation_confidence", "")
                val_summary    = f.get("validation_summary", "")
                val_skepticism = f.get("validation_skepticism", "")
                val_weakest    = f.get("validation_weakest_link", "")
                val_required   = f.get("validation_required_evidence", "")
                val_notes      = f.get("validation_notes", "")

                # Summary block (plain English for non-technical readers)
                summary_text = self._generate_finding_summary(
                    vuln_type, url, param, method, payload, evidence, sev
                )
                confidence_html = ""
                if confidence_score is not None:
                    if confidence_score >= 80:
                        dot_color = "#22c55e"
                    elif confidence_score >= 60:
                        dot_color = "#ca8a04"
                    else:
                        dot_color = "#94a3b8"
                    confidence_html = (
                        '<span class="confidence-badge">'
                        '<span class="confidence-dot" style="background:{c};"></span>'
                        '{label} ({score}/100)'
                        '</span>'
                    ).format(c=dot_color, label=_escape_html(confidence_label or ""), score=confidence_score)

                narrative_html = ""
                if attack_narrative and attack_narrative.strip():
                    narrative_html = (
                        '<p class="narrative"><strong>Attack scenario:</strong> {}</p>'
                    ).format(_escape_html(attack_narrative))

                summary_html = (
                    '<div class="finding-summary">'
                    '<div class="summary-label">Summary {confidence}</div>'
                    '<p>{summary}</p>'
                    '{narrative}'
                    '</div>'
                ).format(
                    confidence=confidence_html,
                    summary=_escape_html(summary_text),
                    narrative=narrative_html,
                )

                # Validation verdict block
                validation_html = ""
                if val_verdict:
                    verdict_class_map = {
                        "VALIDATED": "verdict-validated",
                        "REJECTED_NEEDS_MORE_PROOF": "verdict-needs-proof",
                        "FALSE_POSITIVE": "verdict-false-positive",
                    }
                    verdict_label_map = {
                        "VALIDATED": "&#10003; Validated",
                        "REJECTED_NEEDS_MORE_PROOF": "&#9888; Needs More Proof",
                        "FALSE_POSITIVE": "&#10007; False Positive",
                    }
                    vclass  = verdict_class_map.get(val_verdict, "verdict-needs-proof")
                    vlabel  = verdict_label_map.get(val_verdict, val_verdict)
                    rows = []
                    if val_summary:
                        rows.append(
                            '<div class="vb-row">'
                            '<span class="vb-label">Reviewer Summary: </span>{}</div>'.format(
                                _escape_html(val_summary)
                            )
                        )
                    if val_skepticism and val_verdict != "VALIDATED":
                        rows.append(
                            '<div class="vb-row">'
                            '<span class="vb-label">Skepticism: </span>{}</div>'.format(
                                _escape_html(val_skepticism[:300])
                            )
                        )
                    if val_weakest and val_verdict != "VALIDATED":
                        rows.append(
                            '<div class="vb-row">'
                            '<span class="vb-label">Weakest Link: </span>{}</div>'.format(
                                _escape_html(val_weakest[:200])
                            )
                        )
                    if val_required and val_verdict != "VALIDATED":
                        rows.append(
                            '<div class="vb-row">'
                            '<span class="vb-label">Evidence Required: </span>{}</div>'.format(
                                _escape_html(val_required[:300])
                            )
                        )
                    if val_notes:
                        rows.append(
                            '<div class="vb-row">'
                            '<span class="vb-label">Report Note: </span>{}</div>'.format(
                                _escape_html(val_notes[:200])
                            )
                        )
                    conf_suffix = " ({})".format(val_confidence) if val_confidence else ""
                    validation_html = (
                        '<div class="validation-block">'
                        '<div class="vb-title">'
                        'Security Reviewer Verdict'
                        '<span class="validation-verdict {vc}" style="margin-left:10px;">'
                        '{vl}{cs}</span>'
                        '</div>'
                        '{rows}'
                        '</div>'
                    ).format(
                        vc=vclass, vl=vlabel, cs=conf_suffix,
                        rows="\n".join(rows),
                    )

                # Affected endpoints list (for deduplicated/aggregated findings)
                affected_endpoints_html_str = ""
                if affected_eps and len(affected_eps) > 1:
                    ep_items = "\n".join(
                        '<li style="font-size:12px;color:#334155;padding:2px 0;">'
                        '<code>{}</code></li>'.format(_escape_html(ep))
                        for ep in affected_eps[:50]  # cap at 50
                    )
                    more = ""
                    if len(affected_eps) > 50:
                        more = '<li style="font-size:12px;color:#64748b;">... and {} more</li>'.format(
                            len(affected_eps) - 50
                        )
                    affected_endpoints_html_str = (
                        '<dt>Affected Endpoints</dt>'
                        '<dd><details style="font-size:12px;">'
                        '<summary style="cursor:pointer;color:#2563eb;font-weight:600;">'
                        '{count} endpoint(s) affected — click to expand</summary>'
                        '<ul style="list-style:none;padding:8px 0 0 0;margin:0;">{items}{more}</ul>'
                        '</details></dd>'
                    ).format(count=len(affected_eps), items=ep_items, more=more)

                # Description — specific to this finding
                description = self._generate_specific_description(
                    vuln_type, url, param, method, payload, rk
                )

                # Proof of Concept — full HTTP request with headers
                parsed_url = urlparse(url)
                path = parsed_url.path or "/"
                query = parsed_url.query
                host = parsed_url.netloc or self.target_host
                is_json = ("json" in url.lower() or "api" in url.lower()
                           or (isinstance(details, dict) and "json" in str(details).lower()))
                active_payload = payload not in ("N/A", "N/A (passive check)", "N/A (passive scan)", "")

                poc_request = ""
                if method.upper() == "GET" and param and active_payload:
                    qs = "{}={}".format(param, payload)
                    if query:
                        qs = "{}&{}".format(query, qs)
                    poc_request = (
                        "GET {path}?{qs} HTTP/1.1\r\n"
                        "Host: {host}\r\n"
                        "User-Agent: Mozilla/5.0 (compatible; PentestAgent/1.0)\r\n"
                        "Accept: text/html,application/xhtml+xml,application/json\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "# Expected: evidence of {vuln} in response"
                    ).format(path=path, qs=qs, host=host, vuln=vuln_type)
                elif method.upper() in ("POST", "PUT", "PATCH") and param and active_payload:
                    if is_json:
                        body = '{{"{}": "{}"}}'.format(param, payload)
                        content_type = "application/json"
                    else:
                        body = "{}={}".format(param, payload)
                        content_type = "application/x-www-form-urlencoded"
                    poc_request = (
                        "{method} {path} HTTP/1.1\r\n"
                        "Host: {host}\r\n"
                        "User-Agent: Mozilla/5.0 (compatible; PentestAgent/1.0)\r\n"
                        "Accept: application/json\r\n"
                        "Content-Type: {ct}\r\n"
                        "Content-Length: {cl}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "{body}\r\n"
                        "\r\n"
                        "# Expected: evidence of {vuln} in response"
                    ).format(
                        method=method.upper(), path=path, host=host,
                        ct=content_type, cl=len(body), body=body, vuln=vuln_type,
                    )
                elif url and url != "N/A":
                    poc_request = (
                        "# Passive / Infrastructure Finding\r\n"
                        "# Affected: {url}\r\n"
                        "# Detection: {evidence}"
                    ).format(
                        url=url,
                        evidence=(evidence[:200] if evidence and evidence != "N/A" else "See Evidence section"),
                    )

                # Reproduction steps — detailed and actionable
                repro_steps = []
                tool_name = "curl" if (method.upper() in ("GET", "POST", "PUT", "PATCH")) else "browser"
                repro_steps.append(
                    "Open a browser or HTTP proxy (e.g., Burp Suite) and navigate to: "
                    "<code>{}</code>".format(_escape_html(url))
                )
                if param:
                    repro_steps.append(
                        "Identify the <strong>{}</strong> parameter sent via <strong>{}</strong>".format(
                            _escape_html(param), _escape_html(method),
                        )
                    )
                if active_payload:
                    repro_steps.append(
                        "Replace the parameter value with the following payload: "
                        "<code>{}</code>".format(_escape_html(payload))
                    )
                    repro_steps.append(
                        "Send the request and examine the HTTP response (status code, body, headers)"
                    )
                else:
                    repro_steps.append(
                        "Inspect the HTTP response headers and body of the above request"
                    )
                # Vuln-specific observation step
                observation = {
                    "sqli": "Look for SQL error messages (e.g. <em>syntax error</em>, <em>ORA-</em>, <em>mysql_fetch_array</em>) or unexpected data rows in the response",
                    "xss": "Check if the payload appears unescaped in the HTML body — open browser DevTools to confirm script execution",
                    "command_injection": "Check for command output (e.g. <em>uid=</em>, <em>root</em>, <em>Windows IP Configuration</em>) in the response body",
                    "path_traversal": "Look for file content in the response (e.g. <em>root:x:0:0</em> from /etc/passwd) indicating successful directory traversal",
                    "csrf": "Confirm that the state-changing request succeeds without a CSRF token from an external origin",
                    "idor": "Change the object ID to belong to another user and confirm the server returns that user's data",
                    "ssrf": "Check whether the server returns content from internal addresses (e.g. AWS metadata, internal APIs) in its response",
                    "open_redirect": "Confirm the server responds with a 3xx redirect pointing to the external attacker-controlled domain",
                    "security_headers": "Use <em>curl -I</em> or DevTools Network tab to verify the absence of the reported security headers",
                    "sensitive_data": "Locate the sensitive information (credentials, stack trace, internal IPs) in the response body",
                    "cors": "Observe that <em>Access-Control-Allow-Origin</em> reflects the attacker origin in the response",
                }.get(rk or "", "Verify the evidence below matches the expected vulnerability indicator")
                repro_steps.append(observation)

                if evidence and evidence != "N/A":
                    repro_steps.append(
                        "Confirm: scanner recorded the following evidence — "
                        "<code>{}</code>".format(_escape_html(evidence[:120]))
                    )

                repro_html = "\n".join(
                    '<div class="chain-step">'
                    '<span class="chain-step-num">{}</span>'
                    '<span style="font-size:13px;padding-top:4px;line-height:1.6;">{}</span>'
                    '</div>'.format(i, step)  # steps already contain safe HTML
                    for i, step in enumerate(repro_steps, 1)
                )

                # Impact assessment
                impact_text = self._get_impact_assessment(rk, sev)

                # Remediation
                remediation_html = ""
                if rk and rk in REMEDIATION:
                    rem = REMEDIATION[rk]
                    remediation_html = '<div class="remediation"><h4>Remediation</h4>'
                    remediation_html += '<p style="font-size:13px;margin-bottom:12px;">{}</p>'.format(
                        _escape_html(rem["description"])
                    )
                    for lang, code in rem.get("examples", {}).items():
                        remediation_html += (
                            '<p style="font-size:12px;font-weight:600;color:#166534;'
                            'margin-top:10px;margin-bottom:4px;">{}</p>'
                            '<div class="code-block">{}</div>'
                        ).format(_escape_html(lang), _escape_html(code))
                    remediation_html += "</div>"

                # CVE / Exploit enrichment section
                cve_refs = f.get("cve_refs", [])
                exploit_refs = f.get("exploit_refs", [])
                cvss_score = f.get("cvss_score")
                enrichment_html = ""
                if cve_refs or exploit_refs:
                    enrichment_html = (
                        '<div style="margin-top:16px;padding:12px 16px;background:#f8fafc;'
                        'border:1px solid #e2e8f0;border-radius:6px;">'
                        '<h4 style="font-size:13px;font-weight:600;color:#475569;margin-bottom:10px;">'
                        'CVE References &amp; Public Exploits</h4>'
                    )
                    if cve_refs:
                        enrichment_html += (
                            '<p style="font-size:12px;font-weight:600;color:#64748b;'
                            'margin-bottom:6px;">NVD / CVE</p>'
                        )
                        for cve in cve_refs:
                            score = cve.get("cvss_score")
                            score_badge = ""
                            if score is not None:
                                color = "#dc2626" if score >= 9 else "#ea580c" if score >= 7 else "#ca8a04"
                                score_badge = (
                                    '<span style="background:{c};color:#fff;font-size:11px;'
                                    'font-weight:700;padding:1px 6px;border-radius:3px;'
                                    'margin-left:8px;">CVSS {s}</span>'.format(c=color, s=score)
                                )
                            enrichment_html += (
                                '<div style="margin-bottom:6px;">'
                                '<a href="{url}" target="_blank" style="font-size:12px;'
                                'color:#2563eb;font-weight:600;">{cve_id}</a>{badge}'
                                '<span style="font-size:11px;color:#64748b;margin-left:8px;">'
                                '{desc}</span></div>'
                            ).format(
                                url=_escape_html(cve.get("url", "#")),
                                cve_id=_escape_html(cve.get("cve_id", "")),
                                badge=score_badge,
                                desc=_escape_html(cve.get("description", "")[:120]),
                            )
                    if exploit_refs:
                        enrichment_html += (
                            '<p style="font-size:12px;font-weight:600;color:#64748b;'
                            'margin-top:10px;margin-bottom:6px;">Public Exploits (Exploit-DB)</p>'
                        )
                        for ex in exploit_refs:
                            enrichment_html += (
                                '<div style="margin-bottom:5px;">'
                                '<a href="{url}" target="_blank" style="font-size:12px;'
                                'color:#2563eb;">EDB-{eid}</a>'
                                '<span style="font-size:11px;color:#64748b;margin-left:8px;">'
                                '{title}</span></div>'
                            ).format(
                                url=_escape_html(ex.get("url", "#")),
                                eid=_escape_html(ex.get("exploit_id", "")),
                                title=_escape_html(ex.get("title", "")[:100]),
                            )
                    enrichment_html += "</div>"

                # Extra details from the validator
                extra_details_html = ""
                if isinstance(details, dict):
                    skip_keys = {"validated", "type", "evidence", "url", "payload", "reason"}
                    extra = {k: v for k, v in details.items() if k not in skip_keys and v}
                    if extra:
                        rows = []
                        for k, v in extra.items():
                            if isinstance(v, (list, dict)):
                                v_str = json.dumps(v, indent=2)
                            else:
                                v_str = str(v)
                            rows.append(
                                "<tr><td style='font-weight:600;'>{}</td>"
                                "<td><code>{}</code></td></tr>".format(
                                    _escape_html(k.replace("_", " ").title()),
                                    _escape_html(v_str),
                                )
                            )
                        if rows:
                            extra_details_html = (
                                '<div style="margin-top:12px;">'
                                '<h4 style="font-size:13px;font-weight:600;color:#475569;'
                                'margin-bottom:6px;">Additional Details</h4>'
                                '<table>{}</table></div>'
                            ).format("\n".join(rows))

                findings_html_parts.append("""
                <div class="card" id="finding-{fid}">
                    <div class="finding-header">
                        <span class="badge {bc}">{sev}</span>
                        <h3>#{num} &mdash; {vt}</h3>
                    </div>

                    <div class="finding-meta">
                        <dt>Classification</dt>
                        <dd>{cwe} &mdash; {cwe_name}</dd>
                        <dt>OWASP Top 10</dt>
                        <dd>{owasp} {owasp_name}</dd>
                        <dt>Affected Endpoint</dt>
                        <dd><code>{url}</code></dd>
                        {affected_endpoints_html}
                        <dt>Method / Parameter</dt>
                        <dd><code>{method}</code> {param_display}</dd>
                        <dt>Source</dt>
                        <dd>{source}</dd>
                        <dt>Finding ID</dt>
                        <dd><code>{fid}</code></dd>
                        {cvss_meta}
                    </div>

                    {summary_block}
                    {validation_block}

                    <h4 style="font-size:13px;font-weight:600;color:#475569;margin-bottom:6px;">
                        Description
                    </h4>
                    <p style="font-size:13px;color:#334155;margin-bottom:16px;line-height:1.65;">
                        {description}
                    </p>

                    {poc_section}

                    <h4 style="font-size:13px;font-weight:600;color:#475569;margin:16px 0 6px;">
                        Evidence
                    </h4>
                    <div class="code-block">{evidence}</div>

                    <h4 style="font-size:13px;font-weight:600;color:#475569;margin:16px 0 6px;">
                        Steps to Reproduce
                    </h4>
                    {repro}

                    <h4 style="font-size:13px;font-weight:600;color:#475569;margin:16px 0 6px;">
                        Impact Assessment
                    </h4>
                    <p style="font-size:13px;color:#334155;margin-bottom:12px;line-height:1.65;">{impact}</p>

                    {enrichment}
                    {extra_details}
                    {remediation}
                </div>
                """.format(
                    fid=fid, bc=badge_cls, sev=_escape_html(sev), num=finding_counter,
                    vt=_escape_html(vuln_type),
                    cwe=_escape_html(cls["cwe"]),
                    cwe_name=_escape_html(cls["cwe_name"]),
                    owasp=_escape_html(cls["owasp"]),
                    owasp_name=_escape_html(cls["owasp_name"]),
                    url=_escape_html(url),
                    method=_escape_html(method),
                    param_display=(
                        "/ <code>{}</code>".format(_escape_html(param)) if param else ""
                    ),
                    affected_endpoints_html=affected_endpoints_html_str,
                    source=_escape_html(source),
                    cvss_meta=(
                        '<dt>CVSS Score</dt><dd><strong style="color:{c};">{s}</strong></dd>'.format(
                            c="#dc2626" if cvss_score >= 9 else "#ea580c" if cvss_score >= 7 else "#ca8a04",
                            s=cvss_score,
                        ) if cvss_score is not None else ""
                    ),
                    summary_block=summary_html,
                    validation_block=validation_html,
                    description=_escape_html(description),
                    poc_section=(
                        '<h4 style="font-size:13px;font-weight:600;color:#475569;margin:16px 0 6px;">'
                        'Proof of Concept</h4>'
                        '<div class="code-block">{}</div>'.format(_escape_html(poc_request))
                    ) if poc_request else "",
                    evidence=_escape_html(evidence),
                    repro=repro_html,
                    impact=_escape_html(impact_text),
                    enrichment=enrichment_html,
                    extra_details=extra_details_html,
                    remediation=remediation_html,
                ))

            findings_html_parts.append("</div>")

        # Attack chains section
        chains_html = ""
        if self.exploit_chains:
            chains_html = '<div class="section" id="attack-chains">'
            chains_html += '<h2 class="section-title">Attack Chains</h2>'
            for chain in self.exploit_chains:
                chains_html += '<div class="card">'
                chains_html += '<h3 style="font-size:15px;margin-bottom:12px;">{}</h3>'.format(
                    _escape_html(chain.get("name", "Unnamed Chain"))
                )
                steps = chain.get("steps", [])
                for i, step in enumerate(steps, 1):
                    chains_html += (
                        '<div class="chain-step">'
                        '<span class="chain-step-num">{}</span>'
                        '<span style="font-size:13px;padding-top:4px;">{}</span>'
                        '</div>'
                    ).format(i, _escape_html(step))
                    if i < len(steps):
                        chains_html += '<div class="chain-arrow">&#8595;</div>'
                impact = chain.get("impact", "")
                if impact:
                    chains_html += (
                        '<div style="margin-top:12px;padding:10px;background:#fef2f2;'
                        'border-radius:4px;border:1px solid #fecaca;">'
                        '<strong style="color:#991b1b;">Impact:</strong> '
                        '<span style="color:#991b1b;font-size:13px;">{}</span>'
                        '</div>'
                    ).format(_escape_html(impact))
                chains_html += "</div>"
            chains_html += "</div>"

        # Summary table
        summary_rows = ""
        for sev in SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c > 0:
                badge_cls = "badge-{}".format(sev.lower())
                summary_rows += (
                    '<tr><td><span class="badge {bc}">{sev}</span></td>'
                    '<td style="font-weight:700;font-size:16px;">{c}</td></tr>'
                ).format(bc=badge_cls, sev=sev, c=c)

        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Technical Security Report &mdash; Penetration Test</title>
<style>
{css}
</style>
</head>
<body>
<div class="header">
    <div>
        <h1>Penetration Test &mdash; Technical Report</h1>
        <div class="subtitle">Confidential &mdash; For Security Team Use Only</div>
    </div>
    <div class="meta">
        <div><strong>Target:</strong> {target}</div>
        <div><strong>Date:</strong> {scan_time}</div>
        {duration_line}
    </div>
</div>
<div class="container">

    <!-- Table of Contents -->
    <div class="section no-print">
        <h2 class="section-title">Table of Contents</h2>
        <div class="card">
            <ul class="toc">{toc}</ul>
        </div>
    </div>

    <!-- Summary -->
    <div class="section" id="summary">
        <h2 class="section-title">Summary</h2>
        <div class="stat-grid">
            <div class="stat-card">
                <div class="number">{total}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#dc2626;">{critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#ea580c;">{high}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#ca8a04;">{medium}</div>
                <div class="label">Medium + Low</div>
            </div>
        </div>
        <div class="card">
            <table>
                <thead><tr><th>Severity</th><th>Count</th></tr></thead>
                <tbody>{summary_rows}</tbody>
            </table>
        </div>
    </div>

    <!-- Findings -->
    {findings}

    <!-- Attack Chains -->
    {chains}

    <!-- Methodology -->
    <div class="section" id="methodology">
        <h2 class="section-title">Methodology</h2>
        <div class="card">
            <p style="font-size:13px;color:#334155;margin-bottom:12px;">
                This assessment was conducted using an automated penetration testing engine
                combining systematic crawling, parameter-level injection testing, and
                deterministic validation. All findings have been confirmed through
                proof-of-concept exploitation — no unvalidated or theoretical findings
                are included.
            </p>
            <table>
                <tr><td style="font-weight:600;width:180px;">Target</td>
                    <td>{target}</td></tr>
                <tr><td style="font-weight:600;">Date</td>
                    <td>{scan_time}</td></tr>
                {duration_row}
                <tr><td style="font-weight:600;">Tools</td>
                    <td>{tools}</td></tr>
                <tr><td style="font-weight:600;">Unique Endpoints</td>
                    <td>{endpoints}</td></tr>
                <tr><td style="font-weight:600;">Vulnerability Types Tested</td>
                    <td>{vuln_types}</td></tr>
            </table>
        </div>
    </div>

</div>
<div class="footer">
    Generated by Pentest Agent &mdash; Confidential &mdash; {scan_time}
</div>
</body>
</html>""".format(
            css=self._base_css(),
            target=_escape_html(self.target_display),
            scan_time=_escape_html(self.scan_time),
            duration_line=(
                "<div><strong>Duration:</strong> {:.0f}s</div>".format(self.scan_duration)
                if self.scan_duration else ""
            ),
            toc="\n".join(toc_items),
            total=total,
            critical=counts.get("Critical", 0),
            high=counts.get("High", 0),
            medium=counts.get("Medium", 0) + counts.get("Low", 0),
            summary_rows=summary_rows,
            findings="\n".join(findings_html_parts),
            chains=chains_html,
            duration_row=(
                "<tr><td style='font-weight:600;'>Duration</td>"
                "<td>{:.1f} seconds</td></tr>".format(self.scan_duration)
                if self.scan_duration else ""
            ),
            tools=_escape_html(", ".join(self.tools_used)),
            endpoints=self.stats["unique_endpoints"],
            vuln_types=self.stats["unique_vuln_types"],
        )

        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return abs_path

    # ── JSON Report ──────────────────────────────────────────────────

    def generate_json(self, output_path: str) -> str:
        """
        Generate a machine-readable JSON report for CI/CD integration.

        Returns the absolute path to the generated file.
        """
        enriched_findings = []
        for f in self.findings:
            cls = _classify_finding(f.get("vuln_type", ""))
            rk = _get_remediation_key(f.get("vuln_type", ""))

            enriched = {
                "id": _finding_id(f),
                "vuln_type": f.get("vuln_type", "Unknown"),
                "severity": f.get("severity", "Medium"),
                "url": f.get("url", ""),
                "method": f.get("method", ""),
                "parameter": f.get("param_name", ""),
                "payload": f.get("payload", ""),
                "evidence": f.get("evidence", ""),
                "source": f.get("source", ""),
                "classification": {
                    "cwe_id": cls["cwe"],
                    "cwe_name": cls["cwe_name"],
                    "owasp_id": cls["owasp"],
                    "owasp_name": cls["owasp_name"],
                    "category": cls["category"],
                },
                "remediation": (
                    REMEDIATION[rk]["description"] if rk and rk in REMEDIATION else None
                ),
                "impact": self._get_impact_assessment(rk, f.get("severity", "Medium")),
            }

            details = f.get("details")
            if isinstance(details, dict):
                skip_keys = {"validated", "type", "evidence", "url", "payload", "reason"}
                extra = {k: v for k, v in details.items() if k not in skip_keys}
                if extra:
                    enriched["details"] = extra

            enriched_findings.append(enriched)

        report = {
            "report_version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "scan_metadata": {
                "target": self.target,
                "target_host": self.target_host,
                "scan_time": self.scan_time,
                "scan_duration_seconds": self.scan_duration,
                "tools_used": self.tools_used,
            },
            "summary": {
                "total_findings": self.stats["total"],
                "risk_score": self.stats["risk_score"],
                "by_severity": self.stats["by_severity"],
                "unique_vuln_types": self.stats["unique_vuln_types"],
                "unique_endpoints": self.stats["unique_endpoints"],
            },
            "findings": enriched_findings,
        }

        if self.exploit_chains:
            report["exploit_chains"] = self.exploit_chains

        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        return abs_path

    # ── Generate All ─────────────────────────────────────────────────

    def generate_all(self, output_dir: str) -> dict:
        """
        Generate all three report types into the specified directory.

        Returns a dict with keys: executive_html, technical_html, json,
        each mapping to the absolute path of the generated file.
        """
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        host_slug = self.target_host.replace(".", "_").replace(":", "_")

        paths = {
            "executive_html": self.generate_executive_html(
                os.path.join(output_dir, "{}_{}_executive.html".format(host_slug, timestamp))
            ),
            "technical_html": self.generate_technical_html(
                os.path.join(output_dir, "{}_{}_technical.html".format(host_slug, timestamp))
            ),
            "json": self.generate_json(
                os.path.join(output_dir, "{}_{}_report.json".format(host_slug, timestamp))
            ),
        }

        return paths

    # ── Internal helpers ─────────────────────────────────────────────

    def _get_impact_assessment(self, remediation_key: Optional[str], severity: str) -> str:
        """Generate an impact assessment string based on vuln type and severity."""
        impacts = {
            "sqli": (
                "SQL Injection allows an attacker to read, modify, or delete database contents. "
                "In severe cases, it can lead to full server compromise through OS command "
                "execution via database functions (e.g., xp_cmdshell, INTO OUTFILE). "
                "Sensitive data including user credentials, personal information, and business "
                "data may be exfiltrated."
            ),
            "xss": (
                "Cross-Site Scripting allows an attacker to execute arbitrary JavaScript in "
                "victims' browsers. This can be used to steal session cookies, capture "
                "keystrokes, redirect users to phishing sites, or perform actions on behalf "
                "of authenticated users. Stored XSS affects all users who view the affected page."
            ),
            "command_injection": (
                "Command Injection allows an attacker to execute arbitrary operating system "
                "commands on the server. This typically leads to full server compromise, "
                "including access to all files, databases, and the ability to pivot to other "
                "internal systems."
            ),
            "path_traversal": (
                "Path Traversal allows an attacker to read arbitrary files on the server, "
                "including configuration files, source code, and sensitive system files "
                "such as /etc/passwd or database credentials. In some cases, it can be "
                "chained with file write capabilities for remote code execution."
            ),
            "csrf": (
                "Cross-Site Request Forgery allows an attacker to trick authenticated users "
                "into performing unintended actions such as changing passwords, transferring "
                "funds, or modifying account settings. The attack requires the victim to "
                "visit an attacker-controlled page while authenticated."
            ),
            "idor": (
                "Insecure Direct Object Reference allows unauthorized access to resources "
                "belonging to other users. An attacker can enumerate object identifiers to "
                "access, modify, or delete data they should not have permission to interact with."
            ),
            "open_redirect": (
                "Open Redirect can be used in phishing attacks by making malicious URLs "
                "appear legitimate. An attacker can redirect users to a look-alike login "
                "page to capture credentials. It may also be chained with SSRF or OAuth "
                "token theft."
            ),
            "ssrf": (
                "Server-Side Request Forgery allows an attacker to make the server perform "
                "requests to internal services, potentially accessing cloud metadata endpoints, "
                "internal APIs, or other services behind the firewall. In cloud environments, "
                "this can lead to credential theft and full infrastructure compromise."
            ),
            "security_headers": (
                "Missing security headers increase the application's exposure to various "
                "client-side attacks. Missing X-Frame-Options enables clickjacking, missing "
                "CSP allows XSS escalation, and server version disclosure aids targeted "
                "exploitation of known vulnerabilities."
            ),
            "sensitive_data": (
                "Exposure of sensitive information such as internal IP addresses, stack traces, "
                "or debug information helps attackers map the internal infrastructure and "
                "identify specific software versions with known vulnerabilities."
            ),
            "file_upload": (
                "Unrestricted file upload allows an attacker to upload malicious files such "
                "as web shells, leading to remote code execution on the server."
            ),
            "cors": (
                "CORS misconfiguration allows attacker-controlled websites to make "
                "authenticated cross-origin requests, potentially reading sensitive data "
                "or performing actions on behalf of the victim."
            ),
        }

        if remediation_key and remediation_key in impacts:
            return impacts[remediation_key]

        severity_fallback = {
            "Critical": "This is a critical severity finding that could lead to full system compromise. Immediate remediation is required.",
            "High": "This is a high severity finding that poses significant risk to the application and its users. Remediation should be prioritized.",
            "Medium": "This is a medium severity finding that should be addressed in the near term to reduce overall attack surface.",
            "Low": "This is a low severity finding that represents a hardening opportunity. Address as part of regular security maintenance.",
            "Informational": "This is an informational finding for awareness purposes.",
        }
        return severity_fallback.get(severity, "Requires assessment.")

    def _generate_finding_summary(
        self,
        vuln_type: str,
        url: str,
        param: str,
        method: str,
        payload: str,
        evidence: str,
        severity: str,
    ) -> str:
        """
        Generate a plain-English 2–3 sentence summary for non-technical readers.
        Answers: What was found? Where? What can an attacker do?
        """
        vt_lower = vuln_type.lower()
        rk = _get_remediation_key(vuln_type)

        # Endpoint reference (short)
        try:
            parsed = urlparse(url)
            loc = "{}{}".format(parsed.netloc or url, parsed.path or "")
        except Exception:
            loc = url

        param_ref = " via the '{}' parameter".format(param) if param else ""

        summaries = {
            "sqli": (
                "A SQL Injection vulnerability was confirmed at {loc}{param}. "
                "An attacker can send specially crafted database commands through this input "
                "to read, modify, or delete records in the backend database. "
                "This could expose user credentials, personal data, and all business records stored in the database."
            ),
            "xss": (
                "A Cross-Site Scripting (XSS) vulnerability was confirmed at {loc}{param}. "
                "An attacker can inject malicious JavaScript that runs in the browser of any user "
                "who visits the affected page. "
                "This enables session hijacking, credential theft, and impersonation of legitimate users."
            ),
            "command_injection": (
                "An OS Command Injection vulnerability was confirmed at {loc}{param}. "
                "An attacker can execute arbitrary operating system commands on the web server — "
                "the same commands an administrator would run on the machine. "
                "This typically leads to complete server compromise, data theft, and backdoor installation."
            ),
            "path_traversal": (
                "A Path Traversal vulnerability was confirmed at {loc}{param}. "
                "An attacker can read arbitrary files on the server by manipulating file path references, "
                "including sensitive configuration files, source code, and credential stores. "
                "In combination with other weaknesses, this can escalate to remote code execution."
            ),
            "csrf": (
                "A Cross-Site Request Forgery (CSRF) vulnerability was confirmed at {loc}. "
                "An attacker can trick a logged-in user into unknowingly performing actions — "
                "such as changing their password or submitting a form — just by visiting a malicious website. "
                "No interaction beyond a page visit is required from the victim."
            ),
            "idor": (
                "An Insecure Direct Object Reference (IDOR) vulnerability was confirmed at {loc}{param}. "
                "An attacker can access or modify data belonging to other users by changing "
                "an ID value in the request (e.g., changing user ID 42 to 43). "
                "This breaks data isolation between user accounts and violates access control boundaries."
            ),
            "ssrf": (
                "A Server-Side Request Forgery (SSRF) vulnerability was confirmed at {loc}{param}. "
                "An attacker can force the application server to make HTTP requests to internal systems "
                "that should not be accessible from the internet — including cloud metadata services, "
                "internal databases, and back-office APIs — potentially leaking credentials and sensitive data."
            ),
            "open_redirect": (
                "An Open Redirect vulnerability was confirmed at {loc}{param}. "
                "An attacker can craft a legitimate-looking URL on this site that silently redirects "
                "victims to a phishing page. "
                "This is commonly used to steal credentials by sending users to a fake login form "
                "that mimics the real application."
            ),
            "security_headers": (
                "Missing or misconfigured HTTP security headers were found on {loc}. "
                "Security headers instruct the browser on how to protect users — "
                "their absence makes the application more susceptible to clickjacking, "
                "cross-site scripting escalation, and MIME-type confusion attacks. "
                "These are typically configuration-only fixes with no code changes required."
            ),
            "sensitive_data": (
                "Sensitive information was found exposed in the HTTP response from {loc}. "
                "This may include internal IP addresses, software version numbers, stack traces, "
                "or API keys that an attacker can use to fingerprint the infrastructure "
                "and plan more targeted attacks."
            ),
            "cors": (
                "A CORS (Cross-Origin Resource Sharing) misconfiguration was found at {loc}. "
                "The server allows any website to make authenticated requests on behalf of a logged-in user, "
                "which means an attacker's website could silently read the user's private data "
                "or perform actions using their session."
            ),
            "file_upload": (
                "An unrestricted file upload vulnerability was confirmed at {loc}. "
                "An attacker can upload malicious server-side scripts (web shells) "
                "disguised as regular files, which can then be executed to gain "
                "remote code execution on the server."
            ),
        }

        template = summaries.get(rk or "")
        if template:
            return template.format(loc=loc, param=param_ref)

        # Generic fallback
        return (
            "A {} vulnerability ({} severity) was confirmed at {}{}.  "
            "An attacker may be able to exploit this to compromise data or application functionality. "
            "Immediate review and remediation is recommended."
        ).format(vuln_type, severity, loc, param_ref)

    def _generate_specific_description(
        self,
        vuln_type: str,
        url: str,
        param: str,
        method: str,
        payload: str,
        rk: Optional[str],
    ) -> str:
        """
        Generate a specific, finding-targeted technical description.
        Combines a technical explanation of the vuln class with finding-specific context.
        """
        try:
            parsed = urlparse(url)
            endpoint = "{}{}".format(parsed.netloc or url, parsed.path or "")
        except Exception:
            endpoint = url

        param_context = ""
        if param:
            param_context = (
                " The vulnerability was confirmed in the '{}' parameter "
                "submitted via {} to <code>{}</code>.".format(param, method, endpoint)
            )
        else:
            param_context = " The issue was identified on <code>{}</code>.".format(endpoint)

        active_payload = payload not in ("N/A", "N/A (passive check)", "N/A (passive scan)", "")
        payload_context = ""
        if active_payload:
            payload_context = (
                " The scanner confirmed exploitation using the payload: <code>{}</code>.".format(
                    payload[:150]
                )
            )

        base = ""
        if rk and rk in REMEDIATION:
            base = REMEDIATION[rk]["description"]
        else:
            base = "This finding requires review and appropriate remediation."

        return "{}{}{}".format(base, param_context, payload_context)
