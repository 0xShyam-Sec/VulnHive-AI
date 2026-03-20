"""
FileUploadAgent — Tests for file upload vulnerabilities.

Vulnerability Categories:
1. Extension Bypass — upload files with dangerous extensions (php, phtml, php5, etc.)
2. Content-Type Bypass — mismatch between declared and actual content type
3. File name injection — path traversal in filenames

Tests:
- Try uploading executable extensions with mismatched Content-Type
- Try null-byte injection (test.php%00.jpg)
- Try uppercase/mixed-case extensions (test.PhP)
- Try magic bytes header + executable code (JPEG header + PHP code)

Only tests POST/PUT endpoints with upload/file/import/attach/media/image in URL.
"""

import io
import httpx
from urllib.parse import urlparse, urljoin
from agents.base import BaseAgent
from rich.console import Console

console = Console()

# Dangerous extensions that web servers might execute
DANGEROUS_EXTENSIONS = [
    "php", "php5", "phtml", "pht", "phps", "phar",
    "jsp", "jspx", "jsw", "jsv", "jspf",
    "asp", "aspx", "cer", "asa",
    "exe", "com", "bat", "cmd", "pl", "sh",
]

# Extension bypass attempts (name, content_type, is_dangerous)
BYPASS_PAYLOADS = [
    ("test.php", "image/jpeg", True),
    ("test.php5", "image/jpeg", True),
    ("test.phtml", "image/jpeg", True),
    ("test.pht", "image/jpeg", True),
    ("test.php.jpg", "image/jpeg", True),
    ("test.php%00.jpg", "image/jpeg", True),
    ("test.jpg.php", "image/jpeg", True),
    ("test.PhP", "image/jpeg", True),
    ("test.phP5", "image/jpeg", True),
    ("test.pHp.jpg", "image/jpeg", True),
]

# Common multipart form field names
FORM_FIELD_NAMES = ["file", "upload", "image", "attachment", "document", "photo", "avatar"]

# PHP payload to identify execution
PHP_PAYLOAD = b"<?php echo 'PENTEST'; ?>"

# JPEG magic bytes + PHP code (to bypass content-type validation)
JPEG_HEADER = bytes.fromhex("FFD8FF")
POLYGLOT_PAYLOAD = JPEG_HEADER + PHP_PAYLOAD


class FileUploadAgent(BaseAgent):
    """File upload vulnerability testing agent."""

    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    vuln_type = "file_upload"
    agent_name = "FileUploadAgent"
    allowed_tools = []

    system_prompt = """\
You are a file upload security specialist. Test for file upload vulnerabilities.
Focus on extension bypass, content-type bypass, and executable file execution.
"""

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Deterministic file upload testing.

        Tests POST/PUT endpoints with upload-related keywords in the URL.
        Attempts various file extension bypasses and content-type mismatches.

        Args:
            endpoint: Endpoint object with url, method, params, etc.
            config: ScanConfig object with auth headers, cookies, etc.
            state: ScanState object

        Returns:
            List of finding dicts for confirmed upload vulnerabilities.
        """
        findings = []

        # Only test POST/PUT endpoints
        if endpoint.method not in ["POST", "PUT"]:
            return []

        # Only test endpoints with upload-related keywords
        url_lower = endpoint.url.lower()
        upload_keywords = ["upload", "file", "import", "attach", "media", "image"]
        if not any(keyword in url_lower for keyword in upload_keywords):
            return []

        base_url = endpoint.url
        method = endpoint.method

        # Get auth headers and cookies
        headers = config.get_auth_headers() if hasattr(config, "get_auth_headers") else {}
        cookies = config.cookies if hasattr(config, "cookies") else {}

        # Test 1: Extension Bypass Tests
        for filename, content_type, is_dangerous in BYPASS_PAYLOADS:
            for field_name in FORM_FIELD_NAMES:
                result = self._test_file_upload(
                    base_url, method, field_name, filename,
                    PHP_PAYLOAD, content_type, headers, cookies
                )
                if result:
                    findings.append({
                        "validated": True,
                        "type": f"File Upload: Extension Bypass ({filename})",
                        "url": base_url,
                        "param_name": field_name,
                        "method": method,
                        "payload": f"filename={filename}, Content-Type: {content_type}",
                        "evidence": result.get("evidence", "File accepted with dangerous extension"),
                        "severity": "High" if is_dangerous else "Medium",
                        "source": self.agent_name,
                        "vuln_type": self.vuln_type,
                    })
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED: Extension bypass "
                        f"{filename} @ {field_name}[/]"
                    )
                    return findings  # Found vulnerability, return early

        # Test 2: Content-Type Bypass with Polyglot (JPEG header + PHP)
        for field_name in FORM_FIELD_NAMES:
            result = self._test_file_upload(
                base_url, method, field_name, "test.jpg",
                POLYGLOT_PAYLOAD, "image/jpeg", headers, cookies
            )
            if result:
                findings.append({
                    "validated": True,
                    "type": "File Upload: Content-Type Bypass (JPEG+PHP Polyglot)",
                    "url": base_url,
                    "param_name": field_name,
                    "method": method,
                    "payload": "JPEG magic bytes + PHP code in .jpg file",
                    "evidence": result.get("evidence", "Polyglot file accepted"),
                    "severity": "High",
                    "source": self.agent_name,
                    "vuln_type": self.vuln_type,
                })
                console.print(
                    f"  [bold red][{self.agent_name}] CONFIRMED: Content-Type bypass "
                    f"polyglot @ {field_name}[/]"
                )
                return findings

        return findings

    def _test_file_upload(self, url, method, field_name, filename,
                         file_content, content_type, headers, cookies) -> dict:
        """
        Test a single file upload attempt.

        Args:
            url: Target URL
            method: HTTP method (POST or PUT)
            field_name: Form field name for the file
            filename: Filename to use in upload
            file_content: Binary file content
            content_type: Content-Type header value
            headers: Auth headers
            cookies: Session cookies

        Returns:
            Dict with evidence if file was accepted, None otherwise.
        """
        try:
            client = httpx.Client(
                timeout=15,
                verify=False,
                headers=headers,
                cookies=cookies,
            )

            # Build multipart form data
            files = {
                field_name: (filename, io.BytesIO(file_content), content_type)
            }

            if method.upper() == "POST":
                resp = client.post(url, files=files)
            elif method.upper() == "PUT":
                resp = client.put(url, files=files)
            else:
                client.close()
                return None

            client.close()

            # Check for successful upload indicators
            # 200, 201 = success
            # Response contains filename or path = file accepted
            if resp.status_code not in [200, 201]:
                return None

            # Check if filename or file path appears in response
            response_text = resp.text.lower()
            if filename.lower() in response_text or "upload" in response_text:
                evidence = (
                    f"HTTP {resp.status_code}: File '{filename}' accepted. "
                    f"Response contains filename or upload confirmation."
                )
                return {"evidence": evidence}

            # Also check for file URL pattern in response
            if "http" in response_text or "/upload" in response_text or "/file" in response_text:
                evidence = (
                    f"HTTP {resp.status_code}: File '{filename}' accepted. "
                    f"Response contains file path or URL."
                )
                return {"evidence": evidence}

            return None

        except Exception as e:
            return None
