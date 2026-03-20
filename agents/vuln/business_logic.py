"""
BusinessLogicAgent — Tests for business logic vulnerabilities in payment/commerce endpoints.

Techniques:
1. Price Tampering — Modify price/amount/total/cost/fee fields with values like 0, -1, 0.01
2. Quantity Manipulation — Send negative, zero, or extremely high quantity values
3. Discount/Coupon Abuse — Set discount to 100 or 999, submit same coupon twice
4. Field Injection — Add unexpected fields like price=0, discount=100, is_free=true to requests

Only targets POST/PUT endpoints with commerce/payment keywords in URL.
"""

import httpx
import json
from agents.base import BaseAgent
from rich.console import Console
from urllib.parse import urlparse

console = Console()


class BusinessLogicAgent(BaseAgent):
    agent_name = "BusinessLogicAgent"
    vuln_type = "business_logic"
    model = "claude-haiku-4-5-20251001"
    max_iterations = 15

    # Keywords that identify commerce/payment endpoints
    COMMERCE_KEYWORDS = [
        "payment", "checkout", "cart", "order", "price",
        "billing", "invoice", "transfer", "amount", "quantity",
        "discount", "coupon", "total"
    ]

    # Field names to look for in request bodies
    PRICE_FIELDS = ["price", "amount", "total", "cost", "fee"]
    QUANTITY_FIELDS = ["quantity", "qty", "count"]
    DISCOUNT_FIELDS = ["discount", "coupon", "promo"]

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Test commerce/payment endpoints for business logic vulnerabilities.

        Args:
            endpoint: Endpoint object with url, method, params, body_fields, etc.
            config: ScanConfig object with auth headers, cookies, etc.
            state: ScanState object (for tracking, logging, etc.)

        Returns:
            List of finding dicts for confirmed vulnerabilities.
        """
        findings = []

        # Only test POST/PUT methods
        if endpoint.method not in ["POST", "PUT"]:
            return findings

        # Check if URL contains commerce/payment keywords
        url_lower = endpoint.url.lower()
        has_commerce_keyword = any(kw in url_lower for kw in self.COMMERCE_KEYWORDS)
        if not has_commerce_keyword:
            return findings

        # Get body fields from endpoint (could be empty dict)
        body_fields = getattr(endpoint, "body_fields", {}) or {}

        # Baseline request
        try:
            baseline_resp = self._make_request(
                endpoint.url,
                endpoint.method,
                config,
                body=body_fields
            )
            baseline_status = baseline_resp.status_code
            baseline_body = self._safe_get_response_body(baseline_resp)
        except Exception:
            return findings

        # Test 1: Price Tampering
        price_field = self._find_matching_field(body_fields, self.PRICE_FIELDS)
        if price_field:
            for tampered_value in [0, -1, 0.01]:
                tampered_body = body_fields.copy()
                tampered_body[price_field] = tampered_value
                try:
                    resp = self._make_request(
                        endpoint.url,
                        endpoint.method,
                        config,
                        body=tampered_body
                    )
                    if resp.status_code in [200, 201] and self._response_differs(resp, baseline_resp):
                        findings.append({
                            "validated": True,
                            "type": "Price Tampering",
                            "url": endpoint.url,
                            "param_name": price_field,
                            "method": endpoint.method,
                            "payload": f"{price_field}={tampered_value}",
                            "evidence": f"Server accepted {price_field}={tampered_value} with status {resp.status_code}",
                            "severity": "High",
                            "source": self.agent_name,
                            "vuln_type": self.vuln_type,
                        })
                        console.print(
                            f"  [bold red][{self.agent_name}] CONFIRMED: Price Tampering ({price_field}={tampered_value}) @ {endpoint.url}[/]"
                        )
                except Exception:
                    pass

        # Test 2: Quantity Manipulation
        quantity_field = self._find_matching_field(body_fields, self.QUANTITY_FIELDS)
        if quantity_field:
            for tampered_value in [-1, 0, 999999]:
                tampered_body = body_fields.copy()
                tampered_body[quantity_field] = tampered_value
                try:
                    resp = self._make_request(
                        endpoint.url,
                        endpoint.method,
                        config,
                        body=tampered_body
                    )
                    if resp.status_code in [200, 201] and self._response_differs(resp, baseline_resp):
                        findings.append({
                            "validated": True,
                            "type": "Quantity Manipulation",
                            "url": endpoint.url,
                            "param_name": quantity_field,
                            "method": endpoint.method,
                            "payload": f"{quantity_field}={tampered_value}",
                            "evidence": f"Server accepted {quantity_field}={tampered_value} with status {resp.status_code}",
                            "severity": "Medium",
                            "source": self.agent_name,
                            "vuln_type": self.vuln_type,
                        })
                        console.print(
                            f"  [bold red][{self.agent_name}] CONFIRMED: Quantity Manipulation ({quantity_field}={tampered_value}) @ {endpoint.url}[/]"
                        )
                except Exception:
                    pass

        # Test 3: Discount/Coupon Abuse
        discount_field = self._find_matching_field(body_fields, self.DISCOUNT_FIELDS)
        if discount_field:
            # Test 3a: High discount values
            for tampered_value in [100, 999]:
                tampered_body = body_fields.copy()
                tampered_body[discount_field] = tampered_value
                try:
                    resp = self._make_request(
                        endpoint.url,
                        endpoint.method,
                        config,
                        body=tampered_body
                    )
                    if resp.status_code in [200, 201] and self._response_differs(resp, baseline_resp):
                        findings.append({
                            "validated": True,
                            "type": "Discount/Coupon Abuse",
                            "url": endpoint.url,
                            "param_name": discount_field,
                            "method": endpoint.method,
                            "payload": f"{discount_field}={tampered_value}",
                            "evidence": f"Server accepted {discount_field}={tampered_value} with status {resp.status_code}",
                            "severity": "Medium",
                            "source": self.agent_name,
                            "vuln_type": self.vuln_type,
                        })
                        console.print(
                            f"  [bold red][{self.agent_name}] CONFIRMED: Discount Abuse ({discount_field}={tampered_value}) @ {endpoint.url}[/]"
                        )
                except Exception:
                    pass

            # Test 3b: Duplicate coupon code in one request (if it's a string field)
            if isinstance(body_fields.get(discount_field), str):
                original_value = body_fields.get(discount_field)
                if original_value:
                    tampered_body = body_fields.copy()
                    tampered_body[discount_field] = f"{original_value},{original_value}"
                    try:
                        resp = self._make_request(
                            endpoint.url,
                            endpoint.method,
                            config,
                            body=tampered_body
                        )
                        if resp.status_code in [200, 201] and self._response_differs(resp, baseline_resp):
                            findings.append({
                                "validated": True,
                                "type": "Coupon Duplication Abuse",
                                "url": endpoint.url,
                                "param_name": discount_field,
                                "method": endpoint.method,
                                "payload": f"{discount_field}={original_value},{original_value}",
                                "evidence": f"Server accepted duplicate coupon codes with status {resp.status_code}",
                                "severity": "Medium",
                                "source": self.agent_name,
                                "vuln_type": self.vuln_type,
                            })
                            console.print(
                                f"  [bold red][{self.agent_name}] CONFIRMED: Coupon Duplication @ {endpoint.url}[/]"
                            )
                    except Exception:
                        pass

        # Test 4: Field Injection
        injection_fields = [
            ("price", 0),
            ("discount", 100),
            ("is_free", True),
            ("trial", True),
        ]
        for inject_field, inject_value in injection_fields:
            # Only inject if field doesn't already exist
            if inject_field not in body_fields:
                tampered_body = body_fields.copy()
                tampered_body[inject_field] = inject_value
                try:
                    resp = self._make_request(
                        endpoint.url,
                        endpoint.method,
                        config,
                        body=tampered_body
                    )
                    if resp.status_code in [200, 201] and self._response_differs(resp, baseline_resp):
                        findings.append({
                            "validated": True,
                            "type": "Field Injection",
                            "url": endpoint.url,
                            "param_name": inject_field,
                            "method": endpoint.method,
                            "payload": f"{inject_field}={inject_value}",
                            "evidence": f"Server accepted injected field {inject_field}={inject_value} with status {resp.status_code}",
                            "severity": "Medium",
                            "source": self.agent_name,
                            "vuln_type": self.vuln_type,
                        })
                        console.print(
                            f"  [bold red][{self.agent_name}] CONFIRMED: Field Injection ({inject_field}) @ {endpoint.url}[/]"
                        )
                except Exception:
                    pass

        return findings

    def _make_request(self, url, method, config, body=None, extra_headers=None):
        """
        Make an HTTP request with auth headers and JSON body.

        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            config: ScanConfig with auth info
            body: Request body as dict (will be sent as JSON)
            extra_headers: Additional headers to include

        Returns:
            httpx.Response object
        """
        headers = config.get_auth_headers() if hasattr(config, "get_auth_headers") else {}
        headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        cookies = config.cookies if hasattr(config, "cookies") else {}

        client = httpx.Client(
            timeout=10,
            verify=False,
            headers=headers,
            cookies=cookies,
        )
        try:
            if body:
                resp = client.request(method.upper(), url, json=body)
            else:
                resp = client.request(method.upper(), url)
            return resp
        finally:
            client.close()

    def _find_matching_field(self, body_fields, field_names):
        """
        Find the first field in body_fields that matches any of the given field names.

        Args:
            body_fields: Dict of request body fields
            field_names: List of field names to match

        Returns:
            Matched field name or None
        """
        if not body_fields:
            return None
        for field_name in field_names:
            if field_name in body_fields:
                return field_name
        return None

    def _safe_get_response_body(self, resp):
        """
        Safely extract response body as text or dict.

        Args:
            resp: httpx.Response object

        Returns:
            Response body as string or dict, or empty string if failed
        """
        try:
            return resp.json()
        except Exception:
            try:
                return resp.text
            except Exception:
                return ""

    def _response_differs(self, resp1, resp2):
        """
        Compare two responses to see if they differ meaningfully.

        Args:
            resp1: httpx.Response object
            resp2: httpx.Response object

        Returns:
            True if responses differ, False otherwise
        """
        # Compare status codes
        if resp1.status_code != resp2.status_code:
            return True

        # Compare response bodies
        try:
            body1 = resp1.json()
            body2 = resp2.json()
            return body1 != body2
        except Exception:
            # Fall back to text comparison
            try:
                return resp1.text != resp2.text
            except Exception:
                return False
