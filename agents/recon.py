"""
ReconAgent — maps the attack surface via direct tool call.
No LLM tokens needed for crawling — scan_target is deterministic.
"""

import json
from rich.console import Console

console = Console()


class ReconAgent:
    """
    Direct recon agent — calls scan_target without LLM overhead.
    Returns raw attack surface dict for use by all vuln agents.
    """

    async def run_recon(self, target: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        """Crawl target and return full attack surface map."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._crawl, target, max_depth, max_pages)

    def _crawl(self, target: str, max_depth: int, max_pages: int) -> dict:
        from tools import TOOL_DISPATCH
        console.print(f"  [dim]ReconAgent: crawling {target}...[/]")
        result = TOOL_DISPATCH["scan_target"](
            base_url=target,
            max_depth=max_depth,
            max_pages=max_pages,
        )

        # Enrich with explicit parameters from forms
        test_targets = self._extract_test_targets(result, target, TOOL_DISPATCH)
        result["test_targets"] = test_targets

        pages = len(result.get("pages_visited", []))
        endpoints = len(result.get("attack_surface", []))
        console.print(
            f"  [dim]ReconAgent: {pages} pages, {endpoints} endpoints, "
            f"{len(test_targets)} testable param(s)[/]"
        )
        return result

    def _extract_test_targets(self, scan_result: dict, target: str, TOOL_DISPATCH) -> list:
        """
        Build a flat list of {url, param, method} from the attack surface.
        This is what each vuln agent actually iterates over.
        """
        test_targets = []
        seen = set()

        # From scan_target forms
        for form in scan_result.get("forms", []):
            url = form.get("action") or form.get("url") or target
            method = form.get("method", "GET").upper()
            for field in form.get("inputs", []):
                name = field.get("name", "")
                if name and name not in ("submit", "csrf_token", "token"):
                    key = (url, name, method)
                    if key not in seen:
                        seen.add(key)
                        test_targets.append({"url": url, "param": name, "method": method})

        # From attack surface endpoints
        for ep in scan_result.get("attack_surface", []):
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            for param in ep.get("params", []):
                if param:
                    key = (url, param, method)
                    if key not in seen:
                        seen.add(key)
                        test_targets.append({"url": url, "param": param, "method": method})

        # Fallback: extract forms directly from known DVWA-style paths
        if not test_targets:
            console.print("  [dim]ReconAgent: extracting forms from discovered pages...[/]")
            pages = scan_result.get("pages_visited", [])
            for page_url in pages[:20]:
                try:
                    forms = TOOL_DISPATCH["extract_forms"](url=page_url)
                    for form in forms.get("forms", []):
                        action = form.get("action") or page_url
                        method = form.get("method", "GET").upper()
                        for field in form.get("inputs", []):
                            name = field.get("name", "")
                            if name and name.lower() not in ("submit", "csrf_token", "token", "btnsubmit"):
                                key = (action, name, method)
                                if key not in seen:
                                    seen.add(key)
                                    test_targets.append({"url": action, "param": name, "method": method})
                except Exception:
                    pass

        return test_targets
