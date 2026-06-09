"""Cross-platform PDF rendering.

Default engine: WeasyPrint — pure Python, Linux/Windows/macOS, no browser dependency.
Optional: Playwright (bundled Chromium) for JS-rendered chart libraries.

Set environment variable VULNHIVE_PDF_ENGINE=playwright to switch globally,
or pass engine="playwright" per call.
"""

from __future__ import annotations

import os
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
_DEFAULT_ENGINE = os.environ.get("VULNHIVE_PDF_ENGINE", "weasyprint")


def render_pdf(html: str, out_path: Path, engine: str = None) -> Path:
    """Render `html` to `out_path` as PDF. Returns out_path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    engine = (engine or _DEFAULT_ENGINE).lower()

    if engine == "weasyprint":
        from weasyprint import HTML
        HTML(string=html, base_url=str(REPORTS_DIR)).write_pdf(str(out_path))
        return out_path

    if engine == "playwright":
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(html, wait_until="networkidle")
            page.pdf(path=str(out_path), format="A4", print_background=True)
            browser.close()
        return out_path

    raise ValueError(f"unknown PDF engine: {engine!r} (choices: weasyprint, playwright)")
