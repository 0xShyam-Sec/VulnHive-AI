from pathlib import Path

import pytest


def test_weasyprint_renders_minimal_html(tmp_path: Path):
    from dashboard.pdf import render_pdf
    out = tmp_path / "report.pdf"
    html = "<!doctype html><html><body><h1>Test</h1><p>hi</p></body></html>"
    render_pdf(html, out, engine="weasyprint")
    assert out.exists()
    assert out.stat().st_size > 200


def test_unknown_engine_raises():
    from dashboard.pdf import render_pdf
    with pytest.raises(ValueError):
        render_pdf("<html></html>", Path("/tmp/x.pdf"), engine="not-a-thing")
